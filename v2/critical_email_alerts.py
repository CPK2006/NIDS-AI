"""Live-session critical-state policy and bounded asynchronous Resend delivery."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import parseaddr
import logging
import os
import queue
import re
import threading
import time
import uuid
import atexit
from typing import Any, Callable, Mapping

import requests
from v2.event_store import (
    PostgreSQLEventRepository, SQLiteEventRepository, create_delivery_repository,
)


logger = logging.getLogger(__name__)
RESEND_EMAILS_URL = "https://api.resend.com/emails"
_EMAIL_PATTERN = re.compile(r"^[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+$")


def _env_int(name: str, default: int, minimum: int, maximum: int) -> int:
    try:
        value = int(os.getenv(name, str(default)))
    except (TypeError, ValueError):
        return default
    return value if minimum <= value <= maximum else default


@dataclass(frozen=True)
class CriticalPolicySettings:
    window_size: int = 20
    attack_threshold: int = 10
    recovery_threshold: int = 4

    def __post_init__(self) -> None:
        if (type(self.window_size) is not int or not 2 <= self.window_size <= 1000
                or type(self.attack_threshold) is not int or not 1 <= self.attack_threshold <= self.window_size
                or type(self.recovery_threshold) is not int
                or not 0 <= self.recovery_threshold < self.attack_threshold):
            raise ValueError("invalid critical-state policy thresholds")

    @classmethod
    def from_environment(cls) -> "CriticalPolicySettings":
        window = _env_int("NETRA_CRITICAL_WINDOW", 20, 2, 1000)
        critical = _env_int("NETRA_CRITICAL_ATTACKS", min(10, window), 1, window)
        recovery = _env_int("NETRA_CRITICAL_RECOVERY_ATTACKS", min(4, critical - 1), 0, critical - 1)
        return cls(window, critical, recovery)


class CriticalStatePolicy:
    """Detect entry/recovery transitions for the currently authorized live run."""

    def __init__(self, settings: CriticalPolicySettings | None = None):
        self.settings = settings or CriticalPolicySettings.from_environment()
        self._lock = threading.Lock()
        self._session_id: str | None = None
        self._labels: deque[str] = deque(maxlen=self.settings.window_size)
        self._active = False

    def begin_live_session(self, session_id: str) -> None:
        with self._lock:
            self._session_id = session_id
            self._labels.clear()
            self._active = False

    def end_live_session(self, session_id: str | None) -> None:
        with self._lock:
            if session_id is not None and session_id == self._session_id:
                self._session_id = None
                self._labels.clear()
                self._active = False

    def observe(self, *, origin: str, session_id: str | None, classification: str) -> dict[str, Any] | None:
        """Return one new incident on critical entry; return nothing for every other state."""
        with self._lock:
            if (origin != "live" or not session_id or session_id != self._session_id
                    or classification not in {"ATTACK", "BENIGN"}):
                return None
            self._labels.append(classification)
            attack_count = sum(label == "ATTACK" for label in self._labels)
            if self._active:
                if attack_count <= self.settings.recovery_threshold:
                    self._active = False
                return None
            if attack_count < self.settings.attack_threshold:
                return None
            self._active = True
            return {
                "alert_id": str(uuid.uuid4()),
                "session_id": session_id,
                "attack_count": attack_count,
                "window_size": self.settings.window_size,
                "occurred_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
            }

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {
                "critical": self._active,
                "attack_count": sum(label == "ATTACK" for label in self._labels),
                "window_size": self.settings.window_size,
                "attack_threshold": self.settings.attack_threshold,
                "recovery_threshold": self.settings.recovery_threshold,
            }


@dataclass(frozen=True)
class ResendConfig:
    enabled: bool
    api_key: str
    sender: str
    recipient: str
    timeout_seconds: float = 5.0
    max_attempts: int = 4
    queue_size: int = 100

    @staticmethod
    def _valid_address(value: str) -> bool:
        if not isinstance(value, str) or "\r" in value or "\n" in value:
            return False
        try:
            address = parseaddr(value)[1]
        except (TypeError, ValueError):
            return False
        return bool(_EMAIL_PATTERN.fullmatch(address))

    @classmethod
    def from_environment(cls) -> "ResendConfig":
        enabled = os.getenv("NETRA_EMAIL_ALERTS_ENABLED", "false").strip().lower() in {"1", "true", "yes", "on"}
        key = os.getenv("RESEND_API_KEY", "").strip()
        sender = os.getenv("RESEND_FROM_EMAIL", "").strip()
        recipient = os.getenv("RESEND_TO_EMAIL", "").strip()
        try:
            timeout = min(30.0, max(1.0, float(os.getenv("NETRA_EMAIL_TIMEOUT_SECONDS", "5"))))
        except ValueError:
            timeout = 5.0
        return cls(
            enabled=enabled,
            api_key=key,
            sender=sender,
            recipient=recipient,
            timeout_seconds=timeout,
            max_attempts=_env_int("NETRA_EMAIL_MAX_ATTEMPTS", 4, 1, 8),
            queue_size=_env_int("NETRA_EMAIL_QUEUE_SIZE", 100, 1, 10000),
        )

    @property
    def configured(self) -> bool:
        return bool(self.api_key and self._valid_address(self.sender) and self._valid_address(self.recipient))


class ResendEmailWorker:
    """SQLite-backed, leased outbox sender. Sending always happens on its worker thread."""

    def __init__(self, config: ResendConfig, *, repository=None, session=None,
                 sleeper: Callable[[float], None] = time.sleep, poll_interval: float = 1.0,
                 autostart: bool = True):
        self.config = config
        self.session = session or requests.Session()
        self._sleep = sleeper
        self.repository = repository or SQLiteEventRepository()
        self._lock = threading.Lock()
        self._wake = threading.Event()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._storage_error: str | None = None
        self._persistence_error_code: str | None = None
        self._pending_persistence: queue.Queue[tuple[dict[str, Any], int]] = queue.Queue(
            maxsize=self.config.queue_size
        )
        self._poll_interval = max(0.1, min(float(poll_interval), 30.0))
        if autostart:
            self.start()

    def configuration_status(self) -> dict[str, str | bool]:
        if not self.config.enabled:
            return {"state": "disabled", "message": "Email alerts are disabled."}
        if not self.config.configured:
            return {"state": "not_configured", "message": "Email alerts enabled, but Resend key or sender/recipient address is missing or invalid."}
        return {"state": "ready", "message": "Resend email alerts are configured."}

    def submit(self, incident: Mapping[str, Any]) -> bool:
        if isinstance(self.repository, PostgreSQLEventRepository):
            # Keep the packet/inference callback off the network-backed database
            # path. A false return means it is staged, not yet durably queued.
            try:
                self._pending_persistence.put_nowait((dict(incident), 0))
            except queue.Full:
                with self._lock:
                    self._storage_error = "PersistenceQueueFull"
                    self._persistence_error_code = "PersistenceQueueFull"
                logger.error("critical alert persistence queue is full")
                return False
            self.start()
            self._wake.set()
            return False
        # Persist even while delivery is disabled or misconfigured. A later enabled
        # restart can resume this eligible live incident without losing the audit.
        try:
            self.repository.enqueue_critical_alert(incident)
            with self._lock:
                self._storage_error = None
            self.start()
            self._wake.set()
            return True
        except Exception as exc:
            code = type(exc).__name__
            with self._lock:
                self._storage_error = code
            logger.warning("critical alert outbox write failed (%s)", code)
            return False

    def start(self) -> None:
        if (self.configuration_status()["state"] != "ready"
                and not isinstance(self.repository, PostgreSQLEventRepository)) or self._stop.is_set():
            return
        with self._lock:
            if self._thread is None or not self._thread.is_alive():
                self._thread = threading.Thread(target=self._run, name="netra-resend-alert-worker", daemon=True)
                self._thread.start()

    def _run(self) -> None:
        storage_backoff = 1.0
        while True:
            if self._stop.is_set():
                return
            try:
                if isinstance(self.repository, PostgreSQLEventRepository):
                    try:
                        staged, persistence_attempt = self._pending_persistence.get_nowait()
                    except queue.Empty:
                        staged = None
                    if staged is not None:
                        try:
                            self.repository.enqueue_critical_alert(staged)
                            with self._lock:
                                self._storage_error = None
                                self._persistence_error_code = None
                            storage_backoff = 1.0
                            self._pending_persistence.task_done()
                        except Exception as exc:
                            code = type(exc).__name__
                            if persistence_attempt < 2 and not self._stop.is_set():
                                delay = min(2 ** persistence_attempt, 4)
                                self._sleep(delay)
                                try:
                                    self._pending_persistence.put_nowait((staged, persistence_attempt + 1))
                                except queue.Full:
                                    with self._lock:
                                        self._storage_error = "PersistenceQueueFull"
                                        self._persistence_error_code = "PersistenceQueueFull"
                                    self._pending_persistence.task_done()
                            else:
                                with self._lock:
                                    self._storage_error = code
                                    self._persistence_error_code = code
                                logger.error("critical alert persistence failed after bounded attempts (%s)", code)
                                self._pending_persistence.task_done()
                        continue
                if self.configuration_status()["state"] != "ready":
                    self._wake.wait(self._poll_interval)
                    self._wake.clear()
                    continue
                # One HTTP attempt is made per claim; the lease covers its timeout
                # and the subsequent SQLite state update with a safety margin.
                lease_seconds = min(3600, int(self.config.timeout_seconds * self.config.max_attempts +
                                                sum(min(2 ** n, 30) for n in range(self.config.max_attempts)) + 30))
                lease, batch = self.repository.claim_critical_alerts(limit=1, lease_seconds=lease_seconds)
                with self._lock:
                    self._storage_error = None
                storage_backoff = 1.0
                if not batch:
                    self._wake.wait(self._poll_interval)
                    self._wake.clear()
                    continue
                incident = batch[0]
                self._deliver_claimed(incident, lease)
            except Exception as exc:
                code = type(exc).__name__
                with self._lock:
                    self._storage_error = code
                logger.warning("critical email outbox worker failed (%s)", code)
                self._wake.wait(storage_backoff)
                self._wake.clear()
                storage_backoff = min(storage_backoff * 2, 30.0)

    @staticmethod
    def _payload(incident: Mapping[str, Any]) -> dict[str, Any]:
        return {
            "from": "",
            "to": [],
            "subject": "NETRA critical live detection state",
            "text": (
                "NETRA entered its critical live detection state.\n"
                f"Incident ID: {incident['alert_id']}\n"
                f"Live capture session: {incident['session_id']}\n"
                f"ATTACK classifications in the rolling window: {incident['attack_count']} / {incident['window_size']}\n"
                f"Detected at (UTC): {incident['occurred_at_utc']}\n\n"
                "Recovery does not generate an email. No IP addresses or packet contents are included."
            ),
        }

    def _attempt_delivery(self, incident: Mapping[str, Any]) -> tuple[bool, bool, str | None]:
        payload = self._payload(incident)
        payload["from"] = self.config.sender
        payload["to"] = [self.config.recipient]
        try:
            response = self.session.post(
                RESEND_EMAILS_URL,
                headers={"Authorization": f"Bearer {self.config.api_key}",
                         "Idempotency-Key": str(incident["alert_id"])},
                json=payload, timeout=self.config.timeout_seconds,
            )
            status = int(response.status_code)
            if 200 <= status < 300:
                return True, False, None
            code = f"http_{status}"
            return False, status in {408, 429} or status >= 500, code
        except requests.RequestException as exc:
            return False, True, type(exc).__name__
        except Exception as exc:
            return False, False, type(exc).__name__

    def _deliver_claimed(self, incident: Mapping[str, Any], lease_token: str) -> bool:
        success, retryable, code = self._attempt_delivery(incident)
        if success:
            updated = self.repository.complete_critical_alert(incident["alert_id"], lease_token)
            if not updated:
                # Lease was lost; let its expiry recover the incident. Stable provider
                # idempotency key handles accepted-but-unrecorded delivery ambiguity.
                logger.warning("critical alert completion lost its lease")
            return updated
        exhausted = retryable and int(incident["attempts_in_cycle"]) >= self.config.max_attempts
        delay = min(2 ** max(0, int(incident["attempts_in_cycle"]) - 1), 300) if retryable and not exhausted else 0
        self.repository.fail_critical_alert(
            incident["alert_id"], lease_token, error_code=code or "delivery_failed",
            delay_seconds=delay, permanent=not retryable, exhausted=exhausted,
        )
        logger.warning("critical email delivery %s (%s)", "exhausted retries" if exhausted else "failed", code)
        return False

    # Kept as a direct helper for isolated unit tests; production uses the leased,
    # persistent _deliver_claimed path exclusively.
    def _deliver(self, incident: Mapping[str, Any]) -> bool:
        for attempt in range(self.config.max_attempts):
            success, retryable, _code = self._attempt_delivery(incident)
            if success or not retryable:
                return success
            if attempt + 1 < self.config.max_attempts:
                self._sleep(min(2 ** attempt, 30))
        return False

    def status_snapshot(self) -> dict[str, Any]:
        config = self.configuration_status()
        with self._lock:
            storage_error = self._storage_error
            persistence_error = self._persistence_error_code
        try:
            counts = self.repository.critical_email_alert_counts()
            failures = self.repository.list_critical_email_alerts(state="failed", limit=20)
            with self._lock:
                if persistence_error is None:
                    self._storage_error = None
                    storage_error = None
                else:
                    storage_error = persistence_error
        except Exception as exc:
            counts = {"pending": 0, "retrying": 0, "delivered": 0, "failed": 0}
            failures = []
            storage_error = type(exc).__name__
        if persistence_error:
            config = {"state": "storage_error",
                      "message": "An incident could not be durably stored; inspect the sanitized storage error status."}
        return {**config, **counts, "sent": counts["delivered"], "queued": counts["pending"],
                "storage_status": "error" if storage_error else "ok",
                "storage_error_code": storage_error,
                "persistence_error_code": persistence_error,
                "staged_not_persisted": self._pending_persistence.qsize(),
                "recent_failures": failures}

    def recent_failures(self) -> list[dict[str, str]]:
        try:
            return self.repository.list_critical_email_alerts(state="failed", limit=20)
        except Exception:
            return []

    def retry_failed(self, alert_ids: list[str]) -> int:
        retried = self.repository.retry_failed_critical_alerts(alert_ids)
        if retried:
            self.start()
            self._wake.set()
        return retried

    def close(self, timeout: float = 2.0) -> bool:
        self._stop.set()
        self._wake.set()
        with self._lock:
            thread = self._thread
        if thread is None or not thread.is_alive():
            return True
        thread.join(max(0.0, timeout))
        return not thread.is_alive()


class CriticalEmailAlerts:
    """Couples the trusted live-flow policy to an asynchronous email sender."""

    def __init__(self, *, policy: CriticalStatePolicy | None = None, notifier: ResendEmailWorker | None = None,
                 repository=None):
        self.policy = policy or CriticalStatePolicy()
        if notifier is None:
            configured_path = os.getenv("NETRA_EMAIL_ALERT_DB_PATH")
            delivery_backend = os.getenv("NETRA_DELIVERY_BACKEND", "").strip().lower()
            if delivery_backend and delivery_backend not in {"sqlite", "postgres", "postgresql"}:
                raise ValueError("NETRA_DELIVERY_BACKEND must be 'sqlite' or 'postgresql'")
            if delivery_backend in {"postgres", "postgresql"}:
                alert_repository = create_delivery_repository(role="local_sensor", backend=delivery_backend)
            elif configured_path:
                alert_repository = create_delivery_repository(role="local_sensor", backend="sqlite",
                                                               sqlite_path=configured_path)
            elif isinstance(repository, SQLiteEventRepository):
                alert_repository = repository
            else:
                alert_repository = create_delivery_repository(
                    role="local_sensor", backend="sqlite",
                    sqlite_path=os.path.join(os.path.dirname(os.path.dirname(__file__)),
                                             "data", "netra_email_alerts.sqlite3"),
                )
            self.notifier = ResendEmailWorker(ResendConfig.from_environment(), repository=alert_repository)
        else:
            self.notifier = notifier

    def begin_live_session(self, session_id: str) -> None:
        self.policy.begin_live_session(session_id)

    def end_live_session(self, session_id: str | None) -> None:
        self.policy.end_live_session(session_id)

    def observe_flow(self, *, origin: str, session_id: str | None, classification: str) -> bool:
        incident = self.policy.observe(origin=origin, session_id=session_id, classification=classification)
        if incident is None:
            return False
        return self.notifier.submit(incident)

    def status_snapshot(self) -> dict[str, Any]:
        delivery = self.notifier.status_snapshot()
        return {**delivery, "policy": self.policy.snapshot()}


def main() -> int:
    """Run the dedicated hosted PostgreSQL email worker until shutdown."""
    try:
        from dotenv import load_dotenv
        from pathlib import Path
        load_dotenv(Path(__file__).resolve().parents[1] / ".env")
    except ImportError:
        pass
    role = os.getenv("NETRA_RUNTIME_ROLE", "").strip().lower()
    if role != "hosted_worker":
        raise SystemExit("Set NETRA_RUNTIME_ROLE=hosted_worker to run the shared outbox worker")
    repository = create_delivery_repository(role=role)
    config = ResendConfig.from_environment()
    if not config.enabled or not config.configured:
        raise SystemExit("Hosted worker requires enabled Resend settings; configuration values are not displayed")
    worker = ResendEmailWorker(config, repository=repository, autostart=True)
    atexit.register(worker.close)
    logger.info("NETRA hosted email worker started")
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        logger.info("NETRA hosted email worker stopping")
    finally:
        worker.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
