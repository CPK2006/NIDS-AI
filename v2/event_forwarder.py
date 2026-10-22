"""Optional, bounded sender for the durable local event outbox."""

from __future__ import annotations

import ipaddress
import logging
import os
import threading
from urllib.parse import urlsplit

import requests


logger = logging.getLogger(__name__)
MAX_BATCH_SIZE = 100
MAX_ATTEMPTS = 8
MAX_BACKOFF_SECONDS = 256


def _enabled(value: str | None) -> bool:
    return (value or "").strip().lower() in {"1", "true", "yes", "on"}


def validate_endpoint(endpoint: str) -> str:
    parsed = urlsplit(endpoint)
    if parsed.scheme not in {"https", "http"} or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("forwarding endpoint must be an HTTP(S) URL without embedded credentials")
    try:
        loopback = ipaddress.ip_address(parsed.hostname).is_loopback
    except ValueError:
        loopback = parsed.hostname.lower() == "localhost"
    if parsed.scheme != "https" and not loopback:
        raise ValueError("HTTPS is required for non-loopback forwarding endpoints")
    if parsed.query or parsed.fragment:
        raise ValueError("forwarding endpoint cannot contain a query string or fragment")
    return endpoint


class EventForwarder:
    """Sends leased outbox batches; only server 2xx responses acknowledge events."""

    def __init__(self, repository, endpoint: str, api_key: str, *, timeout: float = 5.0,
                 batch_size: int = MAX_BATCH_SIZE, session=None):
        if not api_key or len(api_key) < 32:
            raise ValueError("sensor API key must contain at least 32 characters")
        if type(batch_size) is not int or not 1 <= batch_size <= MAX_BATCH_SIZE:
            raise ValueError("forwarding batch size must be between 1 and 100")
        self.repository = repository
        self.endpoint = validate_endpoint(endpoint)
        self.api_key = api_key
        self.timeout = max(0.1, min(float(timeout), 20.0))
        self.batch_size = batch_size
        self.session = session or requests.Session()

    @classmethod
    def from_environment(cls, repository):
        if not _enabled(os.getenv("NETRA_FORWARDING_ENABLED")):
            return None
        if not all(hasattr(repository, method) for method in ("claim_outbox", "acknowledge_outbox", "retry_outbox")):
            raise RuntimeError("event forwarding requires a repository with a durable outbox (SQLite)")
        endpoint = os.getenv("NETRA_INGESTION_URL", "")
        api_key = os.getenv("NETRA_SENSOR_API_KEY", "")
        if not endpoint or not api_key:
            raise RuntimeError("enabled forwarding requires NETRA_INGESTION_URL and NETRA_SENSOR_API_KEY")
        return cls(repository, endpoint, api_key,
                   timeout=float(os.getenv("NETRA_FORWARD_TIMEOUT_SECONDS", "5")),
                   batch_size=int(os.getenv("NETRA_FORWARD_BATCH_SIZE", str(MAX_BATCH_SIZE))))

    def send_once(self) -> int:
        lease_token, events, prior_attempts = self.repository.claim_outbox(limit=self.batch_size)
        if not events:
            return 0
        event_ids = [event["event_id"] for event in events]
        try:
            response = self.session.post(
                self.endpoint,
                json={"events": events},
                headers={"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"},
                timeout=self.timeout,
                allow_redirects=False,
            )
            status = int(response.status_code)
        except requests.RequestException as exc:
            attempt = prior_attempts + 1
            delay = min(2 ** min(attempt, 8), MAX_BACKOFF_SECONDS)
            blocked = attempt >= MAX_ATTEMPTS
            self.repository.retry_outbox(
                event_ids, lease_token, delay_seconds=delay,
                error_code=f"network_{type(exc).__name__}", blocked=blocked,
            )
            logger.warning("event forwarding deferred (%s)%s", type(exc).__name__, "; retry limit reached" if blocked else "")
            return 0

        if 200 <= status < 300:
            return self.repository.acknowledge_outbox(event_ids, lease_token)
        permanent = (400 <= status < 500 and status not in {408, 429}) or 300 <= status < 400
        attempt = prior_attempts + 1
        blocked = permanent or attempt >= MAX_ATTEMPTS
        delay = min(2 ** min(attempt, 8), MAX_BACKOFF_SECONDS)
        self.repository.retry_outbox(
            event_ids, lease_token, delay_seconds=delay,
            error_code=f"http_{status}", blocked=blocked,
        )
        logger.warning("event forwarding rejected (HTTP %s)%s", status, "; batch retained for operator review" if blocked else "; retry scheduled")
        return 0

class ForwardingWorker:
    def __init__(self, forwarder: EventForwarder, *, poll_seconds: float = 2.0):
        self.forwarder = forwarder
        self.poll_seconds = max(0.1, float(poll_seconds))
        self._stop = threading.Event()
        self._thread = None

    def start(self) -> None:
        if self._thread is None or not self._thread.is_alive():
            self._stop.clear()
            self._thread = threading.Thread(target=self._run, name="netra-event-forwarder", daemon=True)
            self._thread.start()

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                count = self.forwarder.send_once()
            except Exception as exc:
                logger.warning("event forwarding worker error (%s)", type(exc).__name__)
                count = 0
            if count == 0:
                self._stop.wait(self.poll_seconds)

    def stop(self, timeout: float = 2.0) -> bool:
        self._stop.set()
        if self._thread is None:
            return True
        self._thread.join(max(0.0, timeout))
        return not self._thread.is_alive()
