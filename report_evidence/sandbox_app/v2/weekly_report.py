"""Seven-day monitoring summaries and an idempotent Resend report outbox."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, time as datetime_time, timedelta, timezone
import json
import logging
import os
from pathlib import Path
import re
import time
from typing import Any, Callable, Mapping
import uuid
from zoneinfo import ZoneInfo

import requests

from v2.critical_email_alerts import RESEND_EMAILS_URL, ResendConfig
from v2.event_store import (
    SQLiteEventRepository, _parse_interval_time, _utc_iso,
    create_delivery_repository, create_event_repository,
)


logger = logging.getLogger(__name__)
REPORT_ID_NAMESPACE = uuid.UUID("c4a5917a-509e-40af-b5c6-4a6dd6e92522")
REPORT_ZONE = ZoneInfo("Asia/Kolkata")
REPORT_ORIGINS = ("live", "pcap", "simulation")
REPORT_EVENT_TYPES = ("flow_classification", "alert", "capture_error", "processing_error")


def _safe_error_code(value: Any) -> str:
    code = str(value)
    return code if re.fullmatch(r"(?:http_[1-5][0-9]{2}|[A-Za-z][A-Za-z0-9_]{0,39})", code) else "delivery_failed"


def weekly_reporting_interval(now: datetime | None = None) -> tuple[datetime, datetime]:
    """Return the most recent Monday 09:00 Asia/Kolkata boundary and prior 7 days in UTC."""
    current = _parse_interval_time(now or datetime.now(timezone.utc), "now").astimezone(REPORT_ZONE)
    days_since_monday = current.weekday()
    monday = current.date() - timedelta(days=days_since_monday)
    boundary = datetime.combine(monday, datetime_time(9, 0), tzinfo=REPORT_ZONE)
    if current < boundary:
        boundary -= timedelta(days=7)
    end = boundary.astimezone(timezone.utc)
    return end - timedelta(days=7), end


def _report_id(start: datetime, end: datetime) -> str:
    canonical = f"netra-weekly-report:{_utc_iso(start, 'start')}:{_utc_iso(end, 'end')}"
    return str(uuid.uuid5(REPORT_ID_NAMESPACE, canonical))


@dataclass(frozen=True)
class WeeklyReportConfig:
    enabled: bool = False
    api_key: str = ""
    sender: str = ""
    recipient: str = ""
    timeout_seconds: float = 5.0
    max_attempts: int = 4

    @classmethod
    def from_environment(cls) -> "WeeklyReportConfig":
        enabled = os.getenv("NETRA_WEEKLY_REPORT_ENABLED", "false").strip().lower() in {"1", "true", "yes", "on"}
        try:
            timeout = min(30.0, max(1.0, float(os.getenv("NETRA_EMAIL_TIMEOUT_SECONDS", "5"))))
        except (TypeError, ValueError):
            timeout = 5.0
        try:
            attempts = int(os.getenv("NETRA_EMAIL_MAX_ATTEMPTS", "4"))
        except (TypeError, ValueError):
            attempts = 4
        return cls(
            enabled=enabled,
            api_key=os.getenv("RESEND_API_KEY", "").strip(),
            sender=os.getenv("RESEND_FROM_EMAIL", "").strip(),
            recipient=os.getenv("NETRA_WEEKLY_REPORT_TO_EMAIL", "").strip(),
            timeout_seconds=timeout,
            max_attempts=max(1, min(attempts, 8)),
        )

    @property
    def configured(self) -> bool:
        return bool(self.api_key and ResendConfig._valid_address(self.sender)
                    and ResendConfig._valid_address(self.recipient))

    def status(self) -> dict[str, str]:
        if not self.enabled:
            return {"state": "disabled", "message": "Weekly email reports are disabled."}
        if not self.configured:
            return {"state": "not_configured", "message": "Weekly email reports need a Resend key, sender, and report recipient."}
        return {"state": "ready", "message": "Weekly email report delivery is configured."}


def _origin_summary(repository, origin: str, start: datetime, end: datetime) -> dict[str, Any]:
    events = 0
    classifications = 0
    benign = 0
    attacks = 0
    event_counts = {event_type: 0 for event_type in REPORT_EVENT_TYPES}
    packet_sum = byte_sum = 0
    packet_records = byte_records = 0
    missing_packet_records = missing_byte_records = 0
    for event in repository.iter_events(start, end, origins=(origin,)):
        event_type = event["event_type"]
        events += 1
        event_counts[event_type] = event_counts.get(event_type, 0) + 1
        if event_type != "flow_classification":
            continue
        classifications += 1
        if event["classification"] == "BENIGN":
            benign += 1
        elif event["classification"] == "ATTACK":
            attacks += 1
        metadata = event.get("metadata") or {}
        packet_count = metadata.get("packet_count")
        byte_count = metadata.get("byte_count")
        if type(packet_count) is int and packet_count >= 0:
            packet_sum += packet_count
            packet_records += 1
        else:
            missing_packet_records += 1
        if type(byte_count) is int and byte_count >= 0:
            byte_sum += byte_count
            byte_records += 1
        else:
            missing_byte_records += 1
    return {
        "available": True,
        "event_count": events,
        "event_counts_by_type": event_counts,
        "classification_count": classifications,
        "benign_classifications": benign,
        "attack_classifications": attacks,
        "recorded_packet_count": {
            "available": classifications > 0 and missing_packet_records == 0,
            "value": packet_sum if classifications > 0 and missing_packet_records == 0 else None,
            "records_with_metric": packet_records,
        },
        "recorded_byte_count": {
            "available": classifications > 0 and missing_byte_records == 0,
            "value": byte_sum if classifications > 0 and missing_byte_records == 0 else None,
            "records_with_metric": byte_records,
        },
    }


def _format_report(report: Mapping[str, Any]) -> str:
    lines = [
        "NETRA weekly monitoring report",
        f"Interval (UTC, start inclusive/end exclusive): {report['interval_start_utc']} to {report['interval_end_utc']}",
        f"Generated (UTC): {report['generated_at_utc']}",
        "",
        "Stored monitoring activity by origin:",
    ]
    origins = report["origins"]
    if not report["history_available"]:
        lines.append("  Historical event data: unavailable for this interval.")
    else:
        for origin in REPORT_ORIGINS:
            metrics = origins[origin]
            lines.append(f"  {origin.upper()}: {metrics['event_count']} events; "
                         f"{metrics['classification_count']} classifications "
                         f"({metrics['benign_classifications']} BENIGN, {metrics['attack_classifications']} ATTACK).")
            type_counts = ", ".join(f"{kind}={count}" for kind, count in metrics["event_counts_by_type"].items())
            lines.append(f"    Event types: {type_counts}.")
            packets = metrics["recorded_packet_count"]
            if packets["available"]:
                lines.append(f"    Packet count recorded on classified flows: {packets['value']} (not a completeness guarantee).")
            elif metrics["classification_count"]:
                lines.append("    Packet totals unavailable: one or more classification records lack packet_count metadata.")
    critical = report["critical_email"]
    if critical["available"]:
        lines.append("Critical live email incidents in interval: "
                     f"{critical['incidents']} total; {critical['delivered']} delivered, "
                     f"{critical['pending']} pending/retrying, {critical['failed']} permanently failed (current status).")
    else:
        lines.append("Critical incident and email delivery diagnostics: unavailable.")
    lines.extend([
        "",
        "Limitations: counts cover persisted records only; collection may be partial. Critical email outcomes cover incidents persisted to the durable outbox; pre-outbox incidents and delivery details are unavailable. This report does not infer Top Talkers or network-wide packet totals. Event history may be absent or unavailable.",
        f"Report ID: {report['report_id']}",
    ])
    return "\n".join(lines)


class WeeklyReportService:
    """Query persisted history, render a report, and optionally deliver it once per interval."""

    def __init__(self, event_repository, delivery_repository: SQLiteEventRepository, *,
                 critical_repository=None, config: WeeklyReportConfig | None = None,
                 session=None, sleeper: Callable[[float], None] = time.sleep):
        self.event_repository = event_repository
        self.delivery_repository = delivery_repository
        self.critical_repository = critical_repository or delivery_repository
        self.config = config or WeeklyReportConfig.from_environment()
        self.session = session or requests.Session()
        self._sleep = sleeper

    def generate(self, start_time: datetime, end_time: datetime, *, generated_at: datetime | None = None) -> dict[str, Any]:
        start = _parse_interval_time(start_time, "start_time")
        end = _parse_interval_time(end_time, "end_time")
        if start >= end:
            raise ValueError("weekly report start_time must precede end_time")
        generated = _parse_interval_time(generated_at or datetime.now(timezone.utc), "generated_at")
        report = {
            "report_id": _report_id(start, end),
            "interval_start_utc": _utc_iso(start, "start_time"),
            "interval_end_utc": _utc_iso(end, "end_time"),
            "generated_at_utc": _utc_iso(generated, "generated_at"),
            "history_available": True,
            "origins": {},
            "critical_email": {"available": False, "incidents": None, "delivered": None,
                               "pending": None, "failed": None},
        }
        try:
            for origin in REPORT_ORIGINS:
                report["origins"][origin] = _origin_summary(self.event_repository, origin, start, end)
        except Exception as exc:
            code = _safe_error_code(type(exc).__name__)
            logger.warning("weekly report event query failed (%s)", code)
            report["history_available"] = False
            report["history_error_category"] = code
            report["origins"] = {origin: {"available": False} for origin in REPORT_ORIGINS}
        try:
            report["critical_email"] = {"available": True, **self.critical_repository.summarize_critical_email_alerts(start, end)}
        except Exception as exc:
            logger.info("weekly report critical delivery diagnostics unavailable (%s)",
                        _safe_error_code(type(exc).__name__))
        report["report_text"] = _format_report(report)
        return report

    def deliver(self, report: Mapping[str, Any]) -> dict[str, Any]:
        """Persist before send; every attempt uses the stable report UUID idempotency key."""
        status = self.config.status()
        report_id = str(report["report_id"])
        if status["state"] != "ready":
            return {"report_id": report_id, **status, "sent": False}
        record = dict(report, recipient_email=self.config.recipient)
        try:
            try:
                existing = self.delivery_repository.get_weekly_report(report_id)
            except Exception:
                existing = None
            if existing is None:
                try:
                    self.delivery_repository.enqueue_weekly_report(record)
                except Exception:
                    # Another scheduler may have inserted the stable interval first.
                    existing = self.delivery_repository.get_weekly_report(report_id)
                    if existing is None:
                        raise
            existing = existing or self.delivery_repository.get_weekly_report(report_id)
            if existing is None:
                raise RuntimeError("weekly report outbox insert was not visible")
            if existing["state"] == "delivered":
                return {"report_id": report_id, "state": "delivered", "sent": False, "message": "This report interval was already delivered."}
            if existing["state"] == "permanently_failed":
                return {"report_id": report_id, "state": "permanently_failed", "sent": False,
                        "error_code": existing.get("last_error_code")}

            for local_attempt in range(self.config.max_attempts):
                lease, claimed = self.delivery_repository.claim_weekly_report(report_id)
                if claimed is None:
                    current = self.delivery_repository.get_weekly_report(report_id) or {}
                    return {"report_id": report_id, "state": current.get("state", "pending"),
                            "sent": False, "message": "Report delivery is already claimed or not yet due."}
                attempt = int(claimed.get("attempts_in_cycle", claimed["attempts"]))
                try:
                    response = self.session.post(
                        RESEND_EMAILS_URL,
                        headers={"Authorization": f"Bearer {self.config.api_key}", "Idempotency-Key": report_id},
                        json={"from": self.config.sender, "to": [claimed["recipient_email"]],
                              "subject": "NETRA weekly monitoring report", "text": claimed["report_text"]},
                        timeout=self.config.timeout_seconds,
                    )
                    http_status = int(response.status_code)
                    if 200 <= http_status < 300:
                        complete = self.delivery_repository.complete_weekly_report(report_id, lease)
                        return {"report_id": report_id, "state": "delivered" if complete else "retrying",
                                "sent": complete, "error_code": None if complete else "lease_lost"}
                    error_code = f"http_{http_status}"
                    retryable = http_status in {408, 429} or http_status >= 500
                except requests.RequestException as exc:
                    error_code = _safe_error_code(type(exc).__name__)
                    retryable = True
                except Exception as exc:
                    error_code = _safe_error_code(type(exc).__name__)
                    retryable = False
                exhausted = retryable and (attempt >= self.config.max_attempts or local_attempt + 1 >= self.config.max_attempts)
                delay = min(2 ** max(0, attempt - 1), 30) if retryable and not exhausted else 0
                self.delivery_repository.fail_weekly_report(
                    report_id, lease, error_code=error_code, delay_seconds=delay,
                    permanent=not retryable, exhausted=exhausted,
                )
                if not retryable or exhausted:
                    logger.warning("weekly report delivery failed (%s)", error_code)
                    return {"report_id": report_id, "state": "permanently_failed", "sent": False,
                            "error_code": error_code}
                self._sleep(delay)
            return {"report_id": report_id, "state": "pending", "sent": False}
        except Exception as exc:
            code = _safe_error_code(type(exc).__name__)
            logger.error("weekly report outbox operation failed (%s)", code)
            return {"report_id": report_id, "state": "unavailable", "sent": False,
                    "error_code": code}

    def deliver_pending(self, *, now: datetime | None = None, limit: int = 20) -> list[dict[str, Any]]:
        """Resume due reports left pending by a prior process or scheduled run."""
        try:
            report_ids = self.delivery_repository.list_due_weekly_reports(limit=limit, now=now)
        except Exception as exc:
            code = _safe_error_code(type(exc).__name__)
            logger.error("weekly report recovery query failed (%s)", code)
            return [{"state": "unavailable", "error_code": code}]
        return [self.deliver({"report_id": report_id}) for report_id in report_ids]

    def run_previous_week(self, *, now: datetime | None = None, deliver: bool = True) -> dict[str, Any]:
        start, end = weekly_reporting_interval(now)
        report = self.generate(start, end, generated_at=now or datetime.now(timezone.utc))
        if deliver:
            report["recovered_deliveries"] = self.deliver_pending(now=now)
            report["delivery"] = self.deliver(report)
        else:
            report["delivery"] = {"state": "not_requested", "sent": False}
        return report


def configured_repositories():
    """Build repositories for a callable command without importing the detector engine."""
    role = os.getenv("NETRA_RUNTIME_ROLE", "local_sensor").strip().lower()
    if role not in {"local_sensor", "report_job"}:
        raise RuntimeError("weekly reports require NETRA_RUNTIME_ROLE=local_sensor or report_job")
    if role == "report_job" and os.getenv("NETRA_EVENT_BACKEND", "").strip().lower() != "postgresql":
        raise RuntimeError("report_job requires NETRA_EVENT_BACKEND=postgresql; refusing local history")
    event_repository = create_event_repository()
    delivery_backend = os.getenv("NETRA_DELIVERY_BACKEND", "").strip().lower()
    if delivery_backend and delivery_backend not in {"sqlite", "postgres", "postgresql"}:
        raise ValueError("NETRA_DELIVERY_BACKEND must be 'sqlite' or 'postgresql'")
    if role == "report_job":
        shared = create_delivery_repository(role=role)
        return event_repository, shared, shared
    if delivery_backend in {"postgres", "postgresql"}:
        shared = create_delivery_repository(role=role, backend=delivery_backend)
        return event_repository, shared, shared
    alert_path = os.getenv("NETRA_EMAIL_ALERT_DB_PATH")
    if alert_path:
        critical_repository = SQLiteEventRepository(alert_path)
    elif isinstance(event_repository, SQLiteEventRepository):
        critical_repository = event_repository
    else:
        critical_repository = SQLiteEventRepository(
            Path(__file__).resolve().parents[1] / "data" / "netra_email_alerts.sqlite3"
        )
    report_path = os.getenv("NETRA_WEEKLY_REPORT_DB_PATH")
    if report_path:
        delivery_repository = SQLiteEventRepository(report_path)
    else:
        delivery_repository = critical_repository
    return event_repository, critical_repository, delivery_repository


def main() -> int:
    try:
        from dotenv import load_dotenv
        load_dotenv(Path(__file__).resolve().parents[1] / ".env")
    except ImportError:
        pass
    role = os.getenv("NETRA_RUNTIME_ROLE", "local_sensor").strip().lower()
    if role not in {"local_sensor", "report_job"}:
        raise SystemExit("Set NETRA_RUNTIME_ROLE=report_job (hosted) or local_sensor to run a weekly report")
    event_repository, critical_repository, delivery_repository = configured_repositories()
    service = WeeklyReportService(event_repository, delivery_repository, critical_repository=critical_repository)
    report = service.run_previous_week(deliver=True)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report.get("delivery", {}).get("state") not in {"unavailable", "permanently_failed"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
