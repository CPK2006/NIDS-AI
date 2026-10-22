"""Local durable event history for NETRA V2.

The repository protocol is intentionally small so a PostgreSQL implementation can
replace SQLite in a later deployment phase without coupling the detector to SQL.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator, Mapping
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import json
import logging
import os
from pathlib import Path
import queue
import re
import sqlite3
import threading
import time
import uuid
from urllib.parse import urlsplit
from typing import Any, Protocol


SCHEMA_VERSION = 2
SQLITE_SCHEMA_VERSION = 5
POSTGRES_DELIVERY_SCHEMA_VERSION = 2
EVENT_SCHEMA_VERSION = 1
ALLOWED_ORIGINS = frozenset({"live", "pcap", "simulation"})
ALLOWED_EVENT_TYPES = frozenset({
    "flow_classification",
    "alert",
    "capture_error",
    "processing_error",
})
ALLOWED_CLASSIFICATIONS = frozenset({"BENIGN", "ATTACK"})
DEFAULT_QUEUE_CAPACITY = 1024
DEFAULT_RETENTION_DAYS = 30
DEFAULT_OUTBOX_MAX_EVENTS = 10_000
_logger = logging.getLogger(__name__)


class EventValidationError(ValueError):
    """Raised when an event does not conform to the versioned event contract."""


class EventRepository(Protocol):
    """Storage contract implemented by local and future hosted repositories."""

    def append(self, event: Mapping[str, Any]) -> bool: ...

    def append_many(self, events: Iterable[Mapping[str, Any]], *, enqueue_forward: bool | None = None) -> int: ...

    def iter_events(
        self,
        start_time: datetime,
        end_time: datetime,
        *,
        origins: Iterable[str] | None = None,
        event_types: Iterable[str] | None = None,
    ) -> Iterator[dict[str, Any]]: ...

    def aggregate_events(
        self, start_time: datetime, end_time: datetime, *, bucket_seconds: int,
        origins: Iterable[str] | None = None,
    ) -> list[dict[str, Any]]: ...

    def prune_expired(
        self,
        retention_days: int | None = None,
        *,
        now: datetime | None = None,
    ) -> int: ...


def _utc_iso(value: datetime, field_name: str) -> str:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise EventValidationError(f"{field_name} must be a timezone-aware datetime")
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _parse_utc(value: str, field_name: str) -> datetime:
    if not isinstance(value, str):
        raise EventValidationError(f"{field_name} must be an ISO-8601 timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise EventValidationError(f"{field_name} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise EventValidationError(f"{field_name} must include a UTC offset")
    return parsed.astimezone(timezone.utc)


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _delivery_retention_days(value: int | None = None) -> int | None:
    """Return configured terminal-audit retention; zero explicitly disables pruning."""
    if value is None:
        raw = os.getenv("NETRA_DELIVERY_AUDIT_RETENTION_DAYS", "3650")
        try:
            value = int(raw)
        except (TypeError, ValueError) as exc:
            raise EventValidationError("NETRA_DELIVERY_AUDIT_RETENTION_DAYS must be 0 or at least 365") from exc
    if type(value) is not int or (value != 0 and value < 365) or value > 36500:
        raise EventValidationError("delivery retention must be 0 or between 365 and 36500 days")
    return value or None


def create_event(
    *,
    origin: str,
    session_id: str | None,
    event_type: str,
    classification: str | None = None,
    metadata: Mapping[str, Any] | None = None,
    occurred_at: datetime | None = None,
    event_id: str | None = None,
) -> dict[str, Any]:
    """Create and validate a version 1 event with a stable UUID identifier."""
    timestamp = occurred_at or datetime.now(timezone.utc)
    record = {
        "event_id": event_id or str(uuid.uuid4()),
        "schema_version": EVENT_SCHEMA_VERSION,
        "occurred_at_utc": _utc_iso(timestamp, "occurred_at"),
        "origin": origin,
        "session_id": session_id,
        "event_type": event_type,
        "classification": classification,
        "metadata": dict(metadata or {}),
    }
    return validate_event(record)


def validate_event(event: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(event, Mapping):
        raise EventValidationError("event must be a mapping")
    required = {
        "event_id", "schema_version", "occurred_at_utc", "origin",
        "session_id", "event_type", "classification", "metadata",
    }
    if set(event) != required:
        missing = sorted(required - set(event))
        extra = sorted(set(event) - required)
        raise EventValidationError(f"event fields mismatch (missing={missing}, extra={extra})")

    event_id = event["event_id"]
    try:
        normalized_id = str(uuid.UUID(str(event_id)))
    except (ValueError, TypeError, AttributeError) as exc:
        raise EventValidationError("event_id must be a UUID") from exc
    if type(event["schema_version"]) is not int or event["schema_version"] != EVENT_SCHEMA_VERSION:
        raise EventValidationError(f"schema_version must be {EVENT_SCHEMA_VERSION}")
    occurred_at = _parse_utc(event["occurred_at_utc"], "occurred_at_utc")
    origin = event["origin"]
    if not isinstance(origin, str) or origin not in ALLOWED_ORIGINS:
        raise EventValidationError(f"origin must be one of {sorted(ALLOWED_ORIGINS)}")
    session_id = event["session_id"]
    if session_id is not None and (not isinstance(session_id, str) or not session_id.strip()):
        raise EventValidationError("session_id must be a non-empty string or None")
    event_type = event["event_type"]
    if not isinstance(event_type, str) or event_type not in ALLOWED_EVENT_TYPES:
        raise EventValidationError(f"event_type must be one of {sorted(ALLOWED_EVENT_TYPES)}")
    classification = event["classification"]
    if classification is not None and (
        not isinstance(classification, str) or classification not in ALLOWED_CLASSIFICATIONS
    ):
        raise EventValidationError("classification must be BENIGN, ATTACK, or None")
    if event_type == "alert" and classification != "ATTACK":
        raise EventValidationError("alert events must have ATTACK classification")
    if event_type == "flow_classification" and classification not in ALLOWED_CLASSIFICATIONS:
        raise EventValidationError("flow_classification events require a classification")
    if event_type in {"capture_error", "processing_error"} and classification is not None:
        raise EventValidationError("operational error events cannot have a classification")
    metadata = event["metadata"]
    if not isinstance(metadata, Mapping):
        raise EventValidationError("metadata must be a mapping")
    try:
        metadata_json = json.dumps(dict(metadata), sort_keys=True, separators=(",", ":"), allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise EventValidationError("metadata must contain finite JSON-compatible values") from exc

    return {
        "event_id": normalized_id,
        "schema_version": EVENT_SCHEMA_VERSION,
        "occurred_at_utc": occurred_at.isoformat(timespec="microseconds").replace("+00:00", "Z"),
        "origin": origin,
        "session_id": session_id,
        "event_type": event_type,
        "classification": classification,
        "metadata": json.loads(metadata_json),
    }


def _validated_batch(events: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Validate, collapse identical repeated IDs, and reject conflicting IDs."""
    unique: dict[str, dict[str, Any]] = {}
    for event in events:
        record = validate_event(event)
        previous = unique.get(record["event_id"])
        if previous is not None and previous != record:
            raise EventValidationError("event_id is repeated with different event content")
        unique[record["event_id"]] = record
    return list(unique.values())


class SQLiteEventRepository:
    """SQLite event store with versioned schema and per-operation connections."""

    def __init__(self, path: str | os.PathLike[str] | None = None, *, busy_timeout: float = 10.0,
                 forwarding_enabled: bool | None = None):
        self._configured_path = os.fspath(path) if path is not None else None
        self._resolved_path: str | None = None
        self._path_lock = threading.Lock()
        self._schema_lock = threading.Lock()
        self._busy_timeout = max(0.1, float(busy_timeout))
        self.forwarding_enabled = (
            _env_bool("NETRA_FORWARDING_ENABLED", False) if forwarding_enabled is None
            else bool(forwarding_enabled)
        )

    def _database_path(self) -> str:
        if self._resolved_path is not None:
            return self._resolved_path
        with self._path_lock:
            if self._resolved_path is None:
                configured = self._configured_path or os.getenv("NETRA_EVENT_DB_PATH")
                if configured:
                    path = Path(configured).expanduser()
                    if not path.is_absolute():
                        path = Path(__file__).resolve().parents[1] / path
                else:
                    path = Path(__file__).resolve().parents[1] / "data" / "netra_events.sqlite3"
                path.parent.mkdir(parents=True, exist_ok=True)
                self._resolved_path = str(path)
        return self._resolved_path

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self._database_path(), timeout=self._busy_timeout)
        connection.row_factory = sqlite3.Row
        try:
            connection.execute(f"PRAGMA busy_timeout = {int(self._busy_timeout * 1000)}")
            yield connection
        finally:
            connection.close()

    def _ensure_schema(self) -> None:
        with self._schema_lock, self._connection() as connection:
            version = connection.execute("PRAGMA user_version").fetchone()[0]
            if version > SQLITE_SCHEMA_VERSION:
                raise RuntimeError(f"event database schema {version} is newer than supported {SQLITE_SCHEMA_VERSION}")
            if version == SQLITE_SCHEMA_VERSION:
                return
            # V2 added sensor forwarding, V3 critical email delivery, and V4 a
            # separate weekly report delivery outbox. These states never mix.
            connection.execute("BEGIN IMMEDIATE")
            try:
                connection.execute(
                    """CREATE TABLE IF NOT EXISTS events (
                        event_id TEXT PRIMARY KEY,
                        schema_version INTEGER NOT NULL,
                        occurred_at_utc TEXT NOT NULL,
                        origin TEXT NOT NULL CHECK (origin IN ('live', 'pcap', 'simulation')),
                        session_id TEXT,
                        event_type TEXT NOT NULL CHECK (
                            event_type IN ('flow_classification', 'alert', 'capture_error', 'processing_error')
                        ),
                        classification TEXT CHECK (classification IS NULL OR classification IN ('BENIGN', 'ATTACK')),
                        metadata_json TEXT NOT NULL
                    )"""
                )
                connection.execute(
                    "CREATE INDEX IF NOT EXISTS idx_events_occurred_at ON events(occurred_at_utc, event_id)"
                )
                connection.execute(
                    "CREATE INDEX IF NOT EXISTS idx_events_origin_time ON events(origin, occurred_at_utc, event_id)"
                )
                connection.execute(
                    "CREATE INDEX IF NOT EXISTS idx_events_type_time ON events(event_type, occurred_at_utc, event_id)"
                )
                connection.execute(
                    """CREATE TABLE IF NOT EXISTS forwarding_outbox (
                        event_id TEXT PRIMARY KEY,
                        event_json TEXT NOT NULL,
                        created_at_utc TEXT NOT NULL,
                        attempts INTEGER NOT NULL DEFAULT 0,
                        next_attempt_utc TEXT NOT NULL,
                        lease_token TEXT,
                        lease_until_utc TEXT,
                        blocked INTEGER NOT NULL DEFAULT 0,
                        last_error TEXT
                    )"""
                )
                connection.execute(
                    "CREATE INDEX IF NOT EXISTS idx_outbox_due ON forwarding_outbox(blocked, next_attempt_utc, lease_until_utc)"
                )
                connection.execute(
                    """CREATE TABLE IF NOT EXISTS critical_email_outbox (
                        alert_id TEXT PRIMARY KEY,
                        session_id TEXT NOT NULL,
                        occurred_at_utc TEXT NOT NULL,
                        attack_count INTEGER NOT NULL CHECK (attack_count >= 1),
                        window_size INTEGER NOT NULL CHECK (window_size >= attack_count),
                        state TEXT NOT NULL CHECK (state IN ('pending', 'retrying', 'delivered', 'permanently_failed')),
                        attempts INTEGER NOT NULL DEFAULT 0,
                        attempts_in_cycle INTEGER NOT NULL DEFAULT 0,
                        created_at_utc TEXT NOT NULL,
                        updated_at_utc TEXT NOT NULL,
                        next_attempt_utc TEXT NOT NULL,
                        last_attempt_at_utc TEXT,
                        delivered_at_utc TEXT,
                        lease_token TEXT,
                        lease_until_utc TEXT,
                        last_error_code TEXT
                    )"""
                )
                connection.execute(
                    "CREATE INDEX IF NOT EXISTS idx_critical_email_due ON critical_email_outbox(state, next_attempt_utc, lease_until_utc)"
                )
                connection.execute(
                    "CREATE INDEX IF NOT EXISTS idx_critical_email_state ON critical_email_outbox(state, updated_at_utc)"
                )
                connection.execute(
                    """CREATE TABLE IF NOT EXISTS weekly_report_outbox (
                        report_id TEXT PRIMARY KEY,
                        interval_start_utc TEXT NOT NULL,
                        interval_end_utc TEXT NOT NULL,
                        generated_at_utc TEXT NOT NULL,
                        recipient_email TEXT NOT NULL,
                        report_text TEXT NOT NULL,
                        state TEXT NOT NULL CHECK (state IN ('pending', 'retrying', 'delivered', 'permanently_failed')),
                        attempts INTEGER NOT NULL DEFAULT 0,
                        attempts_in_cycle INTEGER NOT NULL DEFAULT 0,
                        created_at_utc TEXT NOT NULL,
                        updated_at_utc TEXT NOT NULL,
                        next_attempt_utc TEXT NOT NULL,
                        last_attempt_at_utc TEXT,
                        delivered_at_utc TEXT,
                        lease_token TEXT,
                        lease_until_utc TEXT,
                        last_error_code TEXT
                    )"""
                )
                weekly_columns = {
                    row[1] for row in connection.execute("PRAGMA table_info(weekly_report_outbox)").fetchall()
                }
                if "attempts_in_cycle" not in weekly_columns:
                    connection.execute(
                        "ALTER TABLE weekly_report_outbox ADD COLUMN attempts_in_cycle INTEGER NOT NULL DEFAULT 0"
                    )
                connection.execute(
                    "CREATE INDEX IF NOT EXISTS idx_weekly_report_due ON weekly_report_outbox(state, next_attempt_utc, lease_until_utc)"
                )
                connection.execute(
                    "CREATE INDEX IF NOT EXISTS idx_weekly_report_interval ON weekly_report_outbox(interval_start_utc, interval_end_utc)"
                )
                connection.execute(f"PRAGMA user_version = {SQLITE_SCHEMA_VERSION}")
                connection.commit()
            except Exception:
                connection.rollback()
                raise


    @staticmethod
    def _row_to_event(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "event_id": row["event_id"],
            "schema_version": row["schema_version"],
            "occurred_at_utc": row["occurred_at_utc"],
            "origin": row["origin"],
            "session_id": row["session_id"],
            "event_type": row["event_type"],
            "classification": row["classification"],
            "metadata": json.loads(row["metadata_json"]),
        }

    def append(self, event: Mapping[str, Any]) -> bool:
        return self.append_many((event,)) == 1

    def append_many(self, events: Iterable[Mapping[str, Any]], *, enqueue_forward: bool | None = None) -> int:
        enqueue_forward = self.forwarding_enabled if enqueue_forward is None else enqueue_forward
        records = _validated_batch(events)
        if not records:
            return 0
        self._ensure_schema()
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                inserted = 0
                outbox_count = 0
                outbox_limit = DEFAULT_OUTBOX_MAX_EVENTS
                if enqueue_forward:
                    try:
                        outbox_limit = int(os.getenv(
                            "NETRA_FORWARD_OUTBOX_MAX_EVENTS", str(DEFAULT_OUTBOX_MAX_EVENTS)
                        ))
                    except ValueError as exc:
                        raise EventValidationError(
                            "NETRA_FORWARD_OUTBOX_MAX_EVENTS must be a positive integer"
                        ) from exc
                    if not 1 <= outbox_limit <= 100_000:
                        raise EventValidationError(
                            "NETRA_FORWARD_OUTBOX_MAX_EVENTS must be between 1 and 100000"
                        )
                    outbox_count = connection.execute(
                        "SELECT COUNT(*) FROM forwarding_outbox"
                    ).fetchone()[0]
                for record in records:
                    metadata_json = json.dumps(record["metadata"], sort_keys=True, separators=(",", ":"), allow_nan=False)
                    cursor = connection.execute(
                        """INSERT INTO events (
                            event_id, schema_version, occurred_at_utc, origin, session_id,
                            event_type, classification, metadata_json
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        ON CONFLICT(event_id) DO NOTHING""",
                        (
                            record["event_id"], record["schema_version"], record["occurred_at_utc"],
                            record["origin"], record["session_id"], record["event_type"],
                            record["classification"], metadata_json,
                        ),
                    )
                    if cursor.rowcount == 0:
                        existing = connection.execute(
                            "SELECT * FROM events WHERE event_id = ?", (record["event_id"],)
                        ).fetchone()
                        if existing is None or self._row_to_event(existing) != record:
                            raise EventValidationError("event_id already exists with different event content")
                    else:
                        inserted += 1
                    if enqueue_forward:
                        encoded = json.dumps(record, sort_keys=True, separators=(",", ":"), allow_nan=False)
                        exists = connection.execute(
                            "SELECT 1 FROM forwarding_outbox WHERE event_id = ?", (record["event_id"],)
                        ).fetchone()
                        if exists:
                            continue
                        if outbox_count >= outbox_limit:
                            raise RuntimeError("durable event forwarding outbox is full; event was not persisted")
                        cursor = connection.execute(
                            """INSERT INTO forwarding_outbox (
                                event_id, event_json, created_at_utc, next_attempt_utc
                            ) VALUES (?, ?, ?, ?) ON CONFLICT(event_id) DO NOTHING""",
                            (record["event_id"], encoded, _utc_iso(datetime.now(timezone.utc), "now"),
                             _utc_iso(datetime.now(timezone.utc), "now")),
                        )
                        outbox_count += cursor.rowcount
                connection.commit()
                return inserted
            except Exception:
                connection.rollback()
                raise

    def ingest_many(self, events: Iterable[Mapping[str, Any]]) -> int:
        """Persist a remote batch atomically without re-enqueueing it for forwarding."""
        return self.append_many(events, enqueue_forward=False)

    @staticmethod
    def _validate_alert_id(value: Any, name: str) -> str:
        try:
            return str(uuid.UUID(str(value)))
        except (ValueError, TypeError, AttributeError) as exc:
            raise EventValidationError(f"{name} must be a UUID") from exc

    def enqueue_critical_alert(self, incident: Mapping[str, Any]) -> bool:
        """Durably insert one logical alert incident. Repeated IDs are idempotent."""
        if not isinstance(incident, Mapping):
            raise EventValidationError("incident must be a mapping")
        alert_id = self._validate_alert_id(incident.get("alert_id"), "alert_id")
        session_id = self._validate_alert_id(incident.get("session_id"), "session_id")
        attack_count, window_size = incident.get("attack_count"), incident.get("window_size")
        if type(attack_count) is not int or type(window_size) is not int or not 1 <= attack_count <= window_size <= 1000:
            raise EventValidationError("incident classification counts are invalid")
        occurred = _utc_iso(_parse_utc(incident.get("occurred_at_utc"), "occurred_at_utc"), "occurred_at_utc")
        now_text = _utc_iso(datetime.now(timezone.utc), "now")
        self._ensure_schema()
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                cursor = connection.execute(
                    """INSERT INTO critical_email_outbox (
                        alert_id, session_id, occurred_at_utc, attack_count, window_size,
                        state, created_at_utc, updated_at_utc, next_attempt_utc
                    ) VALUES (?, ?, ?, ?, ?, 'pending', ?, ?, ?)
                    ON CONFLICT(alert_id) DO NOTHING""",
                    (alert_id, session_id, occurred, attack_count, window_size, now_text, now_text, now_text),
                )
                if cursor.rowcount == 0:
                    existing = connection.execute(
                        "SELECT session_id, occurred_at_utc, attack_count, window_size FROM critical_email_outbox WHERE alert_id = ?",
                        (alert_id,),
                    ).fetchone()
                    if existing is None or tuple(existing) != (session_id, occurred, attack_count, window_size):
                        raise EventValidationError("alert_id already exists with different incident data")
                connection.commit()
                return cursor.rowcount == 1
            except Exception:
                connection.rollback()
                raise

    def claim_critical_alerts(self, *, limit: int = 1, lease_seconds: int = 180,
                              now: datetime | None = None,
                              alert_ids: Iterable[str] | None = None) -> tuple[str, list[dict[str, Any]]]:
        if type(limit) is not int or not 1 <= limit <= 10:
            raise ValueError("critical alert claim limit must be between 1 and 10")
        current = _parse_interval_time(now or datetime.now(timezone.utc), "now")
        selected_ids = (tuple(dict.fromkeys(self._validate_alert_id(item, "alert_id") for item in alert_ids))
                        if alert_ids is not None else None)
        if selected_ids is not None and not 1 <= len(selected_ids) <= 10:
            raise ValueError("provide between 1 and 10 alert IDs to claim")
        now_text = _utc_iso(current, "now")
        lease_until = _utc_iso(current + timedelta(seconds=max(1, min(lease_seconds, 3600))), "lease_until")
        token = str(uuid.uuid4())
        self._ensure_schema()
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                claim_sql = """SELECT alert_id, session_id, occurred_at_utc, attack_count, window_size,
                                      attempts_in_cycle
                               FROM critical_email_outbox
                               WHERE state IN ('pending', 'retrying') AND next_attempt_utc <= ?
                                 AND (lease_until_utc IS NULL OR lease_until_utc <= ?)"""
                claim_params: tuple[Any, ...] = (now_text, now_text)
                if selected_ids is not None:
                    claim_sql += f" AND alert_id IN ({','.join('?' for _ in selected_ids)})"
                    claim_params += selected_ids
                claim_sql += " ORDER BY created_at_utc, alert_id LIMIT ?"
                rows = connection.execute(claim_sql, claim_params + (limit,)).fetchall()
                for row in rows:
                    connection.execute(
                        """UPDATE critical_email_outbox SET state = 'retrying', attempts = attempts + 1,
                           attempts_in_cycle = attempts_in_cycle + 1, last_attempt_at_utc = ?,
                           updated_at_utc = ?, lease_token = ?, lease_until_utc = ? WHERE alert_id = ?""",
                        (now_text, now_text, token, lease_until, row["alert_id"]),
                    )
                connection.commit()
                claimed = [dict(row) | {"attempts_in_cycle": int(row["attempts_in_cycle"]) + 1}
                           for row in rows]
                return token, claimed
            except Exception:
                connection.rollback()
                raise

    def complete_critical_alert(self, alert_id: str, lease_token: str) -> bool:
        alert_id = self._validate_alert_id(alert_id, "alert_id")
        now_text = _utc_iso(datetime.now(timezone.utc), "now")
        self._ensure_schema()
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            cursor = connection.execute(
                """UPDATE critical_email_outbox SET state = 'delivered', delivered_at_utc = ?,
                   updated_at_utc = ?, lease_token = NULL, lease_until_utc = NULL, last_error_code = NULL
                   WHERE alert_id = ? AND state = 'retrying' AND lease_token = ?""",
                (now_text, now_text, alert_id, lease_token),
            )
            connection.commit()
            return cursor.rowcount == 1

    def fail_critical_alert(self, alert_id: str, lease_token: str, *, error_code: str,
                            delay_seconds: int = 0, permanent: bool = False,
                            exhausted: bool = False) -> bool:
        alert_id = self._validate_alert_id(alert_id, "alert_id")
        code = error_code if re.fullmatch(r"(?:http_[1-5][0-9]{2}|[A-Za-z][A-Za-z0-9_]{0,39})", str(error_code)) else "delivery_failed"
        now = datetime.now(timezone.utc)
        now_text = _utc_iso(now, "now")
        next_text = _utc_iso(now + timedelta(seconds=max(0, min(int(delay_seconds), 86400))), "next_attempt")
        failed = permanent or exhausted
        state = "permanently_failed" if failed else "pending"
        self._ensure_schema()
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            cursor = connection.execute(
                """UPDATE critical_email_outbox SET state = ?, next_attempt_utc = ?, updated_at_utc = ?,
                   lease_token = NULL, lease_until_utc = NULL, last_error_code = ?
                   WHERE alert_id = ? AND state = 'retrying' AND lease_token = ?""",
                (state, next_text, now_text, code, alert_id, lease_token),
            )
            connection.commit()
            return cursor.rowcount == 1

    def retry_failed_critical_alerts(self, alert_ids: Iterable[str]) -> int:
        ids = tuple(dict.fromkeys(self._validate_alert_id(item, "alert_id") for item in alert_ids))
        if not 1 <= len(ids) <= 100:
            raise ValueError("provide between 1 and 100 alert IDs")
        now_text = _utc_iso(datetime.now(timezone.utc), "now")
        self._ensure_schema()
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            cursor = connection.executemany(
                """UPDATE critical_email_outbox SET state = 'pending', attempts_in_cycle = 0,
                   next_attempt_utc = ?, updated_at_utc = ?, lease_token = NULL,
                   lease_until_utc = NULL, last_error_code = NULL
                   WHERE alert_id = ? AND state = 'permanently_failed'""",
                [(now_text, now_text, item) for item in ids],
            )
            connection.commit()
            return cursor.rowcount

    def critical_email_alert_counts(self) -> dict[str, int]:
        self._ensure_schema()
        with self._connection() as connection:
            rows = connection.execute(
                "SELECT state, COUNT(*) AS n FROM critical_email_outbox GROUP BY state"
            ).fetchall()
        counts = {"pending": 0, "retrying": 0, "delivered": 0, "failed": 0}
        for row in rows:
            if row["state"] == "permanently_failed":
                counts["failed"] = int(row["n"])
            else:
                counts[row["state"]] = int(row["n"])
        counts["pending"] += counts["retrying"]
        return counts

    def list_critical_email_alerts(self, *, state: str | None = None, limit: int = 50) -> list[dict[str, Any]]:
        if type(limit) is not int or not 1 <= limit <= 100:
            raise ValueError("critical alert list limit must be between 1 and 100")
        states = {"pending": "pending", "retrying": "retrying", "delivered": "delivered",
                  "failed": "permanently_failed", "permanently_failed": "permanently_failed"}
        if state is not None and state not in states:
            raise ValueError("unsupported critical alert state")
        self._ensure_schema()
        with self._connection() as connection:
            if state is None:
                rows = connection.execute(
                    """SELECT alert_id, state, attempts, created_at_utc, updated_at_utc,
                              next_attempt_utc, last_attempt_at_utc, delivered_at_utc, last_error_code
                       FROM critical_email_outbox ORDER BY created_at_utc DESC, alert_id LIMIT ?""", (limit,)
                ).fetchall()
            else:
                rows = connection.execute(
                    """SELECT alert_id, state, attempts, created_at_utc, updated_at_utc,
                              next_attempt_utc, last_attempt_at_utc, delivered_at_utc, last_error_code
                       FROM critical_email_outbox WHERE state = ? ORDER BY created_at_utc DESC, alert_id LIMIT ?""",
                    (states[state], limit),
                ).fetchall()
        return [dict(row) for row in rows]

    def summarize_critical_email_alerts(self, start_time: datetime, end_time: datetime) -> dict[str, int]:
        """Count persisted critical incidents in [start, end), grouped by current outcome."""
        start = _utc_iso(_parse_interval_time(start_time, "start_time"), "start_time")
        end = _utc_iso(_parse_interval_time(end_time, "end_time"), "end_time")
        if start >= end:
            raise EventValidationError("start_time must be earlier than end_time")
        self._ensure_schema()
        with self._connection() as connection:
            rows = connection.execute(
                """SELECT state, COUNT(*) AS n FROM critical_email_outbox
                   WHERE occurred_at_utc >= ? AND occurred_at_utc < ? GROUP BY state""", (start, end)
            ).fetchall()
        result = {"incidents": 0, "pending": 0, "delivered": 0, "failed": 0}
        for row in rows:
            count = int(row["n"])
            result["incidents"] += count
            if row["state"] in {"pending", "retrying"}:
                result["pending"] += count
            elif row["state"] == "delivered":
                result["delivered"] += count
            elif row["state"] == "permanently_failed":
                result["failed"] += count
        return result

    def enqueue_weekly_report(self, report: Mapping[str, Any]) -> bool:
        """Durably store one rendered report; repeated report IDs are idempotent."""
        if not isinstance(report, Mapping):
            raise EventValidationError("report must be a mapping")
        report_id = self._validate_alert_id(report.get("report_id"), "report_id")
        start = _utc_iso(_parse_utc(report.get("interval_start_utc"), "interval_start_utc"), "interval_start_utc")
        end = _utc_iso(_parse_utc(report.get("interval_end_utc"), "interval_end_utc"), "interval_end_utc")
        generated = _utc_iso(_parse_utc(report.get("generated_at_utc"), "generated_at_utc"), "generated_at_utc")
        if start >= end:
            raise EventValidationError("report interval must be positive")
        recipient = report.get("recipient_email")
        body = report.get("report_text")
        if not isinstance(recipient, str) or not recipient.strip() or len(recipient) > 320:
            raise EventValidationError("report recipient is invalid")
        if not isinstance(body, str) or not body.strip() or len(body) > 100_000:
            raise EventValidationError("report text is invalid")
        now_text = _utc_iso(datetime.now(timezone.utc), "now")
        self._ensure_schema()
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                cursor = connection.execute(
                    """INSERT INTO weekly_report_outbox (
                        report_id, interval_start_utc, interval_end_utc, generated_at_utc,
                        recipient_email, report_text, state, created_at_utc, updated_at_utc, next_attempt_utc
                    ) VALUES (?, ?, ?, ?, ?, ?, 'pending', ?, ?, ?) ON CONFLICT(report_id) DO NOTHING""",
                    (report_id, start, end, generated, recipient, body, now_text, now_text, now_text),
                )
                if cursor.rowcount == 0:
                    existing = connection.execute(
                        "SELECT interval_start_utc, interval_end_utc, recipient_email, report_text FROM weekly_report_outbox WHERE report_id = ?",
                        (report_id,),
                    ).fetchone()
                    if existing is None or tuple(existing) != (start, end, recipient, body):
                        raise EventValidationError("report_id already exists with different report content")
                connection.commit()
                return cursor.rowcount == 1
            except Exception:
                connection.rollback()
                raise

    def get_weekly_report(self, report_id: str) -> dict[str, Any] | None:
        report_id = self._validate_alert_id(report_id, "report_id")
        self._ensure_schema()
        with self._connection() as connection:
            row = connection.execute(
                """SELECT report_id, interval_start_utc, interval_end_utc, generated_at_utc,
                          report_text, state, attempts, attempts_in_cycle, next_attempt_utc, delivered_at_utc,
                          last_error_code FROM weekly_report_outbox WHERE report_id = ?""",
                (report_id,),
            ).fetchone()
        return dict(row) if row is not None else None

    def list_due_weekly_reports(self, *, limit: int = 20,
                                now: datetime | None = None) -> list[str]:
        if type(limit) is not int or not 1 <= limit <= 100:
            raise ValueError("weekly report due limit must be between 1 and 100")
        current_text = _utc_iso(_parse_interval_time(now or datetime.now(timezone.utc), "now"), "now")
        self._ensure_schema()
        with self._connection() as connection:
            rows = connection.execute(
                """SELECT report_id FROM weekly_report_outbox
                   WHERE state IN ('pending', 'retrying') AND next_attempt_utc <= ?
                     AND (lease_until_utc IS NULL OR lease_until_utc <= ?)
                   ORDER BY created_at_utc, report_id LIMIT ?""",
                (current_text, current_text, limit),
            ).fetchall()
        return [row["report_id"] for row in rows]

    def claim_weekly_report(self, report_id: str, *, lease_seconds: int = 180,
                            now: datetime | None = None) -> tuple[str, dict[str, Any] | None]:
        report_id = self._validate_alert_id(report_id, "report_id")
        current = _parse_interval_time(now or datetime.now(timezone.utc), "now")
        now_text = _utc_iso(current, "now")
        lease_until = _utc_iso(current + timedelta(seconds=max(1, min(lease_seconds, 3600))), "lease_until")
        token = str(uuid.uuid4())
        self._ensure_schema()
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                row = connection.execute(
                    """SELECT report_id, recipient_email, report_text, attempts, attempts_in_cycle FROM weekly_report_outbox
                       WHERE report_id = ? AND state IN ('pending', 'retrying') AND next_attempt_utc <= ?
                         AND (lease_until_utc IS NULL OR lease_until_utc <= ?)""",
                    (report_id, now_text, now_text),
                ).fetchone()
                if row is not None:
                    connection.execute(
                        """UPDATE weekly_report_outbox SET state = 'retrying', attempts = attempts + 1,
                           attempts_in_cycle = attempts_in_cycle + 1,
                           last_attempt_at_utc = ?, updated_at_utc = ?, lease_token = ?, lease_until_utc = ?
                           WHERE report_id = ?""",
                        (now_text, now_text, token, lease_until, report_id),
                    )
                connection.commit()
                return token, ({**dict(row), "attempts": int(row["attempts"]) + 1,
                                "attempts_in_cycle": int(row["attempts_in_cycle"]) + 1}
                               if row is not None else None)
            except Exception:
                connection.rollback()
                raise

    def complete_weekly_report(self, report_id: str, lease_token: str) -> bool:
        report_id = self._validate_alert_id(report_id, "report_id")
        now_text = _utc_iso(datetime.now(timezone.utc), "now")
        self._ensure_schema()
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            cursor = connection.execute(
                """UPDATE weekly_report_outbox SET state = 'delivered', delivered_at_utc = ?,
                   updated_at_utc = ?, lease_token = NULL, lease_until_utc = NULL, last_error_code = NULL
                   WHERE report_id = ? AND state = 'retrying' AND lease_token = ?""",
                (now_text, now_text, report_id, lease_token),
            )
            connection.commit()
            return cursor.rowcount == 1

    def fail_weekly_report(self, report_id: str, lease_token: str, *, error_code: str,
                           delay_seconds: int = 0, permanent: bool = False,
                           exhausted: bool = False) -> bool:
        report_id = self._validate_alert_id(report_id, "report_id")
        code = error_code if re.fullmatch(r"(?:http_[1-5][0-9]{2}|[A-Za-z][A-Za-z0-9_]{0,39})", str(error_code)) else "delivery_failed"
        now = datetime.now(timezone.utc)
        now_text = _utc_iso(now, "now")
        next_text = _utc_iso(now + timedelta(seconds=max(0, min(int(delay_seconds), 86400))), "next_attempt")
        state = "permanently_failed" if permanent or exhausted else "pending"
        self._ensure_schema()
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            cursor = connection.execute(
                """UPDATE weekly_report_outbox SET state = ?, next_attempt_utc = ?, updated_at_utc = ?,
                   lease_token = NULL, lease_until_utc = NULL, last_error_code = ?
                   WHERE report_id = ? AND state = 'retrying' AND lease_token = ?""",
                (state, next_text, now_text, code, report_id, lease_token),
            )
            connection.commit()
            return cursor.rowcount == 1

    def retry_failed_weekly_reports(self, report_ids: Iterable[str]) -> int:
        ids = tuple(dict.fromkeys(self._validate_alert_id(item, "report_id") for item in report_ids))
        if not 1 <= len(ids) <= 100:
            raise ValueError("provide between 1 and 100 report IDs")
        now_text = _utc_iso(datetime.now(timezone.utc), "now")
        self._ensure_schema()
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                cursor = connection.executemany(
                    """UPDATE weekly_report_outbox SET state = 'pending', attempts_in_cycle = 0,
                       next_attempt_utc = ?,
                       updated_at_utc = ?, lease_token = NULL, lease_until_utc = NULL, last_error_code = NULL
                       WHERE report_id = ? AND state = 'permanently_failed'""",
                    [(now_text, now_text, item) for item in ids],
                )
                connection.commit()
                return cursor.rowcount
            except Exception:
                connection.rollback()
                raise

    def prune_delivery_records(self, *, retention_days: int | None = None,
                               now: datetime | None = None, limit: int = 1000) -> int:
        """Delete old delivered audit rows only; failed rows remain operator-actionable."""
        days = _delivery_retention_days(retention_days)
        if days is None:
            return 0
        if type(limit) is not int or not 1 <= limit <= 10000:
            raise ValueError("delivery pruning limit must be between 1 and 10000")
        cutoff = _utc_iso(_parse_interval_time(now or datetime.now(timezone.utc), "now") - timedelta(days=days), "cutoff")
        self._ensure_schema()
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                cursor = connection.execute(
                    """DELETE FROM critical_email_outbox WHERE rowid IN (
                           SELECT rowid FROM critical_email_outbox
                           WHERE state = 'delivered' AND updated_at_utc < ?
                           ORDER BY updated_at_utc LIMIT ?
                       )""", (cutoff, limit),
                )
                deleted = cursor.rowcount
                connection.commit()
                return deleted
            except Exception:
                connection.rollback()
                raise

    def claim_outbox(self, *, limit: int, lease_seconds: int = 30,
                     now: datetime | None = None) -> tuple[str, list[dict[str, Any]], int]:
        if type(limit) is not int or not 1 <= limit <= 100:
            raise ValueError("outbox limit must be between 1 and 100")
        current = _parse_interval_time(now or datetime.now(timezone.utc), "now")
        token = str(uuid.uuid4())
        now_text = _utc_iso(current, "now")
        lease_until = _utc_iso(current + timedelta(seconds=max(1, lease_seconds)), "lease_until")
        self._ensure_schema()
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                rows = connection.execute(
                    """SELECT event_id, event_json, attempts FROM forwarding_outbox
                       WHERE blocked = 0 AND next_attempt_utc <= ?
                         AND (lease_until_utc IS NULL OR lease_until_utc <= ?)
                         AND attempts = (
                            SELECT MIN(attempts) FROM forwarding_outbox AS due
                            WHERE due.blocked = 0 AND due.next_attempt_utc <= ?
                              AND (due.lease_until_utc IS NULL OR due.lease_until_utc <= ?)
                         )
                       ORDER BY created_at_utc, event_id LIMIT ?""",
                    (now_text, now_text, now_text, now_text, limit),
                ).fetchall()
                ids = [row["event_id"] for row in rows]
                if ids:
                    connection.executemany(
                        "UPDATE forwarding_outbox SET lease_token = ?, lease_until_utc = ? WHERE event_id = ?",
                        [(token, lease_until, event_id) for event_id in ids],
                    )
                connection.commit()
                return token, [json.loads(row["event_json"]) for row in rows], max(
                    (int(row["attempts"]) for row in rows), default=0
                )
            except Exception:
                connection.rollback()
                raise

    def acknowledge_outbox(self, event_ids: Iterable[str], lease_token: str) -> int:
        ids = tuple(event_ids)
        if not ids:
            return 0
        self._ensure_schema()
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            cursor = connection.executemany(
                "DELETE FROM forwarding_outbox WHERE event_id = ? AND lease_token = ?",
                [(event_id, lease_token) for event_id in ids],
            )
            connection.commit()
            return cursor.rowcount

    def retry_outbox(self, event_ids: Iterable[str], lease_token: str, *, delay_seconds: int,
                     error_code: str, blocked: bool = False) -> int:
        ids = tuple(event_ids)
        if not ids:
            return 0
        next_attempt = _utc_iso(datetime.now(timezone.utc) + timedelta(seconds=max(0, delay_seconds)), "next_attempt")
        self._ensure_schema()
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            cursor = connection.executemany(
                """UPDATE forwarding_outbox SET attempts = attempts + 1, next_attempt_utc = ?,
                   lease_token = NULL, lease_until_utc = NULL, blocked = ?, last_error = ?
                   WHERE event_id = ? AND lease_token = ?""",
                [(next_attempt, int(blocked), error_code[:80], event_id, lease_token) for event_id in ids],
            )
            connection.commit()
            return cursor.rowcount

    def outbox_counts(self) -> dict[str, int]:
        self._ensure_schema()
        with self._connection() as connection:
            row = connection.execute(
                "SELECT COUNT(*) AS pending, SUM(blocked) AS blocked FROM forwarding_outbox"
            ).fetchone()
            return {"pending": int(row["pending"] or 0), "blocked": int(row["blocked"] or 0)}

    def list_blocked_outbox(self, *, limit: int = 100) -> list[dict[str, Any]]:
        if type(limit) is not int or not 1 <= limit <= 1000:
            raise ValueError("blocked outbox limit must be between 1 and 1000")
        self._ensure_schema()
        with self._connection() as connection:
            rows = connection.execute(
                """SELECT event_id, created_at_utc, attempts, last_error
                   FROM forwarding_outbox WHERE blocked = 1
                   ORDER BY created_at_utc, event_id LIMIT ?""",
                (limit,),
            ).fetchall()
            return [dict(row) for row in rows]

    def requeue_blocked_outbox(self, event_ids: Iterable[str]) -> int:
        ids = tuple(event_ids)
        if not ids or len(ids) > 1000:
            raise ValueError("provide between 1 and 1000 blocked event IDs")
        now_text = _utc_iso(datetime.now(timezone.utc), "now")
        self._ensure_schema()
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            cursor = connection.executemany(
                """UPDATE forwarding_outbox SET blocked = 0, attempts = 0,
                   next_attempt_utc = ?, lease_token = NULL, lease_until_utc = NULL, last_error = NULL
                   WHERE event_id = ? AND blocked = 1""",
                [(now_text, event_id) for event_id in ids],
            )
            connection.commit()
            return cursor.rowcount

    def iter_events(
        self,
        start_time: datetime,
        end_time: datetime,
        *,
        origins: Iterable[str] | None = None,
        event_types: Iterable[str] | None = None,
    ) -> Iterator[dict[str, Any]]:
        start = _utc_iso(_parse_interval_time(start_time, "start_time"), "start_time")
        end = _utc_iso(_parse_interval_time(end_time, "end_time"), "end_time")
        if start >= end:
            raise EventValidationError("start_time must be earlier than end_time")
        clauses = ["occurred_at_utc >= ?", "occurred_at_utc < ?"]
        params: list[Any] = [start, end]
        for field, values, allowed in (
            ("origin", origins, ALLOWED_ORIGINS),
            ("event_type", event_types, ALLOWED_EVENT_TYPES),
        ):
            if values is not None:
                normalized = tuple(values)
                if any(value not in allowed for value in normalized):
                    raise EventValidationError(f"invalid {field} filter")
                if not normalized:
                    return iter(())
                clauses.append(f"{field} IN ({','.join('?' for _ in normalized)})")
                params.extend(normalized)
        self._ensure_schema()
        query = (
            "SELECT * FROM events WHERE " + " AND ".join(clauses)
            + " ORDER BY occurred_at_utc, event_id"
        )

        def generate() -> Iterator[dict[str, Any]]:
            with self._connection() as connection:
                connection.row_factory = sqlite3.Row
                cursor = connection.execute(query, params)
                try:
                    while True:
                        rows = cursor.fetchmany(256)
                        if not rows:
                            break
                        for row in rows:
                            yield self._row_to_event(row)
                finally:
                    cursor.close()

        return generate()

    def aggregate_events(self, start_time: datetime, end_time: datetime, *, bucket_seconds: int,
                         origins: Iterable[str] | None = None) -> list[dict[str, Any]]:
        start = _parse_interval_time(start_time, "start_time")
        end = _parse_interval_time(end_time, "end_time")
        if start >= end or type(bucket_seconds) is not int or bucket_seconds < 1:
            raise EventValidationError("invalid aggregation interval or bucket size")
        clauses = ["occurred_at_utc >= ?", "occurred_at_utc < ?"]
        filter_params: list[Any] = [_utc_iso(start, "start_time"), _utc_iso(end, "end_time")]
        if origins is not None:
            selected = tuple(origins)
            if any(origin not in ALLOWED_ORIGINS for origin in selected):
                raise EventValidationError("invalid origin filter")
            if not selected:
                return []
            clauses.append(f"origin IN ({','.join('?' for _ in selected)})")
            filter_params.extend(selected)
        params = [bucket_seconds, bucket_seconds, *filter_params]
        self._ensure_schema()
        query = """SELECT CAST(strftime('%s', occurred_at_utc) AS INTEGER) / ? * ? AS bucket_epoch,
            COUNT(*) AS event_count,
            SUM(CASE WHEN event_type='flow_classification' THEN 1 ELSE 0 END) AS flow_count,
            SUM(CASE WHEN event_type='flow_classification' AND classification='BENIGN' THEN 1 ELSE 0 END) AS benign_count,
            SUM(CASE WHEN event_type='flow_classification' AND classification='ATTACK' THEN 1 ELSE 0 END) AS attack_count,
            SUM(CASE WHEN event_type='alert' THEN 1 ELSE 0 END) AS alert_count,
            SUM(CASE WHEN event_type='capture_error' THEN 1 ELSE 0 END) AS capture_error_count,
            SUM(CASE WHEN event_type='processing_error' THEN 1 ELSE 0 END) AS processing_error_count,
            SUM(CASE WHEN event_type='flow_classification' THEN COALESCE(CAST(json_extract(metadata_json, '$.packet_count') AS INTEGER), 0) ELSE 0 END) AS packet_count,
            SUM(CASE WHEN event_type='flow_classification' THEN COALESCE(CAST(json_extract(metadata_json, '$.byte_count') AS INTEGER), 0) ELSE 0 END) AS byte_count
            FROM events WHERE """ + " AND ".join(clauses) + " GROUP BY bucket_epoch ORDER BY bucket_epoch LIMIT 1000"
        with self._connection() as connection:
            connection.row_factory = sqlite3.Row
            rows = connection.execute(query, params).fetchall()
        return [{"bucket_start_utc": datetime.fromtimestamp(row["bucket_epoch"], timezone.utc).isoformat().replace("+00:00", "Z"),
                 **{key: int(row[key] or 0) for key in ("event_count", "flow_count", "benign_count", "attack_count",
                    "alert_count", "capture_error_count", "processing_error_count", "packet_count", "byte_count")}}
                for row in rows]

    def prune_expired(self, retention_days: int | None = None, *, now: datetime | None = None) -> int:
        if retention_days is None:
            raw_days = os.getenv("NETRA_EVENT_RETENTION_DAYS", str(DEFAULT_RETENTION_DAYS))
            try:
                retention_days = int(raw_days)
            except ValueError as exc:
                raise EventValidationError("NETRA_EVENT_RETENTION_DAYS must be a positive integer") from exc
        if type(retention_days) is not int or retention_days < 1:
            raise EventValidationError("retention_days must be a positive integer")
        current = now or datetime.now(timezone.utc)
        current = _parse_interval_time(current, "now")
        cutoff = current - timedelta(days=retention_days)
        cutoff_text = _utc_iso(cutoff, "now")
        self._ensure_schema()
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                cursor = connection.execute("DELETE FROM events WHERE occurred_at_utc < ?", (cutoff_text,))
                deleted = cursor.rowcount
                connection.commit()
                return deleted
            except Exception:
                connection.rollback()
                raise



class PostgreSQLEventRepository:
    """PostgreSQL adapter; psycopg is imported only when this backend is selected."""

    def __init__(self, database_url: str | None = None, *, connect_timeout: int = 3):
        self._database_url = database_url or os.getenv("DATABASE_URL")
        if not self._database_url:
            raise RuntimeError("NETRA_EVENT_BACKEND=postgresql requires DATABASE_URL; refusing a storage fallback")
        try:
            parsed_url = urlsplit(self._database_url)
            valid_url = (
                parsed_url.scheme in {"postgres", "postgresql"}
                and bool(parsed_url.hostname)
                and (parsed_url.port is None or 1 <= parsed_url.port <= 65535)
            )
        except ValueError:
            valid_url = False
        if not valid_url:
            raise RuntimeError("PostgreSQL storage requires a valid DATABASE_URL")
        self._connect_timeout = max(1, min(int(connect_timeout), 15))
        self._delivery_schema_ready = False
        self._delivery_schema_lock = threading.Lock()

    @contextmanager
    def _connection(self):
        try:
            import psycopg
            from psycopg.rows import dict_row
        except ImportError as exc:
            raise RuntimeError(
                "PostgreSQL event storage requires psycopg; install with "
                "python -m pip install \"psycopg[binary]==3.3.6\""
            ) from exc
        connection = psycopg.connect(
            self._database_url, connect_timeout=self._connect_timeout, row_factory=dict_row
        )
        try:
            yield connection
        finally:
            connection.close()

    def _ensure_schema(self) -> None:
        with self._connection() as connection:
            with connection.transaction():
                connection.execute("SELECT pg_advisory_xact_lock(%s)", (7291842001,))
                connection.execute(
                    "CREATE TABLE IF NOT EXISTS netra_schema_version "
                    "(component TEXT PRIMARY KEY, version INTEGER NOT NULL)"
                )
                connection.execute(
                    "INSERT INTO netra_schema_version(component, version) VALUES ('events', 0) "
                    "ON CONFLICT(component) DO NOTHING"
                )
                row = connection.execute(
                    "SELECT version FROM netra_schema_version WHERE component = 'events' FOR UPDATE"
                ).fetchone()
                version = int(row["version"])
                if version > SCHEMA_VERSION:
                    raise RuntimeError(
                        f"event database schema {version} is newer than supported {SCHEMA_VERSION}"
                    )
                connection.execute(
                    """CREATE TABLE IF NOT EXISTS events (
                        event_id UUID PRIMARY KEY,
                        schema_version INTEGER NOT NULL,
                        occurred_at_utc TIMESTAMPTZ NOT NULL,
                        origin TEXT NOT NULL CHECK (origin IN ('live', 'pcap', 'simulation')),
                        session_id TEXT,
                        event_type TEXT NOT NULL CHECK (
                            event_type IN ('flow_classification', 'alert', 'capture_error', 'processing_error')
                        ),
                        classification TEXT CHECK (classification IS NULL OR classification IN ('BENIGN', 'ATTACK')),
                        metadata JSONB NOT NULL
                    )"""
                )
                connection.execute(
                    "CREATE INDEX IF NOT EXISTS idx_events_occurred_at ON events(occurred_at_utc, event_id)"
                )
                connection.execute(
                    "CREATE INDEX IF NOT EXISTS idx_events_origin_time ON events(origin, occurred_at_utc, event_id)"
                )
                connection.execute(
                    "CREATE INDEX IF NOT EXISTS idx_events_type_time ON events(event_type, occurred_at_utc, event_id)"
                )
                connection.execute(
                    "UPDATE netra_schema_version SET version = %s WHERE component = 'events'",
                    (SCHEMA_VERSION,),
                )

    def _ensure_delivery_schema(self) -> None:
        """Apply the independent, repeatable PostgreSQL delivery schema migration."""
        if self._delivery_schema_ready:
            return
        with self._delivery_schema_lock:
            if self._delivery_schema_ready:
                return
            with self._connection() as connection:
                with connection.transaction():
                    connection.execute("SELECT pg_advisory_xact_lock(%s)", (7291842002,))
                    connection.execute(
                        "CREATE TABLE IF NOT EXISTS netra_schema_version "
                        "(component TEXT PRIMARY KEY, version INTEGER NOT NULL)"
                    )
                    connection.execute(
                        "INSERT INTO netra_schema_version(component, version) VALUES ('delivery', 0) "
                        "ON CONFLICT(component) DO NOTHING"
                    )
                    row = connection.execute(
                        "SELECT version FROM netra_schema_version WHERE component = 'delivery' FOR UPDATE"
                    ).fetchone()
                    version = int(row["version"])
                    if version > POSTGRES_DELIVERY_SCHEMA_VERSION:
                        raise RuntimeError("delivery database schema is newer than this NETRA version")
                    connection.execute(
                        """CREATE TABLE IF NOT EXISTS critical_email_outbox (
                            alert_id UUID PRIMARY KEY,
                            session_id UUID NOT NULL,
                            occurred_at_utc TIMESTAMPTZ NOT NULL,
                            attack_count INTEGER NOT NULL CHECK (attack_count >= 1),
                            window_size INTEGER NOT NULL CHECK (window_size >= attack_count),
                            state TEXT NOT NULL CHECK (state IN ('pending','retrying','delivered','permanently_failed')),
                            attempts INTEGER NOT NULL DEFAULT 0,
                            attempts_in_cycle INTEGER NOT NULL DEFAULT 0,
                            created_at_utc TIMESTAMPTZ NOT NULL,
                            updated_at_utc TIMESTAMPTZ NOT NULL,
                            next_attempt_utc TIMESTAMPTZ NOT NULL,
                            last_attempt_at_utc TIMESTAMPTZ,
                            delivered_at_utc TIMESTAMPTZ,
                            lease_token UUID,
                            lease_until_utc TIMESTAMPTZ,
                            last_error_code TEXT
                        )"""
                    )
                    connection.execute(
                        "CREATE INDEX IF NOT EXISTS idx_critical_email_due "
                        "ON critical_email_outbox(state, next_attempt_utc, lease_until_utc)"
                    )
                    connection.execute(
                        "CREATE INDEX IF NOT EXISTS idx_critical_email_state "
                        "ON critical_email_outbox(state, updated_at_utc)"
                    )
                    connection.execute(
                        "CREATE INDEX IF NOT EXISTS idx_critical_email_occurred "
                        "ON critical_email_outbox(occurred_at_utc, state)"
                    )
                    connection.execute(
                        """CREATE TABLE IF NOT EXISTS weekly_report_outbox (
                            report_id UUID PRIMARY KEY,
                            interval_start_utc TIMESTAMPTZ NOT NULL,
                            interval_end_utc TIMESTAMPTZ NOT NULL,
                            generated_at_utc TIMESTAMPTZ NOT NULL,
                            recipient_email TEXT NOT NULL,
                            report_text TEXT NOT NULL,
                            state TEXT NOT NULL CHECK (state IN ('pending','retrying','delivered','permanently_failed')),
                            attempts INTEGER NOT NULL DEFAULT 0,
                            attempts_in_cycle INTEGER NOT NULL DEFAULT 0,
                            created_at_utc TIMESTAMPTZ NOT NULL,
                            updated_at_utc TIMESTAMPTZ NOT NULL,
                            next_attempt_utc TIMESTAMPTZ NOT NULL,
                            last_attempt_at_utc TIMESTAMPTZ,
                            delivered_at_utc TIMESTAMPTZ,
                            lease_token UUID,
                            lease_until_utc TIMESTAMPTZ,
                            last_error_code TEXT,
                            CHECK (interval_start_utc < interval_end_utc)
                        )"""
                    )
                    connection.execute(
                        "ALTER TABLE weekly_report_outbox ADD COLUMN IF NOT EXISTS "
                        "attempts_in_cycle INTEGER NOT NULL DEFAULT 0"
                    )
                    connection.execute(
                        "CREATE INDEX IF NOT EXISTS idx_weekly_report_due "
                        "ON weekly_report_outbox(state, next_attempt_utc, lease_until_utc)"
                    )
                    connection.execute(
                        "CREATE INDEX IF NOT EXISTS idx_weekly_report_interval "
                        "ON weekly_report_outbox(interval_start_utc, interval_end_utc)"
                    )
                    connection.execute(
                        "UPDATE netra_schema_version SET version = %s WHERE component = 'delivery'",
                    (POSTGRES_DELIVERY_SCHEMA_VERSION,),
                    )
            self._delivery_schema_ready = True

    @staticmethod
    def _pg_utc_text(value: Any) -> Any:
        if isinstance(value, datetime):
            return value.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")
        return value

    @classmethod
    def _pg_delivery_row(cls, row: Mapping[str, Any]) -> dict[str, Any]:
        return {key: cls._pg_utc_text(value) for key, value in dict(row).items()}

    @staticmethod
    def _safe_delivery_error(error_code: Any) -> str:
        code = str(error_code)
        return code if re.fullmatch(r"(?:http_[1-5][0-9]{2}|[A-Za-z][A-Za-z0-9_]{0,39})", code) else "delivery_failed"

    @staticmethod
    def _validate_alert_id(value: Any, name: str) -> str:
        try:
            return str(uuid.UUID(str(value)))
        except (ValueError, TypeError, AttributeError) as exc:
            raise EventValidationError(f"{name} must be a UUID") from exc

    def enqueue_critical_alert(self, incident: Mapping[str, Any]) -> bool:
        if not isinstance(incident, Mapping):
            raise EventValidationError("incident must be a mapping")
        alert_id = self._validate_alert_id(incident.get("alert_id"), "alert_id")
        session_id = self._validate_alert_id(incident.get("session_id"), "session_id")
        attack_count, window_size = incident.get("attack_count"), incident.get("window_size")
        if type(attack_count) is not int or type(window_size) is not int or not 1 <= attack_count <= window_size <= 1000:
            raise EventValidationError("incident classification counts are invalid")
        occurred = _parse_utc(incident.get("occurred_at_utc"), "occurred_at_utc")
        now = datetime.now(timezone.utc)
        self._ensure_delivery_schema()
        with self._connection() as connection:
            with connection.transaction():
                cursor = connection.execute(
                    """INSERT INTO critical_email_outbox
                       (alert_id, session_id, occurred_at_utc, attack_count, window_size, state,
                        created_at_utc, updated_at_utc, next_attempt_utc)
                       VALUES (%s,%s,%s,%s,%s,'pending',%s,%s,%s)
                       ON CONFLICT(alert_id) DO NOTHING""",
                    (alert_id, session_id, occurred, attack_count, window_size, now, now, now),
                )
                if cursor.rowcount == 1:
                    return True
                existing = connection.execute(
                    "SELECT session_id, occurred_at_utc, attack_count, window_size "
                    "FROM critical_email_outbox WHERE alert_id = %s", (alert_id,),
                ).fetchone()
                if existing is None or (
                    str(existing["session_id"]) != session_id
                    or self._pg_utc_text(existing["occurred_at_utc"]) != self._pg_utc_text(occurred)
                    or int(existing["attack_count"]) != attack_count
                    or int(existing["window_size"]) != window_size
                ):
                    raise EventValidationError("alert_id already exists with different incident data")
                return False

    def claim_critical_alerts(self, *, limit: int = 1, lease_seconds: int = 180,
                              now: datetime | None = None,
                              alert_ids: Iterable[str] | None = None) -> tuple[str, list[dict[str, Any]]]:
        if type(limit) is not int or not 1 <= limit <= 10:
            raise ValueError("critical alert claim limit must be between 1 and 10")
        current = _parse_interval_time(now or datetime.now(timezone.utc), "now")
        selected_ids = (tuple(dict.fromkeys(self._validate_alert_id(item, "alert_id") for item in alert_ids))
                        if alert_ids is not None else None)
        if selected_ids is not None and not 1 <= len(selected_ids) <= 10:
            raise ValueError("provide between 1 and 10 alert IDs to claim")
        lease_until = current + timedelta(seconds=max(1, min(lease_seconds, 3600)))
        token = str(uuid.uuid4())
        self._ensure_delivery_schema()
        with self._connection() as connection:
            with connection.transaction():
                claim_sql = """SELECT alert_id, session_id, occurred_at_utc, attack_count, window_size,
                                      attempts_in_cycle
                               FROM critical_email_outbox
                               WHERE state IN ('pending','retrying') AND next_attempt_utc <= %s
                                 AND (lease_until_utc IS NULL OR lease_until_utc <= %s)"""
                claim_params: tuple[Any, ...] = (current, current)
                if selected_ids is not None:
                    claim_sql += " AND alert_id = ANY(%s)"
                    claim_params += (list(selected_ids),)
                claim_sql += " ORDER BY created_at_utc, alert_id LIMIT %s FOR UPDATE SKIP LOCKED"
                rows = connection.execute(claim_sql, claim_params + (limit,)).fetchall()
                claimed: list[dict[str, Any]] = []
                for row in rows:
                    connection.execute(
                        """UPDATE critical_email_outbox SET state='retrying', attempts=attempts+1,
                           attempts_in_cycle=attempts_in_cycle+1, last_attempt_at_utc=%s,
                           updated_at_utc=%s, lease_token=%s, lease_until_utc=%s WHERE alert_id=%s""",
                        (current, current, token, lease_until, row["alert_id"]),
                    )
                    claimed.append(self._pg_delivery_row(dict(row) | {
                        "alert_id": str(row["alert_id"]), "session_id": str(row["session_id"]),
                        "attempts_in_cycle": int(row["attempts_in_cycle"]) + 1,
                    }))
                return token, claimed

    def complete_critical_alert(self, alert_id: str, lease_token: str) -> bool:
        alert_id = self._validate_alert_id(alert_id, "alert_id")
        self._ensure_delivery_schema()
        with self._connection() as connection:
            with connection.transaction():
                cursor = connection.execute(
                    """UPDATE critical_email_outbox SET state='delivered', delivered_at_utc=%s,
                       updated_at_utc=%s, lease_token=NULL, lease_until_utc=NULL, last_error_code=NULL
                       WHERE alert_id=%s AND state='retrying' AND lease_token=%s""",
                    (datetime.now(timezone.utc), datetime.now(timezone.utc), alert_id, lease_token),
                )
                return cursor.rowcount == 1

    def fail_critical_alert(self, alert_id: str, lease_token: str, *, error_code: str,
                            delay_seconds: int = 0, permanent: bool = False,
                            exhausted: bool = False) -> bool:
        alert_id = self._validate_alert_id(alert_id, "alert_id")
        now = datetime.now(timezone.utc)
        state = "permanently_failed" if permanent or exhausted else "pending"
        next_attempt = now + timedelta(seconds=max(0, min(int(delay_seconds), 86400)))
        self._ensure_delivery_schema()
        with self._connection() as connection:
            with connection.transaction():
                cursor = connection.execute(
                    """UPDATE critical_email_outbox SET state=%s, next_attempt_utc=%s, updated_at_utc=%s,
                       lease_token=NULL, lease_until_utc=NULL, last_error_code=%s
                       WHERE alert_id=%s AND state='retrying' AND lease_token=%s""",
                    (state, next_attempt, now, self._safe_delivery_error(error_code), alert_id, lease_token),
                )
                return cursor.rowcount == 1

    def retry_failed_critical_alerts(self, alert_ids: Iterable[str]) -> int:
        ids = tuple(dict.fromkeys(self._validate_alert_id(item, "alert_id") for item in alert_ids))
        if not 1 <= len(ids) <= 100:
            raise ValueError("provide between 1 and 100 alert IDs")
        now = datetime.now(timezone.utc)
        self._ensure_delivery_schema()
        with self._connection() as connection:
            with connection.transaction():
                count = 0
                for alert_id in ids:
                    cursor = connection.execute(
                        """UPDATE critical_email_outbox SET state='pending', attempts_in_cycle=0,
                           next_attempt_utc=%s, updated_at_utc=%s, lease_token=NULL, lease_until_utc=NULL,
                           last_error_code=NULL WHERE alert_id=%s AND state='permanently_failed'""",
                        (now, now, alert_id),
                    )
                    count += cursor.rowcount
                return count

    def critical_email_alert_counts(self) -> dict[str, int]:
        self._ensure_delivery_schema()
        with self._connection() as connection:
            rows = connection.execute(
                "SELECT state, COUNT(*) AS n FROM critical_email_outbox GROUP BY state"
            ).fetchall()
        counts = {"pending": 0, "retrying": 0, "delivered": 0, "failed": 0}
        for row in rows:
            key = "failed" if row["state"] == "permanently_failed" else row["state"]
            counts[key] = int(row["n"])
        counts["pending"] += counts["retrying"]
        return counts

    def list_critical_email_alerts(self, *, state: str | None = None, limit: int = 50) -> list[dict[str, Any]]:
        if type(limit) is not int or not 1 <= limit <= 100:
            raise ValueError("critical alert list limit must be between 1 and 100")
        states = {"pending": "pending", "retrying": "retrying", "failed": "permanently_failed",
                  "permanently_failed": "permanently_failed", "delivered": "delivered"}
        if state is not None and state not in states:
            raise ValueError("unsupported critical alert state")
        self._ensure_delivery_schema()
        columns = "alert_id,state,attempts,created_at_utc,updated_at_utc,next_attempt_utc,last_attempt_at_utc,delivered_at_utc,last_error_code"
        with self._connection() as connection:
            if state is None:
                rows = connection.execute(
                    f"SELECT {columns} FROM critical_email_outbox ORDER BY created_at_utc DESC,alert_id LIMIT %s", (limit,)
                ).fetchall()
            else:
                rows = connection.execute(
                    f"SELECT {columns} FROM critical_email_outbox WHERE state=%s ORDER BY created_at_utc DESC,alert_id LIMIT %s",
                    (states[state], limit),
                ).fetchall()
        result = []
        for row in rows:
            item = self._pg_delivery_row(row)
            item["alert_id"] = str(item["alert_id"])
            result.append(item)
        return result

    def summarize_critical_email_alerts(self, start_time: datetime, end_time: datetime) -> dict[str, int]:
        start, end = _parse_interval_time(start_time, "start_time"), _parse_interval_time(end_time, "end_time")
        if start >= end:
            raise EventValidationError("start_time must be earlier than end_time")
        self._ensure_delivery_schema()
        with self._connection() as connection:
            rows = connection.execute(
                """SELECT state,COUNT(*) AS n FROM critical_email_outbox
                   WHERE occurred_at_utc >= %s AND occurred_at_utc < %s GROUP BY state""", (start, end)
            ).fetchall()
        result = {"incidents": 0, "pending": 0, "delivered": 0, "failed": 0}
        for row in rows:
            count = int(row["n"])
            result["incidents"] += count
            if row["state"] in {"pending", "retrying"}:
                result["pending"] += count
            elif row["state"] == "delivered":
                result["delivered"] += count
            else:
                result["failed"] += count
        return result

    def enqueue_weekly_report(self, report: Mapping[str, Any]) -> bool:
        if not isinstance(report, Mapping):
            raise EventValidationError("report must be a mapping")
        report_id = self._validate_alert_id(report.get("report_id"), "report_id")
        start, end = _parse_utc(report.get("interval_start_utc"), "interval_start_utc"), _parse_utc(report.get("interval_end_utc"), "interval_end_utc")
        generated = _parse_utc(report.get("generated_at_utc"), "generated_at_utc")
        recipient, body = report.get("recipient_email"), report.get("report_text")
        if start >= end:
            raise EventValidationError("report interval must be positive")
        if not isinstance(recipient, str) or not recipient.strip() or len(recipient) > 320:
            raise EventValidationError("report recipient is invalid")
        if not isinstance(body, str) or not body.strip() or len(body) > 100_000:
            raise EventValidationError("report text is invalid")
        now = datetime.now(timezone.utc)
        self._ensure_delivery_schema()
        with self._connection() as connection:
            with connection.transaction():
                cursor = connection.execute(
                    """INSERT INTO weekly_report_outbox
                       (report_id,interval_start_utc,interval_end_utc,generated_at_utc,recipient_email,report_text,
                        state,created_at_utc,updated_at_utc,next_attempt_utc)
                       VALUES (%s,%s,%s,%s,%s,%s,'pending',%s,%s,%s)
                       ON CONFLICT(report_id) DO NOTHING""",
                    (report_id, start, end, generated, recipient, body, now, now, now),
                )
                if cursor.rowcount == 1:
                    return True
                existing = connection.execute(
                    "SELECT interval_start_utc,interval_end_utc,recipient_email,report_text "
                    "FROM weekly_report_outbox WHERE report_id=%s", (report_id,),
                ).fetchone()
                if existing is None or (
                    existing["interval_start_utc"] != start or existing["interval_end_utc"] != end
                    or existing["recipient_email"] != recipient or existing["report_text"] != body
                ):
                    raise EventValidationError("report_id already exists with different report content")
                return False

    def get_weekly_report(self, report_id: str) -> dict[str, Any] | None:
        report_id = self._validate_alert_id(report_id, "report_id")
        self._ensure_delivery_schema()
        with self._connection() as connection:
            row = connection.execute(
                """SELECT report_id,interval_start_utc,interval_end_utc,generated_at_utc,report_text,state,
                   attempts,attempts_in_cycle,next_attempt_utc,delivered_at_utc,last_error_code FROM weekly_report_outbox WHERE report_id=%s""",
                (report_id,),
            ).fetchone()
        if row is None:
            return None
        result = self._pg_delivery_row(row)
        result["report_id"] = str(result["report_id"])
        return result

    def list_due_weekly_reports(self, *, limit: int = 20, now: datetime | None = None) -> list[str]:
        if type(limit) is not int or not 1 <= limit <= 100:
            raise ValueError("weekly report due limit must be between 1 and 100")
        current = _parse_interval_time(now or datetime.now(timezone.utc), "now")
        self._ensure_delivery_schema()
        with self._connection() as connection:
            rows = connection.execute(
                """SELECT report_id FROM weekly_report_outbox WHERE state IN ('pending','retrying')
                   AND next_attempt_utc <= %s AND (lease_until_utc IS NULL OR lease_until_utc <= %s)
                   ORDER BY created_at_utc,report_id LIMIT %s""", (current, current, limit),
            ).fetchall()
        return [str(row["report_id"]) for row in rows]

    def claim_weekly_report(self, report_id: str, *, lease_seconds: int = 180,
                            now: datetime | None = None) -> tuple[str, dict[str, Any] | None]:
        report_id = self._validate_alert_id(report_id, "report_id")
        current = _parse_interval_time(now or datetime.now(timezone.utc), "now")
        lease_until = current + timedelta(seconds=max(1, min(lease_seconds, 3600)))
        token = str(uuid.uuid4())
        self._ensure_delivery_schema()
        with self._connection() as connection:
            with connection.transaction():
                row = connection.execute(
                   """SELECT report_id,recipient_email,report_text,attempts,attempts_in_cycle FROM weekly_report_outbox
                       WHERE report_id=%s AND state IN ('pending','retrying') AND next_attempt_utc <= %s
                         AND (lease_until_utc IS NULL OR lease_until_utc <= %s) FOR UPDATE SKIP LOCKED""",
                    (report_id, current, current),
                ).fetchone()
                if row is None:
                    return token, None
                connection.execute(
                       """UPDATE weekly_report_outbox SET state='retrying',attempts=attempts+1,
                       attempts_in_cycle=attempts_in_cycle+1,
                       last_attempt_at_utc=%s,updated_at_utc=%s,lease_token=%s,lease_until_utc=%s WHERE report_id=%s""",
                    (current, current, token, lease_until, report_id),
                )
                return token, {**dict(row), "report_id": str(row["report_id"]),
                               "attempts": int(row["attempts"]) + 1,
                               "attempts_in_cycle": int(row["attempts_in_cycle"]) + 1}

    def complete_weekly_report(self, report_id: str, lease_token: str) -> bool:
        report_id = self._validate_alert_id(report_id, "report_id")
        now = datetime.now(timezone.utc)
        self._ensure_delivery_schema()
        with self._connection() as connection:
            with connection.transaction():
                cursor = connection.execute(
                    """UPDATE weekly_report_outbox SET state='delivered',delivered_at_utc=%s,updated_at_utc=%s,
                       lease_token=NULL,lease_until_utc=NULL,last_error_code=NULL
                       WHERE report_id=%s AND state='retrying' AND lease_token=%s""",
                    (now, now, report_id, lease_token),
                )
                return cursor.rowcount == 1

    def fail_weekly_report(self, report_id: str, lease_token: str, *, error_code: str,
                           delay_seconds: int = 0, permanent: bool = False,
                           exhausted: bool = False) -> bool:
        report_id = self._validate_alert_id(report_id, "report_id")
        now = datetime.now(timezone.utc)
        next_attempt = now + timedelta(seconds=max(0, min(int(delay_seconds), 86400)))
        state = "permanently_failed" if permanent or exhausted else "pending"
        self._ensure_delivery_schema()
        with self._connection() as connection:
            with connection.transaction():
                cursor = connection.execute(
                    """UPDATE weekly_report_outbox SET state=%s,next_attempt_utc=%s,updated_at_utc=%s,
                       lease_token=NULL,lease_until_utc=NULL,last_error_code=%s
                       WHERE report_id=%s AND state='retrying' AND lease_token=%s""",
                    (state, next_attempt, now, self._safe_delivery_error(error_code), report_id, lease_token),
                )
                return cursor.rowcount == 1

    def retry_failed_weekly_reports(self, report_ids: Iterable[str]) -> int:
        ids = tuple(dict.fromkeys(self._validate_alert_id(item, "report_id") for item in report_ids))
        if not 1 <= len(ids) <= 100:
            raise ValueError("provide between 1 and 100 report IDs")
        now = datetime.now(timezone.utc)
        self._ensure_delivery_schema()
        with self._connection() as connection:
            with connection.transaction():
                count = 0
                for report_id in ids:
                    cursor = connection.execute(
                       """UPDATE weekly_report_outbox SET state='pending',attempts_in_cycle=0,
                       next_attempt_utc=%s,updated_at_utc=%s,
                           lease_token=NULL,lease_until_utc=NULL,last_error_code=NULL
                           WHERE report_id=%s AND state='permanently_failed'""",
                        (now, now, report_id),
                    )
                    count += cursor.rowcount
                return count

    def prune_delivery_records(self, *, retention_days: int | None = None,
                               now: datetime | None = None, limit: int = 1000) -> int:
        days = _delivery_retention_days(retention_days)
        if days is None:
            return 0
        cutoff = _parse_interval_time(now or datetime.now(timezone.utc), "now") - timedelta(days=days)
        if type(limit) is not int or not 1 <= limit <= 10000:
            raise ValueError("delivery pruning limit must be between 1 and 10000")
        self._ensure_delivery_schema()
        deleted = 0
        with self._connection() as connection:
            with connection.transaction():
                cursor = connection.execute(
                    """WITH old_delivered AS (
                           SELECT ctid FROM critical_email_outbox
                           WHERE state='delivered' AND updated_at_utc < %s
                           ORDER BY updated_at_utc LIMIT %s FOR UPDATE SKIP LOCKED
                       ) DELETE FROM critical_email_outbox WHERE ctid IN (SELECT ctid FROM old_delivered)""",
                    (cutoff, limit),
                )
                deleted = cursor.rowcount
        return deleted

    @staticmethod
    def _row_to_event(row: Mapping[str, Any]) -> dict[str, Any]:
        timestamp = row["occurred_at_utc"].astimezone(timezone.utc)
        return {
            "event_id": str(row["event_id"]),
            "schema_version": row["schema_version"],
            "occurred_at_utc": timestamp.isoformat(timespec="microseconds").replace("+00:00", "Z"),
            "origin": row["origin"],
            "session_id": row["session_id"],
            "event_type": row["event_type"],
            "classification": row["classification"],
            "metadata": row["metadata"],
        }

    def append(self, event: Mapping[str, Any]) -> bool:
        return self.append_many((event,)) == 1

    def append_many(self, events: Iterable[Mapping[str, Any]], *, enqueue_forward: bool | None = None) -> int:
        del enqueue_forward  # Hosted PostgreSQL is a receiver, not a sensor forwarding outbox.
        records = _validated_batch(events)
        if not records:
            return 0
        self._ensure_schema()
        from psycopg.types.json import Jsonb
        inserted = 0
        with self._connection() as connection:
            with connection.transaction():
                for record in records:
                    timestamp = _parse_utc(record["occurred_at_utc"], "occurred_at_utc")
                    cursor = connection.execute(
                        """INSERT INTO events (
                            event_id, schema_version, occurred_at_utc, origin, session_id,
                            event_type, classification, metadata
                        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                        ON CONFLICT(event_id) DO NOTHING""",
                        (record["event_id"], record["schema_version"], timestamp,
                         record["origin"], record["session_id"], record["event_type"],
                         record["classification"], Jsonb(record["metadata"])),
                    )
                    if cursor.rowcount == 1:
                        inserted += 1
                        continue
                    existing = connection.execute(
                        "SELECT * FROM events WHERE event_id = %s", (record["event_id"],)
                    ).fetchone()
                    if existing is None or self._row_to_event(existing) != record:
                        raise EventValidationError("event_id already exists with different event content")
        return inserted

    def ingest_many(self, events: Iterable[Mapping[str, Any]]) -> int:
        return self.append_many(events, enqueue_forward=False)

    def iter_events(self, start_time: datetime, end_time: datetime, *,
                    origins: Iterable[str] | None = None,
                    event_types: Iterable[str] | None = None) -> Iterator[dict[str, Any]]:
        start = _parse_interval_time(start_time, "start_time")
        end = _parse_interval_time(end_time, "end_time")
        if start >= end:
            raise EventValidationError("start_time must be earlier than end_time")
        clauses = ["occurred_at_utc >= %s", "occurred_at_utc < %s"]
        params: list[Any] = [start, end]
        for field, values, allowed in (
            ("origin", origins, ALLOWED_ORIGINS),
            ("event_type", event_types, ALLOWED_EVENT_TYPES),
        ):
            if values is not None:
                normalized = tuple(values)
                if any(value not in allowed for value in normalized):
                    raise EventValidationError(f"invalid {field} filter")
                if not normalized:
                    return iter(())
                clauses.append(f"{field} IN ({','.join('%s' for _ in normalized)})")
                params.extend(normalized)
        self._ensure_schema()
        query = "SELECT * FROM events WHERE " + " AND ".join(clauses) + " ORDER BY occurred_at_utc, event_id"

        def generate() -> Iterator[dict[str, Any]]:
            with self._connection() as connection:
                with connection.cursor(name="netra_event_query") as cursor:
                    cursor.execute(query, params)
                    while rows := cursor.fetchmany(256):
                        for row in rows:
                            yield self._row_to_event(row)
        return generate()

    def aggregate_events(self, start_time: datetime, end_time: datetime, *, bucket_seconds: int,
                         origins: Iterable[str] | None = None) -> list[dict[str, Any]]:
        start = _parse_interval_time(start_time, "start_time")
        end = _parse_interval_time(end_time, "end_time")
        if start >= end or type(bucket_seconds) is not int or bucket_seconds < 1:
            raise EventValidationError("invalid aggregation interval or bucket size")
        clauses = ["occurred_at_utc >= %s", "occurred_at_utc < %s"]
        filter_params: list[Any] = [start, end]
        if origins is not None:
            selected = tuple(origins)
            if any(origin not in ALLOWED_ORIGINS for origin in selected):
                raise EventValidationError("invalid origin filter")
            if not selected:
                return []
            clauses.append(f"origin IN ({','.join('%s' for _ in selected)})")
            filter_params.extend(selected)
        self._ensure_schema()
        query = """SELECT floor(extract(epoch from occurred_at_utc) / %s)::bigint * %s AS bucket_epoch,
            COUNT(*) AS event_count,
            SUM(CASE WHEN event_type='flow_classification' THEN 1 ELSE 0 END) AS flow_count,
            SUM(CASE WHEN event_type='flow_classification' AND classification='BENIGN' THEN 1 ELSE 0 END) AS benign_count,
            SUM(CASE WHEN event_type='flow_classification' AND classification='ATTACK' THEN 1 ELSE 0 END) AS attack_count,
            SUM(CASE WHEN event_type='alert' THEN 1 ELSE 0 END) AS alert_count,
            SUM(CASE WHEN event_type='capture_error' THEN 1 ELSE 0 END) AS capture_error_count,
            SUM(CASE WHEN event_type='processing_error' THEN 1 ELSE 0 END) AS processing_error_count,
            SUM(CASE WHEN event_type='flow_classification' THEN COALESCE((metadata->>'packet_count')::bigint, 0) ELSE 0 END) AS packet_count,
            SUM(CASE WHEN event_type='flow_classification' THEN COALESCE((metadata->>'byte_count')::bigint, 0) ELSE 0 END) AS byte_count
            FROM events WHERE """ + " AND ".join(clauses) + " GROUP BY bucket_epoch ORDER BY bucket_epoch LIMIT 1000"
        # SELECT placeholders precede the WHERE placeholders in SQL order.
        params = [bucket_seconds, bucket_seconds, *filter_params]
        with self._connection() as connection:
            with connection.cursor() as cursor:
                cursor.execute(query, params)
                rows = cursor.fetchall()
        return [{"bucket_start_utc": datetime.fromtimestamp(int(row["bucket_epoch"]), timezone.utc).isoformat().replace("+00:00", "Z"),
                 **{key: int(row[key] or 0) for key in ("event_count", "flow_count", "benign_count", "attack_count",
                    "alert_count", "capture_error_count", "processing_error_count", "packet_count", "byte_count")}}
                for row in rows]

    def prune_expired(self, retention_days: int | None = None, *, now: datetime | None = None) -> int:
        if retention_days is None:
            try:
                retention_days = int(os.getenv("NETRA_EVENT_RETENTION_DAYS", str(DEFAULT_RETENTION_DAYS)))
            except ValueError as exc:
                raise EventValidationError("NETRA_EVENT_RETENTION_DAYS must be a positive integer") from exc
        if type(retention_days) is not int or retention_days < 1:
            raise EventValidationError("retention_days must be a positive integer")
        cutoff = _parse_interval_time(now or datetime.now(timezone.utc), "now") - timedelta(days=retention_days)
        self._ensure_schema()
        deleted = 0
        while True:
            with self._connection() as connection:
                with connection.transaction():
                    cursor = connection.execute(
                        """WITH expired AS (
                            SELECT event_id FROM events WHERE occurred_at_utc < %s
                            ORDER BY occurred_at_utc LIMIT 1000
                        ) DELETE FROM events WHERE event_id IN (SELECT event_id FROM expired)""",
                        (cutoff,),
                    )
                    count = cursor.rowcount
            deleted += count
            if count < 1000:
                return deleted


def create_event_repository(*, backend: str | None = None, database_url: str | None = None,
                            sqlite_path: str | os.PathLike[str] | None = None) -> EventRepository:
    """Select a configured backend explicitly; PostgreSQL misconfiguration never falls back."""
    selected = (backend or os.getenv("NETRA_EVENT_BACKEND", "sqlite")).strip().lower()
    if selected == "sqlite":
        return SQLiteEventRepository(sqlite_path)
    if selected in {"postgres", "postgresql"}:
        return PostgreSQLEventRepository(database_url)
    raise ValueError("NETRA_EVENT_BACKEND must be 'sqlite' or 'postgresql'")


def create_delivery_repository(*, role: str | None = None, backend: str | None = None,
                               database_url: str | None = None,
                               sqlite_path: str | os.PathLike[str] | None = None):
    """Select delivery storage by process role; hosted roles cannot use SQLite."""
    selected_role = (role or os.getenv("NETRA_RUNTIME_ROLE", "local_sensor")).strip().lower()
    valid_roles = {"local_sensor", "hosted_web", "hosted_worker", "report_job"}
    if selected_role not in valid_roles:
        raise ValueError("NETRA_RUNTIME_ROLE is not a supported delivery role")
    selected = (backend or os.getenv("NETRA_DELIVERY_BACKEND", "")).strip().lower()
    if not selected:
        if selected_role == "local_sensor":
            selected = "sqlite"
        else:
            raise RuntimeError(
                f"{selected_role} requires NETRA_DELIVERY_BACKEND=postgresql; refusing local storage"
            )
    if selected_role != "local_sensor" and selected not in {"postgres", "postgresql"}:
        raise RuntimeError(f"{selected_role} requires PostgreSQL delivery storage; refusing SQLite fallback")
    if selected == "sqlite":
        return SQLiteEventRepository(sqlite_path)
    if selected in {"postgres", "postgresql"}:
        timeout_raw = os.getenv("NETRA_DATABASE_CONNECT_TIMEOUT_SECONDS", "3")
        try:
            timeout = int(timeout_raw)
        except ValueError as exc:
            raise ValueError("NETRA_DATABASE_CONNECT_TIMEOUT_SECONDS must be an integer") from exc
        if not 1 <= timeout <= 15:
            raise ValueError("NETRA_DATABASE_CONNECT_TIMEOUT_SECONDS must be between 1 and 15")
        repository = PostgreSQLEventRepository(database_url, connect_timeout=timeout)
        try:
            import psycopg  # noqa: F401
        except ImportError as exc:
            raise RuntimeError("PostgreSQL delivery storage requires the psycopg driver") from exc
        return repository
    raise ValueError("NETRA_DELIVERY_BACKEND must be 'sqlite' or 'postgresql'")

def _parse_interval_time(value: datetime, field_name: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise EventValidationError(f"{field_name} must be a timezone-aware datetime")
    return value.astimezone(timezone.utc)


class EventWriteQueue:
    """Bounded nonblocking handoff from detector threads to the SQLite writer."""

    def __init__(
        self,
        repository: EventRepository,
        *,
        capacity: int = DEFAULT_QUEUE_CAPACITY,
        on_error=None,
    ):
        if type(capacity) is not int or capacity < 1:
            raise ValueError("capacity must be a positive integer")
        self.repository = repository
        self._queue: queue.Queue[dict[str, Any] | None] = queue.Queue(maxsize=capacity)
        self._error_callbacks = [on_error] if on_error is not None else []
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()
        self._metrics_lock = threading.Lock()
        self._closed = False
        self._sentinel_sent = False
        self.failure_count = 0
        self.last_error: str | None = None

    def submit(self, event: Mapping[str, Any]) -> bool:
        record = validate_event(event)
        with self._lock:
            if self._closed:
                self._record_failure(RuntimeError("event writer is closed"))
                return False
            if self._thread is None:
                self._thread = threading.Thread(target=self._run, name="netra-event-writer", daemon=True)
                self._thread.start()
            try:
                self._queue.put_nowait(record)
                return True
            except queue.Full:
                self._record_failure(RuntimeError("event history queue is full; event was not persisted"))
                return False

    def _record_failure(self, error: Exception) -> None:
        with self._metrics_lock:
            self.failure_count += 1
            self.last_error = str(error)
            callbacks = tuple(self._error_callbacks)
        for callback in callbacks:
            try:
                callback(error)
            except Exception:
                _logger.exception("Event history error callback failed")

    def add_error_handler(self, callback) -> None:
        if callback is None:
            return
        with self._metrics_lock:
            if callback not in self._error_callbacks:
                self._error_callbacks.append(callback)

    def _run(self) -> None:
        while True:
            item = self._queue.get()
            try:
                if item is None:
                    return
                try:
                    self.repository.append(item)
                except Exception as exc:
                    self._record_failure(exc)
                    _logger.exception("NETRA event history write failed")
            finally:
                self._queue.task_done()

    def flush(self, timeout: float = 5.0) -> bool:
        deadline = time.monotonic() + max(0.0, timeout)
        while self._queue.unfinished_tasks:
            if time.monotonic() >= deadline:
                return False
            time.sleep(0.005)
        return True

    def close(self, timeout: float = 5.0) -> bool:
        deadline = time.monotonic() + max(0.0, timeout)
        with self._lock:
            if self._closed:
                thread = self._thread
            else:
                self._closed = True
                thread = self._thread
        if thread is None:
            return True
        if not self.flush(max(0.0, deadline - time.monotonic())):
            return False
        with self._lock:
            if not self._sentinel_sent:
                try:
                    self._queue.put(None, timeout=max(0.0, deadline - time.monotonic()))
                except queue.Full:
                    return False
                self._sentinel_sent = True
        thread.join(max(0.0, deadline - time.monotonic()))
        return not thread.is_alive()
