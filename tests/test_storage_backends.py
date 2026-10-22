from contextlib import closing, contextmanager, nullcontext
from datetime import datetime, timezone
import os
import sqlite3
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

from v2.event_store import (
    PostgreSQLEventRepository,
    SQLiteEventRepository,
    create_delivery_repository,
    create_event,
    create_event_repository,
)


class StorageBackendTests(unittest.TestCase):
    def sample_event(self):
        return create_event(
            origin="live", session_id="run", event_type="flow_classification",
            classification="BENIGN", metadata={"packet_count": 3},
            occurred_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        )

    def test_repository_selection_is_explicit_and_postgres_never_falls_back(self):
        self.assertIsInstance(create_event_repository(backend="sqlite"), SQLiteEventRepository)
        with patch.dict(os.environ, {"DATABASE_URL": ""}):
            with self.assertRaisesRegex(RuntimeError, "requires DATABASE_URL"):
                create_event_repository(backend="postgresql")
        with self.assertRaisesRegex(ValueError, "NETRA_EVENT_BACKEND"):
            create_event_repository(backend="mysql")

    def test_hosted_delivery_roles_require_explicit_postgresql_without_sqlite_fallback(self):
        with patch.dict(os.environ, {"NETRA_DELIVERY_BACKEND": "", "DATABASE_URL": ""}):
            with self.assertRaisesRegex(RuntimeError, "requires NETRA_DELIVERY_BACKEND=postgresql"):
                create_delivery_repository(role="hosted_worker")
        with patch.dict(os.environ, {"NETRA_DELIVERY_BACKEND": "sqlite"}):
            with self.assertRaisesRegex(RuntimeError, "refusing SQLite fallback"):
                create_delivery_repository(role="report_job")
        with patch.dict(os.environ, {"NETRA_DELIVERY_BACKEND": "postgresql",
                                     "DATABASE_URL": "file:///private/path"}):
            with self.assertRaisesRegex(RuntimeError, "valid DATABASE_URL"):
                create_delivery_repository(role="hosted_worker")
        with patch.dict(os.environ, {"NETRA_DELIVERY_BACKEND": "postgresql",
                                     "DATABASE_URL": "postgresql://user:pass@localhost/netra"}), \
             patch.dict(sys.modules, {"psycopg": None}):
            with self.assertRaisesRegex(RuntimeError, "requires the psycopg driver"):
                create_delivery_repository(role="hosted_worker")
        local = create_delivery_repository(role="local_sensor", backend="sqlite")
        self.assertIsInstance(local, SQLiteEventRepository)

    def test_sqlite_outbox_survives_repository_restart_retry_and_ack(self):
        with tempfile.TemporaryDirectory() as temp:
            path = os.path.join(temp, "events.sqlite3")
            repository = SQLiteEventRepository(path, forwarding_enabled=True)
            event = self.sample_event()
            repository.append(event)
            event["metadata"]["packet_count"] = 999
            reopened = SQLiteEventRepository(path, forwarding_enabled=True)
            token, batch, attempts = reopened.claim_outbox(limit=10)
            self.assertEqual(attempts, 0)
            self.assertEqual(batch[0]["metadata"]["packet_count"], 3)
            self.assertEqual(reopened.retry_outbox(
                [batch[0]["event_id"]], token, delay_seconds=0, error_code="network_Timeout"
            ), 1)
            token, batch, attempts = reopened.claim_outbox(limit=10)
            self.assertEqual(attempts, 1)
            self.assertEqual(reopened.acknowledge_outbox([batch[0]["event_id"]], token), 1)
            self.assertEqual(reopened.outbox_counts(), {"pending": 0, "blocked": 0})

    def test_sqlite_v1_schema_migrates_without_discarding_events(self):
        with tempfile.TemporaryDirectory() as temp:
            path = os.path.join(temp, "legacy.sqlite3")
            legacy_event = self.sample_event()
            import json
            connection = sqlite3.connect(path)
            try:
                connection.execute("""CREATE TABLE events (
                    event_id TEXT PRIMARY KEY, schema_version INTEGER NOT NULL,
                    occurred_at_utc TEXT NOT NULL, origin TEXT NOT NULL, session_id TEXT,
                    event_type TEXT NOT NULL, classification TEXT, metadata_json TEXT NOT NULL
                )""")
                connection.execute("INSERT INTO events VALUES (?, ?, ?, ?, ?, ?, ?, ?)", (
                    legacy_event["event_id"], legacy_event["schema_version"],
                    legacy_event["occurred_at_utc"], legacy_event["origin"],
                    legacy_event["session_id"], legacy_event["event_type"],
                    legacy_event["classification"], json.dumps(legacy_event["metadata"]),
                ))
                connection.execute("PRAGMA user_version = 1")
                connection.commit()
            finally:
                connection.close()
            repository = SQLiteEventRepository(path)
            rows = list(repository.iter_events(
                datetime(2025, 1, 1, tzinfo=timezone.utc), datetime(2027, 1, 1, tzinfo=timezone.utc)
            ))
            self.assertEqual(rows, [legacy_event])
            connection = sqlite3.connect(path)
            try:
                self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], 5)
                self.assertIsNotNone(connection.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'forwarding_outbox'"
                ).fetchone())
                self.assertIsNotNone(connection.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'critical_email_outbox'"
                ).fetchone())
                self.assertIsNotNone(connection.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'weekly_report_outbox'"
                ).fetchone())
            finally:
                connection.close()

    def test_sqlite_v4_delivery_schema_adds_weekly_retry_cycle_column_idempotently(self):
        with tempfile.TemporaryDirectory() as temp:
            path = os.path.join(temp, "v4.sqlite3")
            repository = SQLiteEventRepository(path)
            repository._ensure_schema()
            with closing(sqlite3.connect(path)) as connection:
                connection.execute("ALTER TABLE weekly_report_outbox DROP COLUMN attempts_in_cycle")
                connection.execute("PRAGMA user_version = 4")
                connection.commit()
            migrated = SQLiteEventRepository(path)
            migrated._ensure_schema()
            migrated._ensure_schema()
            with closing(sqlite3.connect(path)) as connection:
                columns = {row[1] for row in connection.execute("PRAGMA table_info(weekly_report_outbox)")}
                self.assertIn("attempts_in_cycle", columns)
                self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], 5)

    def test_full_outbox_rejects_write_without_partial_event_row(self):
        with tempfile.TemporaryDirectory() as temp, patch.dict(
            os.environ, {"NETRA_FORWARD_OUTBOX_MAX_EVENTS": "1"}
        ):
            repository = SQLiteEventRepository(
                os.path.join(temp, "events.sqlite3"), forwarding_enabled=True
            )
            first = self.sample_event()
            second = self.sample_event()
            repository.append(first)
            with self.assertRaisesRegex(RuntimeError, "outbox is full"):
                repository.append(second)
            rows = list(repository.iter_events(
                datetime(2025, 1, 1, tzinfo=timezone.utc), datetime(2027, 1, 1, tzinfo=timezone.utc)
            ))
            self.assertEqual([row["event_id"] for row in rows], [first["event_id"]])
            self.assertEqual(repository.outbox_counts(), {"pending": 1, "blocked": 0})

    def test_postgres_adapter_uses_parameterized_insert_and_transaction(self):
        statements = []

        class Cursor:
            rowcount = 1

        class Connection:
            def transaction(self):
                return nullcontext()

            def execute(self, query, params):
                statements.append((query, params))
                return Cursor()

        @contextmanager
        def fake_connection():
            yield Connection()

        pg_module = types.ModuleType("psycopg")
        pg_module.__path__ = []
        types_module = types.ModuleType("psycopg.types")
        types_module.__path__ = []
        json_module = types.ModuleType("psycopg.types.json")
        json_module.Jsonb = lambda value: value
        event_repository = PostgreSQLEventRepository("postgresql://user:pass@localhost/db")
        event_repository._ensure_schema = lambda: None
        with patch.object(event_repository, "_connection", fake_connection), patch.dict(
            sys.modules,
            {"psycopg": pg_module, "psycopg.types": types_module, "psycopg.types.json": json_module},
        ):
            self.assertEqual(event_repository.append(self.sample_event()), True)
        insert, params = statements[0]
        self.assertIn("VALUES (%s, %s, %s, %s, %s, %s, %s, %s)", insert)
        self.assertEqual(len(params), 8)
        self.assertEqual(params[-1], {"packet_count": 3})


if __name__ == "__main__":
    unittest.main()
