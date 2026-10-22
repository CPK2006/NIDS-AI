"""Opt-in integration checks for a local disposable PostgreSQL test database."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager, nullcontext
from datetime import datetime, timedelta, timezone
from importlib.util import find_spec
import os
import unittest
import uuid
from urllib.parse import urlsplit

from v2.event_store import PostgreSQLEventRepository


_DATABASE_URL = os.getenv("NETRA_TEST_DATABASE_URL", "").strip()
try:
    _LOCAL_DATABASE = bool(_DATABASE_URL and find_spec("psycopg") and urlsplit(_DATABASE_URL).hostname in {
        "localhost", "127.0.0.1", "::1",
    })
except ValueError:
    _LOCAL_DATABASE = False


class PostgreSQLDeliveryUnitTests(unittest.TestCase):
    def repository_with_connection(self, connection):
        repository = PostgreSQLEventRepository("postgresql://user:password@localhost/netra")

        @contextmanager
        def fake_connection():
            yield connection

        repository._connection = fake_connection
        return repository

    def test_migration_is_versioned_transactional_and_idempotent_per_instance(self):
        statements = []

        class Cursor:
            rowcount = 0
            def fetchone(self): return {"version": 1}

        class Connection:
            transactions = 0
            def transaction(self):
                self.transactions += 1
                return nullcontext()
            def execute(self, query, params=None):
                statements.append((query, params))
                return Cursor()

        connection = Connection()
        repository = self.repository_with_connection(connection)
        repository._ensure_delivery_schema()
        repository._ensure_delivery_schema()
        sql = "\n".join(query for query, _ in statements)
        self.assertEqual(connection.transactions, 1)
        self.assertIn("pg_advisory_xact_lock", sql)
        self.assertIn("CREATE TABLE IF NOT EXISTS critical_email_outbox", sql)
        self.assertIn("CREATE TABLE IF NOT EXISTS weekly_report_outbox", sql)
        self.assertIn("component = 'delivery'", sql)

    def test_alert_insert_is_parameterized_and_uses_stable_uuid(self):
        statements = []

        class Cursor:
            rowcount = 1

        class Connection:
            def transaction(self): return nullcontext()
            def execute(self, query, params=None):
                statements.append((query, params))
                return Cursor()

        repository = self.repository_with_connection(Connection())
        repository._ensure_delivery_schema = lambda: None
        alert_id, session_id = str(uuid.uuid4()), str(uuid.uuid4())
        incident = {"alert_id": alert_id, "session_id": session_id, "attack_count": 10,
                    "window_size": 20, "occurred_at_utc": datetime.now(timezone.utc).isoformat()}
        self.assertTrue(repository.enqueue_critical_alert(incident))
        query, params = statements[0]
        self.assertIn("VALUES (%s,%s,%s,%s,%s,'pending',%s,%s,%s)", query)
        self.assertEqual(params[0:2], (alert_id, session_id))
        self.assertNotIn(alert_id, query)

    def test_critical_claim_uses_row_skip_lock_and_lease_token(self):
        statements = []
        alert_id, session_id = uuid.uuid4(), uuid.uuid4()

        class Cursor:
            rowcount = 1
            def fetchall(self):
                return [{"alert_id": alert_id, "session_id": session_id,
                         "occurred_at_utc": datetime.now(timezone.utc), "attack_count": 10,
                         "window_size": 20, "attempts_in_cycle": 0}]

        class Connection:
            def transaction(self): return nullcontext()
            def execute(self, query, params=None):
                statements.append((query, params))
                return Cursor()

        repository = self.repository_with_connection(Connection())
        repository._ensure_delivery_schema = lambda: None
        token, claims = repository.claim_critical_alerts()
        self.assertEqual(len(claims), 1)
        self.assertEqual(claims[0]["attempts_in_cycle"], 1)
        self.assertIn("FOR UPDATE SKIP LOCKED", statements[0][0])
        self.assertEqual(statements[1][1][2], token)


@unittest.skipUnless(_LOCAL_DATABASE, "requires psycopg and NETRA_TEST_DATABASE_URL for a disposable local PostgreSQL database")
class PostgreSQLDeliveryIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.repository = PostgreSQLEventRepository(_DATABASE_URL)
        cls.alert_ids = []
        cls.report_ids = []
        cls.repository._ensure_delivery_schema()

    @classmethod
    def tearDownClass(cls):
        with cls.repository._connection() as connection:
            with connection.transaction():
                for alert_id in cls.alert_ids:
                    connection.execute("DELETE FROM critical_email_outbox WHERE alert_id=%s", (alert_id,))
                for report_id in cls.report_ids:
                    connection.execute("DELETE FROM weekly_report_outbox WHERE report_id=%s", (report_id,))

    def incident(self):
        alert_id = str(uuid.uuid4())
        self.alert_ids.append(alert_id)
        return {"alert_id": alert_id, "session_id": str(uuid.uuid4()), "attack_count": 10,
                "window_size": 20, "occurred_at_utc": datetime.now(timezone.utc).isoformat()}

    def test_migration_is_idempotent_and_alert_insert_is_stable(self):
        self.repository._ensure_delivery_schema()
        with self.repository._connection() as connection:
            versions = connection.execute(
                "SELECT version FROM netra_schema_version WHERE component='delivery'").fetchone()
        self.assertEqual(versions["version"], 2)
        incident = self.incident()
        self.assertTrue(self.repository.enqueue_critical_alert(incident))
        self.assertFalse(self.repository.enqueue_critical_alert(incident))
        with self.repository._connection() as connection:
            row = connection.execute("SELECT state FROM critical_email_outbox WHERE alert_id=%s",
                                     (incident["alert_id"],)).fetchone()
        self.assertEqual(row["state"], "pending")
        token, claimed = self.repository.claim_critical_alerts(alert_ids=[incident["alert_id"]])
        self.assertEqual(len(claimed), 1)
        self.assertEqual(claimed[0]["alert_id"], incident["alert_id"])
        self.assertTrue(self.repository.complete_critical_alert(incident["alert_id"], token))

    def test_concurrent_claims_lease_expiry_and_bounded_retry_state(self):
        incident = self.incident()
        self.repository.enqueue_critical_alert(incident)
        other = PostgreSQLEventRepository(_DATABASE_URL)
        with ThreadPoolExecutor(max_workers=2) as pool:
            claims = list(pool.map(lambda repo: repo.claim_critical_alerts(limit=1, lease_seconds=1),
                                   (self.repository, other)))
        nonempty = [(token, rows) for token, rows in claims if rows]
        self.assertEqual(len(nonempty), 1)
        _token, rows = nonempty[0]
        self.assertEqual(rows[0]["alert_id"], incident["alert_id"])
        claim_time = datetime.now(timezone.utc) + timedelta(seconds=2)
        reclaim_token, reclaimed = self.repository.claim_critical_alerts(
            limit=1, lease_seconds=1, now=claim_time)
        self.assertEqual(len(reclaimed), 1)
        self.assertEqual(reclaimed[0]["attempts_in_cycle"], 2)
        self.assertTrue(self.repository.fail_critical_alert(
            incident["alert_id"], reclaim_token, error_code="http_503", permanent=True))
        self.assertEqual(self.repository.retry_failed_critical_alerts([incident["alert_id"]]), 1)

    def test_report_id_visibility_retry_and_delivery_summary(self):
        incident = self.incident()
        self.repository.enqueue_critical_alert(incident)
        report_id = str(uuid.uuid4())
        self.report_ids.append(report_id)
        report = {"report_id": report_id,
                  "interval_start_utc": (datetime.now(timezone.utc) - timedelta(days=7)).isoformat(),
                  "interval_end_utc": datetime.now(timezone.utc).isoformat(),
                  "generated_at_utc": datetime.now(timezone.utc).isoformat(),
                  "recipient_email": "test@example.invalid", "report_text": "test report"}
        self.assertTrue(self.repository.enqueue_weekly_report(report))
        self.assertFalse(self.repository.enqueue_weekly_report(report))
        token, claimed = self.repository.claim_weekly_report(report_id)
        self.assertIsNotNone(claimed)
        self.assertTrue(self.repository.fail_weekly_report(report_id, token,
                                                           error_code="http_503", permanent=True))
        self.assertEqual(self.repository.retry_failed_weekly_reports([report_id]), 1)
        self.assertEqual(self.repository.get_weekly_report(report_id)["state"], "pending")
        token, claimed = self.repository.claim_weekly_report(report_id)
        self.assertIsNotNone(claimed)
        self.assertTrue(self.repository.complete_weekly_report(report_id, token))
        summary = self.repository.summarize_critical_email_alerts(
            datetime.now(timezone.utc) - timedelta(days=1), datetime.now(timezone.utc) + timedelta(seconds=1))
        self.assertGreaterEqual(summary["incidents"], 1)

    def test_retention_prunes_only_old_delivered_critical_rows(self):
        delivered = self.incident()
        pending = self.incident()
        failed = self.incident()
        for item in (delivered, pending, failed):
            self.repository.enqueue_critical_alert(item)
        now = datetime.now(timezone.utc)
        token, claimed = self.repository.claim_critical_alerts(limit=10)
        for item in claimed:
            if item["alert_id"] == delivered["alert_id"]:
                self.repository.complete_critical_alert(item["alert_id"], token)
            elif item["alert_id"] == failed["alert_id"]:
                self.repository.fail_critical_alert(item["alert_id"], token,
                                                     error_code="http_422", permanent=True)
            else:
                # Leave the final claimed record retryable under an unexpired lease.
                pass
        old = now - timedelta(days=500)
        with self.repository._connection() as connection:
            with connection.transaction():
                for item in (delivered, pending, failed):
                    connection.execute("UPDATE critical_email_outbox SET updated_at_utc=%s WHERE alert_id=%s",
                                       (old, item["alert_id"]))
        self.assertEqual(self.repository.prune_delivery_records(retention_days=365), 1)
        with self.repository._connection() as connection:
            states = {str(row["alert_id"]): row["state"] for row in connection.execute(
                "SELECT alert_id,state FROM critical_email_outbox WHERE alert_id::text = ANY(%s)",
                ([item["alert_id"] for item in (pending, failed)],),
            ).fetchall()}
        self.assertEqual(states[pending["alert_id"]], "retrying")
        self.assertEqual(states[failed["alert_id"]], "permanently_failed")


if __name__ == "__main__":
    unittest.main()
