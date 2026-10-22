"""Durable critical-email outbox behavior; all provider calls use fakes."""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import os
import tempfile
import time
import unittest
import uuid
from unittest.mock import patch

from app.app import app, v2_engine
from v2.critical_email_alerts import ResendConfig, ResendEmailWorker
from v2.event_store import EventValidationError, PostgreSQLEventRepository, SQLiteEventRepository


class Response:
    def __init__(self, status):
        self.status_code = status


class Session:
    def __init__(self, *results):
        self.results = list(results)
        self.calls = []

    def post(self, url, **kwargs):
        self.calls.append((url, kwargs))
        result = self.results.pop(0)
        if isinstance(result, Exception):
            raise result
        return Response(result)


class CriticalEmailOutboxTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.temp.name, "email.sqlite3")
        self.repo = SQLiteEventRepository(self.path)

    def tearDown(self):
        self.temp.cleanup()

    def incident(self, alert_id=None):
        return {"alert_id": alert_id or str(uuid.uuid4()), "session_id": str(uuid.uuid4()),
                "attack_count": 10, "window_size": 20,
                "occurred_at_utc": datetime.now(timezone.utc).isoformat()}

    def config(self, **kwargs):
        values = {"enabled": True, "api_key": "test-only-secret", "sender": "alerts@example.com",
                  "recipient": "soc@example.com", "timeout_seconds": 1, "max_attempts": 2}
        values.update(kwargs)
        return ResendConfig(**values)

    def await_state(self, worker, key, expected, timeout=4):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if worker.status_snapshot()[key] == expected:
                return worker.status_snapshot()
            time.sleep(0.01)
        self.fail(f"timed out waiting for {key}={expected}")

    def test_outbox_persists_across_restart_and_duplicate_incident_ids(self):
        incident = self.incident()
        self.assertTrue(self.repo.enqueue_critical_alert(incident))
        reopened = SQLiteEventRepository(self.path)
        self.assertFalse(reopened.enqueue_critical_alert(incident))
        self.assertEqual(reopened.critical_email_alert_counts()["pending"], 1)
        changed = dict(incident, attack_count=11)
        with self.assertRaises(EventValidationError):
            reopened.enqueue_critical_alert(changed)
        token, claimed = reopened.claim_critical_alerts()
        self.assertEqual(claimed[0]["alert_id"], incident["alert_id"])
        self.assertEqual(reopened.critical_email_alert_counts()["retrying"], 1)
        self.assertTrue(reopened.fail_critical_alert(incident["alert_id"], token,
                                                     error_code="http_503", delay_seconds=0))
        worker = ResendEmailWorker(self.config(), repository=SQLiteEventRepository(self.path),
                                   session=Session(200), poll_interval=0.01)
        try:
            self.await_state(worker, "delivered", 1)
        finally:
            worker.close()
        self.assertEqual(SQLiteEventRepository(self.path).critical_email_alert_counts()["pending"], 0)

    def test_concurrent_claimers_never_claim_one_record_twice(self):
        self.repo.enqueue_critical_alert(self.incident())
        second = SQLiteEventRepository(self.path)
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda repo: repo.claim_critical_alerts(), (self.repo, second)))
        claims = [item for _token, batch in results for item in batch]
        self.assertEqual(len(claims), 1)

    def test_filtered_claim_targets_incident_and_only_current_lease_can_complete(self):
        unrelated = self.incident()
        target = self.incident()
        self.repo.enqueue_critical_alert(unrelated)
        self.repo.enqueue_critical_alert(target)

        token, claimed = self.repo.claim_critical_alerts(alert_ids=[target["alert_id"]])

        self.assertEqual([row["alert_id"] for row in claimed], [target["alert_id"]])
        self.assertFalse(self.repo.complete_critical_alert(target["alert_id"], str(uuid.uuid4())))
        self.assertTrue(self.repo.complete_critical_alert(target["alert_id"], token))
        self.assertEqual(self.repo.critical_email_alert_counts()["pending"], 1)

    def test_success_records_delivery_and_stable_provider_idempotency_key(self):
        incident = self.incident()
        session = Session(200)
        worker = ResendEmailWorker(self.config(), repository=self.repo, session=session, poll_interval=0.01)
        try:
            self.assertTrue(worker.submit(incident))
            state = self.await_state(worker, "delivered", 1)
        finally:
            worker.close()
        self.assertEqual(state["pending"], 0)
        self.assertEqual(session.calls[0][1]["headers"]["Idempotency-Key"], incident["alert_id"])

    def test_retryable_failure_exhaustion_is_persistent_and_explicitly_retried(self):
        incident = self.incident()
        session = Session(503, 503, 200)
        worker = ResendEmailWorker(self.config(max_attempts=2), repository=self.repo,
                                   session=session, poll_interval=0.01)
        try:
            self.assertTrue(worker.submit(incident))
            state = self.await_state(worker, "failed", 1, timeout=5)
            row = state["recent_failures"][0]
            self.assertEqual(row["last_error_code"], "http_503")
            self.assertEqual(row["attempts"], 2)
            self.assertEqual(worker.retry_failed([incident["alert_id"]]), 1)
            state = self.await_state(worker, "delivered", 1)
        finally:
            worker.close()
        self.assertEqual(len(session.calls), 3)
        self.assertEqual({call[1]["headers"]["Idempotency-Key"] for call in session.calls},
                         {incident["alert_id"]})

    def test_permanent_failure_is_retained_and_status_is_sanitized(self):
        worker = ResendEmailWorker(self.config(max_attempts=3), repository=self.repo,
                                   session=Session(422), poll_interval=0.01)
        try:
            worker.submit(self.incident())
            state = self.await_state(worker, "failed", 1)
        finally:
            worker.close()
        self.assertEqual(state["recent_failures"][0]["last_error_code"], "http_422")
        self.assertNotIn("test-only-secret", str(state))
        self.assertNotIn("soc@example.com", str(state))

    def test_disabled_configuration_persists_but_does_not_send(self):
        incident = self.incident()
        session = Session(200)
        worker = ResendEmailWorker(self.config(enabled=False), repository=self.repo,
                                   session=session, poll_interval=0.01)
        try:
            self.assertTrue(worker.submit(incident))
            self.assertEqual(worker.status_snapshot()["pending"], 1)
            self.assertEqual(session.calls, [])
        finally:
            worker.close()

    def test_storage_failure_does_not_send_and_reports_sanitized_category(self):
        class BrokenRepository:
            def enqueue_critical_alert(self, _incident):
                raise OSError("sensitive database details")

            def critical_email_alert_counts(self):
                raise OSError("sensitive database details")

            def list_critical_email_alerts(self, **_kwargs):
                return []

        session = Session(200)
        worker = ResendEmailWorker(self.config(), repository=BrokenRepository(), session=session,
                                   poll_interval=0.01)
        try:
            self.assertFalse(worker.submit(self.incident()))
            state = worker.status_snapshot()
        finally:
            worker.close()
        self.assertEqual(session.calls, [])
        self.assertEqual(state["storage_error_code"], "OSError")
        self.assertNotIn("sensitive database details", str(state))

    def test_postgres_incident_insert_is_staged_off_the_calling_thread(self):
        class StagingRepository(PostgreSQLEventRepository):
            def __init__(self):
                super().__init__("postgresql://user:password@localhost/netra")
                self.persisted = []
                self.writer_thread_id = None

            def enqueue_critical_alert(self, incident):
                self.writer_thread_id = __import__("threading").get_ident()
                self.persisted.append(dict(incident))
                return True

            def claim_critical_alerts(self, **_kwargs): return str(uuid.uuid4()), []
            def critical_email_alert_counts(self): return {"pending": 0, "retrying": 0, "delivered": 0, "failed": 0}
            def list_critical_email_alerts(self, **_kwargs): return []

        repository = StagingRepository()
        caller_thread_id = __import__("threading").get_ident()
        worker = ResendEmailWorker(self.config(enabled=False), repository=repository,
                                   session=Session(), poll_interval=0.01, autostart=False)
        try:
            self.assertFalse(worker.submit(self.incident()), "staging is not yet durable acceptance")
            deadline = time.monotonic() + 2
            while not repository.persisted and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertEqual(len(repository.persisted), 1)
            self.assertNotEqual(repository.writer_thread_id, caller_thread_id)
            self.assertEqual(worker.status_snapshot()["staged_not_persisted"], 0)
            self.assertEqual(worker.session.calls, [])
        finally:
            worker.close()

    def test_postgres_persistence_failure_is_bounded_visible_and_sanitized(self):
        class BrokenPostgresRepository(PostgreSQLEventRepository):
            def __init__(self):
                super().__init__("postgresql://user:password@localhost/netra")
                self.attempts = 0
            def enqueue_critical_alert(self, _incident):
                self.attempts += 1
                raise OSError("private host, password, and database path")
            def claim_critical_alerts(self, **_kwargs): return str(uuid.uuid4()), []
            def critical_email_alert_counts(self): return {"pending": 0, "retrying": 0, "delivered": 0, "failed": 0}
            def list_critical_email_alerts(self, **_kwargs): return []

        repository = BrokenPostgresRepository()
        worker = ResendEmailWorker(self.config(enabled=False), repository=repository,
                                   session=Session(), sleeper=lambda _delay: None,
                                   poll_interval=0.01, autostart=False)
        try:
            self.assertFalse(worker.submit(self.incident()))
            deadline = time.monotonic() + 2
            while worker._persistence_error_code is None and time.monotonic() < deadline:
                time.sleep(0.01)
            status = worker.status_snapshot()
            self.assertEqual(repository.attempts, 3)
            self.assertEqual(status["persistence_error_code"], "OSError")
            self.assertEqual(status["state"], "storage_error")
            self.assertNotIn("private host", str(status))
            self.assertNotIn("password", str(status))
        finally:
            worker.close()

    def test_status_and_explicit_retry_routes_require_remote_dashboard_auth(self):
        old_user = app.config["NETRA_AUTH_USERNAME"]
        old_password = app.config["NETRA_AUTH_PASSWORD"]
        app.config["NETRA_AUTH_USERNAME"] = "operator"
        app.config["NETRA_AUTH_PASSWORD"] = "test-password"
        client = app.test_client()
        try:
            no_auth = client.get("/api/v2/email-alerts/status", environ_base={"REMOTE_ADDR": "203.0.113.9"})
            self.assertEqual(no_auth.status_code, 401)
            status = client.get("/api/v2/email-alerts/status", environ_base={"REMOTE_ADDR": "203.0.113.9"},
                                headers={"Authorization": "Basic b3BlcmF0b3I6dGVzdC1wYXNzd29yZA=="})
            self.assertEqual(status.status_code, 200)
            payload = status.get_json()
            self.assertTrue({"pending", "delivered", "failed"}.issubset(payload))
            self.assertNotIn("test-only-secret", str(payload))
            self.assertNotIn("recipient", str(payload).lower())
            retry = client.post("/api/v2/email-alerts/retry", json={"alert_ids": [str(uuid.uuid4())]},
                                environ_base={"REMOTE_ADDR": "203.0.113.9"})
            self.assertEqual(retry.status_code, 401)
            with patch.object(v2_engine.critical_email_alerts.notifier, "retry_failed", return_value=1) as method:
                authorized = client.post("/api/v2/email-alerts/retry", json={"alert_ids": [str(uuid.uuid4())]},
                                         environ_base={"REMOTE_ADDR": "203.0.113.9"},
                                         headers={"Authorization": "Basic b3BlcmF0b3I6dGVzdC1wYXNzd29yZA=="})
            self.assertEqual(authorized.status_code, 200)
            method.assert_called_once()
        finally:
            app.config["NETRA_AUTH_USERNAME"] = old_user
            app.config["NETRA_AUTH_PASSWORD"] = old_password


if __name__ == "__main__":
    unittest.main()
