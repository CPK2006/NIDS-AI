import os
import tempfile
import threading
import time
import unittest
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch
import uuid

from app.app import app, v2_engine
from v2.critical_email_alerts import (
    CriticalEmailAlerts,
    CriticalPolicySettings,
    CriticalStatePolicy,
    ResendConfig,
    ResendEmailWorker,
)
from v2.event_store import SQLiteEventRepository, create_event
from v2.live_detector import Flow, LiveDetectorEngine


class FakeNotifier:
    def __init__(self):
        self.incidents = []

    def submit(self, incident):
        self.incidents.append(dict(incident))
        return True

    def status_snapshot(self):
        return {"state": "ready", "message": "test", "queued": 0, "sent": 0,
                "failed": 0, "dropped": 0, "last_error_code": None}


class FakeResponse:
    def __init__(self, status):
        self.status_code = status


class FakeSession:
    def __init__(self, results):
        self.results = list(results)
        self.calls = []

    def post(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        result = self.results.pop(0)
        if isinstance(result, Exception):
            raise result
        return FakeResponse(result)


def critical_manager():
    policy = CriticalStatePolicy(CriticalPolicySettings(window_size=5, attack_threshold=3, recovery_threshold=1))
    notifier = FakeNotifier()
    return CriticalEmailAlerts(policy=policy, notifier=notifier), notifier


class CriticalEmailPolicyTests(unittest.TestCase):
    def test_only_current_live_capture_session_is_eligible(self):
        manager, notifier = critical_manager()
        manager.begin_live_session("live-session")
        for _ in range(3):
            manager.observe_flow(origin="pcap", session_id="replay-session", classification="ATTACK")
            manager.observe_flow(origin="simulation", session_id="sim-session", classification="ATTACK")
            manager.observe_flow(origin="live", session_id="hosted-session", classification="ATTACK")
        self.assertEqual(notifier.incidents, [])
        for _ in range(3):
            manager.observe_flow(origin="live", session_id="live-session", classification="ATTACK")
        self.assertEqual(len(notifier.incidents), 1)

    def test_critical_entry_deduplicates_until_recovery_then_rearms(self):
        manager, notifier = critical_manager()
        manager.begin_live_session("live-session")
        for _ in range(3):
            manager.observe_flow(origin="live", session_id="live-session", classification="ATTACK")
        for _ in range(3):
            manager.observe_flow(origin="live", session_id="live-session", classification="ATTACK")
        self.assertEqual(len(notifier.incidents), 1, "continued critical classifications do not send repeats")
        for _ in range(4):
            manager.observe_flow(origin="live", session_id="live-session", classification="BENIGN")
        self.assertFalse(manager.policy.snapshot()["critical"], "benign traffic recovers without sending a message")
        for _ in range(3):
            manager.observe_flow(origin="live", session_id="live-session", classification="ATTACK")
        self.assertEqual(len(notifier.incidents), 2, "a later incident after recovery is independently alertable")
        self.assertNotEqual(notifier.incidents[0]["alert_id"], notifier.incidents[1]["alert_id"])

    def test_concurrent_critical_predictions_create_one_incident(self):
        manager, notifier = critical_manager()
        manager.begin_live_session("live-session")
        with ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(lambda _index: manager.observe_flow(
                origin="live", session_id="live-session", classification="ATTACK"), range(32)))
        self.assertEqual(len(notifier.incidents), 1)

    def test_session_end_and_restart_reject_stale_flows(self):
        manager, notifier = critical_manager()
        manager.begin_live_session("old-session")
        manager.end_live_session("old-session")
        manager.begin_live_session("new-session")
        for _ in range(3):
            manager.observe_flow(origin="live", session_id="old-session", classification="ATTACK")
        self.assertEqual(notifier.incidents, [])

    def test_email_handoff_failure_does_not_fail_flow_classification(self):
        class Sink:
            def add_error_handler(self, _callback):
                pass

            def submit(self, _event):
                return True

        class AttackModel:
            def predict(self, _frame):
                return [1]

            def predict_proba(self, _frame):
                return [[0.05, 0.95]]

        with patch("v2.live_detector.os.path.exists", return_value=False):
            engine = LiveDetectorEngine(model_file="missing-model", event_writer=Sink())
        engine.model = AttackModel()

        class FailingAlerts:
            def observe_flow(self, **_kwargs):
                raise OSError("mail worker unavailable")

            def status_snapshot(self):
                return {"state": "ready"}

        engine.critical_email_alerts = FailingAlerts()
        flow = Flow("192.0.2.1", "198.51.100.1", 1234, 443, "TCP", 1.0)
        flow.traffic_origin = "live"
        flow.session_id = "active-session"
        engine._classify_and_alert(flow)
        self.assertEqual(engine.get_status()["stats"]["classified_flows"], 1)
        self.assertEqual(engine.get_status()["stats"]["attack_count"], 1)


class ResendWorkerTests(unittest.TestCase):
    def config(self, **kwargs):
        values = {"enabled": True, "api_key": "test-secret", "sender": "NETRA <sender@example.com>",
                  "recipient": "soc@example.com", "max_attempts": 4, "queue_size": 2}
        values.update(kwargs)
        return ResendConfig(**values)

    def incident(self):
        return {"alert_id": str(uuid.uuid4()), "session_id": str(uuid.uuid4()), "attack_count": 10,
                "window_size": 20, "occurred_at_utc": datetime.now(timezone.utc).isoformat()}

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.repository = SQLiteEventRepository(os.path.join(self.temp.name, "alerts.sqlite3"))

    def tearDown(self):
        self.temp.cleanup()

    def make_worker(self, *args, **kwargs):
        kwargs.setdefault("repository", self.repository)
        kwargs.setdefault("autostart", False)
        return ResendEmailWorker(*args, **kwargs)

    def test_disabled_and_incomplete_configuration_are_clear_and_sanitized(self):
        disabled = self.make_worker(self.config(enabled=False, api_key="actual-secret"))
        incomplete = self.make_worker(self.config(sender="invalid"))
        self.assertEqual(disabled.configuration_status()["state"], "disabled")
        self.assertEqual(incomplete.configuration_status()["state"], "not_configured")
        self.assertNotIn("actual-secret", str(disabled.status_snapshot()))

    def test_environment_configuration_is_opt_in_and_uses_resend_fields(self):
        settings = {
            "NETRA_EMAIL_ALERTS_ENABLED": "true",
            "RESEND_API_KEY": "test-key-only",
            "RESEND_FROM_EMAIL": "alerts@example.com",
            "RESEND_TO_EMAIL": "soc@example.com",
            "NETRA_EMAIL_MAX_ATTEMPTS": "3",
        }
        with patch.dict(os.environ, settings):
            configured = ResendConfig.from_environment()
        self.assertTrue(configured.enabled)
        self.assertTrue(configured.configured)
        self.assertEqual(configured.max_attempts, 3)
        self.assertEqual(ResendConfig(enabled=False, api_key="", sender="", recipient="").configured, False)

    def test_retryable_failure_retries_with_stable_idempotency_key(self):
        session = FakeSession([503, 200])
        pauses = []
        worker = self.make_worker(self.config(), session=session, sleeper=pauses.append)
        incident = self.incident()
        self.assertTrue(worker._deliver(incident))
        keys = [call[1]["headers"]["Idempotency-Key"] for call in session.calls]
        self.assertEqual(keys, [incident["alert_id"], incident["alert_id"]])
        self.assertEqual(pauses, [1])
        self.assertEqual(worker.status_snapshot()["sent"], 0, "direct test helper does not mutate durable state")
        self.assertTrue(all(call[0][0] == "https://api.resend.com/emails" for call in session.calls))

    def test_permanent_http_failure_is_not_retried_and_body_is_not_logged(self):
        session = FakeSession([422, 200])
        worker = self.make_worker(self.config(), session=session, sleeper=lambda _delay: None)
        incident = self.incident()
        self.assertFalse(worker._deliver(incident))
        self.assertEqual(len(session.calls), 1)
        self.assertEqual(worker.status_snapshot()["failed"], 0)
        self.assertNotIn("test-secret", str(worker.status_snapshot()))
        payload = session.calls[0][1]["json"]
        self.assertNotIn("192.0.2.", payload["text"])
        self.assertNotIn("payload", payload["text"].lower())

    def test_exhausted_retryable_failures_are_counted_once(self):
        session = FakeSession([429, 503])
        worker = self.make_worker(self.config(max_attempts=2), session=session, sleeper=lambda _delay: None)
        self.assertFalse(worker._deliver(self.incident()))
        self.assertEqual(len(session.calls), 2)
        self.assertEqual(worker.status_snapshot()["failed"], 0)

    def test_worker_failure_is_sanitized_and_monitoring_call_is_nonblocking(self):
        session = FakeSession([RuntimeError("private response details")])
        worker = self.make_worker(self.config(max_attempts=1), session=session)
        self.assertTrue(worker.submit(self.incident()))
        worker.start()
        deadline = time.monotonic() + 2
        while worker.status_snapshot()["failed"] == 0 and time.monotonic() < deadline:
            time.sleep(0.01)
        state = worker.status_snapshot()
        worker.close()
        self.assertEqual(state["failed"], 1)
        self.assertEqual(state["recent_failures"][0]["last_error_code"], "RuntimeError")
        self.assertNotIn("private response details", str(state))

    def test_persistent_outbox_accepts_more_than_one_in_memory_item(self):
        started = threading.Event()
        release = threading.Event()

        class BlockingSession:
            def post(self, *_args, **_kwargs):
                started.set()
                release.wait(2)
                return FakeResponse(200)

        worker = self.make_worker(self.config(queue_size=1), session=BlockingSession())
        self.assertTrue(worker.submit(self.incident()))
        worker.start()
        self.assertTrue(started.wait(1))
        self.assertTrue(worker.submit(self.incident()))
        self.assertTrue(worker.submit(self.incident()))
        self.assertEqual(worker.status_snapshot()["pending"], 3)
        release.set()
        deadline = time.monotonic() + 2
        while worker.status_snapshot()["sent"] < 3 and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertEqual(worker.status_snapshot()["sent"], 3)
        self.assertTrue(worker.close())

    def test_historical_ingestion_path_does_not_observe_or_enqueue_email(self):
        temp = tempfile.TemporaryDirectory()
        repository = SQLiteEventRepository(os.path.join(temp.name, "events.sqlite3"))
        old_repository = v2_engine.event_writer.repository
        old_key = app.config["NETRA_SENSOR_API_KEY"]
        v2_engine.event_writer.repository = repository
        app.config["NETRA_SENSOR_API_KEY"] = "test-sensor-key-long-enough-for-ingestion"
        session_id = str(uuid.uuid4())
        event = create_event(
            origin="live", session_id=session_id, event_type="flow_classification",
            classification="ATTACK", metadata={"packet_count": 20, "byte_count": 1000},
        )
        client = app.test_client()
        try:
            with patch.object(v2_engine.critical_email_alerts, "observe_flow", wraps=v2_engine.critical_email_alerts.observe_flow) as observe:
                response = client.post("/api/v1/sensor/events", json={"events": [event]},
                                       headers={"Authorization": f"Bearer {app.config['NETRA_SENSOR_API_KEY']}"})
            self.assertEqual(response.status_code, 200)
            observe.assert_not_called()
        finally:
            app.config["NETRA_SENSOR_API_KEY"] = old_key
            v2_engine.event_writer.repository = old_repository
            temp.cleanup()


if __name__ == "__main__":
    unittest.main()
