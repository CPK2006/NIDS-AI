import os
import tempfile
import unittest
from datetime import datetime, timezone

import requests

from v2.event_forwarder import EventForwarder, validate_endpoint
from v2.event_store import SQLiteEventRepository, create_event


class FakeResponse:
    def __init__(self, status_code, text="sensitive response body"):
        self.status_code = status_code
        self.text = text


class FakeSession:
    def __init__(self, result):
        self.result = result
        self.calls = []

    def post(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


class EventForwardingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.repository = SQLiteEventRepository(
            os.path.join(self.temp.name, "sensor.sqlite3"), forwarding_enabled=True
        )
        self.event = create_event(
            origin="live", session_id="sensor-run", event_type="flow_classification",
            classification="BENIGN", metadata={"packet_count": 2},
            occurred_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        )
        self.repository.append(self.event)

    def tearDown(self):
        self.temp.cleanup()

    def forwarder(self, result):
        return EventForwarder(
            self.repository, "https://sensor.example/api/v1/sensor/events",
            "test-forwarding-key-that-is-long-enough", session=FakeSession(result),
        )

    def test_only_successful_server_response_acknowledges_durable_event(self):
        forwarder = self.forwarder(FakeResponse(200))
        self.assertEqual(forwarder.send_once(), 1)
        self.assertEqual(self.repository.outbox_counts(), {"pending": 0, "blocked": 0})
        call = forwarder.session.calls[0]
        self.assertEqual(call[1]["json"]["events"][0]["event_id"], self.event["event_id"])
        self.assertEqual(call[1]["headers"]["Authorization"], "Bearer test-forwarding-key-that-is-long-enough")

    def test_timeout_keeps_event_and_logs_no_credential(self):
        forwarder = self.forwarder(requests.Timeout("private detail"))
        with self.assertLogs("v2.event_forwarder", level="WARNING") as captured:
            self.assertEqual(forwarder.send_once(), 0)
        self.assertEqual(self.repository.outbox_counts(), {"pending": 1, "blocked": 0})
        self.assertNotIn("test-forwarding-key-that-is-long-enough", "\n".join(captured.output))
        self.assertNotIn("private detail", "\n".join(captured.output))

    def test_permanent_rejection_retains_blocked_event(self):
        forwarder = self.forwarder(FakeResponse(422, "do not log this"))
        with self.assertLogs("v2.event_forwarder", level="WARNING") as captured:
            self.assertEqual(forwarder.send_once(), 0)
        self.assertEqual(self.repository.outbox_counts(), {"pending": 1, "blocked": 1})
        blocked = self.repository.list_blocked_outbox()
        self.assertEqual(blocked[0]["event_id"], self.event["event_id"])
        self.assertEqual(blocked[0]["last_error"], "http_422")
        self.assertNotIn("do not log this", "\n".join(captured.output))
        self.assertEqual(self.repository.requeue_blocked_outbox([self.event["event_id"]]), 1)
        self.assertEqual(self.repository.outbox_counts(), {"pending": 1, "blocked": 0})

    def test_non_loopback_requires_https(self):
        with self.assertRaises(ValueError):
            validate_endpoint("http://receiver.example/api/v1/sensor/events")
        with self.assertRaises(ValueError):
            validate_endpoint("https://receiver.example/api/v1/sensor/events?token=secret")
        self.assertEqual(validate_endpoint("http://127.0.0.1:5000/ingest"),
                         "http://127.0.0.1:5000/ingest")


if __name__ == "__main__":
    unittest.main()
