import unittest
from datetime import datetime, timezone
import tempfile
import os
import uuid
from unittest.mock import patch

from app.app import app
from v2.event_store import SQLiteEventRepository, create_event


class SensorIngestionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.repository = SQLiteEventRepository(os.path.join(self.temp.name, "events.sqlite3"))
        self.engine = __import__("app.app", fromlist=["v2_engine"]).v2_engine
        self.old_repository = self.engine.event_writer.repository
        self.engine.event_writer.repository = self.repository
        self.client = app.test_client()
        self.old_key = app.config["NETRA_SENSOR_API_KEY"]
        app.config["NETRA_SENSOR_API_KEY"] = "test-only-sensor-key-that-is-long-enough"
        self.headers = {"Authorization": f"Bearer {app.config['NETRA_SENSOR_API_KEY']}"}

    def tearDown(self):
        app.config["NETRA_SENSOR_API_KEY"] = self.old_key
        self.engine.event_writer.repository = self.old_repository
        self.temp.cleanup()

    def event(self, **kwargs):
        return create_event(
            origin=kwargs.get("origin", "live"), session_id=str(uuid.uuid4()),
            event_type="flow_classification", classification="BENIGN",
            metadata={"packet_count": 4},
            occurred_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
            event_id=kwargs.get("event_id"),
        )

    def post_events(self, events, headers=None):
        return self.client.post(
            "/api/v1/sensor/events", json={"events": events},
            headers=self.headers if headers is None else headers,
        )

    def test_requires_dedicated_sensor_credential(self):
        self.assertEqual(self.post_events([self.event()], headers={}).status_code, 401)
        app.config["NETRA_SENSOR_API_KEY"] = ""
        self.assertEqual(self.post_events([self.event()]).status_code, 503)

    def test_persists_valid_batch_and_deduplicates_retries(self):
        event = self.event(origin="pcap")
        first = self.post_events([event, event])
        second = self.post_events([event])
        self.assertEqual(first.status_code, 200)
        self.assertEqual(first.get_json(), {"accepted": 2, "inserted": 1, "duplicates": 1})
        self.assertEqual(second.get_json(), {"accepted": 1, "inserted": 0, "duplicates": 1})
        stored = list(self.repository.iter_events(
            datetime(2025, 1, 1, tzinfo=timezone.utc), datetime(2027, 1, 1, tzinfo=timezone.utc)
        ))
        self.assertEqual(len(stored), 1)
        self.assertEqual(stored[0]["origin"], "pcap")

    def test_rejects_invalid_timestamp_metadata_and_oversized_batch(self):
        event = self.event()
        malformed_time = dict(event, occurred_at_utc="yesterday")
        self.assertEqual(self.post_events([malformed_time]).status_code, 400)
        malformed_session = dict(event, session_id="not-a-uuid")
        self.assertEqual(self.post_events([malformed_session]).status_code, 400)
        malformed_metadata = dict(event, event_id=str(uuid.uuid4()))
        malformed_metadata["metadata"] = ["metadata must be an object"]
        self.assertEqual(self.post_events([malformed_metadata]).status_code, 400)
        raw_payload = dict(event, event_id=str(uuid.uuid4()))
        raw_payload["metadata"] = {"packet_payload": "raw bytes are not accepted"}
        self.assertEqual(self.post_events([raw_payload]).status_code, 400)
        self.assertEqual(self.post_events([self.event()] * 101).status_code, 413)
        stored = list(self.repository.iter_events(
            datetime(2025, 1, 1, tzinfo=timezone.utc), datetime(2027, 1, 1, tzinfo=timezone.utc)
        ))
        self.assertEqual(stored, [])

    def test_rejects_oversized_request(self):
        response = self.client.post(
            "/api/v1/sensor/events", data=b"{" + b" " * (256 * 1024),
            content_type="application/json", headers=self.headers,
        )
        self.assertEqual(response.status_code, 413)
        self.assertEqual(response.get_json(), {"error": "Request body exceeds the configured limit."})

    def test_rate_limit_and_validation_errors_are_sanitized(self):
        with patch("app.app._sensor_rate_limited", return_value=True):
            response = self.post_events([self.event()])
        self.assertEqual(response.status_code, 429)
        self.assertEqual(response.headers["Retry-After"], "60")
        self.assertNotIn(app.config["NETRA_SENSOR_API_KEY"], response.get_data(as_text=True))

    def test_process_rate_window_allows_sixty_then_blocks_and_resets(self):
        from app.app import _sensor_rate_limited, _sensor_rate_windows
        _sensor_rate_windows.clear()
        for _ in range(60):
            self.assertFalse(_sensor_rate_limited("192.0.2.7", now=10.0))
        self.assertTrue(_sensor_rate_limited("192.0.2.7", now=10.0))
        self.assertFalse(_sensor_rate_limited("192.0.2.7", now=70.0))
        _sensor_rate_windows.clear()


if __name__ == "__main__":
    unittest.main()
