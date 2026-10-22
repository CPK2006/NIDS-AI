import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from app.app import app
from v2.event_store import SQLiteEventRepository, create_event


class HistoryAnalyticsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.repository = SQLiteEventRepository(os.path.join(self.temp.name, "history.sqlite3"))
        self.engine = __import__("app.app", fromlist=["v2_engine"]).v2_engine
        self.previous_repository = self.engine.event_writer.repository
        self.engine.event_writer.repository = self.repository
        self.client = app.test_client()
        now = datetime.now(timezone.utc)
        self.now = now
        for origin, classification, minute, event_type in (
            ("live", "BENIGN", 1, "flow_classification"),
            ("live", "ATTACK", 2, "flow_classification"),
            ("live", "ATTACK", 2, "alert"),
            ("pcap", "BENIGN", 2, "flow_classification"),
            ("simulation", "ATTACK", 3, "flow_classification"),
            ("live", "BENIGN", 120, "flow_classification"),
        ):
            self.repository.append(create_event(
                origin=origin, session_id="history-test", event_type=event_type,
                classification=classification if event_type in {"flow_classification", "alert"} else None,
                metadata={"packet_count": 4, "byte_count": 512},
                occurred_at=now - timedelta(minutes=minute),
            ))

    def tearDown(self):
        self.engine.event_writer.repository = self.previous_repository
        self.temp.cleanup()

    def test_trends_default_to_live_origin_and_aggregate_flow_metrics(self):
        response = self.client.get("/api/v2/history/trends?window=1h")
        self.assertEqual(response.status_code, 200)
        body = response.get_json()
        self.assertEqual(body["origin_filter"], "live")
        self.assertEqual(body["timezone"], "UTC")
        self.assertTrue(all(bucket["flow_count"] <= 2 for bucket in body["buckets"]))
        self.assertEqual(sum(bucket["flow_count"] for bucket in body["buckets"]), 2)
        self.assertEqual(sum(bucket["attack_count"] for bucket in body["buckets"]), 1)
        self.assertEqual(sum(bucket["packet_count"] for bucket in body["buckets"]), 8)
        self.assertEqual(sum(bucket["alert_count"] for bucket in body["buckets"]), 1)
        self.assertTrue(all(bucket["bucket_start_utc"].endswith("Z") for bucket in body["buckets"]))

    def test_explicit_origin_filter_does_not_mix_sources(self):
        pcap = self.client.get("/api/v2/history/trends?window=1h&origin=pcap").get_json()
        all_origins = self.client.get("/api/v2/history/trends?window=1h&origin=all").get_json()
        self.assertEqual(sum(row["flow_count"] for row in pcap["buckets"]), 1)
        self.assertEqual(sum(row["flow_count"] for row in all_origins["buckets"]), 4)
        self.assertEqual(all_origins["origin_filter"], "all")

    def test_time_window_excludes_older_events(self):
        one_hour = self.client.get("/api/v2/history/trends?window=1h").get_json()
        six_hours = self.client.get("/api/v2/history/trends?window=6h").get_json()
        self.assertEqual(sum(row["flow_count"] for row in one_hour["buckets"]), 2)
        self.assertEqual(sum(row["flow_count"] for row in six_hours["buckets"]), 3)

    def test_empty_range_and_validation_are_explicit(self):
        empty_repository = SQLiteEventRepository(os.path.join(self.temp.name, "empty.sqlite3"))
        self.engine.event_writer.repository = empty_repository
        empty = self.client.get("/api/v2/history/trends?window=1h").get_json()
        self.assertEqual(empty["buckets"], [])
        for query in ("window=forever", "origin=unknown", "window=1h&window=24h", "unexpected=x"):
            self.assertEqual(self.client.get(f"/api/v2/history/trends?{query}").status_code, 400)

    def test_database_failure_is_sanitized(self):
        with patch.object(self.repository, "aggregate_events", side_effect=RuntimeError("secret db path")):
            response = self.client.get("/api/v2/history/trends?window=1h")
        self.assertEqual(response.status_code, 503)
        self.assertNotIn("secret", response.get_data(as_text=True))

    def test_top_talkers_is_honestly_unavailable_without_endpoint_metadata(self):
        response = self.client.get("/api/v2/history/top-talkers?window=7d&origin=live")
        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.get_json()["available"])
        self.assertEqual(response.get_json()["talkers"], [])
        self.assertEqual(response.get_json()["window"], "7d")
        self.assertIn("does not include", response.get_json()["reason"])

    def test_repository_rejects_invalid_interval_and_origin(self):
        start = self.now - timedelta(hours=1)
        with self.assertRaises(ValueError):
            self.repository.aggregate_events(start, self.now, bucket_seconds=0)
        with self.assertRaises(ValueError):
            self.repository.aggregate_events(start, self.now, bucket_seconds=60, origins=("spoofed",))


if __name__ == "__main__":
    unittest.main()
