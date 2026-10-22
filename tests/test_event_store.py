from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from datetime import datetime, timedelta, timezone
import os
import sqlite3
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from v2.event_store import (
    EventValidationError,
    EventWriteQueue,
    SQLiteEventRepository,
    create_event,
)


UTC = timezone.utc
START = datetime(2026, 1, 1, tzinfo=UTC)
END = datetime(2026, 2, 1, tzinfo=UTC)


def sample_event(*, origin="live", event_type="flow_classification", label="BENIGN",
                 occurred_at=None, event_id=None, session_id="run-1"):
    return create_event(
        origin=origin,
        session_id=session_id,
        event_type=event_type,
        classification=label if event_type in {"flow_classification", "alert"} else None,
        metadata={"packet_count": 4, "byte_count": 512},
        occurred_at=occurred_at or START,
        event_id=event_id,
    )


class SQLiteEventRepositoryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp.name, "events.sqlite3")
        self.repository = SQLiteEventRepository(self.db_path)

    def tearDown(self):
        self.temp.cleanup()

    def test_validates_origin_classification_and_timezone_and_normalizes_utc(self):
        local_time = datetime(2026, 1, 1, 5, 30, tzinfo=timezone(timedelta(hours=5, minutes=30)))
        event = sample_event(occurred_at=local_time)
        self.assertEqual(event["occurred_at_utc"], "2026-01-01T00:00:00.000000Z")
        with self.assertRaises(EventValidationError):
            create_event(origin="unknown", session_id="x", event_type="flow_classification",
                         classification="BENIGN")
        with self.assertRaises(EventValidationError):
            create_event(origin="live", session_id="x", event_type="flow_classification",
                         classification="BENIGN", occurred_at=datetime(2026, 1, 1))
        with self.assertRaises(EventValidationError):
            create_event(origin="live", session_id="x", event_type="flow_classification",
                         classification="MAYBE")
        with self.assertRaises(EventValidationError):
            create_event(origin="live", session_id="x", event_type="flow_classification",
                         classification="BENIGN", metadata={"invalid": float("nan")})

    def test_persists_across_repository_reinitialization_and_is_idempotent(self):
        event = sample_event(origin="pcap", session_id="pcap-run")
        self.assertTrue(self.repository.append(event))
        reopened = SQLiteEventRepository(self.db_path)
        self.assertFalse(reopened.append(event))
        records = list(reopened.iter_events(START, END))
        self.assertEqual(records, [event])
        self.assertEqual(records[0]["origin"], "pcap")
        self.assertEqual(records[0]["session_id"], "pcap-run")

    def test_duplicate_id_with_different_content_is_rejected(self):
        event = sample_event()
        self.repository.append(event)
        conflict = dict(event, origin="simulation")
        with self.assertRaises(EventValidationError):
            self.repository.append(conflict)

    def test_half_open_time_boundaries_and_filters(self):
        at_start = sample_event(origin="live", occurred_at=START)
        at_middle = sample_event(origin="pcap", occurred_at=START + timedelta(days=1))
        at_end = sample_event(origin="simulation", occurred_at=END)
        for event in (at_start, at_middle, at_end):
            self.repository.append(event)
        selected = list(self.repository.iter_events(START, END))
        self.assertEqual([item["event_id"] for item in selected], [at_start["event_id"], at_middle["event_id"]])
        pcap = list(self.repository.iter_events(START, END, origins=("pcap",)))
        self.assertEqual([item["event_id"] for item in pcap], [at_middle["event_id"]])
        classifications = list(self.repository.iter_events(START, END, event_types=("flow_classification",)))
        self.assertEqual(len(classifications), 2)
        self.assertEqual(list(self.repository.iter_events(START, END, origins=())), [])
        with self.assertRaises(EventValidationError):
            list(self.repository.iter_events(datetime(2026, 1, 1), END))

    def test_retention_deletes_only_rows_strictly_before_utc_cutoff_and_is_repeatable(self):
        now = datetime(2026, 2, 1, 12, tzinfo=UTC)
        cutoff = now - timedelta(days=30)
        expired = sample_event(occurred_at=cutoff - timedelta(microseconds=1))
        exactly_at_cutoff = sample_event(occurred_at=cutoff)
        newer = sample_event(occurred_at=cutoff + timedelta(seconds=1))
        for event in (expired, exactly_at_cutoff, newer):
            self.repository.append(event)
        with closing(sqlite3.connect(self.db_path)) as connection:
            connection.execute("CREATE TABLE notification_outbox_sentinel (record_id INTEGER PRIMARY KEY)")
            connection.execute("INSERT INTO notification_outbox_sentinel(record_id) VALUES (1)")
            connection.commit()
        self.assertEqual(self.repository.prune_expired(now=now), 1)
        self.assertEqual(self.repository.prune_expired(now=now), 0)
        records = list(self.repository.iter_events(cutoff - timedelta(seconds=1), now + timedelta(seconds=1)))
        self.assertEqual({item["event_id"] for item in records}, {exactly_at_cutoff["event_id"], newer["event_id"]})
        with closing(sqlite3.connect(self.db_path)) as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM notification_outbox_sentinel").fetchone()[0], 1)

    def test_retention_days_can_be_configured(self):
        now = datetime(2026, 2, 1, tzinfo=UTC)
        ten_days_old = sample_event(occurred_at=now - timedelta(days=10))
        self.repository.append(ten_days_old)
        with patch.dict(os.environ, {"NETRA_EVENT_RETENTION_DAYS": "7"}):
            self.assertEqual(self.repository.prune_expired(now=now), 1)
        self.assertEqual(list(self.repository.iter_events(now - timedelta(days=20), now)), [])

    def test_database_error_does_not_leave_open_connections(self):
        connections = []
        real_connect = sqlite3.connect

        def track_connection(*args, **kwargs):
            connection = real_connect(*args, **kwargs)
            connections.append(connection)
            return connection

        with patch("v2.event_store.sqlite3.connect", side_effect=track_connection):
            self.repository.append(sample_event())
            list(self.repository.iter_events(START, END))
        self.assertGreaterEqual(len(connections), 3)
        for connection in connections:
            with self.assertRaises(sqlite3.ProgrammingError):
                connection.execute("SELECT 1")

        corrupt_path = os.path.join(self.temp.name, "corrupt.sqlite3")
        with open(corrupt_path, "wb") as corrupt_file:
            corrupt_file.write(b"not a sqlite database")
        corrupt = SQLiteEventRepository(corrupt_path)
        with self.assertRaises(sqlite3.DatabaseError):
            corrupt.append(sample_event())
        renamed_path = corrupt_path + ".moved"
        os.replace(corrupt_path, renamed_path)
        self.assertTrue(os.path.exists(renamed_path))

    def test_concurrent_writes_are_not_lost(self):
        barrier = threading.Barrier(6)

        def write_batch(batch):
            barrier.wait(timeout=3)
            for index in range(20):
                event = sample_event(
                    origin="live",
                    occurred_at=START + timedelta(seconds=batch * 20 + index),
                )
                self.repository.append(event)

        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(write_batch, batch) for batch in range(5)]
            barrier.wait(timeout=3)
            for future in futures:
                future.result(timeout=15)
        events = list(self.repository.iter_events(START, END))
        self.assertEqual(len(events), 100)
        self.assertEqual(len({item["event_id"] for item in events}), 100)


class EventWriteQueueTests(unittest.TestCase):
    def test_queue_saturation_is_nonblocking_and_reported(self):
        entered = threading.Event()
        release = threading.Event()
        failures = []

        class BlockingRepository:
            def append(self, event):
                entered.set()
                release.wait(3)
                return True

        writer = EventWriteQueue(BlockingRepository(), capacity=1, on_error=failures.append)
        self.assertTrue(writer.submit(sample_event()))
        self.assertTrue(entered.wait(2))
        self.assertTrue(writer.submit(sample_event(occurred_at=START + timedelta(seconds=1))))
        started = time.monotonic()
        self.assertFalse(writer.submit(sample_event(occurred_at=START + timedelta(seconds=2))))
        self.assertLess(time.monotonic() - started, 0.2)
        self.assertEqual(writer.failure_count, 1)
        self.assertEqual(len(failures), 1)
        release.set()
        self.assertTrue(writer.close(timeout=3))

    def test_database_write_failure_is_counted(self):
        temp = tempfile.TemporaryDirectory()
        try:
            blocked_parent = os.path.join(temp.name, "file-not-directory")
            with open(blocked_parent, "w", encoding="utf-8") as output:
                output.write("x")
            repository = SQLiteEventRepository(os.path.join(blocked_parent, "events.sqlite3"))
            writer = EventWriteQueue(repository)
            self.assertTrue(writer.submit(sample_event()))
            self.assertTrue(writer.flush(timeout=3))
            self.assertEqual(writer.failure_count, 1)
            self.assertIsNotNone(writer.last_error)
            self.assertTrue(writer.close(timeout=3))
        finally:
            temp.cleanup()


if __name__ == "__main__":
    unittest.main()
