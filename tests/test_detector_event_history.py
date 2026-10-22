from datetime import datetime, timezone
import os
import tempfile
import threading
import unittest
from unittest.mock import patch

from scapy.all import Ether, IP, TCP, PcapWriter

from v2.event_store import EventWriteQueue, SQLiteEventRepository
from v2.live_detector import Flow, LiveDetectorEngine


class AttackModel:
    def predict(self, frame):
        return [1]

    def predict_proba(self, frame):
        return [[0.05, 0.95]]


def packet(index):
    item = Ether() / IP(src="192.0.2.10", dst="198.51.100.20") / TCP(sport=43123, dport=443)
    item.time = 1_700_000_000 + index * 0.01
    return item


def all_events(repository):
    return list(repository.iter_events(
        datetime(2000, 1, 1, tzinfo=timezone.utc),
        datetime(2100, 1, 1, tzinfo=timezone.utc),
    ))


class DetectorEventHistoryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.repository = SQLiteEventRepository(os.path.join(self.temp.name, "events.sqlite3"))
        self.writer = EventWriteQueue(self.repository)
        with patch("v2.live_detector.os.path.exists", return_value=False):
            self.engine = LiveDetectorEngine(model_file="missing-model", event_writer=self.writer)
        self.engine.model = AttackModel()

    def tearDown(self):
        self.writer.close(timeout=3)
        self.temp.cleanup()

    def test_live_packet_flow_gets_live_origin_and_capture_session(self):
        self.engine.mode = "live"
        self.engine.current_session_id = "live-run-42"
        for index in range(5):
            self.engine._process_packet(packet(index))
        self.assertTrue(self.writer.flush(timeout=3))
        events = all_events(self.repository)
        self.assertEqual({event["event_type"] for event in events}, {"flow_classification", "alert"})
        self.assertTrue(all(event["origin"] == "live" for event in events))
        self.assertTrue(all(event["session_id"] == "live-run-42" for event in events))
        classification = next(event for event in events if event["event_type"] == "flow_classification")
        self.assertEqual(classification["classification"], "ATTACK")
        self.assertEqual(classification["metadata"]["packet_count"], 5)
        self.assertEqual(classification["metadata"]["byte_count"], 5 * len(packet(0)))

    def test_pcap_replay_records_pcap_origin_and_run_id(self):
        pcap_path = os.path.join(self.temp.name, "replay.pcap")
        with PcapWriter(pcap_path, sync=True) as pcap:
            for index in range(4):
                pcap.write(packet(index))
        started, _ = self.engine.start_pcap_replay(pcap_path)
        self.assertTrue(started)
        self.engine.thread.join(3)
        self.assertFalse(self.engine.thread.is_alive())
        self.assertTrue(self.writer.flush(timeout=3))
        events = all_events(self.repository)
        self.assertEqual(len(events), 2)
        self.assertTrue(all(event["origin"] == "pcap" for event in events))
        self.assertTrue(all(event["session_id"] for event in events))

    def test_pcap_capture_error_is_a_separate_operational_event(self):
        pcap_path = os.path.join(self.temp.name, "failing-replay.pcap")
        with open(pcap_path, "wb") as output:
            output.write(b"fixture")

        class BrokenReader:
            def __init__(self, path):
                pass

            def __enter__(self):
                raise OSError("fixture read failure")

            def __exit__(self, exc_type, exc, tb):
                return False

        with patch("v2.live_detector.PcapReader", BrokenReader):
            started, _ = self.engine.start_pcap_replay(pcap_path)
            self.assertTrue(started)
            self.engine.thread.join(3)
        self.assertTrue(self.writer.flush(timeout=3))
        events = all_events(self.repository)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["event_type"], "capture_error")
        self.assertEqual(events[0]["origin"], "pcap")
        self.assertEqual(events[0]["metadata"], {"phase": "pcap_replay", "error_type": "OSError"})

    def test_simulator_records_simulation_origin_and_shared_batch_session(self):
        self.engine.inject_simulated_attack(count=2)
        self.assertTrue(self.writer.flush(timeout=3))
        events = all_events(self.repository)
        self.assertEqual(len(events), 4)
        self.assertTrue(all(event["origin"] == "simulation" for event in events))
        self.assertEqual(len({event["session_id"] for event in events}), 1)

    def test_inference_error_is_recorded_without_becoming_a_classification(self):
        class FailingModel:
            def predict(self, frame):
                raise RuntimeError("fixture failure")

        self.engine.model = FailingModel()
        flow = Flow("192.0.2.1", "198.51.100.1", 1000, 443, "TCP", 1.0)
        flow.traffic_origin = "live"
        flow.session_id = "run-error"
        self.engine._classify_and_alert(flow)
        self.assertTrue(self.writer.flush(timeout=3))
        events = all_events(self.repository)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["event_type"], "processing_error")
        self.assertEqual(events[0]["origin"], "live")
        self.assertIsNone(events[0]["classification"])
        self.assertEqual(events[0]["metadata"], {"phase": "inference", "error_type": "RuntimeError"})

    def test_persistence_failure_does_not_abort_classification(self):
        class FailingRepository:
            def append(self, event):
                raise OSError("storage unavailable")

        writer = EventWriteQueue(FailingRepository())
        with patch("v2.live_detector.os.path.exists", return_value=False):
            engine = LiveDetectorEngine(model_file="missing-model", event_writer=writer)
        engine.model = AttackModel()
        engine.mode = "live"
        engine.current_session_id = "run-storage-error"
        for index in range(5):
            engine._process_packet(packet(index))
        self.assertTrue(writer.flush(timeout=3))
        self.assertEqual(engine.get_status()["stats"]["completed_flows"], 1)
        self.assertGreater(writer.failure_count, 0)
        self.assertGreater(engine.event_history_errors, 0)
        writer.close(timeout=3)

    def test_repository_write_runs_outside_detector_state_lock(self):
        detector_lock_was_available = threading.Event()
        engine_ref = {}

        class LockCheckingRepository:
            def append(self, event):
                detector = engine_ref["engine"]
                acquired = detector.lock.acquire(blocking=False)
                if acquired:
                    detector.lock.release()
                    detector_lock_was_available.set()
                else:
                    raise AssertionError("event repository called while detector lock held")
                return True

        writer = EventWriteQueue(LockCheckingRepository())
        with patch("v2.live_detector.os.path.exists", return_value=False):
            engine = LiveDetectorEngine(model_file="missing-model", event_writer=writer)
        engine_ref["engine"] = engine
        engine.model = AttackModel()
        engine.mode = "live"
        engine.current_session_id = "lock-check"
        for index in range(5):
            engine._process_packet(packet(index))
        self.assertTrue(writer.flush(timeout=3))
        self.assertTrue(detector_lock_was_available.is_set())
        writer.close(timeout=3)


if __name__ == "__main__":
    unittest.main()
