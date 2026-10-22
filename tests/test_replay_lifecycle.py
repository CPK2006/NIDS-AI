import os
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

import joblib
import numpy as np
from scapy.all import Ether, IP, TCP, PcapReader as ScapyPcapReader, PcapWriter

from v2.live_detector import FEATURES, Flow, LiveDetectorEngine, generate_features, predict_flow
from v2.simple_feature_extractor import generate_features as generate_offline_features
from v2.simple_feature_extractor import Flow as OfflineFlow


class ConstantModel:
    classes_ = np.array([0, 1])
    n_features_in_ = len(FEATURES)
    feature_names_in_ = np.array(FEATURES)

    def __init__(self, prediction=1):
        self.prediction = prediction
        self.calls = []

    def predict(self, frame):
        self.calls.append(frame.copy())
        return np.array([self.prediction])

    def predict_proba(self, frame):
        return np.array([[0.1, 0.9]]) if self.prediction else np.array([[0.9, 0.1]])


def packet(index):
    pkt = Ether() / IP(src="192.0.2.10", dst="198.51.100.20") / TCP(sport=43123, dport=443)
    pkt.time = 1_700_000_000 + index * 0.01
    return pkt


def write_pcap(path, count=4):
    with PcapWriter(path, sync=True) as writer:
        for i in range(count):
            writer.write(packet(i))


class ReplayLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.pcap_path = os.path.join(self.temp.name, "small.pcap")
        write_pcap(self.pcap_path)
        self.engine = LiveDetectorEngine(model_file=os.path.join(self.temp.name, "missing.pkl"))
        self.model = ConstantModel()
        self.engine.model = self.model

    def tearDown(self):
        self.temp.cleanup()

    def wait_for_worker(self, timeout=3):
        worker = self.engine.thread
        self.assertIsNotNone(worker)
        worker.join(timeout)
        self.assertFalse(worker.is_alive(), "worker did not finish within the bounded test timeout")

    def test_missing_model_blocks_live_and_replay_with_actionable_unavailable_status(self):
        self.engine.model = None

        status = self.engine.get_status()
        self.assertFalse(status["model_available"])
        self.assertIn("restore the expected model artifact", status["model_status_message"].lower())

        started_live, live_message = self.engine.start_live("test-interface")
        self.assertFalse(started_live)
        self.assertEqual(live_message, status["model_status_message"])
        self.assertFalse(self.engine.is_running)
        self.assertIsNone(self.engine.thread)

        started_replay, replay_message = self.engine.start_pcap_replay(self.pcap_path)
        self.assertFalse(started_replay)
        self.assertEqual(replay_message, status["model_status_message"])
        final_status = self.engine.get_status()
        self.assertFalse(final_status["is_running"])
        self.assertEqual(final_status["last_run_status"], "error")
        self.assertEqual(final_status["error_message"], status["model_status_message"])
        self.assertIsNone(self.engine.thread)

    def test_failed_model_load_is_sanitized_and_blocks_capture_and_replay(self):
        self.engine.model = None
        with patch("v2.live_detector.os.path.exists", return_value=True), patch(
            "v2.live_detector.joblib.load", side_effect=ValueError("private model path and details")
        ):
            self.engine._load_model()

        status = self.engine.get_status()
        self.assertFalse(status["model_available"])
        self.assertNotIn("private model path", str(status))
        self.assertIn("restart the local sensor", status["model_status_message"].lower())
        self.assertFalse(self.engine.start_live("test-interface")[0])
        self.assertFalse(self.engine.start_pcap_replay(self.pcap_path)[0])
        self.assertFalse(self.engine.is_running)
        self.assertIsNone(self.engine.thread)

    def test_model_with_incompatible_feature_count_is_not_usable(self):
        class IncompatibleModel(ConstantModel):
            n_features_in_ = len(FEATURES) - 1

        self.engine.model = IncompatibleModel()
        status = self.engine.get_status()
        self.assertFalse(status["model_available"])
        self.assertFalse(self.engine.start_live("test-interface")[0])
        self.assertFalse(self.engine.start_pcap_replay(self.pcap_path)[0])
        self.assertFalse(self.engine.is_running)

    def test_inference_does_not_silently_reload_model_after_startup(self):
        self.engine.model = None
        with patch.object(self.engine, "_load_model") as reload_model:
            self.engine._classify_and_alert(Flow("192.0.2.1", "198.51.100.1", 50000, 443, "TCP", 1.0))
        reload_model.assert_not_called()
        status = self.engine.get_status()
        self.assertFalse(status["model_available"])
        self.assertEqual(status["stats"]["processing_errors"], 1)
        self.assertEqual(status["stats"]["completed_flows"], 0)
        self.assertEqual(self.engine.get_alerts(), [])

    def test_pcap_reaches_eof_once_flushes_tail_and_returns_to_idle(self):
        closed = []

        class TrackedReader:
            def __init__(self, path):
                self.reader = ScapyPcapReader(path)

            def __enter__(self):
                self.reader.__enter__()
                return self

            def __iter__(self):
                return iter(self.reader)

            def __exit__(self, exc_type, exc, tb):
                self.reader.close()
                closed.append(True)

        with patch("v2.live_detector.PcapReader", TrackedReader):
            ok, _ = self.engine.start_pcap_replay(self.pcap_path)
            self.assertTrue(ok)
            self.wait_for_worker()

        status = self.engine.get_status()
        self.assertFalse(status["is_running"])
        self.assertEqual(status["mode"], "idle")
        self.assertEqual(status["last_run_status"], "completed")
        self.assertEqual(status["last_run_mode"], "pcap")
        self.assertIsNone(status["active_interface"])
        self.assertEqual(status["stats"]["packets_processed"], 4)
        self.assertEqual(status["stats"]["completed_flows"], 1)
        self.assertEqual(status["stats"]["active_flows"], 0)
        self.assertEqual(len(self.model.calls), 1)
        self.assertEqual(closed, [True])

    def test_manual_stop_keeps_stopping_state_until_cleanup_and_blocks_restart(self):
        reader_waiting = threading.Event()
        allow_reader_exit = threading.Event()
        reader_closed = threading.Event()

        class BlockingReader:
            def __init__(self, path):
                pass

            def __enter__(self):
                return self

            def __iter__(self):
                yield packet(0)
                reader_waiting.set()
                allow_reader_exit.wait(2)
                yield packet(1)

            def __exit__(self, exc_type, exc, tb):
                reader_closed.set()

        with patch("v2.live_detector.PcapReader", BlockingReader):
            ok, _ = self.engine.start_pcap_replay(self.pcap_path)
            self.assertTrue(ok)
            self.assertTrue(reader_waiting.wait(2))
            ok, message = self.engine.stop(timeout=0)
            self.assertFalse(ok)
            self.assertIn("did not stop before the timeout", message)
            status = self.engine.get_status()
            self.assertTrue(status["is_running"])
            self.assertTrue(status["stop_requested"])
            self.assertEqual(status["mode"], "pcap")
            restarted, _ = self.engine.start_pcap_replay(self.pcap_path)
            self.assertFalse(restarted)
            allow_reader_exit.set()
            self.wait_for_worker()

        status = self.engine.get_status()
        self.assertTrue(reader_closed.is_set())
        self.assertFalse(status["is_running"])
        self.assertEqual(status["mode"], "idle")
        self.assertEqual(status["last_run_status"], "stopped")
        self.assertEqual(status["stats"]["packets_processed"], 1)
        self.assertEqual(status["stats"]["completed_flows"], 1)
        self.assertEqual(len(self.model.calls), 1)

    def test_stop_timeout_keeps_resources_open_until_capture_terminates(self):
        reader_waiting = threading.Event()
        allow_reader_exit = threading.Event()
        close_order = []

        class BlockingReader:
            def __init__(self, path):
                pass

            def __enter__(self):
                return self

            def __iter__(self):
                reader_waiting.set()
                allow_reader_exit.wait(2)
                return iter(())

            def __exit__(self, exc_type, exc, tb):
                close_order.append("reader")

        writer_close = self.engine.event_writer.close
        notifier_close = self.engine.critical_email_alerts.notifier.close

        def close_writer(timeout=5):
            self.assertFalse(self.engine.thread.is_alive())
            close_order.append("writer")
            return writer_close(timeout)

        def close_notifier(timeout=2):
            self.assertFalse(self.engine.thread.is_alive())
            close_order.append("notifier")
            return notifier_close(timeout)

        self.engine.event_writer.close = close_writer
        self.engine.critical_email_alerts.notifier.close = close_notifier
        with patch("v2.live_detector.PcapReader", BlockingReader):
            ok, _ = self.engine.start_pcap_replay(self.pcap_path)
            self.assertTrue(ok)
            self.assertTrue(reader_waiting.wait(2))

            stopped, message = self.engine.stop(timeout=0.01)
            self.assertFalse(stopped)
            self.assertIn("did not stop before the timeout", message)
            self.assertFalse(self.engine.shutdown(timeout=0.01))
            self.assertEqual(close_order, [])
            status = self.engine.get_status()
            self.assertTrue(status["stop_requested"])
            self.assertIn("capture resources remain open", status["shutdown_warning"].lower())
            self.assertNotIn(self.pcap_path, str(status))
            self.assertNotIn(self.temp.name, str(status))
            self.assertNotIn("postgresql://", str(status).lower())

            allow_reader_exit.set()
            self.wait_for_worker()
            self.assertTrue(self.engine.shutdown(timeout=1))

        self.assertEqual(close_order, ["reader", "writer", "notifier"])
        self.assertTrue(self.engine.shutdown(timeout=1))  # idempotent resource close

    def test_capture_failure_during_shutdown_finishes_cleanup_and_allows_restart(self):
        reader_waiting = threading.Event()
        allow_reader_exit = threading.Event()

        class FailingBlockingReader:
            def __init__(self, path):
                pass

            def __enter__(self):
                return self

            def __iter__(self):
                reader_waiting.set()
                allow_reader_exit.wait(2)
                raise OSError("capture failed while stopping")

            def __exit__(self, exc_type, exc, tb):
                pass

        with patch("v2.live_detector.PcapReader", FailingBlockingReader):
            ok, _ = self.engine.start_pcap_replay(self.pcap_path)
            self.assertTrue(ok)
            self.assertTrue(reader_waiting.wait(2))
            release = threading.Thread(target=lambda: (time.sleep(0.03), allow_reader_exit.set()))
            release.start()
            stopped, _ = self.engine.stop(timeout=1)
            release.join(1)
            self.assertTrue(stopped)
            status = self.engine.get_status()
            self.assertFalse(status["is_running"])
            self.assertEqual(status["last_run_status"], "error")
            self.assertEqual(status["stats"]["capture_errors"], 1)

            ok, _ = self.engine.start_pcap_replay(self.pcap_path)
            # The patched reader fails immediately on the next run too; the new
            # thread proves the prior capture worker no longer blocks a restart.
            self.assertTrue(ok)
            self.wait_for_worker()

    def test_reader_error_is_reported_and_partial_flow_is_cleaned_up(self):
        reader_closed = threading.Event()

        class FailingReader:
            def __init__(self, path):
                pass

            def __enter__(self):
                return self

            def __iter__(self):
                yield packet(0)
                raise OSError("fixture read failure")

            def __exit__(self, exc_type, exc, tb):
                reader_closed.set()

        with patch("v2.live_detector.PcapReader", FailingReader):
            ok, _ = self.engine.start_pcap_replay(self.pcap_path)
            self.assertTrue(ok)
            self.wait_for_worker()

        status = self.engine.get_status()
        self.assertTrue(reader_closed.is_set())
        self.assertFalse(status["is_running"])
        self.assertEqual(status["mode"], "idle")
        self.assertEqual(status["last_run_status"], "error")
        self.assertEqual(status["stats"]["capture_errors"], 1)
        self.assertIn("fixture read failure", status["error_message"])
        self.assertEqual(status["stats"]["completed_flows"], 1)
        self.assertEqual(len(self.model.calls), 1)

    def test_live_capture_can_start_after_replay_finishes(self):
        ok, _ = self.engine.start_pcap_replay(self.pcap_path)
        self.assertTrue(ok)
        self.wait_for_worker()
        self.model.calls.clear()

        sniff_started = threading.Event()

        def fake_sniff(**kwargs):
            self.engine._process_packet(packet(0))
            sniff_started.set()
            self.engine._sweeper_stop.wait(2)

        with patch("v2.live_detector.sniff", fake_sniff):
            ok, _ = self.engine.start_live("test-interface")
            self.assertTrue(ok)
            self.assertTrue(sniff_started.wait(2))
            self.assertEqual(self.engine.get_status()["mode"], "live")
            stopped, _ = self.engine.stop(timeout=1)
            self.assertTrue(stopped)
            self.wait_for_worker()
            self.assertFalse(self.engine.stop()[0])

        status = self.engine.get_status()
        self.assertFalse(status["is_running"])
        self.assertEqual(status["mode"], "idle")
        self.assertEqual(status["last_run_status"], "stopped")
        self.assertEqual(status["stats"]["completed_flows"], 1)
        self.assertEqual(status["stats"]["active_flows"], 0)
        self.assertEqual(len(self.model.calls), 1)

    def test_benign_flow_updates_prediction_counter_without_becoming_an_alert(self):
        self.engine.model = ConstantModel(prediction=0)
        self.engine._process_packet(packet(0))
        flow_key = next(iter(self.engine.active_flows))
        with self.engine.lock:
            flow = self.engine.active_flows.pop(flow_key)
        self.engine._classify_and_alert(flow)
        status = self.engine.get_status()
        self.assertEqual(status["stats"]["completed_flows"], 1)
        self.assertEqual(status["stats"]["benign_count"], 1)
        self.assertEqual(status["stats"]["attack_count"], 0)
        self.assertEqual(status["stats"]["attacks_flagged"], 0)
        self.assertEqual(self.engine.get_alerts(), [])
        self.assertEqual(self.engine.get_dashboard_snapshot()["feed"][0]["label"], "BENIGN")

    def test_status_snapshot_remains_available_during_model_inference(self):
        inference_started = threading.Event()
        allow_inference = threading.Event()

        class BlockingModel(ConstantModel):
            def predict(self, frame):
                inference_started.set()
                allow_inference.wait(2)
                return super().predict(frame)

        self.engine.model = BlockingModel()
        for index in range(4):
            self.engine._process_packet(packet(index))
        classifier = threading.Thread(target=self.engine._process_packet, args=(packet(4),))
        classifier.start()
        self.assertTrue(inference_started.wait(1))
        status = self.engine.get_status()
        self.assertEqual(status["stats"]["packets_processed"], 5)
        self.assertEqual(status["stats"]["active_flows"], 0)
        allow_inference.set()
        classifier.join(2)
        self.assertFalse(classifier.is_alive())
        self.assertEqual(self.engine.get_status()["stats"]["completed_flows"], 1)

    def test_injected_demo_flows_do_not_inflate_packet_or_capture_flow_counts(self):
        self.engine.inject_simulated_attack(count=1)
        status = self.engine.get_status()
        self.assertEqual(status["stats"]["packets_processed"], 0)
        self.assertEqual(status["stats"]["completed_flows"], 0)
        self.assertEqual(status["stats"]["attack_count"], 0)
        self.assertEqual(status["stats"]["attacks_flagged"], 1)
        self.assertEqual(status["stats"]["simulated_flows"], 1)
        self.assertEqual(status["stats"]["threat_level"], "MEDIUM")
        self.assertEqual(self.engine.get_dashboard_snapshot()["feed"][0]["label"], "ATTACK")
        self.assertEqual(self.engine.get_alerts()[0]["traffic_origin"], "simulation")

    def test_simulated_attacks_raise_threat_level_and_roll_out_of_live_feed(self):
        self.engine.inject_simulated_attack(count=5)
        self.assertEqual(self.engine.get_status()["stats"]["threat_level"], "HIGH")
        self.engine.inject_simulated_attack(count=5)
        self.assertEqual(self.engine.get_status()["stats"]["threat_level"], "CRITICAL")

        for index in range(105):
            flow = Flow(f"192.0.2.{index % 250 + 1}", "198.51.100.9", 40000 + index,
                        443, "TCP", 100.0)
            flow.fwd_packets = 1
            flow.fwd_bytes = 100
            flow.fwd_lengths = [100]
            flow.packet_lengths = [100]
            flow.last_time = 101.0
            self.engine._classify_and_alert(flow)

        feed = self.engine.get_dashboard_snapshot(limit=100)["feed"]
        self.assertEqual(len(feed), 100)
        self.assertTrue(all(item["traffic_origin"] != "simulation" for item in feed))


class FlowSchemaTests(unittest.TestCase):
    def test_extractor_schema_matches_trained_model_schema_and_is_finite(self):
        model_path = os.path.join(os.path.dirname(__file__), "..", "v2", "model", "nids_v2_model.pkl")
        if not os.path.exists(model_path):
            self.skipTest("V2 model artifact is not present in this checkout")
        model = joblib.load(model_path)
        self.assertEqual(list(model.feature_names_in_), FEATURES)
        self.assertEqual(model.n_features_in_, len(FEATURES))
        self.assertEqual(list(model.classes_), [0, 1])

        flow = Flow("192.0.2.1", "198.51.100.1", 50000, 443, "TCP", 100.0)
        flow.fwd_packets = 2
        flow.bwd_packets = 1
        flow.fwd_bytes = 200
        flow.bwd_bytes = 100
        flow.fwd_lengths = [100, 100]
        flow.bwd_lengths = [100]
        flow.packet_lengths = [100, 100, 100]
        flow.last_time = 100.5
        values = generate_features(flow)
        self.assertTrue(np.isfinite(values).all())
        label, confidence, _ = predict_flow(model, flow)
        self.assertIn(label, {"BENIGN", "ATTACK"})
        self.assertGreaterEqual(confidence, 0)
        self.assertLessEqual(confidence, 100)

    def test_live_and_offline_extractors_use_microsecond_duration(self):
        live = Flow("a", "b", 1, 2, "TCP", 10.0)
        offline = OfflineFlow("a", "b", 1, 2, "TCP", 10.0)
        for current in (live, offline):
            current.fwd_packets = 1
            current.fwd_bytes = 100
            current.fwd_lengths = [100]
            current.packet_lengths = [100]
            current.last_time = 10.5
        self.assertEqual(generate_features(live)[FEATURES.index("Flow Duration")], 500_000.0)
        self.assertEqual(generate_offline_features(offline)[FEATURES.index("Flow Duration")], 500_000.0)


if __name__ == "__main__":
    unittest.main()
