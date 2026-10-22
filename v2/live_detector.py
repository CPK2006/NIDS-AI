import time
import datetime
import atexit
import logging
import threading
import os
import sys
import uuid
import pandas as pd
import joblib
from scapy.all import PcapReader, IP, IPv6, TCP, UDP, sniff, conf
from v2.event_store import (
    ALLOWED_ORIGINS,
    EventWriteQueue,
    create_event_repository,
    create_event,
)
from v2.critical_email_alerts import CriticalEmailAlerts

logger = logging.getLogger(__name__)

# ============================================================
# CONFIGURATION
# ============================================================

MODEL_FILE = os.path.join(
    os.path.dirname(__file__),
    "model",
    "nids_v2_model.pkl"
)

FEATURES = [
    "Destination Port",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Fwd Packet Length Max",
    "Bwd Packet Length Mean",
    "Packet Length Mean",
    "Flow Bytes/s",
]

MODEL_UNAVAILABLE_MESSAGE = (
    "V2 model is unavailable or incompatible. Restore the expected model artifact "
    "and restart the local sensor."
)


# ============================================================
# FLOW CLASS
# ============================================================

class Flow:

    def __init__(
        self,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        protocol,
        timestamp
    ):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol

        self.start_time = timestamp
        self.last_time = timestamp

        self.fwd_packets = 0
        self.bwd_packets = 0

        self.fwd_bytes = 0
        self.bwd_bytes = 0

        self.fwd_lengths = []
        self.bwd_lengths = []

        self.packet_lengths = []


# ============================================================
# PACKET INFORMATION
# ============================================================

def get_packet_info(packet):
    if IPv6 in packet:
        ip_layer = packet[IPv6]
    elif IP in packet:
        ip_layer = packet[IP]
    else:
        return None

    src_ip = ip_layer.src
    dst_ip = ip_layer.dst

    if TCP in packet:
        protocol = "TCP"
        src_port = int(packet[TCP].sport)
        dst_port = int(packet[TCP].dport)
    elif UDP in packet:
        protocol = "UDP"
        src_port = int(packet[UDP].sport)
        dst_port = int(packet[UDP].dport)
    else:
        return None

    return {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": protocol,
        "length": len(packet),
        "timestamp": float(getattr(packet, "time", time.time())),
    }


# ============================================================
# FLOW KEYS
# ============================================================

def make_flow_keys(info):
    forward = (
        info["src_ip"],
        info["dst_ip"],
        info["src_port"],
        info["dst_port"],
        info["protocol"],
    )

    backward = (
        info["dst_ip"],
        info["src_ip"],
        info["dst_port"],
        info["src_port"],
        info["protocol"],
    )

    return forward, backward


# ============================================================
# UPDATE FLOW
# ============================================================

def update_flow(flow, info, direction):
    timestamp = info["timestamp"]
    length = info["length"]

    flow.last_time = timestamp
    flow.packet_lengths.append(length)

    if direction == "F":
        flow.fwd_packets += 1
        flow.fwd_bytes += length
        flow.fwd_lengths.append(length)
    else:
        flow.bwd_packets += 1
        flow.bwd_bytes += length
        flow.bwd_lengths.append(length)


# ============================================================
# GENERATE FEATURES
# ============================================================

def generate_features(flow):
    duration_sec = max(0.000001, flow.last_time - flow.start_time)
    duration_us = duration_sec * 1_000_000.0  # CICIDS2017 uses microseconds
    total_packets = flow.fwd_packets + flow.bwd_packets
    total_bytes = flow.fwd_bytes + flow.bwd_bytes

    if total_packets > 0:
        packet_length_mean = sum(flow.packet_lengths) / total_packets
    else:
        packet_length_mean = 0.0

    if flow.bwd_packets > 0:
        bwd_packet_length_mean = sum(flow.bwd_lengths) / flow.bwd_packets
    else:
        bwd_packet_length_mean = 0.0

    if flow.fwd_packets > 0:
        fwd_packet_length_max = max(flow.fwd_lengths)
    else:
        fwd_packet_length_max = 0.0

    if duration_sec > 0:
        flow_bytes_per_second = total_bytes / duration_sec
    else:
        flow_bytes_per_second = 0.0

    return [
        flow.dst_port,
        duration_us,
        flow.fwd_packets,
        flow.bwd_packets,
        flow.fwd_bytes,
        flow.bwd_bytes,
        fwd_packet_length_max,
        bwd_packet_length_mean,
        packet_length_mean,
        flow_bytes_per_second,
    ]


# ============================================================
# PREDICT FLOW
# ============================================================

def predict_flow(model, flow):
    if model is None:
        raise RuntimeError("V2 detection model is unavailable.")
    values = generate_features(flow)
    dataframe = pd.DataFrame([values], columns=FEATURES)
    prediction = model.predict(dataframe)[0]
    probability = model.predict_proba(dataframe)[0]
    confidence = float(max(probability) * 100)

    label = "ATTACK" if prediction == 1 else "BENIGN"
    return label, confidence, values


# ============================================================
# LIVE DETECTOR ENGINE CLASS
# ============================================================

class LiveDetectorEngine:

    def __init__(self, model_file=MODEL_FILE, event_writer=None):
        self.model_file = model_file
        self.model = None
        self.is_running = False
        self.mode = "idle"  # "live", "pcap"
        self.active_interface = "Default / Auto"
        self.last_run_mode = None
        self.last_run_source = None
        self.last_run_status = "idle"
        self.shutdown_warning = None
        self.stop_requested = False
        self._sweeper_stop = threading.Event()
        self.lock = threading.Lock()
        self.thread = None
        self.sweeper_thread = None
        self.current_session_id = None
        self.event_history_errors = 0
        self.last_event_history_error = None
        self.event_writer = event_writer or EventWriteQueue(
            create_event_repository(), on_error=self._on_event_history_error
        )
        self.critical_email_alerts = CriticalEmailAlerts(repository=getattr(self.event_writer, "repository", None))
        if event_writer is not None:
            self.event_writer.add_error_handler(self._on_event_history_error)
        self.error_message = None
        try:
            self.alert_cooldown_seconds = max(0.0, float(os.getenv("NETRA_ALERT_COOLDOWN_SECONDS", "60")))
        except ValueError:
            self.alert_cooldown_seconds = 60.0
        self._recent_alerts = {}
        self._recent_classifications = []
        self._next_alert_id = 1

        self.stats = {
            "packets_processed": 0,
            "ignored_packets": 0,
            "active_flows": 0,
            "completed_flows": 0,
            "classified_flows": 0,
            "simulated_flows": 0,
            "benign_count": 0,
            "attack_count": 0,
            "attacks_flagged": 0,
            "threat_level": "LOW",
            "start_time": None,
            "last_packet_time": None,
            "last_flow_time": None,
            "last_inference_time": None,
            "processing_errors": 0,
            "last_processing_error": None,
            "capture_errors": 0,
            "last_capture_error": None
        }

        self.alerts = []
        self.classification_feed = []
        self.active_flows = {}
        self._load_model()

    def _load_model(self):
        loaded_model = None
        try:
            if os.path.exists(self.model_file):
                loaded_model = joblib.load(self.model_file)
            else:
                with self.lock:
                    self.error_message = MODEL_UNAVAILABLE_MESSAGE
                print("[V2 Engine] Model unavailable; local capture and replay are disabled.")
                return
        except Exception:
            with self.lock:
                self.error_message = MODEL_UNAVAILABLE_MESSAGE
            print("[V2 Engine] Model unavailable; local capture and replay are disabled.")
            return
        if not self._prediction_model_is_usable(loaded_model):
            with self.lock:
                self.error_message = MODEL_UNAVAILABLE_MESSAGE
            print("[V2 Engine] Model unavailable; local capture and replay are disabled.")
            return
        with self.lock:
            if self.model is None:
                self.model = loaded_model
                self.error_message = None

    @staticmethod
    def _prediction_model_is_usable(model):
        if model is None or not callable(getattr(model, "predict", None)) \
                or not callable(getattr(model, "predict_proba", None)):
            return False
        feature_count = getattr(model, "n_features_in_", len(FEATURES))
        try:
            if int(feature_count) != len(FEATURES):
                return False
        except (TypeError, ValueError):
            return False
        feature_names = getattr(model, "feature_names_in_", None)
        return feature_names is None or list(feature_names) == FEATURES

    def _model_is_usable(self):
        return self._prediction_model_is_usable(self.model)

    def get_interfaces(self):
        interfaces = []
        try:
            for iface in conf.ifaces.values():
                name = getattr(iface, "name", str(iface))
                description = getattr(iface, "description", name)
                interfaces.append({"name": name, "description": description})
        except Exception:
            pass

        # Sort physical / loopback interfaces first
        def _iface_priority(item):
            desc = item["description"].lower()
            name = item["name"].lower()
            if "loopback" in desc or "loopback" in name:
                return 0
            if "wi-fi" in desc or "wifi" in desc or "ethernet" in desc:
                return 1
            if "miniport" in desc or "virtual" in desc:
                return 3
            return 2

        interfaces.sort(key=_iface_priority)

        if not interfaces:
            interfaces = [{"name": "default", "description": "Default System Network Adapter"}]
        return interfaces

    def start_live(self, interface=None):
        with self.lock:
            if self._worker_active():
                return False, "The detection engine is already running or stopping."
            if not self._prediction_model_is_usable(self.model):
                self.error_message = MODEL_UNAVAILABLE_MESSAGE
                self.last_run_status = "error"
                return False, MODEL_UNAVAILABLE_MESSAGE

            self._reset_stats()
            self.shutdown_warning = None
            self.current_session_id = str(uuid.uuid4())
            self.critical_email_alerts.begin_live_session(self.current_session_id)
            self.is_running = True
            self.stop_requested = False
            self._sweeper_stop.clear()
            self.mode = "live"
            self.active_interface = interface or "Default Interface"
            self.last_run_mode = self.mode
            self.last_run_source = self.active_interface
            self.last_run_status = "running"
            self.error_message = None

            self.thread = threading.Thread(
                target=self._run_live_sniffer,
                args=(interface,),
                daemon=True
            )
            self.thread.start()
            return True, "Live sniffer started successfully."

    def start_pcap_replay(self, pcap_path):
        with self.lock:
            if self._worker_active():
                return False, "The detection engine is already running or stopping."
            if not self._prediction_model_is_usable(self.model):
                self.error_message = MODEL_UNAVAILABLE_MESSAGE
                self.last_run_status = "error"
                return False, MODEL_UNAVAILABLE_MESSAGE

            if not os.path.exists(pcap_path):
                return False, f"PCAP file not found: {pcap_path}"

            self._reset_stats()
            self.shutdown_warning = None
            self.critical_email_alerts.end_live_session(self.current_session_id)
            self.current_session_id = str(uuid.uuid4())
            self.is_running = True
            self.stop_requested = False
            self._sweeper_stop.clear()
            self.mode = "pcap"
            self.active_interface = f"Replay: {os.path.basename(pcap_path)}"
            self.last_run_mode = self.mode
            self.last_run_source = self.active_interface
            self.last_run_status = "running"
            self.error_message = None

            self.thread = threading.Thread(
                target=self._run_pcap_replay,
                args=(pcap_path,),
                daemon=True
            )
            self.thread.start()
            return True, "PCAP replay engine started."

    def stop(self, timeout=5.0):
        """Request shutdown and wait a bounded time for capture cleanup to finish."""
        with self.lock:
            worker = self.thread
            worker_alive = worker is not None and worker.is_alive()
            if not self.is_running and not worker_alive:
                return False, "Engine is not running."
            if self.is_running and not self.stop_requested:
                self.stop_requested = True
                self.last_run_status = "stopping"
                self._sweeper_stop.set()

        if worker is not None and worker is not threading.current_thread():
            worker.join(max(0.0, float(timeout)))
            if worker.is_alive():
                with self.lock:
                    self.shutdown_warning = (
                        "Capture shutdown is still in progress; capture resources remain open. "
                        "Check the local sensor if it does not stop."
                    )
                return False, "Stop requested, but the capture worker did not stop before the timeout."
        return True, "Capture worker stopped and cleanup completed."

    def shutdown(self, timeout=5.0):
        """Stop capture before closing resources used by the capture thread.

        If capture or its final cleanup remains active at the deadline, leave the
        writer and alert worker open so their in-flight submissions are not cut off.
        """
        with self.lock:
            worker_active = self._worker_active()
        if worker_active:
            self.stop(timeout=timeout)
            with self.lock:
                worker = self.thread
                sweeper = self.sweeper_thread
            if ((worker is not None and worker.is_alive())
                    or (sweeper is not None and sweeper.is_alive())):
                with self.lock:
                    self.shutdown_warning = (
                        "Shutdown is incomplete; a capture worker did not stop before the timeout. "
                        "Capture resources remain open."
                    )
                logger.error("NETRA shutdown timed out; capture resources left open")
                return False

        with self.lock:
            worker = self.thread
            sweeper = self.sweeper_thread
        if ((worker is not None and worker.is_alive())
                or (sweeper is not None and sweeper.is_alive())):
            with self.lock:
                self.shutdown_warning = (
                    "Shutdown is incomplete; a capture worker did not stop before the timeout. "
                    "Capture resources remain open."
                )
            logger.error("NETRA shutdown timed out; capture resources left open")
            return False

        writer_closed = self.event_writer.close(timeout=timeout)
        alerts_closed = self.critical_email_alerts.notifier.close(timeout=timeout)
        if not writer_closed or not alerts_closed:
            logger.error("NETRA shutdown did not stop every persistence worker before the deadline")
            return False
        return True

    def _worker_active(self):
        worker_alive = self.thread is not None and self.thread.is_alive()
        sweeper_alive = self.sweeper_thread is not None and self.sweeper_thread.is_alive()
        return self.is_running or worker_alive or sweeper_alive

    def _reset_stats(self):
        self.stats = {
            "packets_processed": 0,
            "ignored_packets": 0,
            "active_flows": 0,
            "completed_flows": 0,
            "classified_flows": 0,
            "simulated_flows": 0,
            "benign_count": 0,
            "attack_count": 0,
            "attacks_flagged": 0,
            "threat_level": "LOW",
            "start_time": datetime.datetime.now().strftime("%H:%M:%S"),
            "last_packet_time": None,
            "last_flow_time": None,
            "last_inference_time": None,
            "processing_errors": 0,
            "last_processing_error": None,
            "capture_errors": 0,
            "last_capture_error": None
        }
        self.active_flows = {}
        self._recent_classifications = []

    def _process_packet(self, packet):
        if self.stop_requested:
            return

        flow_to_classify = None
        with self.lock:
            self.stats["packets_processed"] += 1
            self.stats["last_packet_time"] = datetime.datetime.now().strftime("%H:%M:%S")

            info = get_packet_info(packet)
            if info is None:
                self.stats["ignored_packets"] += 1
                return

            forward_key, backward_key = make_flow_keys(info)
            timestamp = info["timestamp"]

            # Update Forward Flow
            if forward_key in self.active_flows:
                flow = self.active_flows[forward_key]
                update_flow(flow, info, "F")
                flow_to_classify = self._check_flow_prediction(flow, forward_key)
                if flow_to_classify is None:
                    return
            # Update Backward Flow
            elif backward_key in self.active_flows:
                flow = self.active_flows[backward_key]
                update_flow(flow, info, "B")
                flow_to_classify = self._check_flow_prediction(flow, backward_key)
                if flow_to_classify is None:
                    return
            else:
                # New Flow
                flow = Flow(
                    src_ip=info["src_ip"],
                    dst_ip=info["dst_ip"],
                    src_port=info["src_port"],
                    dst_port=info["dst_port"],
                    protocol=info["protocol"],
                    timestamp=timestamp,
                )
                flow.traffic_origin = self.mode if self.mode in {"live", "pcap"} else None
                flow.session_id = self.current_session_id
                update_flow(flow, info, "F")
                self.active_flows[forward_key] = flow
                self.stats["active_flows"] = len(self.active_flows)
                flow_to_classify = self._check_flow_prediction(flow, forward_key)

        if flow_to_classify is not None:
            self._classify_and_alert(flow_to_classify)

    def _check_flow_prediction(self, flow, flow_key):
        total_packets = flow.fwd_packets + flow.bwd_packets
        # Classify at five packets; idle and replay-finalization paths flush shorter flows.
        if total_packets >= 5:
            if flow_key in self.active_flows:
                del self.active_flows[flow_key]
                self.stats["active_flows"] = len(self.active_flows)
            return flow
        return None

    def _classify_and_alert(self, flow):
        flow_origin = getattr(flow, "traffic_origin", None)
        flow_session_id = getattr(flow, "session_id", None)
        model = self.model
        try:
            label, confidence, values = predict_flow(model, flow)
        except Exception as exc:
            with self.lock:
                self.stats["processing_errors"] += 1
                self.stats["last_processing_error"] = f"Inference failed: {exc}"
                self.error_message = self.stats["last_processing_error"]
            self._record_operational_event(
                "processing_error",
                origin=flow_origin,
                session_id=flow_session_id,
                metadata={"phase": "inference", "error_type": type(exc).__name__},
            )
            return

        now = datetime.datetime.now()
        now_text = now.strftime("%Y-%m-%d %H:%M:%S")
        traffic_origin = flow_origin
        if traffic_origin not in ALLOWED_ORIGINS:
            traffic_origin = self.mode if self.mode in {"live", "pcap"} else "capture"
        metadata = {
            "packet_count": int(flow.fwd_packets + flow.bwd_packets),
            "byte_count": int(flow.fwd_bytes + flow.bwd_bytes),
            "protocol": str(flow.protocol),
            "confidence_percent": round(float(confidence), 2),
        }
        history_events = []
        if flow_origin in ALLOWED_ORIGINS:
            try:
                history_events.append(create_event(
                    origin=flow_origin,
                    session_id=flow_session_id,
                    event_type="flow_classification",
                    classification=label,
                    metadata=metadata,
                    occurred_at=datetime.datetime.now(datetime.timezone.utc),
                ))
                if label == "ATTACK":
                    history_events.append(create_event(
                        origin=flow_origin,
                        session_id=flow_session_id,
                        event_type="alert",
                        classification="ATTACK",
                        metadata={
                            "packet_count": metadata["packet_count"],
                            "byte_count": metadata["byte_count"],
                            "protocol": metadata["protocol"],
                            "alert_source": "ml",
                        },
                        occurred_at=datetime.datetime.now(datetime.timezone.utc),
                    ))
            except Exception as exc:
                self._on_event_history_error(exc)
        try:
            # Session eligibility is checked by the policy; it only accepts sessions
            # explicitly opened by start_live(), never PCAP, simulation or ingestion.
            self.critical_email_alerts.observe_flow(
                origin=flow_origin, session_id=flow_session_id, classification=label,
            )
        except Exception as exc:
            logger.warning("critical email alert handoff failed (%s)", type(exc).__name__)
        with self.lock:
            self.stats["last_inference_time"] = now.strftime("%H:%M:%S")
            self.stats["last_flow_time"] = now.strftime("%H:%M:%S")
            self.stats["classified_flows"] += 1
            feed_item = {
                "id": len(self.classification_feed) + 1,
                "timestamp": now_text,
                "last_seen": now_text,
                "occurrence_count": 1,
                "detection_source": "ml",
                "traffic_origin": traffic_origin,
                "src_ip": flow.src_ip,
                "dst_ip": flow.dst_ip,
                "src_port": flow.src_port,
                "dst_port": flow.dst_port,
                "protocol": flow.protocol,
                "label": label,
                "confidence": round(confidence, 2),
                "packets": flow.fwd_packets + flow.bwd_packets,
            }
            self.classification_feed.insert(0, feed_item)
            if len(self.classification_feed) > 100:
                self.classification_feed.pop()

            self._recent_classifications.append(label)
            self._recent_classifications = self._recent_classifications[-20:]
            if traffic_origin != "simulation":
                self.stats["completed_flows"] += 1

            if label == "BENIGN":
                if traffic_origin != "simulation":
                    self.stats["benign_count"] += 1
                self._update_threat_level()
            else:
                self.stats["attacks_flagged"] += 1
                if traffic_origin != "simulation":
                    self.stats["attack_count"] += 1

                key = (traffic_origin, flow.src_ip, flow.dst_ip, flow.src_port, flow.dst_port, flow.protocol, label, "ml")
                monotonic_now = time.monotonic()
                previous = self._recent_alerts.get(key)
                if (self.alert_cooldown_seconds > 0 and previous
                        and monotonic_now - previous[0] <= self.alert_cooldown_seconds):
                    alert = previous[1]
                    alert["occurrence_count"] += 1
                    alert["last_seen"] = now_text
                    alert["packets"] += flow.fwd_packets + flow.bwd_packets
                    alert["bytes"] += flow.fwd_bytes + flow.bwd_bytes
                    alert["confidence"] = round(confidence, 2)
                    self._recent_alerts[key] = (monotonic_now, alert)
                else:
                    alert = {
                        "id": self._next_alert_id,
                        "timestamp": now_text,
                        "last_seen": now_text,
                        "occurrence_count": 1,
                        "detection_source": "ml",
                        "traffic_origin": traffic_origin,
                        "src_ip": flow.src_ip,
                        "dst_ip": flow.dst_ip,
                        "src_port": flow.src_port,
                        "dst_port": flow.dst_port,
                        "protocol": flow.protocol,
                        "label": label,
                        "confidence": round(confidence, 2),
                        "packets": flow.fwd_packets + flow.bwd_packets,
                        "duration": round(flow.last_time - flow.start_time, 4),
                        "bytes": flow.fwd_bytes + flow.bwd_bytes
                    }
                    self._next_alert_id += 1

                    self.alerts.insert(0, alert)
                    self._recent_alerts[key] = (monotonic_now, alert)
                    cutoff = monotonic_now - max(self.alert_cooldown_seconds, 1.0)
                    self._recent_alerts = {k: v for k, v in self._recent_alerts.items() if v[0] >= cutoff}
                    if len(self.alerts) > 100:
                        self.alerts.pop()

                self._update_threat_level()

        # The handoff is nonblocking. SQLite work runs only on EventWriteQueue's worker.
        for event in history_events:
            try:
                self.event_writer.submit(event)
            except Exception as exc:
                self._on_event_history_error(exc)

    def _on_event_history_error(self, error):
        with self.lock:
            self.event_history_errors += 1
            self.last_event_history_error = str(error)
        logger.error("NETRA event history persistence failed: %s", error)

    def _record_operational_event(self, event_type, *, origin, session_id, metadata):
        if origin not in ALLOWED_ORIGINS:
            return
        try:
            event = create_event(
                origin=origin,
                session_id=session_id,
                event_type=event_type,
                metadata=metadata,
                occurred_at=datetime.datetime.now(datetime.timezone.utc),
            )
            self.event_writer.submit(event)
        except Exception as exc:
            self._on_event_history_error(exc)

    def _update_threat_level(self):
        recent_attacks = sum(1 for label in self._recent_classifications if label == "ATTACK")
        if recent_attacks >= 10:
            self.stats["threat_level"] = "CRITICAL"
        elif recent_attacks >= 5:
            self.stats["threat_level"] = "HIGH"
        elif recent_attacks >= 1:
            self.stats["threat_level"] = "MEDIUM"
        else:
            self.stats["threat_level"] = "LOW"

    def _start_flow_sweeper(self):
        def _sweeper():
            while not self._sweeper_stop.wait(1.5):
                expired_flows = []
                with self.lock:
                    if not self.is_running or self.stop_requested:
                        return
                    now = time.time()
                    for flow_key, flow in list(self.active_flows.items()):
                        # Flush flows inactive for > 2.0 seconds or with packets
                        if (now - flow.last_time) > 2.0 or (flow.fwd_packets + flow.bwd_packets) >= 5:
                            expired_flows.append(flow)
                            del self.active_flows[flow_key]
                            self.stats["active_flows"] = len(self.active_flows)
                for flow in expired_flows:
                    self._classify_and_alert(flow)
        self.sweeper_thread = threading.Thread(target=_sweeper, daemon=True)
        self.sweeper_thread.start()

    def _finish_worker(self):
        with self.lock:
            self._sweeper_stop.set()
        sweeper = self.sweeper_thread
        if sweeper is not None and sweeper is not threading.current_thread():
            sweeper.join()

        with self.lock:
            pending_flows = list(self.active_flows.values())
            self.active_flows.clear()
            self.stats["active_flows"] = 0

        for flow in pending_flows:
            self._classify_and_alert(flow)

        with self.lock:
            finished_mode = self.mode
            finished_session = self.current_session_id
        if finished_mode == "live":
            self.critical_email_alerts.end_live_session(finished_session)

        with self.lock:
            self.is_running = False
            self.mode = "idle"
            self.active_interface = None
            if self.error_message:
                self.last_run_status = "error"
            elif self.last_run_status == "stopping":
                self.last_run_status = "stopped"
            else:
                self.last_run_status = "completed"
            self.stop_requested = False

    def _run_live_sniffer(self, interface):
        try:
            self._start_flow_sweeper()
            def stop_check(pkt):
                return self.stop_requested

            sniff_args = {
                "prn": self._process_packet,
                "stop_filter": stop_check,
                "store": False,
                "timeout": 3
            }
            if interface and interface != "default" and interface != "Default Interface":
                sniff_args["iface"] = interface

            while self.is_running and not self.stop_requested:
                try:
                    sniff(**sniff_args)
                except Exception as ex:
                    # Retry sniff loop gracefully if minor packet decode exception occurs
                    if self.stop_requested:
                        break
                    with self.lock:
                        self.stats["capture_errors"] += 1
                        self.stats["last_capture_error"] = str(ex)
                    self._record_operational_event(
                        "capture_error", origin="live", session_id=self.current_session_id,
                        metadata={"phase": "live_capture", "error_type": type(ex).__name__},
                    )
                    if self._sweeper_stop.wait(0.5):
                        break

        except Exception as e:
            with self.lock:
                self.error_message = f"Sniffer notice: {str(e)}"
                self.stats["capture_errors"] += 1
                self.stats["last_capture_error"] = str(e)
            self._record_operational_event(
                "capture_error", origin="live", session_id=self.current_session_id,
                metadata={"phase": "live_capture", "error_type": type(e).__name__},
            )
            print(f"[V2 Engine Error] {self.error_message}")
        finally:
            self._finish_worker()

    def _run_pcap_replay(self, pcap_path):
        try:
            with PcapReader(pcap_path) as reader:
                for packet in reader:
                    if self.stop_requested:
                        break
                    self._process_packet(packet)
        except Exception as e:
            with self.lock:
                self.error_message = f"PCAP replay notice: {str(e)}"
                self.stats["capture_errors"] += 1
                self.stats["last_capture_error"] = str(e)
            self._record_operational_event(
                "capture_error", origin="pcap", session_id=self.current_session_id,
                metadata={"phase": "pcap_replay", "error_type": type(e).__name__},
            )
        finally:
            self._finish_worker()

    def get_status(self):
        with self.lock:
            status = self._status_snapshot_locked()
        status["email_alerts"] = self.critical_email_alerts.status_snapshot()
        return status

    def _status_snapshot_locked(self):
        return {
            "is_running": self.is_running,
            "stop_requested": self.stop_requested,
            "mode": self.mode,
            "active_interface": self.active_interface,
            "last_run_mode": self.last_run_mode,
            "last_run_source": self.last_run_source,
            "last_run_status": self.last_run_status,
            "shutdown_warning": self.shutdown_warning,
            "error_message": self.error_message,
            "model_available": self._model_is_usable(),
            "model_status_message": (
                "V2 model is available." if self._model_is_usable() else MODEL_UNAVAILABLE_MESSAGE
            ),
            "alert_processing_status": "error" if self.stats["last_processing_error"] else "ok",
            "alert_cooldown_seconds": self.alert_cooldown_seconds,
            "stats": dict(self.stats)
        }

    def get_dashboard_snapshot(self, limit=50):
        with self.lock:
            snapshot = {
                "alerts": [dict(alert) for alert in self.alerts[:limit]],
                "feed": [dict(item) for item in self.classification_feed[:limit]],
                "status": self._status_snapshot_locked()
            }
        snapshot["status"]["email_alerts"] = self.critical_email_alerts.status_snapshot()
        return snapshot

    def get_alerts(self, limit=50):
        with self.lock:
            return [dict(alert) for alert in self.alerts[:limit]]

    def inject_simulated_attack(self, count=5):
        """Inject simulated attack flows for live tracking demonstration."""
        import random
        attack_ports = [8080]
        flows = []
        simulation_session_id = str(uuid.uuid4())

        with self.lock:
            for i in range(count):
                dst_port = random.choice(attack_ports)
                src_port = random.randint(49152, 65535)
                src_ip = f"172.16.0.{random.randint(10, 250)}"
                dst_ip = "192.168.10.50"

                flow = Flow(
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=src_port,
                    dst_port=dst_port,
                    protocol="TCP",
                    timestamp=time.time() - 0.070987
                )
                flow.fwd_packets = 3
                flow.bwd_packets = 3
                flow.fwd_bytes = 6
                flow.bwd_bytes = 18
                flow.fwd_lengths = [2, 2, 2]
                flow.bwd_lengths = [6, 6, 6]
                flow.packet_lengths = [6, 6, 6, 6, 6, 6]
                flow.last_time = time.time()

                flow.traffic_origin = "simulation"
                flow.session_id = simulation_session_id
                self.stats["simulated_flows"] += 1
                flows.append(flow)

        for flow in flows:
            self._classify_and_alert(flow)

    def clear_alerts(self):
        with self.lock:
            self.alerts.clear()
            self.classification_feed.clear()
            self._recent_alerts.clear()
            self._recent_classifications.clear()
            self.stats["packets_processed"] = 0
            self.stats["completed_flows"] = 0
            self.stats["classified_flows"] = 0
            self.stats["simulated_flows"] = 0
            self.stats["benign_count"] = 0
            self.stats["attack_count"] = 0
            self.stats["attacks_flagged"] = 0
            self.stats["threat_level"] = "LOW"
            return True


# Global singleton instance
engine = LiveDetectorEngine()
atexit.register(engine.shutdown)


# ============================================================
# CLI MAIN RUNNER
# ============================================================

def main():
    if len(sys.argv) < 2:
        print("\nUsage:\n  python v2/live_detector.py <pcap_file>\n")
        return

    pcap_path = sys.argv[1]
    if not os.path.exists(pcap_path):
        print(f"ERROR: PCAP not found: {pcap_path}")
        return

    print("=" * 70)
    print("NIDS-AI V2 - LIVE DETECTION TEST (CLI)")
    print("=" * 70)

    ok, msg = engine.start_pcap_replay(pcap_path)
    print(msg)

    while engine.is_running:
        time.sleep(1)
        status = engine.get_status()
        print(f"Packets: {status['stats']['packets_processed']} | Flows: {status['stats']['completed_flows']} | Benign: {status['stats']['benign_count']} | Attack: {status['stats']['attack_count']}")

    print("\nAlerts generated:")
    for a in engine.get_alerts(10):
        print(f"[{a['label']:6}] {a['src_ip']}:{a['src_port']} -> {a['dst_ip']}:{a['dst_port']} (Conf: {a['confidence']}%)")


if __name__ == "__main__":
    main()
