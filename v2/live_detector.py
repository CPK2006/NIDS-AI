import time
import datetime
import threading
import os
import sys
import pandas as pd
import joblib
from scapy.all import PcapReader, IP, IPv6, TCP, UDP, sniff, conf

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
    values = generate_features(flow)
    dataframe = pd.DataFrame([values], columns=FEATURES)

    try:
        prediction = model.predict(dataframe)[0]
        probability = model.predict_proba(dataframe)[0]
        confidence = float(max(probability) * 100)
    except Exception as e:
        prediction = 0
        confidence = 50.0

    label = "ATTACK" if prediction == 1 else "BENIGN"
    return label, confidence, values


# ============================================================
# LIVE DETECTOR ENGINE CLASS
# ============================================================

class LiveDetectorEngine:

    def __init__(self, model_file=MODEL_FILE):
        self.model_file = model_file
        self.model = None
        self.is_running = False
        self.mode = "idle"  # "live", "pcap"
        self.active_interface = "Default / Auto"
        self.stop_requested = False
        self.lock = threading.Lock()
        self.thread = None
        self.error_message = None

        self.stats = {
            "packets_processed": 0,
            "ignored_packets": 0,
            "active_flows": 0,
            "completed_flows": 0,
            "benign_count": 0,
            "attack_count": 0,
            "threat_level": "LOW",
            "start_time": None,
            "last_packet_time": None
        }

        self.alerts = []
        self.active_flows = {}
        self._load_model()

    def _load_model(self):
        try:
            if os.path.exists(self.model_file):
                self.model = joblib.load(self.model_file)
                print(f"[V2 Engine] Model loaded from {self.model_file}")
            else:
                print(f"[V2 Engine] Warning: Model file not found at {self.model_file}")
        except Exception as e:
            print(f"[V2 Engine] Error loading model: {e}")
            self.error_message = str(e)

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
            if self.is_running:
                return False, "Sniffer is already running."

            self._reset_stats()
            self.is_running = True
            self.stop_requested = False
            self.mode = "live"
            self.active_interface = interface or "Default Interface"
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
            if self.is_running:
                return False, "Engine is already running."

            if not os.path.exists(pcap_path):
                return False, f"PCAP file not found: {pcap_path}"

            self._reset_stats()
            self.is_running = True
            self.stop_requested = False
            self.mode = "pcap"
            self.active_interface = f"Replay: {os.path.basename(pcap_path)}"
            self.error_message = None

            self.thread = threading.Thread(
                target=self._run_pcap_replay,
                args=(pcap_path,),
                daemon=True
            )
            self.thread.start()
            return True, "PCAP replay engine started."

    def stop(self):
        with self.lock:
            if not self.is_running:
                return False, "Engine is not running."
            self.stop_requested = True
            self.is_running = False
            self.mode = "idle"
            return True, "Stop signal sent to sniffer."

    def _reset_stats(self):
        self.stats = {
            "packets_processed": 0,
            "ignored_packets": 0,
            "active_flows": 0,
            "completed_flows": 0,
            "benign_count": 0,
            "attack_count": 0,
            "threat_level": "LOW",
            "start_time": datetime.datetime.now().strftime("%H:%M:%S"),
            "last_packet_time": None
        }
        self.active_flows = {}

    def _process_packet(self, packet):
        if self.stop_requested:
            return

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
                self._check_flow_prediction(flow, forward_key)
                return

            # Update Backward Flow
            if backward_key in self.active_flows:
                flow = self.active_flows[backward_key]
                update_flow(flow, info, "B")
                self._check_flow_prediction(flow, backward_key)
                return

            # New Flow
            flow = Flow(
                src_ip=info["src_ip"],
                dst_ip=info["dst_ip"],
                src_port=info["src_port"],
                dst_port=info["dst_port"],
                protocol=info["protocol"],
                timestamp=timestamp,
            )
            update_flow(flow, info, "F")
            self.active_flows[forward_key] = flow
            self.stats["active_flows"] = len(self.active_flows)
            self._check_flow_prediction(flow, forward_key)

    def _check_flow_prediction(self, flow, flow_key):
        total_packets = flow.fwd_packets + flow.bwd_packets
        # Predict once flow has at least 5 packets or duration > 2s
        if total_packets >= 5:
            self._classify_and_alert(flow)
            if flow_key in self.active_flows:
                del self.active_flows[flow_key]
                self.stats["active_flows"] = len(self.active_flows)

    def _classify_and_alert(self, flow):
        if self.model is None:
            self._load_model()

        label, confidence, values = predict_flow(self.model, flow)
        self.stats["completed_flows"] += 1

        if label == "BENIGN":
            self.stats["benign_count"] += 1
        else:
            self.stats["attack_count"] += 1

        alert = {
            "id": len(self.alerts) + 1,
            "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
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

        self.alerts.insert(0, alert)
        if len(self.alerts) > 100:
            self.alerts.pop()

        self._update_threat_level()

    def _update_threat_level(self):
        recent_attacks = sum(1 for a in self.alerts[:20] if a["label"] == "ATTACK")
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
            while self.is_running and not self.stop_requested:
                time.sleep(1.5)
                with self.lock:
                    now = time.time()
                    for flow_key, flow in list(self.active_flows.items()):
                        # Flush flows inactive for > 2.0 seconds or with packets
                        if (now - flow.last_time) > 2.0 or (flow.fwd_packets + flow.bwd_packets) >= 5:
                            self._classify_and_alert(flow)
                            if flow_key in self.active_flows:
                                del self.active_flows[flow_key]
                            self.stats["active_flows"] = len(self.active_flows)
        t = threading.Thread(target=_sweeper, daemon=True)
        t.start()

    def _run_live_sniffer(self, interface):
        self._start_flow_sweeper()
        try:
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
                    time.sleep(0.5)

        except Exception as e:
            self.error_message = f"Sniffer notice: {str(e)}"
            print(f"[V2 Engine Error] {self.error_message}")
        finally:
            with self.lock:
                for flow_key, flow in list(self.active_flows.items()):
                    self._classify_and_alert(flow)
                self.active_flows.clear()
                self.stats["active_flows"] = 0
                self.is_running = False
                self.mode = "idle"

    def _run_pcap_replay(self, pcap_path):
        self._start_flow_sweeper()
        try:
            while self.is_running and not self.stop_requested:
                with PcapReader(pcap_path) as reader:
                    for packet in reader:
                        if self.stop_requested:
                            break
                        self._process_packet(packet)
                        time.sleep(0.005)  # Pace packet flow arrival rate
        except Exception as e:
            self.error_message = f"PCAP replay notice: {str(e)}"
        finally:
            with self.lock:
                for flow_key, flow in list(self.active_flows.items()):
                    self._classify_and_alert(flow)
                self.active_flows.clear()
                self.stats["active_flows"] = 0
                self.is_running = False
                self.mode = "idle"

    def get_status(self):
        with self.lock:
            return {
                "is_running": self.is_running,
                "mode": self.mode,
                "active_interface": self.active_interface,
                "error_message": self.error_message,
                "stats": dict(self.stats)
            }

    def get_alerts(self, limit=50):
        with self.lock:
            return list(self.alerts[:limit])

    def inject_simulated_attack(self, count=5):
        """Inject simulated attack flows for live tracking demonstration."""
        import random
        attack_ports = [8080]

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

                self.stats["packets_processed"] += 6
                self.stats["last_packet_time"] = datetime.datetime.now().strftime("%H:%M:%S")
                self._classify_and_alert(flow)

    def clear_alerts(self):
        with self.lock:
            self.alerts.clear()
            self.stats["packets_processed"] = 0
            self.stats["completed_flows"] = 0
            self.stats["benign_count"] = 0
            self.stats["attack_count"] = 0
            self.stats["threat_level"] = "LOW"
            return True


# Global singleton instance
engine = LiveDetectorEngine()


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