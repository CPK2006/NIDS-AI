from scapy.all import PcapReader, IP, IPv6, TCP, UDP
from collections import defaultdict
import csv
import os
import sys


# ============================================================
# CONFIGURATION
# ============================================================

FLOW_TIMEOUT = 120.0

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
# FLOW
# ============================================================

class Flow:

    def __init__(self, src_ip, dst_ip, src_port, dst_port,
                 protocol, timestamp):

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

        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport

    elif UDP in packet:

        protocol = "UDP"

        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport

    else:
        return None

    return {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": int(src_port),
        "dst_port": int(dst_port),
        "protocol": protocol,
        "length": len(packet),
        "timestamp": float(packet.time),
    }


# ============================================================
# FLOW KEY
# ============================================================

def make_flow_key(info):

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

    duration = flow.last_time - flow.start_time

    total_packets = (
        flow.fwd_packets +
        flow.bwd_packets
    )

    total_bytes = (
        flow.fwd_bytes +
        flow.bwd_bytes
    )

    # Avoid division by zero
    if total_packets > 0:
        packet_length_mean = (
            sum(flow.packet_lengths) /
            total_packets
        )
    else:
        packet_length_mean = 0.0

    if flow.bwd_packets > 0:
        bwd_packet_length_mean = (
            sum(flow.bwd_lengths) /
            flow.bwd_packets
        )
    else:
        bwd_packet_length_mean = 0.0

    if flow.fwd_packets > 0:
        fwd_packet_length_max = max(
            flow.fwd_lengths
        )
    else:
        fwd_packet_length_max = 0.0

    if duration > 0:
        flow_bytes_per_second = (
            total_bytes / duration
        )
    else:
        flow_bytes_per_second = 0.0

    return [
        flow.dst_port,
        duration,
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
# WRITE FLOW
# ============================================================

def write_flow(writer, flow):

    row = generate_features(flow)

    writer.writerow(row)


# ============================================================
# MAIN
# ============================================================

def main():

    if len(sys.argv) < 3:

        print(
            "Usage:\n"
            "python v2/simple_feature_extractor.py "
            "<input.pcap> <output.csv>"
        )

        return

    pcap_path = sys.argv[1]
    output_path = sys.argv[2]

    os.makedirs(
        os.path.dirname(output_path) or ".",
        exist_ok=True
    )

    print("=" * 70)
    print("NIDS-AI V2 - SIMPLE FEATURE EXTRACTOR")
    print("=" * 70)

    print()
    print("PCAP   :", pcap_path)
    print("Output :", output_path)
    print("Features:", len(FEATURES))

    print()
    print("Features being extracted:")

    for i, feature in enumerate(FEATURES, 1):

        print(f"{i:2}. {feature}")

    print()
    print("Starting packet processing...")
    print()

    active_flows = {}

    total_packets = 0
    ignored_packets = 0
    completed_flows = 0
    expired_flows = 0

    with open(
        output_path,
        "w",
        newline=""
    ) as csv_file:

        writer = csv.writer(csv_file)

        writer.writerow(FEATURES)

        with PcapReader(pcap_path) as packets:

            for packet in packets:

                total_packets += 1

                info = get_packet_info(packet)

                if info is None:

                    ignored_packets += 1
                    continue

                timestamp = info["timestamp"]

                forward_key, backward_key = \
                    make_flow_key(info)

                # --------------------------------------------
                # EXISTING FORWARD FLOW
                # --------------------------------------------

                if forward_key in active_flows:

                    flow = active_flows[forward_key]

                    if (
                        timestamp -
                        flow.last_time
                    ) > FLOW_TIMEOUT:

                        write_flow(writer, flow)

                        completed_flows += 1
                        expired_flows += 1

                        del active_flows[
                            forward_key
                        ]

                    else:

                        update_flow(
                            flow,
                            info,
                            "F"
                        )

                        continue

                # --------------------------------------------
                # EXISTING BACKWARD FLOW
                # --------------------------------------------

                if backward_key in active_flows:

                    flow = active_flows[backward_key]

                    if (
                        timestamp -
                        flow.last_time
                    ) > FLOW_TIMEOUT:

                        write_flow(writer, flow)

                        completed_flows += 1
                        expired_flows += 1

                        del active_flows[
                            backward_key
                        ]

                    else:

                        update_flow(
                            flow,
                            info,
                            "B"
                        )

                        continue

                # --------------------------------------------
                # NEW FLOW
                # --------------------------------------------

                flow = Flow(
                    src_ip=info["src_ip"],
                    dst_ip=info["dst_ip"],
                    src_port=info["src_port"],
                    dst_port=info["dst_port"],
                    protocol=info["protocol"],
                    timestamp=timestamp,
                )

                update_flow(
                    flow,
                    info,
                    "F"
                )

                active_flows[
                    forward_key
                ] = flow

                # --------------------------------------------
                # PROGRESS
                # --------------------------------------------

                if total_packets % 100000 == 0:

                    print(
                        f"Processed packets: "
                        f"{total_packets:,} | "
                        f"Active flows: "
                        f"{len(active_flows):,}"
                    )

    # ========================================================
    # WRITE REMAINING FLOWS
    # ========================================================

        for flow in active_flows.values():

            write_flow(writer, flow)

            completed_flows += 1

    # ========================================================
    # SUMMARY
    # ========================================================

    print()
    print("=" * 70)
    print("V2 FEATURE EXTRACTION SUMMARY")
    print("=" * 70)

    print()
    print(
        f"Packets processed : "
        f"{total_packets:,}"
    )

    print(
        f"Ignored packets   : "
        f"{ignored_packets:,}"
    )

    print(
        f"Flows generated   : "
        f"{completed_flows:,}"
    )

    print(
        f"Expired flows     : "
        f"{expired_flows:,}"
    )

    print()
    print("Output file       :", output_path)

    print()
    print("=" * 70)
    print("V2 FEATURE EXTRACTION COMPLETED")
    print("=" * 70)


if __name__ == "__main__":
    main()