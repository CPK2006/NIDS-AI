from scapy.all import PcapReader, IP, IPv6, TCP, UDP
from dataclasses import dataclass, field
import csv
import os
import sys
import time


# ============================================================
# CONFIGURATION
# ============================================================

FLOW_TIMEOUT = 120.0
PROGRESS_INTERVAL = 100000

DEFAULT_OUTPUT = "results/pcap/flows.csv"


# ============================================================
# FLOW STATE
# ============================================================

@dataclass
class FlowState:

    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str

    start_time: float
    last_time: float

    forward_packets: int = 0
    backward_packets: int = 0

    forward_bytes: int = 0
    backward_bytes: int = 0

    # Packet statistics
    forward_lengths: list = field(default_factory=list)
    backward_lengths: list = field(default_factory=list)

    forward_times: list = field(default_factory=list)
    backward_times: list = field(default_factory=list)

    # TCP flags
    fin_count: int = 0
    syn_count: int = 0
    rst_count: int = 0
    psh_count: int = 0
    ack_count: int = 0
    urg_count: int = 0
    ece_count: int = 0
    cwr_count: int = 0

    # Header statistics
    forward_header_lengths: list = field(default_factory=list)
    backward_header_lengths: list = field(default_factory=list)

    # Initial TCP window sizes
    init_win_forward: int = 0
    init_win_backward: int = 0

    # Minimum segment size
    min_seg_size_forward: int = 0


# ============================================================
# FLOW KEY
# ============================================================

def make_flow_key(
    src_ip,
    src_port,
    dst_ip,
    dst_port,
    protocol
):

    endpoint_a = (
        src_ip,
        src_port
    )

    endpoint_b = (
        dst_ip,
        dst_port
    )

    if endpoint_a <= endpoint_b:

        return (
            endpoint_a,
            endpoint_b,
            protocol
        )

    return (
        endpoint_b,
        endpoint_a,
        protocol
    )


# ============================================================
# PACKET INFORMATION
# ============================================================

def get_packet_info(packet):

    src_ip = None
    dst_ip = None
    src_port = None
    dst_port = None
    protocol = None

    ip_layer = None

    if IP in packet:

        ip_layer = packet[IP]

        src_ip = ip_layer.src
        dst_ip = ip_layer.dst

    elif IPv6 in packet:

        ip_layer = packet[IPv6]

        src_ip = ip_layer.src
        dst_ip = ip_layer.dst

    else:

        return None

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
        "ip_layer": ip_layer
    }


# ============================================================
# TCP FLAGS
# ============================================================

def update_tcp_flags(flow, packet):

    if TCP not in packet:

        return

    flags = packet[TCP].flags

    if "F" in flags:
        flow.fin_count += 1

    if "S" in flags:
        flow.syn_count += 1

    if "R" in flags:
        flow.rst_count += 1

    if "P" in flags:
        flow.psh_count += 1

    if "A" in flags:
        flow.ack_count += 1

    if "U" in flags:
        flow.urg_count += 1

    if "E" in flags:
        flow.ece_count += 1

    if "C" in flags:
        flow.cwr_count += 1


# ============================================================
# WRITE FLOW
# ============================================================

def flow_to_row(flow):

    return [
        flow.src_ip,
        flow.dst_ip,
        flow.src_port,
        flow.dst_port,
        flow.protocol,

        flow.start_time,
        flow.last_time,
        flow.last_time - flow.start_time,

        flow.forward_packets,
        flow.backward_packets,

        flow.forward_bytes,
        flow.backward_bytes,

        flow.fin_count,
        flow.syn_count,
        flow.rst_count,
        flow.psh_count,
        flow.ack_count,
        flow.urg_count,
        flow.ece_count,
        flow.cwr_count,

        flow.init_win_forward,
        flow.init_win_backward,

        flow.min_seg_size_forward
    ]


CSV_HEADER = [
    "Src IP",
    "Dst IP",
    "Src Port",
    "Dst Port",
    "Protocol",

    "Start Time",
    "End Time",
    "Flow Duration",

    "Total Fwd Packets",
    "Total Backward Packets",

    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",

    "FIN Flag Count",
    "SYN Flag Count",
    "RST Flag Count",
    "PSH Flag Count",
    "ACK Flag Count",
    "URG Flag Count",
    "ECE Flag Count",
    "CWE Flag Count",

    "Init_Win_bytes_forward",
    "Init_Win_bytes_backward",

    "min_seg_size_forward"
]


# ============================================================
# BUILD FLOWS
# ============================================================

def build_flows(pcap_path, output_path=DEFAULT_OUTPUT):

    if not os.path.exists(pcap_path):

        raise FileNotFoundError(
            f"PCAP file not found: {pcap_path}"
        )

    output_directory = os.path.dirname(output_path)

    if output_directory:

        os.makedirs(
            output_directory,
            exist_ok=True
        )

    print("=" * 70)
    print("CICIDS2017 NIDS - MEMORY-SAFE FLOW BUILDER")
    print("=" * 70)

    print()
    print(f"PCAP: {pcap_path}")
    print(f"Output: {output_path}")
    print(f"Flow timeout: {FLOW_TIMEOUT} seconds")

    print()
    print("Starting streaming flow reconstruction...")
    print("Completed flows will be written directly to disk.")
    print()

    active_flows = {}

    total_packets = 0
    ignored_packets = 0

    completed_flows = 0
    expired_flows = 0

    tcp_flows = 0
    udp_flows = 0

    forward_packets_total = 0
    backward_packets_total = 0

    forward_bytes_total = 0
    backward_bytes_total = 0

    start_time = time.time()

    # ========================================================
    # OPEN OUTPUT
    # ========================================================

    with open(
        output_path,
        "w",
        newline="",
        encoding="utf-8"
    ) as output_file:

        writer = csv.writer(output_file)

        writer.writerow(CSV_HEADER)

        # ====================================================
        # STREAM PCAP
        # ====================================================

        with PcapReader(pcap_path) as packets:

            previous_packet_bytes = None
            duplicate_packets = 0

            for packet in packets:
            
                total_packets += 1

                # ----------------------------------------------------
                # Remove immediately repeated identical packets.
                # This handles duplicate copies present in the PCAP
                # while preserving identical packets separated by
                # other packets.
                # ----------------------------------------------------
                current_packet_bytes = bytes(packet)

                if (
                    previous_packet_bytes is not None
                    and current_packet_bytes == previous_packet_bytes
                ):
                    duplicate_packets += 1
                    continue
                
                previous_packet_bytes = current_packet_bytes

                info = get_packet_info(packet)
                if info is None:

                    ignored_packets += 1

                    continue

                src_ip = info["src_ip"]
                dst_ip = info["dst_ip"]

                src_port = info["src_port"]
                dst_port = info["dst_port"]

                protocol = info["protocol"]

                timestamp = float(packet.time)

                packet_length = len(packet)

                flow_key = make_flow_key(
                    src_ip,
                    src_port,
                    dst_ip,
                    dst_port,
                    protocol
                )

                # --------------------------------------------
                # FIND / CREATE FLOW
                # --------------------------------------------

                flow = active_flows.get(flow_key)

                if flow is None:

                    flow = FlowState(

                        src_ip=src_ip,
                        dst_ip=dst_ip,

                        src_port=src_port,
                        dst_port=dst_port,

                        protocol=protocol,

                        start_time=timestamp,
                        last_time=timestamp
                    )

                    active_flows[flow_key] = flow

                # --------------------------------------------
                # FLOW TIMEOUT
                # --------------------------------------------

                elif (
                    timestamp - flow.last_time
                    > FLOW_TIMEOUT
                ):

                    writer.writerow(
                        flow_to_row(flow)
                    )

                    completed_flows += 1
                    expired_flows += 1

                    if flow.protocol == "TCP":

                        tcp_flows += 1

                    else:

                        udp_flows += 1

                    forward_packets_total += (
                        flow.forward_packets
                    )

                    backward_packets_total += (
                        flow.backward_packets
                    )

                    forward_bytes_total += (
                        flow.forward_bytes
                    )

                    backward_bytes_total += (
                        flow.backward_bytes
                    )

                    # Remove old flow
                    del active_flows[flow_key]

                    # Create new flow
                    flow = FlowState(

                        src_ip=src_ip,
                        dst_ip=dst_ip,

                        src_port=src_port,
                        dst_port=dst_port,

                        protocol=protocol,

                        start_time=timestamp,
                        last_time=timestamp
                    )

                    active_flows[flow_key] = flow

                # --------------------------------------------
                # UPDATE TIMESTAMP
                # --------------------------------------------

                flow.last_time = timestamp

                # --------------------------------------------
                # DIRECTION
                # --------------------------------------------

                forward = (
                    src_ip == flow.src_ip
                    and
                    src_port == flow.src_port
                    and
                    dst_ip == flow.dst_ip
                    and
                    dst_port == flow.dst_port
                )

                # --------------------------------------------
                # FORWARD
                # --------------------------------------------

                if forward:

                    flow.forward_packets += 1

                    flow.forward_bytes += packet_length

                    flow.forward_lengths.append(
                        packet_length
                    )

                    flow.forward_times.append(
                        timestamp
                    )

                    # Header length
                    if IP in packet:

                        flow.forward_header_lengths.append(
                            int(packet[IP].ihl) * 4
                        )

                    # Initial TCP window
                    if (
                        TCP in packet
                        and
                        flow.forward_packets == 1
                    ):

                        flow.init_win_forward = int(
                            packet[TCP].window
                        )

                    # Minimum segment size
                    if TCP in packet:

                        segment_size = len(
                            packet[TCP]
                        )

                        if (
                            flow.min_seg_size_forward == 0
                            or
                            segment_size
                            <
                            flow.min_seg_size_forward
                        ):

                            flow.min_seg_size_forward = (
                                segment_size
                            )

                # --------------------------------------------
                # BACKWARD
                # --------------------------------------------

                else:

                    flow.backward_packets += 1

                    flow.backward_bytes += packet_length

                    flow.backward_lengths.append(
                        packet_length
                    )

                    flow.backward_times.append(
                        timestamp
                    )

                    if IP in packet:

                        flow.backward_header_lengths.append(
                            int(packet[IP].ihl) * 4
                        )

                    if (
                        TCP in packet
                        and
                        flow.backward_packets == 1
                    ):

                        flow.init_win_backward = int(
                            packet[TCP].window
                        )

                # --------------------------------------------
                # TCP FLAGS
                # --------------------------------------------

                update_tcp_flags(
                    flow,
                    packet
                )

                # --------------------------------------------
                # PROGRESS
                # --------------------------------------------

                if (
                    total_packets
                    %
                    PROGRESS_INTERVAL
                    == 0
                ):

                    elapsed = (
                        time.time()
                        -
                        start_time
                    )

                    rate = (
                        total_packets / elapsed
                        if elapsed > 0
                        else 0
                    )

                    print(
                        f"Processed: "
                        f"{total_packets:,} | "
                        f"Active flows: "
                        f"{len(active_flows):,} | "
                        f"Completed: "
                        f"{completed_flows:,} | "
                        f"Rate: "
                        f"{rate:,.0f} packets/sec",
                        flush=True
                    )

        # ====================================================
        # WRITE REMAINING ACTIVE FLOWS
        # ====================================================

        for flow in active_flows.values():

            writer.writerow(
                flow_to_row(flow)
            )

            completed_flows += 1

            if flow.protocol == "TCP":

                tcp_flows += 1

            else:

                udp_flows += 1

            forward_packets_total += (
                flow.forward_packets
            )

            backward_packets_total += (
                flow.backward_packets
            )

            forward_bytes_total += (
                flow.forward_bytes
            )

            backward_bytes_total += (
                flow.backward_bytes
            )

    elapsed = time.time() - start_time

    # ========================================================
    # SUMMARY
    # ========================================================

    print()
    print("=" * 70)
    print("MEMORY-SAFE FLOW RECONSTRUCTION SUMMARY")
    print("=" * 70)

    print()
    print(
        f"Packets processed       : "
        f"{total_packets:,}"
    )

    print(
        f"Ignored packets         : "
        f"{ignored_packets:,}"
    )
    print(f"Duplicate packets skipped : {duplicate_packets:,}")

    print(
        f"Completed flows         : "
        f"{completed_flows:,}"
    )

    print(
        f"Expired flows           : "
        f"{expired_flows:,}"
    )

    print()
    print(
        f"TCP flows               : "
        f"{tcp_flows:,}"
    )

    print(
        f"UDP flows               : "
        f"{udp_flows:,}"
    )

    print()
    print(
        f"Forward packets         : "
        f"{forward_packets_total:,}"
    )

    print(
        f"Backward packets        : "
        f"{backward_packets_total:,}"
    )

    print(
        f"Forward bytes           : "
        f"{forward_bytes_total:,}"
    )

    print(
        f"Backward bytes          : "
        f"{backward_bytes_total:,}"
    )

    print()
    print(
        f"Processing time         : "
        f"{elapsed:.2f} seconds"
    )

    if elapsed > 0:

        print(
            f"Processing rate         : "
            f"{total_packets / elapsed:,.0f} "
            f"packets/sec"
        )

    print()
    print(
        f"Output file             : "
        f"{output_path}"
    )

    if os.path.exists(output_path):

        output_size_mb = (
            os.path.getsize(output_path)
            / (1024 ** 2)
        )

        print(
            f"Output size             : "
            f"{output_size_mb:.2f} MB"
        )

    print()
    print("=" * 70)
    print("MEMORY-SAFE FLOW BUILDING COMPLETED")
    print("=" * 70)

    return output_path


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":

    if len(sys.argv) < 2:

        print()
        print("Usage:")
        print(
            "python pcap\\flow_builder.py "
            "<pcap_path> [output_csv]"
        )
        print()

        sys.exit(1)

    pcap_path = sys.argv[1]

    if len(sys.argv) >= 3:

        output_path = sys.argv[2]

    else:

        output_path = DEFAULT_OUTPUT

    build_flows(
        pcap_path,
        output_path
    )