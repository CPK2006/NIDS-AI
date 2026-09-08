from scapy.all import PcapReader, IP, IPv6, TCP, UDP
from dataclasses import dataclass
import csv
import math
import os
import sys
import time


# ============================================================
# CONFIGURATION
# ============================================================

FLOW_TIMEOUT = 120.0
PROGRESS_INTERVAL = 100000

DEFAULT_OUTPUT = "data/pcap/test_100k_features.csv"


# ============================================================
# THE EXACT 20 FEATURES USED BY THE FINAL CATBOOST MODEL
# ============================================================

FEATURES = [
    "Destination Port",
    "Bwd Packet Length Std",
    "Init_Win_bytes_forward",
    "Init_Win_bytes_backward",
    "Fwd Header Length",
    "Average Packet Size",
    "min_seg_size_forward",
    "Flow IAT Mean",
    "Bwd Header Length",
    "PSH Flag Count",
    "Flow IAT Min",
    "Fwd Packet Length Max",
    "Fwd IAT Min",
    "Total Length of Bwd Packets",
    "Max Packet Length",
    "Fwd IAT Total",
    "Packet Length Std",
    "Flow Bytes/s",
    "Bwd Packet Length Mean",
    "Packet Length Variance",
]


# ============================================================
# ONLINE STATISTICS
# ============================================================

class RunningStats:

    def __init__(self):

        self.count = 0
        self.mean = 0.0
        self.m2 = 0.0

        self.minimum = None
        self.maximum = None
        self.total = 0.0

    def add(self, value):

        value = float(value)

        self.count += 1
        self.total += value

        if self.minimum is None or value < self.minimum:
            self.minimum = value

        if self.maximum is None or value > self.maximum:
            self.maximum = value

        delta = value - self.mean

        self.mean += delta / self.count

        delta2 = value - self.mean

        self.m2 += delta * delta2

    def variance(self):

        if self.count == 0:
            return 0.0

        # CICFlowMeter-style population variance
        return self.m2 / self.count

    def std(self):

        return math.sqrt(self.variance())


# ============================================================
# RUNNING IAT STATISTICS
# ============================================================

class IATStats:

    def __init__(self):

        self.previous = None

        self.count = 0
        self.total = 0.0

        self.minimum = None
        self.maximum = None

        self.mean = 0.0
        self.m2 = 0.0

    def add_timestamp(self, timestamp):

        timestamp = float(timestamp)

        if self.previous is None:

            self.previous = timestamp

            return None

        iat = timestamp - self.previous

        self.previous = timestamp

        self.count += 1
        self.total += iat

        if self.minimum is None or iat < self.minimum:
            self.minimum = iat

        if self.maximum is None or iat > self.maximum:
            self.maximum = iat

        delta = iat - self.mean

        self.mean += delta / self.count

        delta2 = iat - self.mean

        self.m2 += delta * delta2

        return iat

    def get_mean(self):

        if self.count == 0:
            return 0.0

        return self.mean

    def get_min(self):

        if self.count == 0:
            return 0.0

        return self.minimum

    def get_std(self):

        if self.count == 0:
            return 0.0

        return math.sqrt(
            self.m2 / self.count
        )


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

    # Packet statistics
    packet_stats: RunningStats = None
    forward_stats: RunningStats = None
    backward_stats: RunningStats = None

    # IAT statistics
    flow_iat: IATStats = None
    forward_iat: IATStats = None

    # Header statistics
    forward_header_length: float = 0.0
    backward_header_length: float = 0.0

    # Packet counts
    forward_packets: int = 0
    backward_packets: int = 0

    # Bytes
    forward_bytes: int = 0
    backward_bytes: int = 0

    # TCP metadata
    init_win_forward: int = 0
    init_win_backward: int = 0

    min_seg_size_forward: int = 0

    psh_count: int = 0

    def __post_init__(self):

        if self.packet_stats is None:
            self.packet_stats = RunningStats()

        if self.forward_stats is None:
            self.forward_stats = RunningStats()

        if self.backward_stats is None:
            self.backward_stats = RunningStats()

        if self.flow_iat is None:
            self.flow_iat = IATStats()

        if self.forward_iat is None:
            self.forward_iat = IATStats()


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

    if IP in packet:

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        ip_header_length = int(
            packet[IP].ihl
        ) * 4

    elif IPv6 in packet:

        src_ip = packet[IPv6].src
        dst_ip = packet[IPv6].dst

        # IPv6 base header = 40 bytes
        ip_header_length = 40

    else:

        return None

    if TCP in packet:

        protocol = "TCP"

        src_port = int(
            packet[TCP].sport
        )

        dst_port = int(
            packet[TCP].dport
        )

        transport_header_length = (
            int(packet[TCP].dataofs or 5)
            * 4
        )

    elif UDP in packet:

        protocol = "UDP"

        src_port = int(
            packet[UDP].sport
        )

        dst_port = int(
            packet[UDP].dport
        )

        transport_header_length = 8

    else:

        return None

    return {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": protocol,
        "header_length":
            ip_header_length
            + transport_header_length
    }


# ============================================================
# CREATE NEW FLOW
# ============================================================

def create_flow(info, timestamp):

    return FlowState(

        src_ip=info["src_ip"],
        dst_ip=info["dst_ip"],

        src_port=info["src_port"],
        dst_port=info["dst_port"],

        protocol=info["protocol"],

        start_time=timestamp,
        last_time=timestamp
    )


# ============================================================
# UPDATE FLOW
# ============================================================

def update_flow(
    flow,
    packet,
    info,
    timestamp
):

    src_ip = info["src_ip"]
    dst_ip = info["dst_ip"]

    src_port = info["src_port"]
    dst_port = info["dst_port"]

    packet_length = len(packet)

    # --------------------------------------------------------
    # Flow IAT
    # --------------------------------------------------------

    flow.flow_iat.add_timestamp(
        timestamp
    )

    flow.last_time = timestamp

    # --------------------------------------------------------
    # Direction
    # --------------------------------------------------------

    forward = (
        src_ip == flow.src_ip
        and
        src_port == flow.src_port
        and
        dst_ip == flow.dst_ip
        and
        dst_port == flow.dst_port
    )

    # --------------------------------------------------------
    # Packet statistics
    # --------------------------------------------------------

    flow.packet_stats.add(
        packet_length
    )

    # --------------------------------------------------------
    # Forward
    # --------------------------------------------------------

    if forward:

        flow.forward_packets += 1

        flow.forward_bytes += packet_length

        flow.forward_stats.add(
            packet_length
        )

        flow.forward_header_length += (
            info["header_length"]
        )

        flow.forward_iat.add_timestamp(
            timestamp
        )

        # First forward TCP window
        if (
            TCP in packet
            and
            flow.forward_packets == 1
        ):

            flow.init_win_forward = int(
                packet[TCP].window
            )

        # Minimum forward segment size
        if TCP in packet:

                        # CICIDS-style minimum forward TCP segment/header size.
            # TCP data offset is measured in 32-bit words.
            if packet[TCP].dataofs is not None:
            
                segment_size = int(packet[TCP].dataofs) * 4

                if (
                    flow.min_seg_size_forward == 0
                    or
                    segment_size < flow.min_seg_size_forward
                ):
                    flow.min_seg_size_forward = segment_size

    # --------------------------------------------------------
    # Backward
    # --------------------------------------------------------

    else:

        flow.backward_packets += 1

        flow.backward_bytes += packet_length

        flow.backward_stats.add(
            packet_length
        )

        flow.backward_header_length += (
            info["header_length"]
        )

        # First backward TCP window
        if (
            TCP in packet
            and
            flow.backward_packets == 1
        ):

            flow.init_win_backward = int(
                packet[TCP].window
            )

    # --------------------------------------------------------
    # PSH FLAG
    # --------------------------------------------------------

    if TCP in packet:

        flags = packet[TCP].flags

        if "P" in flags:

            flow.psh_count = 1


# ============================================================
# GENERATE THE 20 FEATURES
# ============================================================

def generate_features(flow):

    duration = (
        flow.last_time
        -
        flow.start_time
    )

    total_packets = (
        flow.forward_packets
        +
        flow.backward_packets
    )

    total_bytes = (
        flow.forward_bytes
        +
        flow.backward_bytes
    )

    # --------------------------------------------------------
    # CICIDS2017 uses seconds for these derived rates
    # --------------------------------------------------------

    if duration > 0:

        flow_bytes_per_second = (
            total_bytes / duration
        )

    else:

        flow_bytes_per_second = 0.0

    # --------------------------------------------------------
    # Feature values
    # --------------------------------------------------------

    destination_port = flow.dst_port

    bwd_packet_length_std = (
        flow.backward_stats.std()
    )

    init_win_forward = (
        flow.init_win_forward
    )

    init_win_backward = (
        flow.init_win_backward
    )

    fwd_header_length = (
        flow.forward_header_length
    )

    if total_packets > 0:

        average_packet_size = (
            total_bytes / total_packets
        )

    else:

        average_packet_size = 0.0

    min_seg_size_forward = (
        flow.min_seg_size_forward
    )

    flow_iat_mean = (
        flow.flow_iat.get_mean()* 1_000_000
    )

    bwd_header_length = (
        flow.backward_header_length
    )

    psh_flag_count = (
        flow.psh_count
    )

    flow_iat_min = (
        flow.flow_iat.get_min()* 1_000_000
    )

    fwd_packet_length_max = (
        flow.forward_stats.maximum
        if flow.forward_stats.count > 0
        else 0.0
    )

    fwd_iat_min = (
        flow.forward_iat.get_min()* 1_000_000
    )

    total_length_bwd_packets = (
        flow.backward_bytes
    )

    max_packet_length = (
        flow.packet_stats.maximum
        if flow.packet_stats.count > 0
        else 0.0
    )

    fwd_iat_total = (
        flow.forward_iat.total* 1_000_000
    )

    packet_length_std = (
        flow.packet_stats.std()
    )

    bwd_packet_length_mean = (
        flow.backward_stats.mean
        if flow.backward_stats.count > 0
        else 0.0
    )

    packet_length_variance = (
        flow.packet_stats.variance()
    )

    # --------------------------------------------------------
    # EXACT MODEL ORDER
    # --------------------------------------------------------

    return [

        destination_port,

        bwd_packet_length_std,

        init_win_forward,

        init_win_backward,

        fwd_header_length,

        average_packet_size,

        min_seg_size_forward,

        flow_iat_mean,

        bwd_header_length,

        psh_flag_count,

        flow_iat_min,

        fwd_packet_length_max,

        fwd_iat_min,

        total_length_bwd_packets,

        max_packet_length,

        fwd_iat_total,

        packet_length_std,

        flow_bytes_per_second,

        bwd_packet_length_mean,

        packet_length_variance
    ]


# ============================================================
# WRITE FEATURE ROW
# ============================================================

def write_feature_row(
    writer,
    flow
):

    values = generate_features(flow)

    writer.writerow(values)


# ============================================================
# MAIN EXTRACTION
# ============================================================

def extract_features(
    pcap_path,
    output_path
):

    if not os.path.exists(pcap_path):

        raise FileNotFoundError(
            f"PCAP file not found: {pcap_path}"
        )

    output_directory = (
        os.path.dirname(output_path)
    )

    if output_directory:

        os.makedirs(
            output_directory,
            exist_ok=True
        )

    print("=" * 70)
    print("CICIDS2017 NIDS - TOP-20 FEATURE EXTRACTOR")
    print("=" * 70)

    print()
    print(f"PCAP   : {pcap_path}")
    print(f"Output : {output_path}")
    print(
        f"Timeout: {FLOW_TIMEOUT} seconds"
    )

    print()
    print(
        "Streaming packets and calculating "
        "Top-20 features..."
    )

    active_flows = {}

    total_packets = 0
    ignored_packets = 0
    completed_flows = 0
    expired_flows = 0

    start_time = time.time()

    # ========================================================
    # OUTPUT
    # ========================================================

    with open(
        output_path,
        "w",
        newline="",
        encoding="utf-8"
    ) as output_file:

        writer = csv.writer(
            output_file
        )

        writer.writerow(
            FEATURES
        )

        # ====================================================
        # STREAM PCAP
        # ====================================================

        with PcapReader(
            pcap_path
        ) as packets:

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

                info = get_packet_info(
                    packet
                )

                if info is None:

                    ignored_packets += 1

                    continue

                timestamp = float(
                    packet.time
                )

                flow_key = make_flow_key(

                    info["src_ip"],
                    info["src_port"],

                    info["dst_ip"],
                    info["dst_port"],

                    info["protocol"]
                )

                flow = active_flows.get(
                    flow_key
                )

                # ------------------------------------------------
                # NEW FLOW
                # ------------------------------------------------

                if flow is None:

                    flow = create_flow(
                        info,
                        timestamp
                    )

                    active_flows[
                        flow_key
                    ] = flow

                # ------------------------------------------------
                # TIMEOUT
                # ------------------------------------------------

                elif (
                    timestamp
                    -
                    flow.last_time
                    >
                    FLOW_TIMEOUT
                ):

                     # Finalize the old flow
                    write_feature_row(
                        writer,
                        flow
                    )

                    completed_flows += 1
                    expired_flows += 1

                    # Remove the expired flow
                    del active_flows[
                        flow_key
                    ]

                    # IMPORTANT:
                    # The current packet must start a NEW flow.
                    flow = create_flow(
                        info,
                        timestamp
                    )

                    update_flow(
                        flow,
                        packet,
                        info,
                        timestamp
                    )

                    active_flows[
                        flow_key
                    ] = flow

                    

                # ------------------------------------------------
                # UPDATE
                # ------------------------------------------------

                update_flow(
                    flow,
                    packet,
                    info,
                    timestamp
                )

                # ------------------------------------------------
                # PROGRESS
                # ------------------------------------------------

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
        # FINAL ACTIVE FLOWS
        # ====================================================

        for flow in active_flows.values():

            write_feature_row(
                writer,
                flow
            )

            completed_flows += 1

    elapsed = (
        time.time()
        -
        start_time
    )

    # ========================================================
    # SUMMARY
    # ========================================================

    print()
    print("=" * 70)
    print("FEATURE EXTRACTION SUMMARY")
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
    print(f"Duplicate packets : {duplicate_packets:,}")

    print(
        f"Completed flows   : "
        f"{completed_flows:,}"
    )

    print(
        f"Expired flows     : "
        f"{expired_flows:,}"
    )

    print()
    print(
        f"Processing time   : "
        f"{elapsed:.2f} seconds"
    )

    if elapsed > 0:

        print(
            f"Processing rate   : "
            f"{total_packets / elapsed:,.0f} "
            f"packets/sec"
        )

    print()
    print(
        f"Output file       : "
        f"{output_path}"
    )

    if os.path.exists(
        output_path
    ):

        size_mb = (
            os.path.getsize(
                output_path
            )
            /
            (1024 ** 2)
        )

        print(
            f"Output size       : "
            f"{size_mb:.2f} MB"
        )

    print()
    print("=" * 70)
    print("TOP-20 FEATURE EXTRACTION COMPLETED")
    print("=" * 70)


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":

    if len(sys.argv) < 2:

        print()
        print("Usage:")
        print(
            "python pcap\\feature_extractor.py "
            "<pcap_path> [output_csv]"
        )
        print()

        sys.exit(1)

    pcap_path = sys.argv[1]

    if len(sys.argv) >= 3:

        output_path = sys.argv[2]

    else:

        output_path = DEFAULT_OUTPUT

    extract_features(
        pcap_path,
        output_path
    )