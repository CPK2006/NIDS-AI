from scapy.all import PcapReader, IP, IPv6, TCP, UDP, ICMP
from collections import Counter
import os
import sys
import time


# ============================================================
# CICIDS2017 NIDS - STREAMING PCAP ANALYZER
# ============================================================

def analyze_pcap(pcap_path):

    print("=" * 70)
    print("CICIDS2017 NIDS - STREAMING PCAP ANALYZER")
    print("=" * 70)

    if not os.path.exists(pcap_path):
        raise FileNotFoundError(
            f"PCAP file not found: {pcap_path}"
        )

    file_size_gb = (
        os.path.getsize(pcap_path)
        / (1024 ** 3)
    )

    print()
    print(f"File: {pcap_path}")
    print(f"File size: {file_size_gb:.2f} GB")

    print()
    print("Opening PCAP using streaming reader...")
    print("Packets will be processed one at a time.")
    print()

    protocol_counts = Counter()

    source_ips = set()
    destination_ips = set()

    tcp_flows = set()
    udp_flows = set()

    tcp_packets = 0
    udp_packets = 0
    icmp_packets = 0
    ip_packets = 0
    ipv6_packets = 0

    total_packets = 0

    packet_size_total = 0
    minimum_packet_size = None
    maximum_packet_size = None

    start_time = time.time()

    # --------------------------------------------------------
    # STREAM PCAP
    # --------------------------------------------------------

    try:

        with PcapReader(pcap_path) as packets:

            for packet in packets:

                total_packets += 1

                packet_length = len(packet)

                packet_size_total += packet_length

                if (
                    minimum_packet_size is None
                    or packet_length < minimum_packet_size
                ):
                    minimum_packet_size = packet_length

                if (
                    maximum_packet_size is None
                    or packet_length > maximum_packet_size
                ):
                    maximum_packet_size = packet_length

                # ------------------------------------------------
                # IPv4
                # ------------------------------------------------

                if IP in packet:

                    ip_packets += 1

                    src_ip = packet[IP].src
                    dst_ip = packet[IP].dst

                    source_ips.add(src_ip)
                    destination_ips.add(dst_ip)

                    # --------------------------------------------
                    # TCP
                    # --------------------------------------------

                    if TCP in packet:

                        tcp_packets += 1
                        protocol_counts["TCP"] += 1

                        src_port = packet[TCP].sport
                        dst_port = packet[TCP].dport

                        flow = (
                            src_ip,
                            src_port,
                            dst_ip,
                            dst_port,
                            "TCP"
                        )

                        tcp_flows.add(flow)

                    # --------------------------------------------
                    # UDP
                    # --------------------------------------------

                    elif UDP in packet:

                        udp_packets += 1
                        protocol_counts["UDP"] += 1

                        src_port = packet[UDP].sport
                        dst_port = packet[UDP].dport

                        flow = (
                            src_ip,
                            src_port,
                            dst_ip,
                            dst_port,
                            "UDP"
                        )

                        udp_flows.add(flow)

                    # --------------------------------------------
                    # ICMP
                    # --------------------------------------------

                    elif ICMP in packet:

                        icmp_packets += 1
                        protocol_counts["ICMP"] += 1

                # ------------------------------------------------
                # IPv6
                # ------------------------------------------------

                elif IPv6 in packet:

                    ipv6_packets += 1
                    protocol_counts["IPv6"] += 1

                # ------------------------------------------------
                # PROGRESS
                # ------------------------------------------------

                if total_packets % 100000 == 0:

                    elapsed = time.time() - start_time

                    rate = (
                        total_packets / elapsed
                        if elapsed > 0
                        else 0
                    )

                    print(
                        f"Processed: {total_packets:,} packets | "
                        f"Rate: {rate:,.0f} packets/sec",
                        flush=True
                    )

    except KeyboardInterrupt:

        print()
        print("PCAP processing interrupted by user.")
        print(
            f"Packets processed before stopping: "
            f"{total_packets:,}"
        )

        return

    elapsed = time.time() - start_time

    # ========================================================
    # FINAL RESULTS
    # ========================================================

    print()
    print("=" * 70)
    print("PCAP SUMMARY")
    print("=" * 70)

    print()
    print(f"Total packets          : {total_packets:,}")
    print(f"IPv4 packets           : {ip_packets:,}")
    print(f"IPv6 packets           : {ipv6_packets:,}")
    print(f"TCP packets            : {tcp_packets:,}")
    print(f"UDP packets            : {udp_packets:,}")
    print(f"ICMP packets           : {icmp_packets:,}")

    print()
    print("Protocol distribution:")

    for protocol, count in protocol_counts.most_common():

        percentage = (
            count / total_packets * 100
            if total_packets > 0
            else 0
        )

        print(
            f"  {protocol:<10}: "
            f"{count:,} "
            f"({percentage:.2f}%)"
        )

    print()
    print(f"Unique source IPs      : {len(source_ips):,}")
    print(
        f"Unique destination IPs : "
        f"{len(destination_ips):,}"
    )

    print()
    print(f"TCP flows              : {len(tcp_flows):,}")
    print(f"UDP flows              : {len(udp_flows):,}")

    if total_packets > 0:

        average_packet_size = (
            packet_size_total / total_packets
        )

        print()
        print("Packet size statistics:")

        print(
            f"  Minimum              : "
            f"{minimum_packet_size} bytes"
        )

        print(
            f"  Maximum              : "
            f"{maximum_packet_size} bytes"
        )

        print(
            f"  Average              : "
            f"{average_packet_size:.2f} bytes"
        )

        print(
            f"  Total bytes          : "
            f"{packet_size_total:,}"
        )

    print()
    print(
        f"Processing time        : "
        f"{elapsed:.2f} seconds"
    )

    if elapsed > 0:

        print(
            f"Processing rate        : "
            f"{total_packets / elapsed:,.0f} packets/sec"
        )

    print()
    print("=" * 70)
    print("STREAMING PCAP ANALYSIS COMPLETED")
    print("=" * 70)


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":

    if len(sys.argv) != 2:

        print()
        print("Usage:")
        print(
            "python pcap\\pcap_reader.py "
            "<path_to_pcap>"
        )
        print()

        sys.exit(1)

    pcap_path = sys.argv[1]

    analyze_pcap(pcap_path)