from scapy.all import rdpcap, IP, IPv6, TCP, UDP, ICMP
import os
import sys
from collections import Counter


def analyze_pcap(pcap_path):

    print("=" * 70)
    print("CICIDS2017 NIDS - PCAP ANALYZER")
    print("=" * 70)

    if not os.path.exists(pcap_path):
        raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

    print()
    print("Loading PCAP...")
    print(f"File: {pcap_path}")

    packets = rdpcap(pcap_path)

    print(f"Total packets: {len(packets)}")

    protocol_counts = Counter()

    source_ips = set()
    destination_ips = set()

    tcp_flows = set()
    udp_flows = set()

    tcp_packets = 0
    udp_packets = 0
    icmp_packets = 0
    ip_packets = 0

    packet_sizes = []

    for packet in packets:

        packet_sizes.append(len(packet))

        # --------------------------------------------------
        # IPv4
        # --------------------------------------------------

        if IP in packet:

            ip_packets += 1

            src_ip = packet[IP].src
            dst_ip = packet[IP].dst

            source_ips.add(src_ip)
            destination_ips.add(dst_ip)

            # TCP
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

            # UDP
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

            # ICMP
            elif ICMP in packet:

                icmp_packets += 1
                protocol_counts["ICMP"] += 1

        # --------------------------------------------------
        # IPv6
        # --------------------------------------------------

        elif IPv6 in packet:

            protocol_counts["IPv6"] += 1

    print()
    print("=" * 70)
    print("PCAP SUMMARY")
    print("=" * 70)

    print(f"Total packets          : {len(packets)}")
    print(f"IP packets             : {ip_packets}")
    print(f"TCP packets            : {tcp_packets}")
    print(f"UDP packets            : {udp_packets}")
    print(f"ICMP packets           : {icmp_packets}")

    print()
    print("Protocol distribution:")

    for protocol, count in protocol_counts.most_common():
        print(f"  {protocol:<10}: {count}")

    print()
    print(f"Unique source IPs      : {len(source_ips)}")
    print(f"Unique destination IPs : {len(destination_ips)}")

    print()
    print(f"TCP flows              : {len(tcp_flows)}")
    print(f"UDP flows              : {len(udp_flows)}")

    if packet_sizes:

        print()
        print("Packet size statistics:")
        print(f"  Minimum              : {min(packet_sizes)} bytes")
        print(f"  Maximum              : {max(packet_sizes)} bytes")
        print(
            f"  Average              : "
            f"{sum(packet_sizes) / len(packet_sizes):.2f} bytes"
        )

    print()
    print("=" * 70)
    print("PCAP ANALYSIS COMPLETED")
    print("=" * 70)


if __name__ == "__main__":

    if len(sys.argv) != 2:

        print("Usage:")
        print(
            "python pcap\\pcap_reader.py "
            "<path_to_pcap>"
        )

        sys.exit(1)

    pcap_path = sys.argv[1]

    analyze_pcap(pcap_path)