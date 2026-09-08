from scapy.all import PcapReader, IP, TCP


PCAP = r"data\pcap\test_100k.pcap"

TARGET_SRC = "192.168.10.17"
TARGET_DST = "192.168.10.3"
TARGET_SPORT = 45344
TARGET_DPORT = 3268


print("=" * 90)
print("TCP SEGMENT SIZE DIAGNOSTIC")
print("=" * 90)

found = 0

with PcapReader(PCAP) as packets:

    for packet in packets:

        if IP not in packet or TCP not in packet:
            continue

        src = packet[IP].src
        dst = packet[IP].dst
        sport = int(packet[TCP].sport)
        dport = int(packet[TCP].dport)

        forward = (
            src == TARGET_SRC
            and dst == TARGET_DST
            and sport == TARGET_SPORT
            and dport == TARGET_DPORT
        )

        backward = (
            src == TARGET_DST
            and dst == TARGET_SRC
            and sport == TARGET_DPORT
            and dport == TARGET_SPORT
        )

        if not (forward or backward):
            continue

        found += 1

        ip_header = int(packet[IP].ihl or 5) * 4
        tcp_header = int(packet[TCP].dataofs or 5) * 4

        packet_length = len(packet)

        tcp_layer_length = len(bytes(packet[TCP]))

        tcp_payload_length = max(
            0,
            tcp_layer_length - tcp_header
        )

        ip_payload_length = max(
            0,
            packet_length - ip_header
        )

        segment_size = (
            packet_length
            - ip_header
        )

        print(
            f"{found:2d} "
            f"{'F' if forward else 'B'}  "
            f"Packet={packet_length:5d}  "
            f"IPHdr={ip_header:2d}  "
            f"TCPHdr={tcp_header:2d}  "
            f"TCPLayer={tcp_layer_length:5d}  "
            f"Payload={tcp_payload_length:5d}  "
            f"IPPayload={ip_payload_length:5d}  "
            f"Seq={packet[TCP].seq:10d}  "
            f"Ack={packet[TCP].ack:10d}"
        )

        if found >= 31:
            break


print()
print("=" * 90)
print(f"Packets inspected: {found}")
print("=" * 90)