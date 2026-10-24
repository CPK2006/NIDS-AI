from scapy.all import PcapReader, IP, TCP, UDP


PCAP = r"data\pcap\test_100k.pcap"

TARGET_SRC = "192.168.10.17"
TARGET_DST = "192.168.10.3"

TARGET_SPORT = 45344
TARGET_DPORT = 3268


print("=" * 80)
print("CICIDS2017 NIDS - HEADER LENGTH DIAGNOSTIC")
print("=" * 80)

print()
print("Target flow:")
print(
    f"{TARGET_SRC}:{TARGET_SPORT} -> "
    f"{TARGET_DST}:{TARGET_DPORT}"
)

print()


# ============================================================
# FIND FIRST FLOW
# ============================================================

flow_packets = []

flow_started = False

start_time = None
last_time = None

with PcapReader(PCAP) as packets:

    for packet in packets:

        if IP not in packet:
            continue

        if TCP not in packet and UDP not in packet:
            continue

        src = packet[IP].src
        dst = packet[IP].dst

        if TCP in packet:

            sport = int(packet[TCP].sport)
            dport = int(packet[TCP].dport)

        else:

            sport = int(packet[UDP].sport)
            dport = int(packet[UDP].dport)

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

            if flow_started:

                current_time = float(packet.time)

                if (
                    last_time is not None
                    and current_time - last_time > 120
                ):
                    break

            continue

        timestamp = float(packet.time)

        if not flow_started:

            flow_started = True
            start_time = timestamp

        flow_packets.append(
            (
                packet,
                timestamp,
                "F" if forward else "B"
            )
        )

        last_time = timestamp


# ============================================================
# PACKET DETAILS
# ============================================================

print(f"Packets found: {len(flow_packets)}")

print()
print("=" * 80)
print("PACKET HEADER DETAILS")
print("=" * 80)

print(
    f"{'No.':>4} "
    f"{'Dir':>3} "
    f"{'IP Hdr':>7} "
    f"{'TCP Hdr':>8} "
    f"{'UDP Hdr':>8} "
    f"{'Total Hdr':>10} "
    f"{'Packet':>8} "
    f"{'Payload':>8}"
)

print("-" * 80)


fwd_header_total = 0
bwd_header_total = 0

fwd_ip_header_total = 0
bwd_ip_header_total = 0

fwd_transport_header_total = 0
bwd_transport_header_total = 0


for i, (packet, timestamp, direction) in enumerate(
    flow_packets,
    start=1
):

    # --------------------------------------------------------
    # IP HEADER
    # --------------------------------------------------------

    ip_header_length = 0

    if IP in packet:

        # IHL is measured in 32-bit words.
        #
        # Example:
        # IHL = 5 -> 20 bytes
        # IHL = 6 -> 24 bytes

        if packet[IP].ihl is not None:
            ip_header_length = int(packet[IP].ihl) * 4
        else:
            ip_header_length = 20


    # --------------------------------------------------------
    # TRANSPORT HEADER
    # --------------------------------------------------------

    tcp_header_length = 0
    udp_header_length = 0

    if TCP in packet:

        if packet[TCP].dataofs is not None:

            # TCP data offset is measured in 32-bit words.

            tcp_header_length = int(packet[TCP].dataofs) * 4

        else:

            tcp_header_length = 20


    elif UDP in packet:

        udp_header_length = 8


    transport_header_length = (
        tcp_header_length
        +
        udp_header_length
    )


    # --------------------------------------------------------
    # TOTAL HEADER
    # --------------------------------------------------------

    total_header_length = (
        ip_header_length
        +
        transport_header_length
    )


    # --------------------------------------------------------
    # PACKET LENGTH
    # --------------------------------------------------------

    packet_length = len(packet)

    payload_length = max(
        0,
        packet_length - total_header_length
    )


    # --------------------------------------------------------
    # ACCUMULATE
    # --------------------------------------------------------

    if direction == "F":

        fwd_header_total += total_header_length

        fwd_ip_header_total += ip_header_length

        fwd_transport_header_total += (
            transport_header_length
        )

    else:

        bwd_header_total += total_header_length

        bwd_ip_header_total += ip_header_length

        bwd_transport_header_total += (
            transport_header_length
        )


    print(
        f"{i:4d} "
        f"{direction:>3} "
        f"{ip_header_length:7d} "
        f"{tcp_header_length:8d} "
        f"{udp_header_length:8d} "
        f"{total_header_length:10d} "
        f"{packet_length:8d} "
        f"{payload_length:8d}"
    )


# ============================================================
# SUMMARY
# ============================================================

print()
print("=" * 80)
print("HEADER LENGTH SUMMARY")
print("=" * 80)

print()

print("FORWARD")
print("-" * 40)

print(
    f"IP header total        : "
    f"{fwd_ip_header_total}"
)

print(
    f"Transport header total : "
    f"{fwd_transport_header_total}"
)

print(
    f"Total header length   : "
    f"{fwd_header_total}"
)

print()

print("BACKWARD")
print("-" * 40)

print(
    f"IP header total        : "
    f"{bwd_ip_header_total}"
)

print(
    f"Transport header total : "
    f"{bwd_transport_header_total}"
)

print(
    f"Total header length   : "
    f"{bwd_header_total}"
)

print()

print("=" * 80)
print("EXPECTED CURRENT EXTRACTOR VALUES")
print("=" * 80)

print()
print(
    "Previous Scapy feature output:"
)

print(
    "Fwd Header Length : 952"
)

print(
    "Bwd Header Length : 692"
)

print()

print("=" * 80)
print("END")
print("=" * 80)