from scapy.all import PcapReader, IP, TCP, UDP


PCAP = r"data\pcap\test_100k.pcap"

TARGET_SRC = "192.168.10.17"
TARGET_DST = "192.168.10.3"

TARGET_SPORT = 45344
TARGET_DPORT = 3268


packets_found = []

flow_started = False
last_timestamp = None

print("=" * 70)
print("FIRST FLOW IAT DIAGNOSTIC")
print("=" * 70)


with PcapReader(PCAP) as packets:

    for packet in packets:

        if IP not in packet:
            continue

        if TCP not in packet:
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

            # Once the first flow has started,
            # don't continue indefinitely.
            if flow_started:
                if last_timestamp is not None:
                    current_time = float(packet.time)

                    if current_time - last_timestamp > 120:
                        break

            continue

        timestamp = float(packet.time)

        # Start first flow
        if not flow_started:

            flow_started = True

        packets_found.append(
            (
                timestamp,
                "F" if forward else "B",
                len(packet)
            )
        )

        last_timestamp = timestamp


# ============================================================
# PRINT PACKETS
# ============================================================

print()
print(
    f"Packets found: {len(packets_found)}"
)

print()
print("PACKET TIMELINE")
print("-" * 70)

for i, (timestamp, direction, length) in enumerate(
    packets_found
):

    print(
        f"{i + 1:2d}  "
        f"{direction}  "
        f"{timestamp:.9f}  "
        f"{length} bytes"
    )


# ============================================================
# FLOW IAT
# ============================================================

flow_iats = []

for i in range(1, len(packets_found)):

    iat = (
        packets_found[i][0]
        -
        packets_found[i - 1][0]
    )

    flow_iats.append(iat)


# ============================================================
# FORWARD IAT
# ============================================================

forward_packets = [
    packet
    for packet in packets_found
    if packet[1] == "F"
]

forward_iats = []

for i in range(1, len(forward_packets)):

    iat = (
        forward_packets[i][0]
        -
        forward_packets[i - 1][0]
    )

    forward_iats.append(iat)


# ============================================================
# RESULTS
# ============================================================

print()
print("=" * 70)
print("RESULTS")
print("=" * 70)


if flow_iats:

    print()
    print("FLOW IAT")

    print(
        f"Mean (seconds): "
        f"{sum(flow_iats) / len(flow_iats)}"
    )

    print(
        f"Mean (microseconds): "
        f"{(sum(flow_iats) / len(flow_iats)) * 1_000_000}"
    )

    print(
        f"Minimum (seconds): "
        f"{min(flow_iats)}"
    )

    print(
        f"Minimum (microseconds): "
        f"{min(flow_iats) * 1_000_000}"
    )

    print(
        f"Total (seconds): "
        f"{sum(flow_iats)}"
    )

    print(
        f"Total (microseconds): "
        f"{sum(flow_iats) * 1_000_000}"
    )


if forward_iats:

    print()
    print("FORWARD IAT")

    print(
        f"Mean (seconds): "
        f"{sum(forward_iats) / len(forward_iats)}"
    )

    print(
        f"Mean (microseconds): "
        f"{(sum(forward_iats) / len(forward_iats)) * 1_000_000}"
    )

    print(
        f"Minimum (seconds): "
        f"{min(forward_iats)}"
    )

    print(
        f"Minimum (microseconds): "
        f"{min(forward_iats) * 1_000_000}"
    )

    print(
        f"Total (seconds): "
        f"{sum(forward_iats)}"
    )

    print(
        f"Total (microseconds): "
        f"{sum(forward_iats) * 1_000_000}"
    )