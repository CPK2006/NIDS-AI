from scapy.all import PcapReader, IP, IPv6, TCP, UDP


PCAP = r"data\pcap\test_100k.pcap"

TARGET_SRC = "192.168.10.17"
TARGET_DST = "192.168.10.3"
TARGET_SPORT = 45344
TARGET_DPORT = 3268


def get_info(packet):

    if IP in packet:
        src = packet[IP].src
        dst = packet[IP].dst

    elif IPv6 in packet:
        src = packet[IPv6].src
        dst = packet[IPv6].dst

    else:
        return None

    if TCP in packet:
        sport = int(packet[TCP].sport)
        dport = int(packet[TCP].dport)
        proto = "TCP"

    elif UDP in packet:
        sport = int(packet[UDP].sport)
        dport = int(packet[UDP].dport)
        proto = "UDP"

    else:
        return None

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
        return None

    return "F" if forward else "B"


timestamps = []

previous_packet_bytes = None
duplicates = 0

with PcapReader(PCAP) as packets:

    for packet in packets:

        current_packet_bytes = bytes(packet)

        if (
            previous_packet_bytes is not None
            and current_packet_bytes == previous_packet_bytes
        ):
            duplicates += 1
            continue

        previous_packet_bytes = current_packet_bytes

        direction = get_info(packet)

        if direction is None:
            continue

        timestamps.append(
            (
                float(packet.time),
                direction,
                len(packet)
            )
        )


print("=" * 80)
print("IAT EXTRACTOR COMPARISON")
print("=" * 80)

print()
print("Target flow:")
print(
    f"{TARGET_SRC}:{TARGET_SPORT} -> "
    f"{TARGET_DST}:{TARGET_DPORT}"
)

print()
print(f"Duplicates removed : {duplicates:,}")
print(f"Packets retained   : {len(timestamps)}")

# ------------------------------------------------------------
# FLOW IAT
# ------------------------------------------------------------

flow_iats = []

for i in range(1, len(timestamps)):
    dt = timestamps[i][0] - timestamps[i - 1][0]

    if dt >= 0:
        flow_iats.append(dt)

# ------------------------------------------------------------
# FORWARD IAT
# ------------------------------------------------------------

forward_times = [
    t for t, direction, size in timestamps
    if direction == "F"
]

forward_iats = []

for i in range(1, len(forward_times)):
    dt = forward_times[i] - forward_times[i - 1]

    if dt >= 0:
        forward_iats.append(dt)


def show(name, values):

    print()
    print("-" * 80)
    print(name)
    print("-" * 80)

    print("Count :", len(values))

    if not values:
        return

    print("Total seconds :", sum(values))
    print("Mean seconds  :", sum(values) / len(values))
    print("Min seconds   :", min(values))

    print("Total us :", sum(values) * 1_000_000)
    print("Mean us  :", (sum(values) / len(values)) * 1_000_000)
    print("Min us   :", min(values) * 1_000_000)


show("FLOW IAT", flow_iats)

show("FORWARD IAT", forward_iats)


print()
print("=" * 80)
print("FIRST 20 FLOW IAT VALUES")
print("=" * 80)

for i, value in enumerate(flow_iats[:20], 1):
    print(
        f"{i:2d}  "
        f"{value:.12f} sec  "
        f"{value * 1_000_000:.3f} us"
    )


print()
print("=" * 80)
print("FIRST 20 FORWARD IAT VALUES")
print("=" * 80)

for i, value in enumerate(forward_iats[:20], 1):
    print(
        f"{i:2d}  "
        f"{value:.12f} sec  "
        f"{value * 1_000_000:.3f} us"
    )

print()
print("=" * 80)
print("END")
print("=" * 80)