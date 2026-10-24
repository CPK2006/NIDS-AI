from scapy.all import PcapReader, IP, TCP, UDP
import statistics


PCAP = r"data\pcap\test_100k.pcap"

TARGET_SRC_IP = "192.168.10.17"
TARGET_DST_IP = "192.168.10.3"
TARGET_SRC_PORT = 45344
TARGET_DST_PORT = 3268


print("=" * 80)
print("FLOW-LEVEL IAT DIAGNOSTIC")
print("=" * 80)

packets = []

# ------------------------------------------------------------
# Read PCAP and remove consecutive duplicate packets
# ------------------------------------------------------------

previous_bytes = None
duplicates = 0

with PcapReader(PCAP) as reader:

    for packet in reader:

        raw = bytes(packet)

        if previous_bytes is not None and raw == previous_bytes:
            duplicates += 1
            continue

        previous_bytes = raw

        if IP not in packet:
            continue

        if TCP not in packet and UDP not in packet:
            continue

        packets.append(packet)


# ------------------------------------------------------------
# Select target flow
# ------------------------------------------------------------

flow = []

for packet in packets:

    if IP not in packet:
        continue

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst

    if TCP in packet:
        src_port = int(packet[TCP].sport)
        dst_port = int(packet[TCP].dport)
    elif UDP in packet:
        src_port = int(packet[UDP].sport)
        dst_port = int(packet[UDP].dport)
    else:
        continue

    forward = (
        src_ip == TARGET_SRC_IP
        and dst_ip == TARGET_DST_IP
        and src_port == TARGET_SRC_PORT
        and dst_port == TARGET_DST_PORT
    )

    backward = (
        src_ip == TARGET_DST_IP
        and dst_ip == TARGET_SRC_IP
        and src_port == TARGET_DST_PORT
        and dst_port == TARGET_SRC_PORT
    )

    if forward or backward:
        direction = "F" if forward else "B"
        flow.append((float(packet.time), direction, packet))


# ------------------------------------------------------------
# Sort packets by timestamp
# ------------------------------------------------------------

flow.sort(key=lambda x: x[0])


print()
print("TARGET FLOW")
print("-" * 80)

print(
    f"{TARGET_SRC_IP}:{TARGET_SRC_PORT}"
    f" -> "
    f"{TARGET_DST_IP}:{TARGET_DST_PORT}"
)

print()
print(f"Consecutive duplicates removed : {duplicates:,}")
print(f"Target flow packets            : {len(flow)}")


# ------------------------------------------------------------
# Print timeline
# ------------------------------------------------------------

print()
print("=" * 80)
print("FILTERED FLOW TIMELINE")
print("=" * 80)

for i, (timestamp, direction, packet) in enumerate(flow, 1):

    print(
        f"{i:2d}  {direction}  "
        f"{timestamp:.9f}  "
        f"{len(packet):4d} bytes"
    )


# ------------------------------------------------------------
# Calculate Flow IAT
# ------------------------------------------------------------

times = [x[0] for x in flow]

flow_iats = []

for i in range(1, len(times)):
    delta = times[i] - times[i - 1]

    if delta >= 0:
        flow_iats.append(delta)


# ------------------------------------------------------------
# Forward IAT
# ------------------------------------------------------------

forward_times = [
    timestamp
    for timestamp, direction, packet in flow
    if direction == "F"
]

forward_iats = []

for i in range(1, len(forward_times)):
    delta = forward_times[i] - forward_times[i - 1]

    if delta >= 0:
        forward_iats.append(delta)


# ------------------------------------------------------------
# Results
# ------------------------------------------------------------

print()
print("=" * 80)
print("FLOW IAT")
print("=" * 80)

if flow_iats:

    print(f"Count              : {len(flow_iats)}")
    print(f"Mean (seconds)     : {statistics.mean(flow_iats)}")
    print(f"Mean (microseconds): {statistics.mean(flow_iats) * 1_000_000}")
    print(f"Minimum (seconds)  : {min(flow_iats)}")
    print(f"Minimum (us)       : {min(flow_iats) * 1_000_000}")
    print(f"Total (seconds)    : {sum(flow_iats)}")
    print(f"Total (us)         : {sum(flow_iats) * 1_000_000}")

else:
    print("No Flow IAT values.")


print()
print("=" * 80)
print("FORWARD IAT")
print("=" * 80)

if forward_iats:

    print(f"Count              : {len(forward_iats)}")
    print(f"Mean (seconds)     : {statistics.mean(forward_iats)}")
    print(f"Mean (microseconds): {statistics.mean(forward_iats) * 1_000_000}")
    print(f"Minimum (seconds)  : {min(forward_iats)}")
    print(f"Minimum (us)       : {min(forward_iats) * 1_000_000}")
    print(f"Total (seconds)    : {sum(forward_iats)}")
    print(f"Total (us)         : {sum(forward_iats) * 1_000_000}")

else:
    print("No Forward IAT values.")


# ------------------------------------------------------------
# Compare with v6 feature row
# ------------------------------------------------------------

print()
print("=" * 80)
print("EXPECTED v6 FEATURE VALUES")
print("=" * 80)

print("Flow IAT Mean  : 837011 approximately")
print("Flow IAT Min   : 72325 approximately")
print("Fwd IAT Min    : 830964 approximately")
print("Fwd IAT Total  : 15852300 approximately")

print()
print("=" * 80)
print("END")
print("=" * 80)