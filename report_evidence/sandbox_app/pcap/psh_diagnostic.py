from scapy.all import PcapReader, IP, TCP


PCAP = r"data\pcap\test_100k.pcap"

TARGET_SRC = "192.168.10.17"
TARGET_DST = "192.168.10.3"

TARGET_SPORT = 45344
TARGET_DPORT = 3268


forward_psh = 0
backward_psh = 0
total_psh = 0

forward_packets = 0
backward_packets = 0

print("=" * 80)
print("PSH FLAG DIAGNOSTIC")
print("=" * 80)

print()
print(
    f"Target flow: "
    f"{TARGET_SRC}:{TARGET_SPORT} -> "
    f"{TARGET_DST}:{TARGET_DPORT}"
)

print()

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

        direction = "F" if forward else "B"

        if forward:
            forward_packets += 1
        else:
            backward_packets += 1

        flags = packet[TCP].flags

        psh = "P" in flags

        if psh:

            total_psh += 1

            if forward:
                forward_psh += 1
            else:
                backward_psh += 1

        print(
            f"{forward_packets + backward_packets:2d} "
            f"{direction} "
            f"Flags={str(flags):8s} "
            f"PSH={'YES' if psh else 'NO '}"
        )

print()
print("=" * 80)
print("PSH SUMMARY")
print("=" * 80)

print()

print(f"Forward packets  : {forward_packets}")
print(f"Backward packets : {backward_packets}")
print(f"Total packets    : {forward_packets + backward_packets}")

print()

print(f"Forward PSH      : {forward_psh}")
print(f"Backward PSH     : {backward_psh}")
print(f"Total PSH        : {total_psh}")

print()

print("=" * 80)
print("EXPECTED FROM CURRENT EXTRACTOR")
print("=" * 80)

print()
print(f"PSH Flag Count = {total_psh}")

print("=" * 80)