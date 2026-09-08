from scapy.all import PcapReader, IP, TCP


PCAP = r"data\pcap\test_100k.pcap"

TARGET_SRC = "192.168.10.17"
TARGET_DST = "192.168.10.3"
TARGET_SPORT = 45344
TARGET_DPORT = 3268


forward_sizes = []


with PcapReader(PCAP) as packets:

    for packet in packets:

        if IP not in packet or TCP not in packet:
            continue

        src = packet[IP].src
        dst = packet[IP].dst

        sport = int(packet[TCP].sport)
        dport = int(packet[TCP].dport)

        if (
            src == TARGET_SRC
            and dst == TARGET_DST
            and sport == TARGET_SPORT
            and dport == TARGET_DPORT
        ):

            dataofs = packet[TCP].dataofs

            if dataofs is not None:

                header_length = int(dataofs) * 4

                forward_sizes.append(header_length)


print("=" * 60)
print("MIN_SEG_SIZE_FORWARD TEST")
print("=" * 60)

print()

print("Forward TCP header lengths:")
print(forward_sizes)

print()

if forward_sizes:

    print("Minimum:")
    print(min(forward_sizes))

    print()

    print("Maximum:")
    print(max(forward_sizes))

    print()

    print("Unique values:")
    print(sorted(set(forward_sizes)))

else:

    print("No matching forward TCP packets found.")

print()

print("=" * 60)