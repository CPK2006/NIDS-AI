from scapy.all import PcapReader, PcapWriter
import os


INPUT = "data/pcap/Friday-WorkingHours.pcap"
OUTPUT = "data/pcap/test_100k.pcap"

PACKET_LIMIT = 100_000


print("=" * 70)
print("CREATE SMALL CICIDS2017 PCAP TEST FILE")
print("=" * 70)

if not os.path.exists(INPUT):
    raise FileNotFoundError(
        f"Input PCAP not found: {INPUT}"
    )

print(f"Input : {INPUT}")
print(f"Output: {OUTPUT}")
print(f"Packets: {PACKET_LIMIT:,}")
print()

count = 0

with PcapReader(INPUT) as reader, PcapWriter(
    OUTPUT,
    sync=True
) as writer:

    for packet in reader:

        writer.write(packet)

        count += 1

        if count % 10_000 == 0:
            print(f"Copied: {count:,} packets", flush=True)

        if count >= PACKET_LIMIT:
            break

print()
print("=" * 70)
print("TEST PCAP CREATED")
print("=" * 70)
print(f"Packets copied: {count:,}")
print(f"File: {OUTPUT}")

if os.path.exists(OUTPUT):

    size_mb = os.path.getsize(OUTPUT) / (1024 ** 2)

    print(f"Size: {size_mb:.2f} MB")

print("=" * 70)