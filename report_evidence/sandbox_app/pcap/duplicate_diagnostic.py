from scapy.all import PcapReader


PCAP = r"data\pcap\test_100k.pcap"

print("=" * 80)
print("DUPLICATE PACKET DIAGNOSTIC")
print("=" * 80)

previous_bytes = None
total = 0
duplicates = 0
kept = 0

all_times = []
kept_times = []

with PcapReader(PCAP) as packets:

    for packet in packets:

        total += 1

        timestamp = float(packet.time)
        raw = bytes(packet)

        all_times.append(timestamp)

        if previous_bytes is not None and raw == previous_bytes:
            duplicates += 1
            continue

        previous_bytes = raw

        kept += 1
        kept_times.append(timestamp)


def calculate_iat(times):

    if len(times) < 2:
        return 0.0, 0.0, 0.0

    iats = [
        times[i] - times[i - 1]
        for i in range(1, len(times))
    ]

    return (
        sum(iats) / len(iats),
        min(iats),
        sum(iats)
    )


all_mean, all_min, all_total = calculate_iat(all_times)
kept_mean, kept_min, kept_total = calculate_iat(kept_times)


print()
print("PACKET COUNTS")
print("-" * 80)

print(f"Original packets       : {total:,}")
print(f"Duplicate packets      : {duplicates:,}")
print(f"Packets after filtering: {kept:,}")


print()
print("DUPLICATE PERCENTAGE")
print("-" * 80)

print(f"{duplicates / total * 100:.2f}%")


print()
print("IAT BEFORE DUPLICATE REMOVAL")
print("-" * 80)

print(f"Mean  : {all_mean:.12f} sec")
print(f"Min   : {all_min:.12f} sec")
print(f"Total : {all_total:.12f} sec")


print()
print("IAT AFTER DUPLICATE REMOVAL")
print("-" * 80)

print(f"Mean  : {kept_mean:.12f} sec")
print(f"Min   : {kept_min:.12f} sec")
print(f"Total : {kept_total:.12f} sec")


print()
print("=" * 80)
print("END")
print("=" * 80)