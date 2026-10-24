from scapy.all import sniff, wrpcap

INTERFACE = r"\Device\NPF_{21655F55-D812-4D9A-B192-7655372DBCEE}"
OUTPUT = "data/pcap/v2_localhost_attack.pcap"

print("=" * 60)
print("NIDS-AI V2 - LOCALHOST TRAFFIC CAPTURE")
print("=" * 60)
print(f"Interface : {INTERFACE}")
print(f"Output    : {OUTPUT}")
print()
print("Waiting for localhost traffic...")
print("Capture will stop after 1000 packets.")
print()

packets = sniff(
    iface=INTERFACE,
    count=1000,
    filter="tcp port 8080"
)

wrpcap(OUTPUT, packets)

print()
print("=" * 60)
print("CAPTURE COMPLETED")
print("=" * 60)
print(f"Packets captured : {len(packets)}")
print(f"PCAP             : {OUTPUT}")
print("=" * 60)