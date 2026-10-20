"""Generate synthetic PCAPs for parser and detection development."""

import time
from pathlib import Path

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.utils import wrpcap


OUTPUT = Path(__file__).resolve().parents[1] / "samples" / "synthetic"


def write_capture(name: str, packets: list[object]) -> None:
    """Write a packet list under samples/synthetic."""
    OUTPUT.mkdir(parents=True, exist_ok=True)
    wrpcap(str(OUTPUT / name), packets)


def generate() -> None:
    """Create normal traffic and four simple anomaly scenarios."""
    normal_start = time.time() - 179.7
    source_hosts = [f"192.0.2.{host}" for host in range(10, 15)]
    destination_hosts = [f"198.51.100.{host}" for host in range(20, 25)]
    normal_packets = []
    for index in range(600):
        source = source_hosts[index % len(source_hosts)]
        destination = destination_hosts[(index // len(source_hosts)) % len(destination_hosts)]
        timestamp = normal_start + index * 0.3
        packet_type = index % 4
        if packet_type == 0:
            packet = Ether() / IP(src=source, dst=destination) / TCP(
                sport=51000 + index % 4000, dport=443, flags="PA",
            )
        elif packet_type == 1:
            packet = Ether() / IP(src=source, dst=destination) / UDP(
                sport=53000 + index % 1000, dport=2000 + index % 4,
            )
        elif packet_type == 2:
            packet = Ether() / IP(src=source, dst="203.0.113.53") / UDP(
                sport=54000 + index % 1000, dport=53,
            ) / DNS(rd=1, qd=DNSQR(qname=f"host{index % 25}.service.test"))
        else:
            packet = Ether() / IP(src=source, dst=destination) / ICMP()
        packet.time = timestamp
        normal_packets.append(packet)
    write_capture("synthetic_normal_traffic.pcap", normal_packets)

    scan_start = time.time() - 20
    scan_background = []
    for index in range(40):
        source = source_hosts[index % len(source_hosts)]
        destination = destination_hosts[index % len(destination_hosts)]
        if index % 4 == 0:
            packet = Ether() / IP(src=source, dst=destination) / TCP(
                sport=51000 + index, dport=443, flags="A",
            )
        elif index % 4 == 1:
            packet = Ether() / IP(src=source, dst=destination) / UDP(sport=53000 + index, dport=123)
        elif index % 4 == 2:
            packet = Ether() / IP(src=source, dst="203.0.113.53") / UDP(
                sport=54000 + index, dport=53,
            ) / DNS(rd=1, qd=DNSQR(qname=f"normal{index}.service.test"))
        else:
            packet = Ether() / IP(src=source, dst=destination) / ICMP()
        packet.time = scan_start + index * 0.25
        scan_background.append(packet)

    scan_packets = []
    burst_start = scan_start + 12
    for index, port in enumerate(range(1, 121)):
        packet = Ether() / IP(src="192.0.2.50", dst="198.51.100.20") / TCP(
            sport=40000 + port, dport=port, flags="S",
        )
        packet.time = burst_start + index * (2.5 / 120)
        scan_packets.append(packet)
    write_capture("port_scan.pcap", scan_background + scan_packets)
    write_capture("syn_flood.pcap", [
        Ether() / IP(src=f"192.0.2.{index % 200 + 1}", dst="198.51.100.80") / TCP(sport=30000 + index, dport=80, flags="S")
        for index in range(500)
    ])
    dns_packets = [
        Ether() / IP(src="192.0.2.60", dst="198.51.100.53") / UDP(sport=53000 + i, dport=53) /
        DNS(rd=1, qd=DNSQR(qname=(".".join(["x" * 60] * 4) + ".test") if i == 0 else f"missing{i}.test"),
            rcode=0 if i == 0 else 3)
        for i in range(100)
    ]
    write_capture("dns_anomalies.pcap", dns_packets)
    write_capture("icmp_flood.pcap", [
        Ether() / IP(src="192.0.2.70", dst="198.51.100.70") / ICMP()
        for _ in range(500)
    ])


if __name__ == "__main__":
    generate()
