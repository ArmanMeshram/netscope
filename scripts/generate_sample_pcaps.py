"""Generate deterministic synthetic PCAPs for parser and detection development."""

from pathlib import Path

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest
from scapy.layers.l2 import Ether
from scapy.utils import wrpcap


OUTPUT = Path(__file__).resolve().parents[1] / "samples" / "synthetic"


def write_capture(name: str, packets: list[object]) -> None:
    """Write a packet list under samples/synthetic."""
    OUTPUT.mkdir(parents=True, exist_ok=True)
    wrpcap(str(OUTPUT / name), packets)


def generate() -> None:
    """Create normal traffic and four simple anomaly scenarios."""
    write_capture("synthetic_normal_traffic.pcap", [
        Ether() / IP(src="192.0.2.10", dst="198.51.100.2") / TCP(sport=51000, dport=443, flags="S"),
        Ether() / IP(src="192.0.2.10", dst="198.51.100.53") / UDP(sport=53000, dport=53) / DNS(rd=1, qd=DNSQR(qname="example.test")),
        Ether() / IPv6(src="2001:db8::10", dst="2001:db8::20") / ICMPv6EchoRequest(),
    ])
    write_capture("port_scan.pcap", [
        Ether() / IP(src="192.0.2.50", dst="198.51.100.20") / TCP(sport=40000 + port, dport=port, flags="S")
        for port in range(1, 101)
    ])
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
