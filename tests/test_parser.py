from pathlib import Path

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Raw
from scapy.utils import wrpcap

from netscope.app.parser import parse_pcap


def parse_packets(tmp_path: Path, packets: list[object]) -> list[dict]:
    path = tmp_path / "packets.pcap"
    wrpcap(str(path), packets)
    return list(parse_pcap(path))


def test_classifies_dns_before_udp_and_normalizes_fields(tmp_path: Path) -> None:
    parsed = parse_packets(tmp_path, [
        Ether() / IP(src="192.0.2.1", dst="192.0.2.53") / UDP(sport=12345, dport=53) /
        DNS(rd=1, qd=DNSQR(qname="example.test")),
        Ether() / IP() / TCP(sport=12, dport=443, flags="SA"),
        Ether() / IP() / UDP(sport=13, dport=9999),
        Ether() / IP() / ICMP(type=8),
    ])
    assert [row["protocol"] for row in parsed] == ["DNS", "TCP", "UDP", "ICMP"]
    assert parsed[0]["dns_query"] == "example.test"
    assert parsed[0]["src_port"] == 12345
    assert parsed[1]["tcp_flags"] == "SA"
    assert parsed[3]["icmp_type"] == 8


def test_supports_ipv6_and_icmpv6(tmp_path: Path) -> None:
    parsed = parse_packets(tmp_path, [
        Ether() / IPv6(src="2001:db8::1", dst="2001:db8::2") / TCP(dport=443),
        Ether() / IPv6(src="2001:db8::1", dst="2001:db8::2") / ICMPv6EchoRequest(),
    ])
    assert parsed[0]["src_ip"] == "2001:db8::1"
    assert parsed[0]["protocol"] == "TCP"
    assert parsed[1]["protocol"] == "ICMP"


def test_non_ip_and_truncated_packets_do_not_crash(tmp_path: Path) -> None:
    parsed = parse_packets(tmp_path, [
        Ether() / ARP(),
        Ether() / IP(src="192.0.2.1", dst="192.0.2.2") / UDP() / Raw(load=b"x"),
    ])
    assert parsed[0]["protocol"] == "OTHER"
    assert parsed[0]["src_ip"] is None
    assert parsed[1]["protocol"] == "UDP"


def test_real_sample_pcaps_are_stream_readable() -> None:
    sample_dir = Path(__file__).resolve().parents[1] / "samples"
    expected = {"dns-remoteshell.pcap", "dns.pcap", "ipv4frags.pcap", "normal_mixed.pcap", "slammer.pcap"}
    existing = {path.name for path in sample_dir.iterdir() if path.is_file()}
    assert expected <= existing
    unreadable = []
    for name in sorted(expected):
        try:
            list(parse_pcap(sample_dir / name))
        except Exception as exc:  # report reader failures with the offending capture
            unreadable.append(f"{name}: {exc}")
    assert not unreadable, "; ".join(unreadable)
