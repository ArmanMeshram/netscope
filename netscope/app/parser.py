"""Streaming packet parsing and normalization for PCAP files."""

from collections.abc import Iterator
from pathlib import Path
from typing import Any

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.utils import PcapReader


def parse_pcap(path: str | Path) -> Iterator[dict[str, Any]]:
    """Yield normalized packet dictionaries from a PCAP without loading it all."""
    reader = PcapReader(str(path))
    try:
        while True:
            try:
                packet = reader.read_packet()
            except (OSError, EOFError, ValueError):
                # A corrupt record may make the remainder of this capture unreadable.
                break
            except Exception:
                # Scapy can raise different decode errors for malformed records.
                break
            if packet is None:
                break
            try:
                yield normalize_packet(packet)
            except Exception:
                # One malformed or truncated packet must not invalidate the capture.
                continue
    finally:
        reader.close()


def normalize_packet(packet: Any) -> dict[str, Any]:
    """Normalize one Scapy packet to the stable NetScope parser schema."""
    src_ip = dst_ip = None
    if IP in packet:
        src_ip, dst_ip = packet[IP].src, packet[IP].dst
    elif IPv6 in packet:
        src_ip, dst_ip = packet[IPv6].src, packet[IPv6].dst

    src_port = dst_port = None
    if TCP in packet:
        src_port, dst_port = int(packet[TCP].sport), int(packet[TCP].dport)
    elif UDP in packet:
        src_port, dst_port = int(packet[UDP].sport), int(packet[UDP].dport)

    tcp_flags = str(packet[TCP].flags) if TCP in packet else None
    dns_query = None
    dns_rcode = None
    icmpv6_layer = next(
        (layer for layer in packet.layers() if layer.__name__.startswith("ICMPv6")),
        None,
    )
    if DNS in packet:
        dns = packet[DNS]
        dns_rcode = int(dns.rcode)
        query = packet[DNSQR].qname if DNSQR in packet else None
        if query:
            dns_query = bytes(query).decode("utf-8", errors="replace").rstrip(".")

    if DNS in packet:
        protocol = "DNS"
    elif TCP in packet:
        protocol = "TCP"
    elif UDP in packet:
        protocol = "UDP"
    elif ICMP in packet or icmpv6_layer is not None:
        protocol = "ICMP"
    else:
        protocol = "OTHER"

    icmp_type = None
    if ICMP in packet:
        icmp_type = int(packet[ICMP].type)
    elif icmpv6_layer is not None:
        icmp_type = int(packet.getlayer(icmpv6_layer).type)

    return {
        "timestamp": float(packet.time),
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": protocol,
        "length": len(packet),
        "tcp_flags": tcp_flags,
        "dns_query": dns_query,
        "dns_rcode": dns_rcode,
        "icmp_type": icmp_type,
    }
