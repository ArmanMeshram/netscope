"""Streaming, rule-based anomaly detection for normalized packet records."""

from collections import defaultdict, deque
from collections.abc import Callable, Iterable
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import DetectionThresholds, detection_thresholds
from app.models import Alert, AlertSeverity, Packet

PacketData = dict[str, Any]
PacketStream = Iterable[PacketData]


def _as_datetime(value: datetime | float | int) -> datetime:
    """Convert packet timestamps into aware UTC datetimes."""
    if isinstance(value, datetime):
        return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)
    return datetime.fromtimestamp(float(value), tz=timezone.utc)


def _alert(
    session_id: int,
    rule: str,
    severity: AlertSeverity,
    description: str,
    src_ip: str | None,
    first_seen: datetime,
    last_seen: datetime,
    evidence: dict[str, Any],
) -> Alert:
    """Build an unpersisted alert row with rule evidence."""
    return Alert(
        session_id=session_id,
        rule=rule,
        severity=severity,
        description=description,
        src_ip=src_ip,
        first_seen=first_seen,
        last_seen=last_seen,
        alert_metadata=evidence,
    )


def detect_port_scans(
    packets: PacketStream,
    session_id: int,
    thresholds: DetectionThresholds | None = None,
) -> list[Alert]:
    """Find sources contacting more than N ports on one target in a window."""
    config = thresholds or detection_thresholds()
    windows: dict[tuple[str, str], deque[tuple[datetime, int]]] = defaultdict(deque)
    port_counts: dict[tuple[str, str], dict[int, int]] = defaultdict(dict)
    alerts: dict[tuple[str, str], Alert] = {}

    for packet in packets:
        source, target, port = packet.get("src_ip"), packet.get("dst_ip"), packet.get("dst_port")
        if not source or not target or port is None:
            continue
        key = (source, target)
        timestamp = _as_datetime(packet["timestamp"])
        events = windows[key]
        counts = port_counts[key]
        while events and (timestamp - events[0][0]).total_seconds() > config.port_scan_window_seconds:
            _, old_port = events.popleft()
            counts[old_port] -= 1
            if counts[old_port] == 0:
                del counts[old_port]
        port_number = int(port)
        events.append((timestamp, port_number))
        counts[port_number] = counts.get(port_number, 0) + 1
        if len(counts) > config.port_scan_distinct_ports:
            alert = alerts.get(key)
            first_seen = events[0][0]
            evidence = {
                "target_ip": target,
                "distinct_ports": len(counts),
                "threshold": config.port_scan_distinct_ports,
                "window_seconds": config.port_scan_window_seconds,
                "ports": sorted(counts),
            }
            if alert is None:
                alert = _alert(
                    session_id, "port_scan", AlertSeverity.MEDIUM,
                    f"{source} contacted many ports on {target}", source,
                    first_seen, timestamp, evidence,
                )
                alerts[key] = alert
            else:
                alert.last_seen = timestamp
                alert.alert_metadata = evidence
    return list(alerts.values())


def detect_syn_floods(
    packets: PacketStream,
    session_id: int,
    thresholds: DetectionThresholds | None = None,
) -> list[Alert]:
    """Find targets with many initial SYNs lacking completed handshakes."""
    config = thresholds or detection_thresholds()
    flow_state: dict[tuple[str, str, int, int], dict[str, Any]] = {}
    events_by_target: dict[str, deque[tuple[datetime, tuple[str, str, int, int]]]] = defaultdict(deque)
    pending_by_target: dict[str, set[tuple[str, str, int, int]]] = defaultdict(set)
    alerts: dict[str, Alert] = {}

    for packet in packets:
        source, target = packet.get("src_ip"), packet.get("dst_ip")
        source_port, target_port = packet.get("src_port"), packet.get("dst_port")
        flags = str(packet.get("tcp_flags") or "").upper()
        if not source or not target or source_port is None or target_port is None:
            continue
        syn, ack = "S" in flags, "A" in flags
        if not syn and not ack:
            continue

        timestamp = _as_datetime(packet["timestamp"])
        forward_key = (source, target, int(source_port), int(target_port))
        reverse_key = (target, source, int(target_port), int(source_port))
        if syn and ack:
            key = reverse_key
            state = flow_state.get(key)
            server = state["target"] if state is not None else source
        elif syn:
            key = forward_key
            server = target
            state = None
        else:
            key = forward_key
            state = flow_state.get(key)
            server = state["target"] if state is not None else target

        events = events_by_target[server]
        pending = pending_by_target[server]
        while events and (timestamp - events[0][0]).total_seconds() > config.syn_flood_window_seconds:
            _, expired_key = events.popleft()
            pending.discard(expired_key)
            flow_state.pop(expired_key, None)

        if syn and not ack:
            state = {"target": server, "syn_ack": False, "first_seen": timestamp}
            flow_state[key] = state
            events.append((timestamp, key))
            pending.add(key)
            pending_count = len(pending)
            if pending_count > config.syn_flood_threshold:
                evidence = {
                    "target_ip": server,
                    "incomplete_handshakes": pending_count,
                    "initial_syns_in_window": len(events),
                    "threshold": config.syn_flood_threshold,
                    "window_seconds": config.syn_flood_window_seconds,
                }
                alert = alerts.get(server)
                if alert is None:
                    alert = _alert(
                        session_id, "syn_flood", AlertSeverity.HIGH,
                        f"Many TCP handshakes to {server} remain incomplete", None,
                        events[0][0], timestamp, evidence,
                    )
                    alerts[server] = alert
                else:
                    alert.last_seen = timestamp
                    alert.alert_metadata = evidence
        elif syn and ack and state is not None:
            state["syn_ack"] = True
        elif ack and not syn and state is not None and state.get("syn_ack"):
            pending.discard(key)
            flow_state.pop(key, None)

    return list(alerts.values())


def detect_long_dns_queries(
    packets: PacketStream,
    session_id: int,
    thresholds: DetectionThresholds | None = None,
) -> list[Alert]:
    """Flag DNS query names longer than the configured maximum."""
    config = thresholds or detection_thresholds()
    alerts: dict[tuple[str | None, str], Alert] = {}
    for packet in packets:
        query = packet.get("dns_query")
        if not query or len(query) <= config.dns_max_query_length:
            continue
        source = packet.get("src_ip")
        timestamp = _as_datetime(packet["timestamp"])
        key = (source, str(query))
        alert = alerts.get(key)
        evidence = {
            "query": str(query)[:255],
            "query_length": len(query),
            "maximum_length": config.dns_max_query_length,
        }
        if alert is None:
            alert = _alert(
                session_id, "dns_long_query", AlertSeverity.MEDIUM,
                f"DNS query name exceeds {config.dns_max_query_length} characters",
                source, timestamp, timestamp, evidence,
            )
            alerts[key] = alert
        else:
            alert.last_seen = timestamp
    return list(alerts.values())


def detect_dns_nxdomain_rate(
    packets: PacketStream,
    session_id: int,
    thresholds: DetectionThresholds | None = None,
) -> list[Alert]:
    """Flag sources with a high rolling NXDOMAIN response rate."""
    config = thresholds or detection_thresholds()
    windows: dict[str, deque[tuple[datetime, bool]]] = defaultdict(deque)
    nxdomain_counts: dict[str, int] = defaultdict(int)
    alerts: dict[str, Alert] = {}
    for packet in packets:
        if packet.get("protocol") != "DNS" or not packet.get("dns_query"):
            continue
        source = packet.get("src_ip")
        if not source:
            continue
        timestamp = _as_datetime(packet["timestamp"])
        events = windows[source]
        count = nxdomain_counts[source]
        while events and (timestamp - events[0][0]).total_seconds() > config.dns_query_rate_window_seconds:
            _, was_nxdomain = events.popleft()
            count -= int(was_nxdomain)
        is_nxdomain = int(packet.get("dns_rcode") or 0) == 3
        events.append((timestamp, is_nxdomain))
        count += int(is_nxdomain)
        nxdomain_counts[source] = count
        rate = count / len(events)
        if len(events) < config.dns_nxdomain_min_queries or rate < config.dns_nxdomain_rate:
            continue
        evidence = {
            "queries": len(events),
            "nxdomain_responses": count,
            "nxdomain_rate": round(rate, 4),
            "minimum_queries": config.dns_nxdomain_min_queries,
            "rate_threshold": config.dns_nxdomain_rate,
            "window_seconds": config.dns_query_rate_window_seconds,
        }
        alert = alerts.get(source)
        if alert is None:
            alert = _alert(
                session_id, "dns_nxdomain_rate", AlertSeverity.HIGH,
                f"DNS NXDOMAIN rate from {source} is unusually high", source,
                events[0][0], timestamp, evidence,
            )
            alerts[source] = alert
        else:
            alert.last_seen = timestamp
            alert.alert_metadata = evidence
    return list(alerts.values())


def detect_dns_query_rate(
    packets: PacketStream,
    session_id: int,
    thresholds: DetectionThresholds | None = None,
) -> list[Alert]:
    """Flag sources generating too many DNS queries in a rolling window."""
    config = thresholds or detection_thresholds()
    windows: dict[str, deque[datetime]] = defaultdict(deque)
    alerts: dict[str, Alert] = {}
    for packet in packets:
        if packet.get("protocol") != "DNS" or not packet.get("dns_query"):
            continue
        source = packet.get("src_ip")
        if not source:
            continue
        timestamp = _as_datetime(packet["timestamp"])
        events = windows[source]
        while events and (timestamp - events[0]).total_seconds() > config.dns_query_rate_window_seconds:
            events.popleft()
        events.append(timestamp)
        if len(events) <= config.dns_query_rate_threshold:
            continue
        evidence = {
            "queries": len(events),
            "threshold": config.dns_query_rate_threshold,
            "window_seconds": config.dns_query_rate_window_seconds,
        }
        alert = alerts.get(source)
        if alert is None:
            alert = _alert(
                session_id, "dns_query_rate", AlertSeverity.MEDIUM,
                f"DNS query rate from {source} exceeds the configured threshold", source,
                events[0], timestamp, evidence,
            )
            alerts[source] = alert
        else:
            alert.last_seen = timestamp
            alert.alert_metadata = evidence
    return list(alerts.values())


def detect_icmp_floods(
    packets: PacketStream,
    session_id: int,
    thresholds: DetectionThresholds | None = None,
) -> list[Alert]:
    """Flag sources sending more than the configured ICMP packets per second."""
    config = thresholds or detection_thresholds()
    windows: dict[str, deque[datetime]] = defaultdict(deque)
    alerts: dict[str, Alert] = {}
    for packet in packets:
        if packet.get("protocol") != "ICMP":
            continue
        source = packet.get("src_ip")
        if not source:
            continue
        timestamp = _as_datetime(packet["timestamp"])
        events = windows[source]
        while events and (timestamp - events[0]).total_seconds() >= 1.0:
            events.popleft()
        events.append(timestamp)
        if len(events) <= config.icmp_flood_pps:
            continue
        evidence = {
            "packets_per_second": len(events),
            "threshold": config.icmp_flood_pps,
            "window_seconds": 1,
        }
        alert = alerts.get(source)
        if alert is None:
            alert = _alert(
                session_id, "icmp_flood", AlertSeverity.HIGH,
                f"ICMP packet rate from {source} exceeds the configured threshold", source,
                events[0], timestamp, evidence,
            )
            alerts[source] = alert
        else:
            alert.last_seen = timestamp
            alert.alert_metadata = evidence
    return list(alerts.values())


def _session_packets(db: Session, session_id: int) -> Iterable[PacketData]:
    """Yield normalized database packets in timestamp order without materializing them."""
    statement = (
        select(Packet)
        .where(Packet.session_id == session_id)
        .order_by(Packet.timestamp, Packet.id)
        .execution_options(yield_per=1000)
    )
    for packet in db.scalars(statement):
        timestamp = packet.timestamp
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)
        row: PacketData = {
            "timestamp": timestamp,
            "src_ip": packet.src_ip,
            "dst_ip": packet.dst_ip,
            "src_port": packet.src_port,
            "dst_port": packet.dst_port,
            "protocol": packet.protocol,
            "length": packet.length,
            "tcp_flags": packet.tcp_flags,
        }
        row.update(packet.extra or {})
        yield row


def run_detection(db: Session, session_id: int) -> list[Alert]:
    """Run all anomaly rules for a session and add the resulting alerts to the unit of work."""
    detectors: tuple[Callable[..., list[Alert]], ...] = (
        detect_port_scans,
        detect_syn_floods,
        detect_long_dns_queries,
        detect_dns_nxdomain_rate,
        detect_dns_query_rate,
        detect_icmp_floods,
    )
    alerts: list[Alert] = []
    for detector in detectors:
        alerts.extend(detector(_session_packets(db, session_id), session_id))
    db.add_all(alerts)
    return alerts
