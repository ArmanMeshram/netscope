"""Pydantic response models for the NetScope REST API."""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict

from app.models import AlertSeverity, CaptureSource, SessionStatus


class SessionRead(BaseModel):
    """Public capture session representation."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    source: CaptureSource
    started_at: datetime
    ended_at: datetime | None
    packet_count: int
    byte_count: int
    status: SessionStatus


class PacketRead(BaseModel):
    """Public normalized packet representation."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    session_id: int
    timestamp: datetime
    src_ip: str | None
    dst_ip: str | None
    src_port: int | None
    dst_port: int | None
    protocol: str
    length: int
    tcp_flags: str | None
    extra: dict[str, Any]


class AlertRead(BaseModel):
    """Public anomaly alert representation."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    session_id: int
    rule: str
    severity: AlertSeverity
    description: str
    src_ip: str | None
    first_seen: datetime
    last_seen: datetime
    alert_metadata: dict[str, Any]


class PacketPage(BaseModel):
    """A page of filtered packet results."""

    items: list[PacketRead]
    total: int
    limit: int
    offset: int


class AddressCount(BaseModel):
    """An address and the number of matching packets."""

    address: str
    count: int


class PortCount(BaseModel):
    """A destination port and the number of matching packets."""

    port: int
    count: int


class TrafficBucket(BaseModel):
    """Packet count in a fixed time bucket."""

    timestamp: datetime
    packets: int


class SessionSummary(BaseModel):
    """Aggregated packet and traffic information for one session."""

    total_packets: int
    total_bytes: int
    duration_seconds: float
    protocol_distribution: dict[str, int]
    top_sources: list[AddressCount]
    top_destinations: list[AddressCount]
    top_ports: list[PortCount]
    packets_per_second: list[TrafficBucket]
