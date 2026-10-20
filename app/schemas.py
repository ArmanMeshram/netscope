"""Pydantic response models for the NetScope REST API."""

from datetime import datetime, timezone
from typing import Any, overload

from pydantic import BaseModel, ConfigDict, field_serializer

from app.models import AlertSeverity, CaptureSource, SessionStatus


@overload
def utc_isoformat(value: datetime) -> str: ...


@overload
def utc_isoformat(value: None) -> None: ...


def utc_isoformat(value: datetime | None) -> str | None:
    """Serialize a datetime as an aware UTC ISO-8601 string with a Z suffix."""
    if value is None:
        return None
    normalized = value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)
    return normalized.isoformat().replace("+00:00", "Z")


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

    @field_serializer("started_at", "ended_at", when_used="json")
    def serialize_session_times(self, value: datetime | None) -> str | None:
        """Return session lifecycle times in UTC."""
        return utc_isoformat(value)


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

    @field_serializer("timestamp", when_used="json")
    def serialize_timestamp(self, value: datetime) -> str:
        """Return packet times in UTC."""
        return utc_isoformat(value)


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

    @field_serializer("first_seen", "last_seen", when_used="json")
    def serialize_alert_times(self, value: datetime) -> str:
        """Return alert times in UTC."""
        return utc_isoformat(value)


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

    @field_serializer("timestamp", when_used="json")
    def serialize_timestamp(self, value: datetime) -> str:
        """Return traffic bucket times in UTC."""
        return utc_isoformat(value)


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
