"""SQLAlchemy models for capture sessions, packets, and alerts."""

from datetime import datetime, timezone
from enum import StrEnum
from typing import Any

from sqlalchemy import (
    DateTime,
    Enum,
    ForeignKey,
    Index,
    Integer,
    JSON,
    String,
    Text,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class CaptureSource(StrEnum):
    """Origin of a capture session."""

    PCAP = "pcap"
    LIVE = "live"


class SessionStatus(StrEnum):
    """Processing state of a capture session."""

    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"


class AlertSeverity(StrEnum):
    """Supported alert severity levels."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


def _enum_values(enum_type: type[StrEnum]) -> list[str]:
    """Return string enum values for portable non-native SQL enums."""
    return [item.value for item in enum_type]


class CaptureSession(Base):
    """A PCAP upload or live network capture session."""

    __tablename__ = "capture_sessions"
    __table_args__ = (
        Index("ix_capture_sessions_status_started", "status", "started_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    source: Mapped[CaptureSource] = mapped_column(
        Enum(CaptureSource, name="capture_source", native_enum=False,
             values_callable=_enum_values),
        nullable=False,
    )
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False,
        default=lambda: datetime.now(timezone.utc), server_default=func.current_timestamp(),
    )
    ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    packet_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0")
    byte_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0")
    status: Mapped[SessionStatus] = mapped_column(
        Enum(SessionStatus, name="capture_status", native_enum=False,
             values_callable=_enum_values),
        nullable=False,
        default=SessionStatus.PROCESSING,
        server_default=SessionStatus.PROCESSING.value,
    )

    packets: Mapped[list["Packet"]] = relationship(
        back_populates="session", cascade="all, delete-orphan",
    )
    alerts: Mapped[list["Alert"]] = relationship(
        back_populates="session", cascade="all, delete-orphan",
    )


class Packet(Base):
    """A normalized packet belonging to a capture session."""

    __tablename__ = "packets"
    __table_args__ = (
        Index("ix_packets_session_timestamp", "session_id", "timestamp"),
        Index("ix_packets_session_protocol", "session_id", "protocol"),
        Index("ix_packets_session_src_ip", "session_id", "src_ip"),
        Index("ix_packets_session_dst_ip", "session_id", "dst_ip"),
        Index("ix_packets_session_src_port", "session_id", "src_port"),
        Index("ix_packets_session_dst_port", "session_id", "dst_port"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    session_id: Mapped[int] = mapped_column(
        ForeignKey("capture_sessions.id", ondelete="CASCADE"), nullable=False, index=True,
    )
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    src_ip: Mapped[str | None] = mapped_column(String(45))
    dst_ip: Mapped[str | None] = mapped_column(String(45))
    src_port: Mapped[int | None] = mapped_column(Integer)
    dst_port: Mapped[int | None] = mapped_column(Integer)
    protocol: Mapped[str] = mapped_column(String(16), nullable=False)
    length: Mapped[int] = mapped_column(Integer, nullable=False)
    tcp_flags: Mapped[str | None] = mapped_column(String(16))
    extra: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)

    session: Mapped[CaptureSession] = relationship(back_populates="packets")


class Alert(Base):
    """A rule-based security alert associated with a capture session."""

    __tablename__ = "alerts"
    __table_args__ = (
        Index("ix_alerts_session_first_seen", "session_id", "first_seen"),
        Index("ix_alerts_session_severity", "session_id", "severity"),
        Index("ix_alerts_session_rule", "session_id", "rule"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    session_id: Mapped[int] = mapped_column(
        ForeignKey("capture_sessions.id", ondelete="CASCADE"), nullable=False, index=True,
    )
    rule: Mapped[str] = mapped_column(String(100), nullable=False)
    severity: Mapped[AlertSeverity] = mapped_column(
        Enum(AlertSeverity, name="alert_severity", native_enum=False,
             values_callable=_enum_values),
        nullable=False,
    )
    description: Mapped[str] = mapped_column(Text, nullable=False)
    src_ip: Mapped[str | None] = mapped_column(String(45))
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    alert_metadata: Mapped[dict[str, Any]] = mapped_column(
        "metadata", JSON, nullable=False, default=dict,
    )

    session: Mapped[CaptureSession] = relationship(back_populates="alerts")
