"""SQLAlchemy engine, session factory, and declarative base."""

from collections.abc import Generator
from collections.abc import Iterable
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import create_engine, insert
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.config import database_url


class Base(DeclarativeBase):
    """Base class for all persisted NetScope models."""


def make_engine(url: str | None = None) -> Engine:
    """Create an engine for SQLite or another SQLAlchemy-supported database."""
    resolved_url = url or database_url()
    if resolved_url.startswith("postgres://"):
        resolved_url = "postgresql+psycopg://" + resolved_url.removeprefix("postgres://")
    elif resolved_url.startswith("postgresql://"):
        resolved_url = "postgresql+psycopg://" + resolved_url.removeprefix("postgresql://")
    options: dict[str, object] = {"pool_pre_ping": True}
    if resolved_url.startswith("sqlite"):
        options["connect_args"] = {"check_same_thread": False}
    return create_engine(resolved_url, **options)


engine = make_engine()
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def get_db() -> Generator[Session, None, None]:
    """Yield a request-scoped database session and always close it."""
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


def create_tables() -> None:
    """Create all tables registered with the declarative base."""
    # Import registers model metadata before create_all is called.
    from app import models  # noqa: F401

    Base.metadata.create_all(bind=engine)


def bulk_insert_packets(
    session: Session,
    session_id: int,
    packets: Iterable[dict[str, Any]],
    batch_size: int = 1000,
) -> int:
    """Insert normalized packet rows in bounded batches without committing."""
    if batch_size < 1:
        raise ValueError("batch_size must be at least 1")

    from app.models import Packet

    parser_fields = {"dns_query", "dns_rcode", "icmp_type"}
    batch: list[dict[str, Any]] = []
    inserted = 0

    def flush_batch() -> None:
        nonlocal inserted
        if batch:
            session.execute(insert(Packet), batch)
            inserted += len(batch)
            batch.clear()

    for packet in packets:
        timestamp = packet["timestamp"]
        if not isinstance(timestamp, datetime):
            timestamp = datetime.fromtimestamp(float(timestamp), tz=timezone.utc)
        extra = dict(packet.get("extra") or {})
        extra.update({key: packet[key] for key in parser_fields if packet.get(key) is not None})
        batch.append({
            "session_id": session_id,
            "timestamp": timestamp,
            "src_ip": packet.get("src_ip"),
            "dst_ip": packet.get("dst_ip"),
            "src_port": packet.get("src_port"),
            "dst_port": packet.get("dst_port"),
            "protocol": packet["protocol"],
            "length": packet["length"],
            "tcp_flags": packet.get("tcp_flags"),
            "extra": extra,
        })
        if len(batch) >= batch_size:
            flush_batch()

    flush_batch()
    return inserted
