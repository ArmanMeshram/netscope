from datetime import datetime, timezone

from sqlalchemy import create_engine, inspect, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.database import Base, bulk_insert_packets, make_engine
from app.models import (
    Alert,
    AlertSeverity,
    CaptureSession,
    CaptureSource,
    Packet,
    SessionStatus,
)


def make_test_engine():
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    return engine


def test_models_persist_capture_packet_and_alert_json() -> None:
    engine = make_test_engine()
    timestamp = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
    with Session(engine) as db:
        session = CaptureSession(
            name="unit test", source=CaptureSource.PCAP, status=SessionStatus.COMPLETED,
            packet_count=1, byte_count=60,
        )
        session.packets.append(Packet(
            timestamp=timestamp, src_ip="192.0.2.1", dst_ip="198.51.100.2",
            src_port=12345, dst_port=443, protocol="TCP", length=60,
            tcp_flags="S", extra={"note": "initial SYN"},
        ))
        session.alerts.append(Alert(
            rule="port_scan", severity=AlertSeverity.MEDIUM,
            description="Multiple ports contacted", src_ip="192.0.2.1",
            first_seen=timestamp, last_seen=timestamp,
            alert_metadata={"distinct_ports": 10},
        ))
        db.add(session)
        db.commit()
        session_id = session.id

        stored = db.scalar(select(CaptureSession).where(CaptureSession.id == session_id))
        assert stored is not None
        assert stored.source == CaptureSource.PCAP
        assert stored.status == SessionStatus.COMPLETED
        assert stored.packet_count == 1
        assert stored.packets[0].extra == {"note": "initial SYN"}
        assert stored.alerts[0].severity == AlertSeverity.MEDIUM
        assert stored.alerts[0].alert_metadata == {"distinct_ports": 10}

    engine.dispose()


def test_session_deletion_cascades_to_packets_and_alerts() -> None:
    engine = make_test_engine()
    timestamp = datetime.now(timezone.utc)
    with Session(engine) as db:
        capture = CaptureSession(name="delete me", source=CaptureSource.LIVE)
        capture.packets.append(Packet(
            timestamp=timestamp, protocol="OTHER", length=14,
        ))
        capture.alerts.append(Alert(
            rule="example", severity=AlertSeverity.LOW, description="example",
            first_seen=timestamp, last_seen=timestamp,
        ))
        db.add(capture)
        db.commit()
        capture_id = capture.id
        db.delete(capture)
        db.commit()

        assert db.scalar(select(Packet.id)) is None
        assert db.scalar(select(Alert.id)) is None
        assert db.get(CaptureSession, capture_id) is None

    engine.dispose()


def test_common_query_indexes_exist() -> None:
    engine = make_test_engine()
    inspector = inspect(engine)
    packet_indexes = {item["name"] for item in inspector.get_indexes("packets")}
    alert_indexes = {item["name"] for item in inspector.get_indexes("alerts")}
    assert "ix_packets_session_timestamp" in packet_indexes
    assert "ix_packets_session_protocol" in packet_indexes
    assert "ix_packets_session_src_ip" in packet_indexes
    assert "ix_packets_session_dst_port" in packet_indexes
    assert "ix_alerts_session_first_seen" in alert_indexes
    assert "ix_alerts_session_severity" in alert_indexes
    engine.dispose()


def test_postgres_url_prefixes_select_psycopg_driver() -> None:
    for prefix in ("postgres://", "postgresql://"):
        engine = make_engine(f"{prefix}user:password@localhost/netscope")
        assert engine.url.drivername == "postgresql+psycopg"
        engine.dispose()


def test_bulk_insert_packets_writes_bounded_batches_and_parser_extras() -> None:
    engine = make_test_engine()
    with Session(engine) as db:
        capture = CaptureSession(name="batch", source=CaptureSource.PCAP)
        db.add(capture)
        db.flush()
        packet_rows = [
            {
                "timestamp": 1_760_000_000 + index,
                "src_ip": "192.0.2.10",
                "dst_ip": "198.51.100.53",
                "src_port": 53000 + index,
                "dst_port": 53,
                "protocol": "DNS",
                "length": 72,
                "tcp_flags": None,
                "dns_query": f"example{index}.test",
                "dns_rcode": 0,
                "icmp_type": None,
            }
            for index in range(5)
        ]
        inserted = bulk_insert_packets(db, capture.id, iter(packet_rows), batch_size=2)
        db.commit()
        assert inserted == 5
        saved = db.scalars(select(Packet).order_by(Packet.src_port)).all()
        assert len(saved) == 5
        assert saved[0].extra == {"dns_query": "example0.test", "dns_rcode": 0}
        assert saved[0].timestamp.replace(tzinfo=timezone.utc) == datetime.fromtimestamp(
            1_760_000_000, tz=timezone.utc,
        )
    engine.dispose()
