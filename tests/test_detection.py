from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool
from sqlalchemy import create_engine

from app.database import Base, bulk_insert_packets
from app.detection import (
    detect_dns_nxdomain_rate,
    detect_dns_query_rate,
    detect_icmp_floods,
    detect_long_dns_queries,
    detect_port_scans,
    detect_syn_floods,
    run_detection,
)
from app.models import Alert, CaptureSession, CaptureSource
from app.parser import parse_pcap
from scripts.generate_sample_pcaps import OUTPUT as SYNTHETIC_DIR
from scripts.generate_sample_pcaps import generate as generate_sample_pcaps


def packets_from(path: Path) -> list[dict]:
    """Read a small synthetic fixture into records for individually tested rules."""
    return list(parse_pcap(path))


def test_each_detection_rule_fires_on_its_synthetic_capture() -> None:
    generate_sample_pcaps()
    port_scan = packets_from(SYNTHETIC_DIR / "port_scan.pcap")
    syn_flood = packets_from(SYNTHETIC_DIR / "syn_flood.pcap")
    dns_anomalies = packets_from(SYNTHETIC_DIR / "dns_anomalies.pcap")
    icmp_flood = packets_from(SYNTHETIC_DIR / "icmp_flood.pcap")

    port_alerts = detect_port_scans(port_scan, session_id=1)
    syn_alerts = detect_syn_floods(syn_flood, session_id=1)
    long_dns_alerts = detect_long_dns_queries(dns_anomalies, session_id=1)
    nxdomain_alerts = detect_dns_nxdomain_rate(dns_anomalies, session_id=1)
    query_rate_alerts = detect_dns_query_rate(dns_anomalies, session_id=1)
    icmp_alerts = detect_icmp_floods(icmp_flood, session_id=1)

    assert port_alerts and port_alerts[0].rule == "port_scan"
    assert port_alerts[0].alert_metadata["distinct_ports"] > port_alerts[0].alert_metadata["threshold"]
    assert syn_alerts and syn_alerts[0].rule == "syn_flood"
    assert syn_alerts[0].alert_metadata["incomplete_handshakes"] > 100
    assert long_dns_alerts and long_dns_alerts[0].alert_metadata["query_length"] > 100
    assert nxdomain_alerts and nxdomain_alerts[0].alert_metadata["nxdomain_rate"] > 0.5
    assert query_rate_alerts and query_rate_alerts[0].rule == "dns_query_rate"
    assert icmp_alerts and icmp_alerts[0].alert_metadata["packets_per_second"] > 100


def test_normal_synthetic_traffic_does_not_trigger_rules() -> None:
    generate_sample_pcaps()
    normal = packets_from(SYNTHETIC_DIR / "synthetic_normal_traffic.pcap")
    detectors = (
        detect_port_scans,
        detect_syn_floods,
        detect_long_dns_queries,
        detect_dns_nxdomain_rate,
        detect_dns_query_rate,
        detect_icmp_floods,
    )
    for detector in detectors:
        assert detector(normal, session_id=1) == []


def test_run_detection_persists_alerts_from_session_packets() -> None:
    generate_sample_pcaps()
    packets = packets_from(SYNTHETIC_DIR / "port_scan.pcap")
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        capture = CaptureSession(name="port scan", source=CaptureSource.PCAP)
        db.add(capture)
        db.flush()
        bulk_insert_packets(db, capture.id, packets, batch_size=25)
        alerts = run_detection(db, capture.id)
        db.commit()

        stored = db.scalars(select(Alert).where(Alert.session_id == capture.id)).all()
        assert len(alerts) == 1
        assert len(stored) == 1
        assert stored[0].rule == "port_scan"
        assert stored[0].alert_metadata["target_ip"] == "198.51.100.20"
    engine.dispose()
