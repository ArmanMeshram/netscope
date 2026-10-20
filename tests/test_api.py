from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import sessionmaker
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether
from scapy.utils import wrpcap

import app.database as database
from app.main import app
from app.models import Alert, AlertSeverity


@pytest.fixture
def client(tmp_path, monkeypatch):
    engine = database.make_engine(f"sqlite+pysqlite:///{(tmp_path / 'api.sqlite3').as_posix()}")
    session_factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    monkeypatch.setattr(database, "engine", engine)
    monkeypatch.setattr(database, "SessionLocal", session_factory)
    with TestClient(app) as test_client:
        yield test_client
    engine.dispose()


def sample_pcap(tmp_path) -> bytes:
    """Create a small deterministic capture for API tests."""
    path = tmp_path / "api-sample.pcap"
    wrpcap(str(path), [
        Ether() / IP(src="192.0.2.1", dst="192.0.2.53") / UDP(sport=53000, dport=53) /
        DNS(rd=1, qd=DNSQR(qname="example.test")),
        Ether() / IP(src="192.0.2.1", dst="198.51.100.2") / TCP(sport=51000, dport=443, flags="S"),
        Ether() / ARP(),
    ])
    return path.read_bytes()


def test_dashboard_and_static_assets_are_served(client) -> None:
    dashboard = client.get("/")
    assert dashboard.status_code == 200
    assert "text/html" in dashboard.headers["content-type"]
    assert "Traffic overview" in dashboard.text
    assert "Live capture is only for networks you own or are authorized to monitor." in dashboard.text
    assert client.get("/static/app.js").status_code == 200
    assert client.get("/static/styles.css").status_code == 200


def test_api_timestamps_are_timezone_aware_utc(client, tmp_path) -> None:
    response = client.post(
        "/api/sessions/upload",
        files={"file": ("timestamp-check.pcap", sample_pcap(tmp_path), "application/octet-stream")},
    )
    session_id = response.json()["id"]
    session = client.get(f"/api/sessions/{session_id}").json()
    packet = client.get(f"/api/sessions/{session_id}/packets?limit=1").json()["items"][0]
    bucket = client.get(f"/api/sessions/{session_id}/summary").json()["packets_per_second"][0]

    with database.SessionLocal() as db:
        db.add(Alert(
            session_id=session_id,
            rule="timestamp_test",
            severity=AlertSeverity.LOW,
            description="Check UTC formatting",
            first_seen=datetime.now(timezone.utc),
            last_seen=datetime.now(timezone.utc),
        ))
        db.commit()
    alert = client.get(f"/api/sessions/{session_id}/alerts").json()[0]

    timestamps = [
        session["started_at"], session["ended_at"], packet["timestamp"],
        bucket["timestamp"], alert["first_seen"], alert["last_seen"],
    ]
    for value in timestamps:
        assert value.endswith("Z")
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        assert parsed.tzinfo is not None
        assert parsed.utcoffset() == timezone.utc.utcoffset(parsed)


def test_upload_lists_reads_summarizes_filters_and_deletes_session(client, tmp_path) -> None:
    response = client.post(
        "/api/sessions/upload",
        files={"file": ("../../capture.pcap", sample_pcap(tmp_path), "application/octet-stream")},
    )
    assert response.status_code == 202
    session = response.json()
    session_id = session["id"]
    assert session["name"] == "capture.pcap"
    # TestClient waits for the registered background task to finish.
    detail = client.get(f"/api/sessions/{session_id}").json()
    assert detail["status"] == "completed"
    assert detail["packet_count"] == 3
    assert detail["byte_count"] > 0

    sessions = client.get("/api/sessions").json()
    assert len(sessions) == 1
    summary = client.get(f"/api/sessions/{session_id}/summary?bucket_size=10").json()
    assert summary["total_packets"] == 3
    assert summary["total_bytes"] == detail["byte_count"]
    assert summary["protocol_distribution"] == {"DNS": 1, "OTHER": 1, "TCP": 1}
    assert sum(item["packets"] for item in summary["packets_per_second"]) == 3
    assert summary["top_sources"][0]["address"] == "192.0.2.1"
    assert summary["top_ports"][0]["port"] == 53

    packet_page = client.get(
        f"/api/sessions/{session_id}/packets?protocol=dns&port=53&limit=1",
    ).json()
    assert packet_page["total"] == 1
    assert packet_page["items"][0]["protocol"] == "DNS"
    assert packet_page["limit"] == 1
    invalid_range = client.get(
        f"/api/sessions/{session_id}/packets?from=2026-01-02T00:00:00&to=2026-01-01T00:00:00",
    )
    assert invalid_range.status_code == 422

    with database.SessionLocal() as db:
        db.add(Alert(
            session_id=session_id,
            rule="test_rule",
            severity=AlertSeverity.LOW,
            description="Test alert",
            src_ip="192.0.2.1",
            first_seen=datetime.now(timezone.utc),
            last_seen=datetime.now(timezone.utc),
            alert_metadata={"evidence": 1},
        ))
        db.commit()
    alerts = client.get(f"/api/sessions/{session_id}/alerts").json()
    assert len(alerts) == 1
    assert alerts[0]["alert_metadata"] == {"evidence": 1}

    csv_export = client.get(f"/api/sessions/{session_id}/export?format=csv")
    assert csv_export.status_code == 200
    assert "text/csv" in csv_export.headers["content-type"]
    assert "192.0.2.1" in csv_export.text
    json_export = client.get(f"/api/sessions/{session_id}/export?format=json")
    assert json_export.status_code == 200
    exported = json_export.json()
    assert len(exported["packets"]) == 3
    assert exported["packets"][0]["timestamp"].endswith("Z")
    assert exported["alerts"][0]["rule"] == "test_rule"
    assert exported["alerts"][0]["first_seen"].endswith("Z")
    assert client.get(f"/api/sessions/{session_id}/export?format=xml").status_code == 422
    assert client.get("/api/sessions/999/export").status_code == 404

    assert client.delete(f"/api/sessions/{session_id}").status_code == 204
    assert client.get(f"/api/sessions/{session_id}").status_code == 404


def test_upload_rejects_bad_extension_and_magic(client) -> None:
    bad_extension = client.post(
        "/api/sessions/upload", files={"file": ("capture.txt", b"data", "text/plain")},
    )
    assert bad_extension.status_code == 415
    bad_magic = client.post(
        "/api/sessions/upload", files={"file": ("capture.pcap", b"nope", "application/octet-stream")},
    )
    assert bad_magic.status_code == 400
    assert client.get("/api/sessions").json() == []


def test_pcap_processing_runs_detection_and_persists_alerts(client, tmp_path) -> None:
    path = tmp_path / "port-scan.pcap"
    wrpcap(str(path), [
        Ether() / IP(src="192.0.2.50", dst="198.51.100.20") /
        TCP(sport=40000 + port, dport=port, flags="S")
        for port in range(1, 26)
    ])
    response = client.post(
        "/api/sessions/upload",
        files={"file": ("port-scan.pcap", path.read_bytes(), "application/octet-stream")},
    )
    assert response.status_code == 202
    session_id = response.json()["id"]
    assert client.get(f"/api/sessions/{session_id}").json()["status"] == "completed"
    alerts = client.get(f"/api/sessions/{session_id}/alerts").json()
    assert len(alerts) == 1
    assert alerts[0]["rule"] == "port_scan"
    assert alerts[0]["alert_metadata"]["distinct_ports"] == 25


def test_upload_enforces_configured_size_limit(client, tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("MAX_UPLOAD_MB", "1")
    payload = bytes.fromhex("d4c3b2a1") + bytes(1024 * 1024)
    response = client.post(
        "/api/sessions/upload",
        files={"file": ("large.pcap", payload, "application/octet-stream")},
    )
    assert response.status_code == 413
    assert client.get("/api/sessions").json() == []


def test_missing_session_returns_not_found(client) -> None:
    assert client.get("/api/sessions/999/summary").status_code == 404
    assert client.get("/api/sessions/999/packets?from=2026-01-02T00:00:00&to=2026-01-01T00:00:00").status_code == 404


def test_live_capture_is_disabled_by_default(client, monkeypatch) -> None:
    monkeypatch.setenv("ENABLE_LIVE_CAPTURE", "false")
    assert client.get("/api/capture/interfaces").status_code == 503
    assert client.get("/api/capture/status").status_code == 503
    response = client.post("/api/capture/start", json={"interface": "lo"})
    assert response.status_code == 503
    assert "ENABLE_LIVE_CAPTURE=true" in response.json()["detail"]


def test_live_capture_starts_flushes_and_stops_cleanly(client, monkeypatch) -> None:
    import time

    import app.capture as capture_module

    class FakeSocket:
        def close(self) -> None:
            pass

    monkeypatch.setenv("ENABLE_LIVE_CAPTURE", "true")
    monkeypatch.setattr(capture_module, "get_if_list", lambda: ["test0"])
    monkeypatch.setattr(capture_module.conf, "L2listen", lambda **kwargs: FakeSocket())

    def fake_sniff(**kwargs) -> None:
        kwargs["prn"](Ether() / IP(src="192.0.2.1", dst="198.51.100.1") / TCP(sport=50000, dport=443, flags="A"))
        time.sleep(0.005)

    monkeypatch.setattr(capture_module, "sniff", fake_sniff)
    response = client.post("/api/capture/start", json={"interface": "test0"})
    assert response.status_code == 202
    session_id = response.json()["session_id"]
    assert response.json()["active"] is True
    assert client.get("/api/capture/status").json()["interface"] == "test0"
    stopped = client.post("/api/capture/stop")
    assert stopped.status_code == 200
    assert stopped.json()["active"] is False
    detail = client.get(f"/api/sessions/{session_id}").json()
    assert detail["status"] == "completed"
    assert detail["packet_count"] > 0
    page = client.get(f"/api/sessions/{session_id}/packets").json()
    assert page["items"][0]["protocol"] == "TCP"
