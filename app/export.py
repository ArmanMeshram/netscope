"""Streaming export endpoints for stored capture sessions."""

import csv
import io
import json
from collections.abc import Iterator
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import StreamingResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import database
from app.database import get_db
from app.models import Alert, CaptureSession, Packet
from app.schemas import utc_isoformat

router = APIRouter(prefix="/api/sessions", tags=["export"])
CSV_FIELDS = (
    "timestamp", "src_ip", "dst_ip", "src_port", "dst_port", "protocol",
    "length", "tcp_flags", "extra",
)


def _packet_values(packet: Packet) -> dict[str, Any]:
    """Convert a packet row to a JSON-ready record."""
    return {
        "timestamp": utc_isoformat(packet.timestamp),
        "src_ip": packet.src_ip,
        "dst_ip": packet.dst_ip,
        "src_port": packet.src_port,
        "dst_port": packet.dst_port,
        "protocol": packet.protocol,
        "length": packet.length,
        "tcp_flags": packet.tcp_flags,
        "extra": packet.extra or {},
    }


def _stream_csv(session_id: int) -> Iterator[str]:
    """Yield CSV text incrementally while keeping database reads bounded."""
    db = database.SessionLocal()
    try:
        buffer = io.StringIO(newline="")
        writer = csv.DictWriter(buffer, fieldnames=CSV_FIELDS)
        writer.writeheader()
        yield buffer.getvalue()
        buffer.seek(0)
        buffer.truncate(0)
        packets = db.scalars(
            select(Packet).where(Packet.session_id == session_id)
            .order_by(Packet.timestamp, Packet.id).execution_options(stream_results=True)
        ).yield_per(1000)
        for packet in packets:
            writer.writerow({**_packet_values(packet), "extra": json.dumps(packet.extra or {})})
            yield buffer.getvalue()
            buffer.seek(0)
            buffer.truncate(0)
    finally:
        db.close()


def _stream_json(session_id: int) -> Iterator[str]:
    """Yield a valid JSON export incrementally, including associated alerts."""
    db = database.SessionLocal()
    try:
        yield '{"packets":['
        packets = db.scalars(
            select(Packet).where(Packet.session_id == session_id)
            .order_by(Packet.timestamp, Packet.id).execution_options(stream_results=True)
        ).yield_per(1000)
        first = True
        for packet in packets:
            if not first:
                yield ","
            yield json.dumps(_packet_values(packet), separators=(",", ":"))
            first = False
        yield '],"alerts":['
        alerts = db.scalars(
            select(Alert).where(Alert.session_id == session_id)
            .order_by(Alert.first_seen, Alert.id).execution_options(stream_results=True)
        ).yield_per(500)
        first = True
        for alert in alerts:
            if not first:
                yield ","
            data = {
                "rule": alert.rule,
                "severity": alert.severity.value,
                "description": alert.description,
                "src_ip": alert.src_ip,
                "first_seen": utc_isoformat(alert.first_seen),
                "last_seen": utc_isoformat(alert.last_seen),
                "metadata": alert.alert_metadata or {},
            }
            yield json.dumps(data, separators=(",", ":"))
            first = False
        yield "]}"
    finally:
        db.close()


@router.get("/{session_id}/export")
def export_session(
    session_id: int,
    format: str = Query(default="json", pattern="^(csv|json)$"),
    db: Session = Depends(get_db),
) -> StreamingResponse:
    """Stream packets as CSV or JSON, with alerts included in JSON exports."""
    capture = db.get(CaptureSession, session_id)
    if capture is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Session not found")
    filename = f"netscope-session-{session_id}.{format}"
    if format == "csv":
        return StreamingResponse(
            _stream_csv(session_id), media_type="text/csv; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )
    return StreamingResponse(
        _stream_json(session_id), media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
