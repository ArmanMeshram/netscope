"""Capture session upload, lifecycle, and summary endpoints."""

import logging
import os
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, BackgroundTasks, Depends, File, HTTPException, Query, UploadFile, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.config import max_upload_bytes
from app.database import bulk_insert_packets, get_db
from app.models import CaptureSession, CaptureSource, Packet, SessionStatus
from app.parser import parse_pcap
from app.schemas import AddressCount, PortCount, SessionRead, SessionSummary, TrafficBucket

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/sessions", tags=["sessions"])

CLASSIC_PCAP_MAGICS = {
    bytes.fromhex("d4c3b2a1"), bytes.fromhex("a1b2c3d4"),
    bytes.fromhex("4d3cb2a1"), bytes.fromhex("a1b23c4d"),
}
PCAPNG_MAGIC = bytes.fromhex("0a0d0d0a")


def _safe_upload_name(filename: str | None) -> str:
    """Reduce an uploaded filename to a short, safe display name."""
    basename = (filename or "capture.pcap").replace("\\", "/").rsplit("/", 1)[-1]
    cleaned = re.sub(r"[\x00-\x1f\x7f]", "", basename).strip()
    return cleaned[:255] or "capture.pcap"


def process_pcap(session_id: int, path: str) -> None:
    """Parse a staged PCAP and persist packet batches in the background."""
    from app.database import SessionLocal

    db = SessionLocal()
    try:
        capture = db.get(CaptureSession, session_id)
        if capture is None:
            return
        byte_count = 0

        def counted_packets():
            nonlocal byte_count
            for packet in parse_pcap(path):
                byte_count += packet["length"]
                yield packet

        capture.packet_count = bulk_insert_packets(
            db, session_id, counted_packets(), batch_size=1000,
        )
        capture.byte_count = byte_count
        capture.status = SessionStatus.COMPLETED
        capture.ended_at = datetime.now(timezone.utc)
        db.commit()
    except Exception:
        db.rollback()
        capture = db.get(CaptureSession, session_id)
        if capture is not None:
            capture.status = SessionStatus.FAILED
            capture.ended_at = datetime.now(timezone.utc)
            db.commit()
        logger.exception("PCAP processing failed for session %s", session_id)
    finally:
        db.close()
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass


def get_capture_or_404(db: Session, session_id: int) -> CaptureSession:
    """Load a capture session or raise a consistent 404 response."""
    capture = db.get(CaptureSession, session_id)
    if capture is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Session not found")
    return capture


@router.post("/upload", response_model=SessionRead, status_code=status.HTTP_202_ACCEPTED)
async def upload_pcap(
    background_tasks: BackgroundTasks,
    file: Annotated[UploadFile, File(...)],
    db: Annotated[Session, Depends(get_db)],
) -> CaptureSession:
    """Validate and queue a PCAP upload for background processing."""
    filename = _safe_upload_name(file.filename)
    extension = Path(filename).suffix.lower()
    if extension not in {".pcap", ".cap", ".pcapng"}:
        raise HTTPException(status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
                            detail="Upload must use .pcap, .cap, or .pcapng extension")

    maximum = max_upload_bytes()
    staged_path: str | None = None
    size = 0
    prefix = bytearray()
    try:
        with tempfile.NamedTemporaryFile(prefix="netscope-upload-", suffix=extension,
                                         delete=False) as staged:
            staged_path = staged.name
            while chunk := await file.read(64 * 1024):
                size += len(chunk)
                if size > maximum:
                    raise HTTPException(status_code=413,
                                        detail=f"Upload exceeds the {maximum} byte limit")
                if len(prefix) < 4:
                    prefix.extend(chunk[: 4 - len(prefix)])
                staged.write(chunk)

        prefix_bytes = bytes(prefix)
        valid_magic = prefix_bytes == PCAPNG_MAGIC if extension == ".pcapng" else prefix_bytes in CLASSIC_PCAP_MAGICS
        if not valid_magic:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                                detail="File contents do not match a supported PCAP format")

        capture = CaptureSession(
            name=filename, source=CaptureSource.PCAP, status=SessionStatus.PROCESSING,
        )
        db.add(capture)
        db.commit()
        db.refresh(capture)
        background_tasks.add_task(process_pcap, capture.id, staged_path)
        staged_path = None
        return capture
    finally:
        await file.close()
        if staged_path is not None:
            try:
                os.unlink(staged_path)
            except FileNotFoundError:
                pass


@router.get("", response_model=list[SessionRead])
def list_sessions(
    db: Annotated[Session, Depends(get_db)],
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[CaptureSession]:
    """Return capture sessions ordered from newest to oldest."""
    statement = select(CaptureSession).order_by(CaptureSession.started_at.desc(), CaptureSession.id.desc())
    return list(db.scalars(statement.offset(offset).limit(limit)).all())


@router.get("/{session_id}", response_model=SessionRead)
def read_session(session_id: int, db: Annotated[Session, Depends(get_db)]) -> CaptureSession:
    """Return one capture session."""
    return get_capture_or_404(db, session_id)


@router.delete("/{session_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_session(session_id: int, db: Annotated[Session, Depends(get_db)]) -> None:
    """Delete a capture session and its associated packets and alerts."""
    db.delete(get_capture_or_404(db, session_id))
    db.commit()


@router.get("/{session_id}/summary", response_model=SessionSummary)
def session_summary(
    session_id: int,
    db: Annotated[Session, Depends(get_db)],
    bucket_size: Annotated[int, Query(ge=1, le=3600)] = 1,
) -> SessionSummary:
    """Return packet totals, distributions, top endpoints, and traffic buckets."""
    capture = get_capture_or_404(db, session_id)
    base_filter = Packet.session_id == session_id

    protocol_rows = db.execute(
        select(Packet.protocol, func.count(Packet.id))
        .where(base_filter).group_by(Packet.protocol).order_by(Packet.protocol)
    ).all()
    source_rows = db.execute(
        select(Packet.src_ip, func.count(Packet.id))
        .where(base_filter, Packet.src_ip.is_not(None))
        .group_by(Packet.src_ip).order_by(func.count(Packet.id).desc(), Packet.src_ip).limit(10)
    ).all()
    destination_rows = db.execute(
        select(Packet.dst_ip, func.count(Packet.id))
        .where(base_filter, Packet.dst_ip.is_not(None))
        .group_by(Packet.dst_ip).order_by(func.count(Packet.id).desc(), Packet.dst_ip).limit(10)
    ).all()
    port_rows = db.execute(
        select(Packet.dst_port, func.count(Packet.id))
        .where(base_filter, Packet.dst_port.is_not(None))
        .group_by(Packet.dst_port).order_by(func.count(Packet.id).desc(), Packet.dst_port).limit(10)
    ).all()

    bucket_counts: dict[int, int] = {}
    timestamps = db.scalars(
        select(Packet.timestamp).where(base_filter).order_by(Packet.timestamp)
    )
    first_timestamp = last_timestamp = None
    for timestamp in timestamps:
        epoch = timestamp.replace(tzinfo=timezone.utc).timestamp() if timestamp.tzinfo is None else timestamp.timestamp()
        bucket = int(epoch // bucket_size) * bucket_size
        bucket_counts[bucket] = bucket_counts.get(bucket, 0) + 1
        if first_timestamp is None:
            first_timestamp = timestamp
        last_timestamp = timestamp

    if first_timestamp is not None and last_timestamp is not None:
        duration = max(0.0, (last_timestamp - first_timestamp).total_seconds())
    elif capture.ended_at is not None:
        started, ended = capture.started_at, capture.ended_at
        if started.tzinfo is not None and ended.tzinfo is None:
            ended = ended.replace(tzinfo=started.tzinfo)
        duration = max(0.0, (ended - started).total_seconds())
    else:
        duration = 0.0

    return SessionSummary(
        total_packets=capture.packet_count,
        total_bytes=capture.byte_count,
        duration_seconds=duration,
        protocol_distribution={protocol: count for protocol, count in protocol_rows},
        top_sources=[AddressCount(address=address, count=count) for address, count in source_rows],
        top_destinations=[AddressCount(address=address, count=count) for address, count in destination_rows],
        top_ports=[PortCount(port=port, count=count) for port, count in port_rows],
        packets_per_second=[
            TrafficBucket(timestamp=datetime.fromtimestamp(epoch, tz=timezone.utc), packets=count)
            for epoch, count in sorted(bucket_counts.items())
        ],
    )
