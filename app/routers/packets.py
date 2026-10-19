"""Paginated and filterable packet endpoints."""

from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import CaptureSession, Packet
from app.schemas import PacketPage

router = APIRouter(prefix="/api/sessions", tags=["packets"])


@router.get("/{session_id}/packets", response_model=PacketPage)
def list_packets(
    session_id: int,
    db: Annotated[Session, Depends(get_db)],
    limit: Annotated[int, Query(ge=1, le=1000)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
    protocol: str | None = None,
    src_ip: str | None = None,
    dst_ip: str | None = None,
    port: Annotated[int | None, Query(ge=0, le=65535)] = None,
    start_time: Annotated[datetime | None, Query(alias="from")] = None,
    end_time: Annotated[datetime | None, Query(alias="to")] = None,
) -> PacketPage:
    """Return one packet page matching the optional query filters."""
    if db.get(CaptureSession, session_id) is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Session not found")
    if start_time is not None and end_time is not None and start_time > end_time:
        raise HTTPException(status_code=422,
                            detail="The 'from' time must not be later than the 'to' time")

    filters = [Packet.session_id == session_id]
    if protocol:
        filters.append(Packet.protocol == protocol.strip().upper())
    if src_ip:
        filters.append(Packet.src_ip == src_ip.strip())
    if dst_ip:
        filters.append(Packet.dst_ip == dst_ip.strip())
    if port is not None:
        filters.append(or_(Packet.src_port == port, Packet.dst_port == port))
    if start_time is not None:
        filters.append(Packet.timestamp >= start_time)
    if end_time is not None:
        filters.append(Packet.timestamp <= end_time)

    total = db.scalar(select(func.count(Packet.id)).where(*filters)) or 0
    items = db.scalars(
        select(Packet).where(*filters)
        .order_by(Packet.timestamp, Packet.id)
        .offset(offset).limit(limit)
    ).all()
    return PacketPage(items=list(items), total=total, limit=limit, offset=offset)
