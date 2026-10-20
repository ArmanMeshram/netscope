"""Opt-in Scapy live capture management."""

import logging
import threading
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field
from scapy.all import conf, get_if_list, sniff
from sqlalchemy.orm import Session

from app import database
from app.config import live_capture_enabled
from app.detection import run_detection
from app.models import CaptureSession, CaptureSource, SessionStatus
from app.parser import normalize_packet

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/capture", tags=["capture"])
BATCH_SIZE = 500


class CaptureStartRequest(BaseModel):
    """Validated options for starting a live capture."""

    model_config = ConfigDict(extra="forbid")

    interface: str = Field(min_length=1, max_length=128)
    bpf_filter: str | None = Field(default=None, max_length=1024)


class CaptureState(BaseModel):
    """Current live capture state and its session, when active."""

    active: bool
    session_id: int | None = None
    interface: str | None = None
    bpf_filter: str | None = None
    status: str = "idle"


_lock = threading.RLock()
_stop_event: threading.Event | None = None
_capture_thread: threading.Thread | None = None
_state: dict[str, Any] = {
    "active": False, "session_id": None, "interface": None,
    "bpf_filter": None, "status": "idle",
}


def _require_enabled() -> None:
    """Reject live capture routes unless explicitly enabled by configuration."""
    if not live_capture_enabled():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Live capture is disabled. Set ENABLE_LIVE_CAPTURE=true to enable it.",
        )


def _capture_worker(session_id: int, interface: str, bpf_filter: str | None, stop_event: threading.Event) -> None:
    """Sniff packets until stopped and persist each bounded batch."""
    db = database.SessionLocal()
    pending: list[dict[str, Any]] = []
    byte_count = 0
    packet_count = 0
    failed = False

    def flush() -> None:
        nonlocal byte_count, packet_count
        if pending:
            count = len(pending)
            byte_count += sum(row["length"] for row in pending)
            database.bulk_insert_packets(db, session_id, pending, batch_size=BATCH_SIZE)
            db.commit()
            pending.clear()
            packet_count += count
            capture = db.get(CaptureSession, session_id)
            if capture is not None:
                capture.packet_count = packet_count
                capture.byte_count = byte_count
                db.commit()

    try:
        capture = db.get(CaptureSession, session_id)
        if capture is None:
            return

        def collect(packet: Any) -> None:
            try:
                pending.append(normalize_packet(packet))
                if len(pending) >= BATCH_SIZE:
                    flush()
            except Exception:
                logger.exception("Could not normalize a live packet")

        while not stop_event.is_set():
            sniff(
                iface=interface, filter=bpf_filter or None, prn=collect,
                timeout=1, store=False,
            )
        flush()
        run_detection(db, session_id)
        capture = db.get(CaptureSession, session_id)
        if capture is not None:
            capture.status = SessionStatus.COMPLETED
            capture.ended_at = datetime.now(timezone.utc)
            db.commit()
    except Exception as exc:
        failed = True
        logger.exception("Live capture failed for session %s", session_id)
        db.rollback()
        capture = db.get(CaptureSession, session_id)
        if capture is not None:
            capture.status = SessionStatus.FAILED
            capture.ended_at = datetime.now(timezone.utc)
            db.commit()
        with _lock:
            _state["error"] = str(exc)
    finally:
        db.close()
        with _lock:
            _state["status"] = "failed" if failed else "completed"
            _state["active"] = False


@router.get("/interfaces", response_model=list[str])
def interfaces() -> list[str]:
    """List available capture interfaces when live capture is enabled."""
    _require_enabled()
    try:
        return sorted(set(get_if_list()))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Could not list capture interfaces: {exc}") from exc


@router.get("/status", response_model=CaptureState)
def capture_status() -> CaptureState:
    """Return the current live capture state."""
    _require_enabled()
    with _lock:
        return CaptureState(**{key: _state.get(key) for key in ("active", "session_id", "interface", "bpf_filter", "status")})


@router.post("/start", response_model=CaptureState, status_code=status.HTTP_202_ACCEPTED)
def start_capture(request: CaptureStartRequest, db: Session = Depends(database.get_db)) -> CaptureState:
    """Start a single background capture after validating interface and privileges."""
    _require_enabled()
    try:
        available = set(get_if_list())
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Could not list capture interfaces: {exc}") from exc
    if request.interface not in available:
        raise HTTPException(status_code=422, detail="Unknown capture interface")
    with _lock:
        if _state.get("active"):
            raise HTTPException(status_code=409, detail="A live capture is already active")
        try:
            test_socket = conf.L2listen(iface=request.interface, filter=request.bpf_filter or None)
            test_socket.close()
        except (OSError, PermissionError) as exc:
            raise HTTPException(
                status_code=403,
                detail="Live capture requires packet-capture privileges and a supported capture driver.",
            ) from exc
        except Exception as exc:
            raise HTTPException(status_code=422, detail=f"Could not apply the capture filter: {exc}") from exc

        capture = CaptureSession(
            name=f"Live · {request.interface}", source=CaptureSource.LIVE,
            status=SessionStatus.PROCESSING,
        )
        db.add(capture)
        db.commit()
        db.refresh(capture)
        stop_event = threading.Event()
        thread = threading.Thread(
            target=_capture_worker,
            args=(capture.id, request.interface, request.bpf_filter, stop_event),
            name=f"netscope-capture-{capture.id}", daemon=True,
        )
        _state.update({
            "active": True, "session_id": capture.id, "interface": request.interface,
            "bpf_filter": request.bpf_filter, "status": "capturing", "error": None,
        })
        global _stop_event, _capture_thread
        _stop_event, _capture_thread = stop_event, thread
        thread.start()
        return CaptureState(**{key: _state.get(key) for key in ("active", "session_id", "interface", "bpf_filter", "status")})


@router.post("/stop", response_model=CaptureState)
def stop_capture() -> CaptureState:
    """Request a clean stop and wait for the capture thread to flush and finish."""
    _require_enabled()
    with _lock:
        if not _state.get("active") or _stop_event is None or _capture_thread is None:
            raise HTTPException(status_code=409, detail="No live capture is active")
        stop_event, thread = _stop_event, _capture_thread
        _state["status"] = "stopping"
        stop_event.set()
    thread.join(timeout=5)
    with _lock:
        if thread.is_alive():
            raise HTTPException(status_code=503, detail="Capture is still stopping; check status again shortly")
        return CaptureState(**{key: _state.get(key) for key in ("active", "session_id", "interface", "bpf_filter", "status")})
