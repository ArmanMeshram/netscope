"""Session alert endpoints."""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Alert, CaptureSession
from app.schemas import AlertRead

router = APIRouter(prefix="/api/sessions", tags=["alerts"])


@router.get("/{session_id}/alerts", response_model=list[AlertRead])
def list_alerts(
    session_id: int,
    db: Annotated[Session, Depends(get_db)],
) -> list[Alert]:
    """Return alerts for a capture session in chronological order."""
    if db.get(CaptureSession, session_id) is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Session not found")
    statement = select(Alert).where(Alert.session_id == session_id).order_by(Alert.first_seen, Alert.id)
    return list(db.scalars(statement).all())
