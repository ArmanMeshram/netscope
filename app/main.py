"""FastAPI entry point for running the NetScope service."""

from contextlib import asynccontextmanager
from collections.abc import AsyncIterator
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.database import create_tables
from app.routers import alerts, packets, sessions
from app import capture, export

@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    """Create database tables before serving requests and close the app cleanly."""
    create_tables()
    yield


app = FastAPI(title="NetScope: Network Traffic Analyzer", lifespan=lifespan)

STATIC_DIR = Path(__file__).resolve().parents[1] / "static"
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


app.include_router(sessions.router)
app.include_router(packets.router)
app.include_router(alerts.router)
app.include_router(export.router)
app.include_router(capture.router)


@app.get("/", include_in_schema=False)
def read_root() -> FileResponse:
    """Serve the single page dashboard."""
    return FileResponse(STATIC_DIR / "index.html")
