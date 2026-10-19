"""FastAPI entry point for running the NetScope service."""

from contextlib import asynccontextmanager
from collections.abc import AsyncIterator

from fastapi import FastAPI

from app.database import create_tables
from app.routers import alerts, packets, sessions

@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    """Create database tables before serving requests and close the app cleanly."""
    create_tables()
    yield


app = FastAPI(title="NetScope: Network Traffic Analyzer", lifespan=lifespan)


app.include_router(sessions.router)
app.include_router(packets.router)
app.include_router(alerts.router)


@app.get("/")
def read_root() -> dict[str, str]:
    """Return a small status response while the API is being built out."""
    return {"name": "NetScope", "status": "ok"}
