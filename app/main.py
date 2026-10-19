"""FastAPI entry point for running the NetScope service."""

from fastapi import FastAPI

app = FastAPI(title="NetScope: Network Traffic Analyzer")


@app.get("/")
def read_root() -> dict[str, str]:
    """Return a small status response while the API is being built out."""
    return {"name": "NetScope", "status": "ok"}
