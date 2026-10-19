"""Environment-backed application settings."""

import os

DEFAULT_DATABASE_URL = "sqlite:///./netscope.db"
DEFAULT_MAX_UPLOAD_MB = 100


def database_url() -> str:
    """Return the configured database URL or the local SQLite default."""
    return os.getenv("DATABASE_URL", DEFAULT_DATABASE_URL)


def max_upload_bytes() -> int:
    """Return the configured maximum upload size in bytes."""
    size_mb = int(os.getenv("MAX_UPLOAD_MB", str(DEFAULT_MAX_UPLOAD_MB)))
    if size_mb < 1:
        raise ValueError("MAX_UPLOAD_MB must be at least 1")
    return size_mb * 1024 * 1024
