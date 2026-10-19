"""Environment-backed application settings."""

import os

DEFAULT_DATABASE_URL = "sqlite:///./netscope.db"


def database_url() -> str:
    """Return the configured database URL or the local SQLite default."""
    return os.getenv("DATABASE_URL", DEFAULT_DATABASE_URL)
