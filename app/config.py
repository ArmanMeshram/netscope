"""Environment-backed application settings."""

import os
from dataclasses import dataclass

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


@dataclass(frozen=True)
class DetectionThresholds:
    """Thresholds used by the independent anomaly detection rules."""

    port_scan_distinct_ports: int = 20
    port_scan_window_seconds: int = 60
    syn_flood_threshold: int = 100
    syn_flood_window_seconds: int = 10
    dns_max_query_length: int = 100
    dns_nxdomain_min_queries: int = 20
    dns_nxdomain_rate: float = 0.5
    dns_query_rate_threshold: int = 50
    dns_query_rate_window_seconds: int = 10
    icmp_flood_pps: int = 100


def detection_thresholds() -> DetectionThresholds:
    """Load anomaly thresholds from environment variables."""
    defaults = DetectionThresholds()
    return DetectionThresholds(
        port_scan_distinct_ports=int(os.getenv("PORT_SCAN_DISTINCT_PORTS", defaults.port_scan_distinct_ports)),
        port_scan_window_seconds=int(os.getenv("PORT_SCAN_WINDOW_SECONDS", defaults.port_scan_window_seconds)),
        syn_flood_threshold=int(os.getenv("SYN_FLOOD_THRESHOLD", defaults.syn_flood_threshold)),
        syn_flood_window_seconds=int(os.getenv("SYN_FLOOD_WINDOW_SECONDS", defaults.syn_flood_window_seconds)),
        dns_max_query_length=int(os.getenv("DNS_MAX_QUERY_LENGTH", defaults.dns_max_query_length)),
        dns_nxdomain_min_queries=int(os.getenv("DNS_NXDOMAIN_MIN_QUERIES", defaults.dns_nxdomain_min_queries)),
        dns_nxdomain_rate=float(os.getenv("DNS_NXDOMAIN_RATE", defaults.dns_nxdomain_rate)),
        dns_query_rate_threshold=int(os.getenv("DNS_QUERY_RATE_THRESHOLD", defaults.dns_query_rate_threshold)),
        dns_query_rate_window_seconds=int(os.getenv("DNS_QUERY_RATE_WINDOW_SECONDS", defaults.dns_query_rate_window_seconds)),
        icmp_flood_pps=int(os.getenv("ICMP_FLOOD_PPS", defaults.icmp_flood_pps)),
    )
