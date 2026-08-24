"""
Log parsers for Patchi hosted mode.

Parses 7 log formats into a unified LogEntry structure.
Uses loguru for internal structured logging of parse errors.

Supported formats:
  nginx, apache, caddy, uvicorn, gunicorn, cloudflare (JSON), generic JSON
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field

from loguru import logger


@dataclass
class LogEntry:
    """Unified log entry across all formats."""

    timestamp: float
    level: str  # INFO / WARNING / ERROR / CRITICAL
    method: str  # HTTP method or ""
    path: str  # URL path or ""
    status: int  # HTTP status or 0
    ip: str  # client IP or ""
    message: str  # raw log line or parsed message
    source: str  # parser name
    extra: dict = field(default_factory=dict)


# ── Shared patterns ────────────────────────────────────────────────────────────

_NGINX_RE = re.compile(
    r"(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] "
    r'"(?P<method>\w+) (?P<path>\S+) [^"]*" (?P<status>\d+) (?P<bytes>\d+)'
)

_APACHE_RE = re.compile(
    r"(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] "
    r'"(?P<method>\w+) (?P<path>\S+) [^"]*" (?P<status>\d+)'
)

_CADDY_RE = re.compile(
    r"(?P<ts>\d{4}-\d{2}-\d{2}T\S+)\s+(?P<level>\w+)\s+"
    r'http\.log\.access.*?"method":"(?P<method>\w+)".*?"uri":"(?P<path>[^"]+)"'
    r'.*?"status":(?P<status>\d+).*?"remote_ip":"(?P<ip>[^"]+)"'
)

_UVICORN_RE = re.compile(
    r'(?P<ip>\S+):(?:\d+) - "(?P<method>\w+) (?P<path>\S+) [^"]*" (?P<status>\d+)'
)

_GUNICORN_RE = re.compile(
    r"(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] "
    r'"(?P<method>\w+) (?P<path>\S+) [^"]*" (?P<status>\d+)'
)


def _status_to_level(status: int) -> str:
    if status >= 500:
        return "ERROR"
    if status >= 400:
        return "WARNING"
    return "INFO"


def _now() -> float:
    return time.time()


# ── Individual parsers ─────────────────────────────────────────────────────────


def parse_nginx(line: str) -> LogEntry | None:
    m = _NGINX_RE.match(line)
    if not m:
        return None
    status = int(m.group("status"))
    return LogEntry(
        timestamp=_now(),
        level=_status_to_level(status),
        method=m.group("method"),
        path=m.group("path"),
        status=status,
        ip=m.group("ip"),
        message=line,
        source="nginx",
        extra={"bytes": m.group("bytes"), "raw_time": m.group("time")},
    )


def parse_apache(line: str) -> LogEntry | None:
    m = _APACHE_RE.match(line)
    if not m:
        return None
    status = int(m.group("status"))
    return LogEntry(
        timestamp=_now(),
        level=_status_to_level(status),
        method=m.group("method"),
        path=m.group("path"),
        status=status,
        ip=m.group("ip"),
        message=line,
        source="apache",
    )


def parse_caddy(line: str) -> LogEntry | None:
    m = _CADDY_RE.search(line)
    if not m:
        return None
    status = int(m.group("status"))
    return LogEntry(
        timestamp=_now(),
        level=_status_to_level(status),
        method=m.group("method"),
        path=m.group("path"),
        status=status,
        ip=m.group("ip"),
        message=line,
        source="caddy",
    )


def parse_uvicorn(line: str) -> LogEntry | None:
    m = _UVICORN_RE.search(line)
    if not m:
        return None
    status = int(m.group("status"))
    return LogEntry(
        timestamp=_now(),
        level=_status_to_level(status),
        method=m.group("method"),
        path=m.group("path"),
        status=status,
        ip=m.group("ip"),
        message=line,
        source="uvicorn",
    )


def parse_gunicorn(line: str) -> LogEntry | None:
    m = _GUNICORN_RE.match(line)
    if not m:
        return None
    status = int(m.group("status"))
    return LogEntry(
        timestamp=_now(),
        level=_status_to_level(status),
        method=m.group("method"),
        path=m.group("path"),
        status=status,
        ip=m.group("ip"),
        message=line,
        source="gunicorn",
    )


def parse_cloudflare(line: str) -> LogEntry | None:
    """Cloudflare logs ship as JSON objects."""
    try:
        d = json.loads(line)
        status = int(d.get("EdgeResponseStatus", d.get("CacheResponseStatus", 0)))
        return LogEntry(
            timestamp=_now(),
            level=_status_to_level(status),
            method=d.get("ClientRequestMethod", ""),
            path=d.get("ClientRequestURI", ""),
            status=status,
            ip=d.get("ClientIP", ""),
            message=line,
            source="cloudflare",
            extra={
                k: v
                for k, v in d.items()
                if k
                not in (
                    "ClientRequestMethod",
                    "ClientRequestURI",
                    "ClientIP",
                    "EdgeResponseStatus",
                    "CacheResponseStatus",
                )
            },
        )
    except (json.JSONDecodeError, ValueError):
        return None


def parse_json(line: str) -> LogEntry | None:
    """Generic JSON log line — best-effort field extraction."""
    try:
        d = json.loads(line)
        status = int(d.get("status", d.get("status_code", 0)))
        return LogEntry(
            timestamp=float(d.get("timestamp", d.get("ts", _now()))),
            level=d.get("level", d.get("severity", _status_to_level(status))).upper(),
            method=d.get("method", ""),
            path=d.get("path", d.get("url", d.get("uri", ""))),
            status=status,
            ip=d.get("ip", d.get("remote_addr", d.get("client_ip", ""))),
            message=d.get("message", d.get("msg", line)),
            source="json",
            extra=d,
        )
    except (json.JSONDecodeError, ValueError):
        return None


# ── Auto-detect and parse ──────────────────────────────────────────────────────

_PARSERS = [
    parse_cloudflare,
    parse_nginx,
    parse_apache,
    parse_caddy,
    parse_uvicorn,
    parse_gunicorn,
    parse_json,  # generic JSON last — format-specific parsers take priority
]


def parse_line(line: str) -> LogEntry | None:
    """Try all parsers in order. Returns first successful result or None."""
    line = line.strip()
    if not line:
        return None
    for parser in _PARSERS:
        try:
            entry = parser(line)
            if entry:
                return entry
        except Exception as e:
            logger.debug(f"Parser {parser.__name__} error: {e}")
    return None


def parse_lines(lines: list[str]) -> list[LogEntry]:
    """Parse a batch of lines, skipping unparseable ones."""
    results = []
    for line in lines:
        entry = parse_line(line)
        if entry:
            results.append(entry)
    return results
