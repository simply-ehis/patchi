"""
Pattern loader for security agents.

Loads sink/source patterns from YAML config and merges them with
agent-specific defaults. Agents call `load_patterns()` once at
startup and use the returned dict.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

_PATTERNS_CACHE: dict[str, Any] | None = None
_PATTERNS_PATH = Path(__file__).parent / "security_patterns.yaml"


def load_patterns(path: Path | None = None) -> dict[str, Any]:
    """Load and cache security patterns from YAML config."""
    global _PATTERNS_CACHE
    if _PATTERNS_CACHE is not None and path is None:
        return _PATTERNS_CACHE

    config_path = path or _PATTERNS_PATH
    if not config_path.exists():
        return {}

    with open(config_path, encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}

    _PATTERNS_CACHE = data
    return data


def get_injection_sinks(patterns: dict | None = None) -> dict[str, dict[str, list[str]]]:
    """Get injection sinks grouped by type and language."""
    p = patterns or load_patterns()
    return p.get("injection", {})


def get_ssrf_patterns(patterns: dict | None = None) -> dict[str, Any]:
    """Get SSRF detection patterns."""
    p = patterns or load_patterns()
    return p.get("ssrf", {})


def get_ssrf_protocol_patterns(patterns: dict | None = None) -> list[tuple[re.Pattern, str, str]]:
    """Get compiled SSRF protocol regex patterns with severity and message."""
    ssrf = get_ssrf_patterns(patterns)
    result = []
    for entry in ssrf.get("protocol_patterns", []):
        try:
            compiled = re.compile(entry["pattern"], re.IGNORECASE)
            result.append((compiled, entry["severity"], entry["message"]))
        except re.error:
            continue
    return result


def get_ssrf_metadata_patterns(patterns: dict | None = None) -> list[tuple[re.Pattern, str, str]]:
    """Get compiled SSRF metadata endpoint regex patterns."""
    ssrf = get_ssrf_patterns(patterns)
    result = []
    for entry in ssrf.get("metadata_patterns", []):
        try:
            compiled = re.compile(entry["pattern"], re.IGNORECASE)
            result.append((compiled, entry["severity"], entry["message"]))
        except re.error:
            continue
    return result


def get_ssrf_internal_network_patterns(patterns: dict | None = None) -> list[tuple[re.Pattern, str, str]]:
    """Get compiled SSRF internal network regex patterns."""
    ssrf = get_ssrf_patterns(patterns)
    result = []
    for entry in ssrf.get("internal_network", []):
        try:
            compiled = re.compile(entry["pattern"])
            result.append((compiled, entry["severity"], entry["message"]))
        except re.error:
            continue
    return result


def get_catch_noop_patterns(patterns: dict | None = None) -> list[re.Pattern]:
    """Get compiled catch block no-op regex patterns."""
    p = patterns or load_patterns()
    cb = p.get("catch_block", {})
    result = []
    for pat_str in cb.get("noop_patterns", []):
        try:
            result.append(re.compile(pat_str))
        except re.error:
            continue
    return result
