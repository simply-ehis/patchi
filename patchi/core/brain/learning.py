"""
Learning Brain — tracks user accept/reject patterns to improve future suggestions.

Maintains a Bayesian-style classifier that learns:
- Which finding types the user always accepts → suggest more aggressively
- Which finding types the user always rejects → stop suggesting
- Which fix agents produce patches the user trusts → prioritize those

All data stored in .patchi/learning.json. Zero external dependencies.
"""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path

_LEARNING_FILE = ".patchi/learning.json"

# Minimum samples before we trust the pattern
_MIN_SAMPLES = 3

# Decay factor: older decisions matter less (per day)
_DECAY_HALF_LIFE_DAYS = 30


_log = logging.getLogger("patchi.brain.learning")


def _load(root: Path) -> dict:
    path = root / _LEARNING_FILE
    if not path.exists():
        return {"acceptances": {}, "rejections": {}, "agent_trust": {}}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as e:
        _log.warning("_load failed: %s", e)
        return {"acceptances": {}, "rejections": {}, "agent_trust": {}}


def _save(root: Path, data: dict) -> None:
    path = root / _LEARNING_FILE
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
    tmp.replace(path)


def record_acceptance(finding_type: str, agent_name: str, root: Path) -> None:
    """Record that the user accepted a fix for this finding type."""
    data = _load(root)
    now = time.time()

    acceptances = data.setdefault("acceptances", {})
    acceptances.setdefault(finding_type, []).append(now)
    # Keep last 100 entries per type
    acceptances[finding_type] = acceptances[finding_type][-100:]

    trust = data.setdefault("agent_trust", {})
    trust.setdefault(agent_name, {"accepts": 0, "rejects": 0})
    trust[agent_name]["accepts"] += 1

    _save(root, data)


def record_rejection(finding_type: str, agent_name: str, root: Path) -> None:
    """Record that the user rejected a fix for this finding type."""
    data = _load(root)
    now = time.time()

    rejections = data.setdefault("rejections", {})
    rejections.setdefault(finding_type, []).append(now)
    rejections[finding_type] = rejections[finding_type][-100:]

    trust = data.setdefault("agent_trust", {})
    trust.setdefault(agent_name, {"accepts": 0, "rejects": 0})
    trust[agent_name]["rejects"] += 1

    _save(root, data)


def should_suggest(finding_type: str, root: Path) -> bool:
    """
    Should we suggest a fix for this finding type?
    Returns False if the user has rejected this type 3+ times more than they accepted it.
    """
    data = _load(root)
    acceptances = data.get("acceptances", {}).get(finding_type, [])
    rejections = data.get("rejections", {}).get(finding_type, [])

    total = len(acceptances) + len(rejections)
    if total < _MIN_SAMPLES:
        return True  # Not enough data yet

    # Weighted by recency
    now = time.time()
    accept_score = _recency_weighted(acceptances, now)
    reject_score = _recency_weighted(rejections, now)

    # If rejections outweigh acceptances 3:1, stop suggesting
    if reject_score > accept_score * 3:
        return False

    return True


def get_agent_trust(agent_name: str, root: Path) -> float:
    """
    Get trust score for an agent (0.0 to 1.0).
    1.0 = user always accepts, 0.0 = user always rejects.
    """
    data = _load(root)
    trust = data.get("agent_trust", {}).get(agent_name, {"accepts": 0, "rejects": 0})
    total = trust["accepts"] + trust["rejects"]
    if total < _MIN_SAMPLES:
        return 0.5  # Neutral until we have data
    return trust["accepts"] / total


def get_summary(root: Path) -> dict:
    """Return a summary of learned patterns."""
    data = _load(root)
    time.time()

    summary = {
        "acceptances": {},
        "rejections": {},
        "agent_trust": {},
        "skip_types": [],
    }

    for ftype, timestamps in data.get("acceptances", {}).items():
        summary["acceptances"][ftype] = len(timestamps)

    for ftype, timestamps in data.get("rejections", {}).items():
        summary["rejections"][ftype] = len(timestamps)

    for agent, scores in data.get("agent_trust", {}).items():
        total = scores["accepts"] + scores["rejects"]
        if total >= _MIN_SAMPLES:
            summary["agent_trust"][agent] = round(scores["accepts"] / total, 2)

    # Find types that should be skipped
    for ftype in set(list(data.get("acceptances", {}).keys()) + list(data.get("rejections", {}).keys())):
        if not should_suggest(ftype, root):
            summary["skip_types"].append(ftype)

    return summary


# ── Fix-pattern memory ─────────────────────────────────────────────────────────


def record_fix_pattern(
    finding_type: str,
    file_pattern: str,
    fix_strategy: str,
    fix_summary: str,
    root: Path,
) -> None:
    """Record a successful fix pattern so it can be reused for similar findings."""
    data = _load(root)
    patterns = data.setdefault("fix_patterns", [])
    patterns.append(
        {
            "finding_type": finding_type,
            "file_pattern": file_pattern,
            "fix_strategy": fix_strategy,
            "fix_summary": fix_summary,
            "timestamp": time.time(),
        }
    )
    # Keep last 500 patterns to avoid unbounded growth
    data["fix_patterns"] = patterns[-500:]
    _save(root, data)


def get_fix_pattern(finding_type: str, file_path: str, root: Path) -> dict | None:
    """Find the best matching fix pattern for a given finding type + file path.

    Matches by finding_type first, then by file extension pattern.
    Returns the most recent match, or None.
    """
    data = _load(root)
    patterns = data.get("fix_patterns", [])
    if not patterns:
        return None

    ext = Path(file_path).suffix if file_path else ""
    # Score each pattern: exact type match + optional ext match
    scored: list[tuple[float, dict]] = []
    for p in patterns:
        score = 0.0
        if p.get("finding_type") == finding_type:
            score += 2.0
        if ext and p.get("file_pattern", "").endswith(ext):
            score += 1.0
        if score > 0:
            # Recency bonus: patterns applied within last 7 days get +1
            age = time.time() - p.get("timestamp", 0)
            if age < 604800:
                score += 1.0
            scored.append((score, p))

    if not scored:
        return None
    scored.sort(key=lambda x: -x[0])
    return scored[0][1]


def list_fix_patterns(root: Path, limit: int = 20) -> list[dict]:
    """Return recent fix patterns for display."""
    data = _load(root)
    patterns = data.get("fix_patterns", [])
    return patterns[-limit:]


def _recency_weighted(timestamps: list[float], now: float) -> float:
    """Weight timestamps by recency using exponential decay."""
    import math

    score = 0.0
    for ts in timestamps:
        days_ago = (now - ts) / 86400
        weight = math.exp(-0.693 * days_ago / _DECAY_HALF_LIFE_DAYS)
        score += weight
    return score
