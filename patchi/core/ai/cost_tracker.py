from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from loguru import logger

_COST_PER_1K_TOKENS = {
    "gpt-4o-mini": (0.00015, 0.00060),
    "gpt-4o": (0.00250, 0.01000),
    "claude-haiku": (0.00025, 0.00125),
    "claude-sonnet": (0.00300, 0.01500),
    "gemini-1.5-flash": (0.000075, 0.00030),
    "llama3-8b": (0.00010, 0.00040),
    "mistral-small": (0.00020, 0.00060),
    "mistralai/Mistral-7B-Instruct-v0.2": (0.0, 0.0),
}

_ACCUMULATED: dict[str, Any] = {
    "total_tokens": 0,
    "calls": 0,
    "cost_estimate": 0.0,
    "by_model": {},
}

_TRACKER_FILE = ""


def init(root: Path) -> None:
    global _TRACKER_FILE
    tracker_dir = root / ".patchi"
    tracker_dir.mkdir(parents=True, exist_ok=True)
    _TRACKER_FILE = str(tracker_dir / "ai_usage.json")
    try:
        with open(_TRACKER_FILE, encoding="utf-8") as f:
            data = json.load(f)
            _ACCUMULATED.update(data)
    except (FileNotFoundError, json.JSONDecodeError):
        pass


# Alias expected by the web app (patchi/web/app.py).
init_cost = init


def _persist() -> None:
    if _TRACKER_FILE:
        try:
            with open(_TRACKER_FILE, "w", encoding="utf-8") as f:
                json.dump(_ACCUMULATED, f, indent=2)
        except Exception as e:
            logger.debug(f"Failed to persist AI usage: {e}")


def track(model: str, prompt_tokens: int, completion_tokens: int) -> None:
    total = prompt_tokens + completion_tokens
    _ACCUMULATED["total_tokens"] += total
    _ACCUMULATED["calls"] += 1

    model_key = model
    for key in _COST_PER_1K_TOKENS:
        if key in model:
            model_key = key
            break
    inp_rate, out_rate = _COST_PER_1K_TOKENS.get(model_key, (0.0, 0.0))
    cost = (prompt_tokens / 1000) * inp_rate + (completion_tokens / 1000) * out_rate
    _ACCUMULATED["cost_estimate"] += cost

    by_model = _ACCUMULATED["by_model"]
    mstats = by_model.setdefault(model, {"calls": 0, "tokens": 0, "cost": 0.0})
    mstats["calls"] += 1
    mstats["tokens"] += total
    mstats["cost"] += cost

    _persist()


def get_stats() -> dict[str, Any]:
    return dict(_ACCUMULATED)


def reset() -> None:
    _ACCUMULATED.clear()
    _ACCUMULATED.update({"total_tokens": 0, "calls": 0, "cost_estimate": 0.0, "by_model": {}})


def check_budget(config: dict) -> str | None:
    limit_cfg = config.get("ai", {})
    if not limit_cfg.get("cost_limit_enabled"):
        return None
    limit = limit_cfg.get("cost_limit", 0)
    if limit <= 0:
        return None
    spent = _ACCUMULATED["cost_estimate"]
    if spent >= limit:
        return f"AI budget exhausted (${spent:.4f} / ${limit:.4f})"
    pct = (spent / limit) * 100
    if pct >= 90:
        return f"AI budget nearly exhausted ({pct:.0f}% used — ${spent:.4f} / ${limit:.4f})"
    if pct >= 75:
        logger.info(f"AI budget at {pct:.0f}% (${spent:.4f} / ${limit:.4f})")
    return None


def estimate_tokens(text: str) -> int:
    return int(len(text) * 1.3)
