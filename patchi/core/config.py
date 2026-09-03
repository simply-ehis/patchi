"""
Config system for Patchi.

Reads and writes .patchi/config.json in the current project directory.
All other modules import config through here — never read the JSON directly.
"""

import json
from pathlib import Path
from typing import Any

from patchi.core.constants import (
    CONFIG_FILE,
    MEMORY_DIR,
    MEMORY_FILES,
    PATCHI_DIR,
    QUEUE_FILE,
    SNAPSHOT_DIR,
    DeviceTier,
    MemoryCategory,
    Mode,
    QueueMode,
    RestrictionType,
)

# ── Default config ─────────────────────────────────────────────────────────────


def _default_config() -> dict:
    return {
        "mode": Mode.CONFIRM.value,
        "queue_mode": QueueMode.SINGLE.value,
        "device_tier": DeviceTier.MID.value,
        "fps": 60,
        "theme": "dark",
        "restrictions": [],
        "ignore_paths": ["node_modules", ".git", "__pycache__", ".patchi"],
        "scan_depth": None,
        "brain_freshness_any_change": True,
        "watch_mode": False,
        "risk_threshold": 30,
        "max_fixes_per_cycle": None,
        "dead_code_confirmation": "follow_mode",
        "require_blast_radius_on_high_risk": True,
        "show_confidence_scores": True,
        "ai": {
            "local_model_path": None,
            "local_model_name": None,
            "keys": [],
            "horde_fallback": True,
            "horde_key": "0000000000",
            "cost_limit_enabled": False,
            "cost_limit": None,
            "cost_limit_per_run": None,
        },
        "notifications": [],
        "quiet_hours": {
            "enabled": False,
            "start": "22:00",
            "end": "08:00",
            "timezone": "UTC",
        },
        "digest_frequency": "daily",
        "queue_max_depth": 50,
        "scan_bus": {"enabled": True, "shards": 4},
        "max_scanner_agents": 8,
        "max_security_agents": 19,
        "max_test_agents": 3,
        "onboarding_complete": False,
        "pipeline": {
            "enabled": True,
            "interceptor": {
                "enabled": True,
                "mode": "asgi",
                "block_threshold": 0.7,
                "rate_limit": 100,
                "exclude_paths": ["/health", "/metrics", "/static", "/favicon.ico"],
            },
            "sigma_rules_dir": ".patchi/sigma",
        },
    }


# ── Patchi root detection ──────────────────────────────────────────────────────


def find_project_root(start: Path | None = None) -> Path | None:
    """
    Walk up from start (default: cwd) looking for a .patchi directory.
    Returns the project root Path if found, else None.
    """
    current = start or Path.cwd()
    while True:
        if (current / PATCHI_DIR).is_dir():
            return current
        parent = current.parent
        if parent == current:
            return None
        current = parent


def require_project_root() -> Path:
    """Like find_project_root but raises if not found."""
    root = find_project_root()
    if root is None:
        raise RuntimeError("No .patchi directory found. Run 'p init' in your project folder first.")
    return root


# ── Low-level JSON helpers ─────────────────────────────────────────────────────


def _config_path(root: Path) -> Path:
    return root / CONFIG_FILE


def _read_raw(root: Path) -> dict:
    path = _config_path(root)
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def _write_raw(root: Path, data: dict) -> None:
    path = _config_path(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


# ── Public API ─────────────────────────────────────────────────────────────────


def init_project(root: Path, device_tier: DeviceTier | None = None) -> dict:
    """
    Create the full .patchi directory structure and write default config.
    Safe to call on an already-initialised project (merges, does not overwrite).
    Returns the resulting config dict.
    """
    # Directories
    for directory in [
        root / PATCHI_DIR,
        root / MEMORY_DIR,
        root / SNAPSHOT_DIR,
    ]:
        directory.mkdir(parents=True, exist_ok=True)

    # Memory files — touch if missing
    for category, rel_path in MEMORY_FILES.items():
        mem_path = root / rel_path
        if not mem_path.exists():
            _write_json(mem_path, _default_memory(category))

    # Queue file
    queue_path = root / QUEUE_FILE
    if not queue_path.exists():
        _write_json(queue_path, {"items": [], "paused": False})

    # Config — merge defaults with existing
    existing = _read_raw(root)
    defaults = _default_config()
    if device_tier:
        defaults["device_tier"] = device_tier.value
        defaults["fps"] = device_tier.default_fps()
    merged = {**defaults, **existing}
    _write_raw(root, merged)

    return merged


def _default_memory(category: MemoryCategory) -> dict | list:
    empties: dict[MemoryCategory, dict | list] = {
        MemoryCategory.BRAIN: {},
        MemoryCategory.PATCHES: [],
        MemoryCategory.FAILED: [],
        MemoryCategory.SCANS: {},
        MemoryCategory.ISSUES: [],
        MemoryCategory.RESTRICTIONS: [],
        MemoryCategory.TOKENS: [],
        MemoryCategory.LAYERS: {},
        MemoryCategory.CHARTER: {},
    }
    return empties[category]


def _write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def load(root: Path | None = None) -> dict:
    """Load config for the current project. Merges with defaults for forward compat."""
    root = root or require_project_root()
    raw = _read_raw(root)
    return {**_default_config(), **raw}


def save(config: dict, root: Path | None = None) -> None:
    """Write config back to disk."""
    root = root or require_project_root()
    _write_raw(root, config)


def get(key: str, root: Path | None = None) -> Any:
    """Get a single top-level config value."""
    return load(root)[key]


def set_value(key: str, value: Any, root: Path | None = None) -> None:
    """Update a single config key and save."""
    root = root or require_project_root()
    config = load(root)
    # Support dot-notation for nested keys (e.g. "ai.local_model_name")
    parts = key.split(".")
    node = config
    for part in parts[:-1]:
        node = node.setdefault(part, {})
    node[parts[-1]] = value
    save(config, root)


# ── Mode helpers ───────────────────────────────────────────────────────────────


def get_mode(root: Path | None = None) -> Mode:
    return Mode(get("mode", root))


def set_mode(mode: Mode, root: Path | None = None) -> None:
    set_value("mode", mode.value, root)


def get_queue_mode(root: Path | None = None) -> QueueMode:
    return QueueMode(get("queue_mode", root))


def set_queue_mode(mode: QueueMode, root: Path | None = None) -> None:
    set_value("queue_mode", mode.value, root)


# ── Restriction helpers ────────────────────────────────────────────────────────


def get_restrictions(root: Path | None = None) -> list[dict]:
    return get("restrictions", root)


def add_restriction(
    path: str, rtype: RestrictionType, reason: str = "", root: Path | None = None
) -> None:
    root = root or require_project_root()
    config = load(root)
    # No duplicates
    existing_paths = {r["path"] for r in config["restrictions"]}
    if path not in existing_paths:
        config["restrictions"].append(
            {
                "path": path,
                "type": rtype.value,
                "reason": reason,
                "enabled": True,
            }
        )
        save(config, root)


def remove_restriction(path: str, root: Path | None = None) -> bool:
    root = root or require_project_root()
    config = load(root)
    before = len(config["restrictions"])
    config["restrictions"] = [r for r in config["restrictions"] if r["path"] != path]
    save(config, root)
    return len(config["restrictions"]) < before


def toggle_restriction(path: str, enabled: bool, root: Path | None = None) -> bool:
    root = root or require_project_root()
    config = load(root)
    for r in config["restrictions"]:
        if r["path"] == path:
            r["enabled"] = enabled
            save(config, root)
            return True
    return False


# ── Dev access token helpers ───────────────────────────────────────────────────


def add_dev_token(name: str, env_var: str, root: Path | None = None) -> None:
    root = root or require_project_root()
    config = load(root)
    tokens = config.get("dev_tokens", [])
    if not any(t["name"] == name for t in tokens):
        tokens.append({"name": name, "env_var": env_var})
        config["dev_tokens"] = tokens
        save(config, root)


def remove_dev_token(name: str, root: Path | None = None) -> bool:
    root = root or require_project_root()
    config = load(root)
    tokens = config.get("dev_tokens", [])
    before = len(tokens)
    config["dev_tokens"] = [t for t in tokens if t["name"] != name]
    save(config, root)
    return len(config["dev_tokens"]) < before


def list_dev_tokens(root: Path | None = None) -> list[dict]:
    return load(root).get("dev_tokens", [])
