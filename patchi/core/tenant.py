"""
Tenant Manager — Project-level state isolation for multi-tenant operation.

Each project gets isolated:
- Brain state (.patchi/)
- Scan results
- Cost tracking
- Findings history
- Configuration

The active project is tracked in the server state and can be switched at runtime.
Supports request-scoped tenant context for concurrent web requests.
"""

from __future__ import annotations

import json
import logging
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

_log = logging.getLogger("patchi.tenant")

# Thread-local storage for request-scoped tenant context
_thread_local = threading.local()


@dataclass
class TenantState:
    """State for a single project/tenant."""

    root: Path
    name: str
    active: bool = True
    last_accessed: str = ""
    findings_count: int = 0
    scan_count: int = 0
    cost_estimate: float = 0.0

    def to_dict(self) -> dict:
        return {
            "root": str(self.root),
            "name": self.name,
            "active": self.active,
            "last_accessed": self.last_accessed,
            "findings_count": self.findings_count,
            "scan_count": self.scan_count,
            "cost_estimate": self.cost_estimate,
        }


class TenantManager:
    """Manages multiple project tenants with state isolation."""

    def __init__(self, state_dir: Path | None = None):
        self._state_dir = state_dir or Path.home() / ".patchi" / "tenants"
        self._state_dir.mkdir(parents=True, exist_ok=True)
        self._tenants: dict[str, TenantState] = {}
        self._active_tenant: str | None = None
        self._load_state()

    def register_project(self, root: Path, name: str | None = None) -> TenantState:
        """Register a project as a tenant."""
        key = str(root.resolve())
        if key in self._tenants:
            self._tenants[key].active = True
            return self._tenants[key]

        tenant = TenantState(
            root=root.resolve(),
            name=name or root.name,
            active=True,
        )
        self._tenants[key] = tenant
        self._save_state()
        _log.info("Registered tenant: %s (%s)", tenant.name, key)
        return tenant

    def switch_project(self, root: Path) -> TenantState:
        """Switch to a different project."""
        key = str(root.resolve())
        if key not in self._tenants:
            self.register_project(root)

        # Deactivate previous
        if self._active_tenant and self._active_tenant in self._tenants:
            self._tenants[self._active_tenant].active = False

        # Activate new
        self._tenants[key].active = True
        self._active_tenant = key

        # Initialize the project state
        self._init_project_state(root)

        self._save_state()
        _log.info("Switched to tenant: %s", self._tenants[key].name)
        return self._tenants[key]

    def get_active(self) -> TenantState | None:
        """Get the currently active tenant."""
        if self._active_tenant:
            return self._tenants.get(self._active_tenant)
        return None

    def get_active_root(self) -> Path:
        """Get the active project root path."""
        tenant = self.get_active()
        if tenant:
            return tenant.root
        # Fallback to current working directory
        return Path.cwd()

    def list_projects(self) -> list[TenantState]:
        """List all registered projects."""
        return list(self._tenants.values())

    def remove_project(self, root: Path) -> bool:
        """Remove a project from the tenant list."""
        key = str(root.resolve())
        if key in self._tenants:
            del self._tenants[key]
            if self._active_tenant == key:
                self._active_tenant = None
            self._save_state()
            return True
        return False

    def discover_projects(
        self, near: Path | None = None, max_depth: int = 2, limit: int = 25
    ) -> list[Path]:
        """Find Patchi projects on disk near a reference directory.

        Search bases (deduplicated):
          - the reference dir itself and its parent (siblings pattern:
            ~/repos/project-a while viewing project-b)
          - one level of children of the parent (workspace folders)

        Only directories containing .patchi/ count. Bounded scan — never
        walks the whole filesystem, and never scans the system temp tree
        (test fixtures would flood the results).
        """
        import tempfile

        base = (near or Path.cwd()).resolve()
        candidates: dict[str, Path] = {}
        roots_to_scan: list[Path] = []

        for candidate_base in (base, base.parent, base.parent.parent):
            if not candidate_base.is_dir():
                continue
            if candidate_base not in roots_to_scan:
                roots_to_scan.append(candidate_base)

        # The system temp tree is full of throwaway test fixtures — exclude it
        # and everything beneath it from discovery.
        try:
            sys_temp = Path(tempfile.gettempdir()).resolve()

            def _in_temp(p: Path) -> bool:
                try:
                    return p == sys_temp or sys_temp in p.parents
                except OSError:
                    return False

            roots_to_scan = [r for r in roots_to_scan if not _in_temp(r)]
        except Exception as _exc:
            _log.warning('discover_projects failed: %s', _exc)

        for scan_root in roots_to_scan:
            try:
                for child in sorted(scan_root.iterdir()):
                    if len(candidates) >= limit:
                        break
                    if not child.is_dir() or child.name.startswith("."):
                        continue
                    if _in_temp(child):
                        continue
                    if (child / ".patchi").is_dir():
                        key = str(child.resolve())
                        candidates.setdefault(key, child)
                # Also the scan root itself may be a project
                if (scan_root / ".patchi").is_dir():
                    key = str(scan_root.resolve())
                    candidates.setdefault(key, scan_root)
            except (PermissionError, OSError):
                continue

        return list(candidates.values())

    def update_stats(self, root: Path, **kwargs) -> None:
        """Update tenant statistics."""
        key = str(root.resolve())
        if key in self._tenants:
            for k, v in kwargs.items():
                if hasattr(self._tenants[key], k):
                    setattr(self._tenants[key], k, v)
            self._save_state()

    def _init_project_state(self, root: Path) -> None:
        """Initialize .patchi/ directory for a project."""
        patchi_dir = root / ".patchi"
        patchi_dir.mkdir(parents=True, exist_ok=True)

        # Ensure required subdirs
        for subdir in ["logs", "evidence", "snapshots", "cache"]:
            (patchi_dir / subdir).mkdir(exist_ok=True)

        # Initialize config if not present
        config_file = patchi_dir / "config.json"
        if not config_file.exists():
            config_file.write_text("{}")

        # Initialize memory (full .patchi structure + default memory files)
        from patchi.core.config import init_project

        init_project(root)

        # Initialize cost tracker
        from patchi.core.ai import cost_tracker

        cost_tracker.init(root)

    def _load_state(self) -> None:
        """Load tenant state from disk."""
        state_file = self._state_dir / "tenants.json"
        try:
            with open(state_file, encoding="utf-8") as f:
                data = json.load(f)
            for key, tdata in data.get("tenants", {}).items():
                self._tenants[key] = TenantState(
                    root=Path(tdata["root"]),
                    name=tdata.get("name", ""),
                    active=tdata.get("active", True),
                    last_accessed=tdata.get("last_accessed", ""),
                    findings_count=tdata.get("findings_count", 0),
                    scan_count=tdata.get("scan_count", 0),
                    cost_estimate=tdata.get("cost_estimate", 0.0),
                )
            self._active_tenant = data.get("active_tenant")
        except (FileNotFoundError, json.JSONDecodeError):
            pass

    def _save_state(self) -> None:
        """Persist tenant state to disk."""
        state_file = self._state_dir / "tenants.json"
        data = {
            "active_tenant": self._active_tenant,
            "tenants": {k: v.to_dict() for k, v in self._tenants.items()},
        }
        try:
            state_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
        except Exception as e:
            _log.warning("Failed to save tenant state: %s", e)


# ── Global Tenant Manager ────────────────────────────────────────────────────

_tenant_manager: TenantManager | None = None


def get_tenant_manager() -> TenantManager:
    """Get the global tenant manager."""
    global _tenant_manager
    if _tenant_manager is None:
        _tenant_manager = TenantManager()
    return _tenant_manager


# ── Request-Scoped Tenant Context ───────────────────────────────────────────


@contextmanager
def tenant_context(root: Path):
    """Context manager that scopes the active tenant for the current thread.

    Used by web request handlers to ensure each request operates on the
    correct project's state without global state corruption.

    Usage::

        with tenant_context(project_root):
            # All memory/config calls use project_root
            scan_results = mem.get_scan_results(project_root)
    """
    previous = getattr(_thread_local, "tenant_root", None)
    _thread_local.tenant_root = root
    try:
        yield root
    finally:
        _thread_local.tenant_root = previous


def get_current_tenant_root() -> Path | None:
    """Get the request-scoped tenant root, or None if not in a context."""
    return getattr(_thread_local, "tenant_root", None)


# ── Per-Tenant Cost Tracking ────────────────────────────────────────────────

_tenant_costs: dict[str, float] = {}  # root -> cumulative cost
tenant_costs_lock = threading.Lock()


def track_tenant_cost(root: Path, cost_usd: float) -> None:
    """Record AI cost for a specific tenant."""
    key = str(root.resolve())
    with tenant_costs_lock:
        _tenant_costs[key] = _tenant_costs.get(key, 0) + cost_usd


def get_tenant_cost(root: Path) -> float:
    """Get cumulative AI cost for a tenant."""
    key = str(root.resolve())
    with tenant_costs_lock:
        return _tenant_costs.get(key, 0.0)


def get_all_tenant_costs() -> dict[str, float]:
    """Get costs for all tenants."""
    with tenant_costs_lock:
        return dict(_tenant_costs)


def check_tenant_cost_alert(root: Path, config: dict | None = None) -> dict | None:
    """Check if per-tenant spending exceeds the configured limit.

    Returns a dict with alert info if threshold exceeded, None otherwise.

    Config keys (under ``ai``):
      cost_limit          — dollar amount that triggers the alert (default 10.0)
      cost_warn_pct       — percentage of limit that triggers warning (default 80)
    """
    cfg = config or {}
    ai_cfg = cfg.get("ai", {})
    limit = float(ai_cfg.get("cost_limit", 10.0))
    warn_pct = float(ai_cfg.get("cost_warn_pct", 80))

    if limit <= 0:
        return None

    spent = get_tenant_cost(root)
    pct = (spent / limit) * 100 if limit > 0 else 0

    if pct >= 100:
        return {
            "level": "critical",
            "message": f"AI budget exhausted: ${spent:.2f} / ${limit:.2f}",
            "spent": spent,
            "limit": limit,
            "pct": round(pct, 1),
        }
    elif pct >= warn_pct:
        return {
            "level": "warning",
            "message": f"AI spending at {pct:.0f}% of budget: ${spent:.2f} / ${limit:.2f}",
            "spent": spent,
            "limit": limit,
            "pct": round(pct, 1),
        }
    return None
