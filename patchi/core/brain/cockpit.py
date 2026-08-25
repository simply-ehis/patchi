"""
Live Cockpit — data layer for `p cockpit` (a.k.a. `p watch --live`).

This is a *view over the brain that already exists*. It adds no analysis of its
own; it just gathers signals the rest of Patchi already computes and shapes them
for a single glanceable dashboard:

    health   → patchi.core.health.compute
    drift    → patchi.core.brain.audit.compute_drift        (Plan-vs-Built)
    fixes    → patchi.core.brain.proactive.build_fix_list    (Prioritized Fix List)
    blast    → patchi.core.brain.reasoning.impact_analysis   (change blast radius)
    secrets  → patchi.core.brain.secrets.scan_secrets        (on-change sweep)

Every patchi import is wrapped so the cockpit still renders (in a degraded state)
when the brain has not been built yet — it just tells the user to run `p scan`.
"""

from __future__ import annotations

import logging
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from patchi.core.brain.file_corpus import FileCorpus

from patchi.core.brain.languages import DEFAULT_IGNORE_DIRS

_log = logging.getLogger("patchi.core.brain.cockpit")

# ── Watcher config (self-contained, no watchdog dependency) ──────────────────────

_WATCH_EXTS = {
    ".py",
    ".js",
    ".ts",
    ".tsx",
    ".jsx",
    ".rs",
    ".go",
    ".rb",
    ".java",
    ".env",
    ".toml",
    ".yaml",
    ".yml",
    ".json",
    ".cfg",
    ".ini",
}
_SKIP_DIRS = DEFAULT_IGNORE_DIRS | {".turbo", ".codebase-memory"}
_MAX_WATCH_FILES = 20_000


# ── State ────────────────────────────────────────────────────────────────────────


@dataclass
class Event:
    ts: float
    level: str  # info | warn | crit
    text: str

    def stamp(self) -> str:
        return time.strftime("%H:%M:%S", time.localtime(self.ts))


@dataclass
class CockpitState:
    root: Path
    area: str | None = None

    health_total: int | None = None
    health_grade: str = "?"
    health_color: str = "#FACC15"

    drift: dict = field(default_factory=dict)
    fixes: list[dict] = field(default_factory=list)

    last_file: str = ""
    blast_affected: list[str] = field(default_factory=list)
    blast_impacted: list[str] = field(default_factory=list)
    blast_summary: str = ""

    secrets: list[dict] = field(default_factory=list)  # deduped, most-recent last
    events: deque = field(default_factory=lambda: deque(maxlen=200))

    metrics_at: float = 0.0
    fixes_at: float = 0.0
    fixes_computing: bool = False
    _fixes_lock: threading.Lock = field(default_factory=threading.Lock, repr=False)


def add_event(state: CockpitState, level: str, text: str) -> None:
    state.events.append(Event(ts=time.time(), level=level, text=text))


# ── Signal gatherers (each fully guarded) ────────────────────────────────────────


def _get_health(state: CockpitState) -> None:
    try:
        from patchi.core.health import compute

        hs = compute(state.root)
        state.health_total = hs.total
        state.health_grade = hs.grade
        state.health_color = hs.color
    except Exception as e:
        # Most common cause is simply "no brain built yet" (p scan not run),
        # which is an expected, frequent state on a fresh project — debug, not
        # warning, so a normal cockpit session against an unscanned repo doesn't
        # spam the log on every refresh interval.
        _log.debug("Health computation unavailable (likely no brain yet): %s", e)
        state.health_total = None
        state.health_grade = "?"


def _get_drift(state: CockpitState) -> None:
    try:
        from patchi.core.brain.audit import compute_drift

        state.drift = compute_drift(state.root) or {}
    except Exception as e:
        _log.debug("Drift computation unavailable (likely no brain/plan yet): %s", e)
        state.drift = {}


def _get_fixes(state: CockpitState) -> None:
    try:
        from patchi.core.brain.proactive import build_fix_list, rank_fixes

        fixes = build_fix_list(state.root, area=state.area)
        fixes = rank_fixes(fixes)
        state.fixes = [
            {
                "fix_type": f.fix_type,
                "file": f.file,
                "name": f.name,
                "description": f.description,
                "safe": f.safe,
            }
            for f in fixes
        ]
    except Exception as e:
        _log.debug("Fix list computation unavailable (likely no brain yet): %s", e)
        state.fixes = []


def update_metrics(state: CockpitState) -> None:
    """Refresh the *fast* whole-project signals (health + drift, both <0.1s)."""
    _get_health(state)
    _get_drift(state)
    state.metrics_at = time.time()


def refresh_fixes_async(state: CockpitState) -> threading.Thread | None:
    """
    Recompute the Prioritized Fix List off the UI thread.

    ``build_fix_list`` scans the whole project (import graph + proactive agent)
    and can take many seconds on large repos, so it must never block rendering.
    A lock ensures only one computation runs at a time; the UI shows a
    'computing…' hint while ``fixes_computing`` is set.

    Returns the background Thread (or None if a computation was already running
    and this call was a no-op) so a caller that wants a best-effort bounded wait
    — e.g. ``--once`` — can ``.join(timeout=...)`` it instead of blocking forever.
    """
    if state.fixes_computing:
        return None

    def _work() -> None:
        with state._fixes_lock:
            state.fixes_computing = True
            try:
                _get_fixes(state)
                state.fixes_at = time.time()
            finally:
                state.fixes_computing = False

    t = threading.Thread(target=_work, daemon=True)
    t.start()
    return t


def gather_full(
    root: Path,
    area: str | None = None,
    scan_secrets: bool = False,
    fixes_sync: bool = False,
    fixes_timeout: float = 12.0,
) -> CockpitState:
    """
    Build a fresh cockpit state (called once at startup).

    Fast signals (health, drift) are computed synchronously; the fix list is
    always computed in the background so a large project can never hang the
    cockpit. When ``fixes_sync`` is set (used by ``--once``, so a single frame
    ideally contains everything), this *waits up to ``fixes_timeout`` seconds*
    for that background computation to finish before returning — a bounded
    best-effort wait, not a blocking call. On a large project where the fix
    list genuinely can't finish in time, the frame still renders on schedule
    with ``fixes_computing`` left set, rather than hanging indefinitely.
    """
    state = CockpitState(root=Path(root), area=area)
    update_metrics(state)

    if state.health_total is None:
        add_event(state, "warn", "No brain found — run `p scan` to populate the cockpit.")
    else:
        add_event(
            state, "info", f"Cockpit armed · health {state.health_total} ({state.health_grade})"
        )

    thread = refresh_fixes_async(state)
    if fixes_sync and thread is not None:
        thread.join(timeout=fixes_timeout)
        if state.fixes_computing:
            add_event(
                state,
                "warn",
                f"Fix list still computing after {fixes_timeout:.0f}s (large project) — "
                "showing partial frame; scope with --area for a faster pass.",
            )

    if scan_secrets:
        _sweep_secrets(state, paths=None, announce=True)

    return state


# ── On-change refresh (cheap, scoped to the saved files) ─────────────────────────


def refresh_on_change(state: CockpitState, changed: list[str]) -> None:
    if not changed:
        return
    state.last_file = changed[-1]
    add_event(
        state,
        "info",
        f"saved {', '.join(changed[:3])}"
        + (f" (+{len(changed) - 3} more)" if len(changed) > 3 else ""),
    )

    _get_blast(state, changed)
    _sweep_secrets(state, paths=changed, announce=False)


def _get_blast(state: CockpitState, changed: list[str]) -> None:
    try:
        from patchi.core.brain.reasoning import ReasoningEngine

        analysis = ReasoningEngine(state.root).impact_analysis(changed)
        state.blast_affected = list(analysis.affected_layers)
        state.blast_impacted = list(analysis.impacted_layers)
        state.blast_summary = analysis.summary
        if analysis.impacted_layers:
            add_event(
                state, "warn", f"blast radius: {len(analysis.impacted_layers)} downstream layer(s)"
            )
    except Exception as e:
        # Triggered per-save during an active session (not the one-time "fresh
        # project" case above) -- more likely a real problem, so this is worth
        # a warning rather than debug.
        _log.warning("Blast radius analysis failed for %s: %s", changed, e)
        state.blast_summary = "Impact needs a layered brain — run `p scan`."


def _sweep_secrets(state: CockpitState, paths: list[str] | None, announce: bool) -> None:
    try:
        from patchi.core.brain.secrets import scan_secrets

        hits = scan_secrets(state.root, paths)
        seen = {(s["path"], s["line"], s["rule"]) for s in state.secrets}
        new = 0
        for h in hits:
            key = (h.path, h.line, h.rule)
            if key in seen:
                continue
            seen.add(key)
            state.secrets.append({"path": h.path, "line": h.line, "rule": h.rule})
            new += 1
        if new:
            add_event(
                state, "crit", f"{new} secret(s) detected — {hits[-1].rule} in {hits[-1].path}"
            )
        elif announce:
            add_event(state, "info", "secrets sweep clean")
    except Exception as e:
        # A silent failure here is exactly the dangerous case for a security
        # tool: the cockpit would look clean while a secrets sweep never
        # actually ran. Warning, not debug.
        _log.warning("Secrets sweep failed for paths=%s: %s", paths, e)


# ── Self-contained source watcher (mtime poll, no external deps) ─────────────────


class SourceWatcher:
    def __init__(self, root: Path, corpus: FileCorpus | None = None):
        self.root = Path(root)
        self._corpus = corpus
        self._mtimes = self._scan()

    def _scan(self) -> dict[str, float]:
        out: dict[str, float] = {}
        count = 0
        if self._corpus is not None:
            for entry in self._corpus.entries.values():
                if count >= _MAX_WATCH_FILES:
                    break
                if entry.abs_path.suffix.lower() not in _WATCH_EXTS:
                    continue
                try:
                    out[entry.abs_path.as_posix()] = entry.abs_path.stat().st_mtime
                    count += 1
                except OSError:
                    continue
        else:
            for p in self.root.rglob("*"):
                if count >= _MAX_WATCH_FILES:
                    break
                try:
                    if any(part in _SKIP_DIRS for part in p.parts):
                        continue
                    if p.suffix.lower() not in _WATCH_EXTS:
                        continue
                    if not p.is_file():
                        continue
                    out[p.as_posix()] = p.stat().st_mtime
                    count += 1
                except OSError:
                    continue
        return out

    def poll(self) -> list[str]:
        current = self._scan()
        changed = [
            str(Path(p).relative_to(self.root).as_posix())
            for p, m in current.items()
            if self._mtimes.get(p) != m
        ]
        self._mtimes = current
        return changed
