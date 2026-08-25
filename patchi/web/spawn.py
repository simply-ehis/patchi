"""
Tap-to-spawn handler for the Patchi Brain Map.

Enforces the full spec from patchi_builder_sidenote.md:
  - Max 5 user-spawned ants simultaneously
  - 10-second tap cooldown per node
  - 60-second ant expiry
  - No spawn if Patchi is idle (returns None — caller shows node inspector)
  - No spawn on restricted nodes
  - No spawn if 3+ ants already working on the node
  - Second tap on same node within 10s is ignored

SpawnManager is instantiated once on server start and shared via FastAPI state.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path

import patchi.core.config as config

# Spec constants
MAX_USER_ANTS = 5
NODE_COOLDOWN_S = 10
ANT_EXPIRY_S = 60
MAX_ANTS_ON_NODE = 3


@dataclass
class SpawnedAnt:
    ant_id: str
    node_id: str
    spawned_at: float = field(default_factory=time.time)
    done: bool = False

    def is_expired(self) -> bool:
        return (time.time() - self.spawned_at) > ANT_EXPIRY_S


class SpawnManager:
    """
    Tracks all user-spawned ants. Called by the WebSocket handler when
    the client sends an `action.spawn_ant` event.
    """

    def __init__(self, root: Path) -> None:
        self._root = root
        self._ants: dict[str, SpawnedAnt] = {}  # ant_id → SpawnedAnt
        self._taps: dict[str, float] = {}  # node_id → last tap timestamp
        self._is_active: bool = False  # set by server when a scan runs

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def set_active(self, active: bool) -> None:
        """Called by the scan runner to indicate whether Patchi is running."""
        self._is_active = active

    def mark_done(self, ant_id: str) -> None:
        if ant_id in self._ants:
            self._ants[ant_id].done = True

    # ── Spawn gate ────────────────────────────────────────────────────────────

    def try_spawn(self, node_id: str) -> tuple[str | None, str]:
        """
        Attempt to spawn an ant on node_id.

        Returns (ant_id, reason):
          - (ant_id, "ok")         → spawned successfully
          - (None, "idle")         → Patchi not running — show inspector instead
          - (None, "restricted")   → node is restricted
          - (None, "cooldown")     → same node tapped within 10s
          - (None, "capacity")     → 5 user-spawned ants already active
          - (None, "node_busy")    → 3+ ants already on this node
        """
        self._expire_ants()

        if not self._is_active:
            return None, "idle"

        if self._is_restricted(node_id):
            return None, "restricted"

        if self._on_cooldown(node_id):
            return None, "cooldown"

        live = self._live_ants()
        if len(live) >= MAX_USER_ANTS:
            return None, "capacity"

        ants_on_node = sum(1 for a in live.values() if a.node_id == node_id)
        if ants_on_node >= MAX_ANTS_ON_NODE:
            return None, "node_busy"

        ant_id = str(uuid.uuid4())[:8]
        self._ants[ant_id] = SpawnedAnt(ant_id=ant_id, node_id=node_id)
        self._taps[node_id] = time.time()
        return ant_id, "ok"

    def active_count(self) -> int:
        self._expire_ants()
        return len(self._live_ants())

    def all_active(self) -> list[dict]:
        self._expire_ants()
        return [
            {"ant_id": a.ant_id, "node_id": a.node_id, "age_s": int(time.time() - a.spawned_at)}
            for a in self._live_ants().values()
        ]

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _live_ants(self) -> dict[str, SpawnedAnt]:
        return {aid: a for aid, a in self._ants.items() if not a.done and not a.is_expired()}

    def _expire_ants(self) -> None:
        expired = [aid for aid, ant in self._ants.items() if ant.is_expired()]
        for aid in expired:
            del self._ants[aid]

    def _on_cooldown(self, node_id: str) -> bool:
        last = self._taps.get(node_id, 0.0)
        return (time.time() - last) < NODE_COOLDOWN_S

    def _is_restricted(self, node_id: str) -> bool:
        """Check config restrictions. node_id is the file path used as Brain Map node key."""
        try:
            restrictions = config.get_restrictions(self._root)
            return any(r["path"] == node_id and r.get("enabled", True) for r in restrictions)
        except Exception as e:
            import logging

            logging.getLogger("patchi.web.spawn").warning(
                "Restriction check failed for %s: %s", node_id, e
            )
            return False
