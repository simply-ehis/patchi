"""
WebSocket manager for live events.

Broadcasts scan progress, finding alerts, guard events to all connected clients.
"""

from __future__ import annotations

import asyncio
import json
import time
from dataclasses import dataclass, field
from typing import Any


@dataclass
class WSManager:
    """Manages WebSocket connections and broadcasts events."""

    _connections: list = field(default_factory=list)
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    async def connect(self, ws: Any) -> None:
        async with self._lock:
            self._connections.append(ws)

    async def disconnect(self, ws: Any) -> None:
        async with self._lock:
            if ws in self._connections:
                self._connections.remove(ws)

    async def broadcast(self, event: str, data: dict | None = None) -> None:
        """Send event to all connected clients."""
        message = json.dumps(
            {
                "event": event,
                "data": data or {},
                "ts": time.time(),
            }
        )
        async with self._lock:
            targets = list(self._connections)
            dead = []
            for ws in targets:
                try:
                    await ws.send_text(message)
                except Exception:
                    dead.append(ws)
            for ws in dead:
                if ws in self._connections:
                    self._connections.remove(ws)
            if dead:
                import logging

                logging.getLogger("patchi.web.ws").warning(
                    "Removed %d dead WS connection(s)", len(dead)
                )

    @property
    def connection_count(self) -> int:
        return len(self._connections)


# Global instance
manager = WSManager()


# ── Event helpers ─────────────────────────────────────────────────────────────


async def evt_scan_started(agent_count: int = 0) -> None:
    await manager.broadcast("scan.started", {"agent_count": agent_count})


async def evt_scan_progress(agent: str, phase: str, current: int, total: int) -> None:
    await manager.broadcast(
        "scan.progress",
        {
            "agent": agent,
            "phase": phase,
            "current": current,
            "total": total,
        },
    )


async def evt_scan_finding(finding: dict) -> None:
    await manager.broadcast("scan.finding", finding)


async def evt_scan_complete(total_findings: int, duration_ms: int) -> None:
    await manager.broadcast(
        "scan.complete",
        {
            "total_findings": total_findings,
            "duration_ms": duration_ms,
        },
    )


async def evt_scan_cancelled(total_findings: int) -> None:
    await manager.broadcast(
        "scan.cancelled",
        {"total_findings": total_findings},
    )


async def evt_agent_started(agent_name: str) -> None:
    await manager.broadcast("agent.started", {"agent": agent_name})


async def evt_agent_done(agent_name: str, finding_count: int) -> None:
    await manager.broadcast(
        "agent.done",
        {
            "agent": agent_name,
            "finding_count": finding_count,
        },
    )


async def evt_guard_alert(alert: dict) -> None:
    await manager.broadcast("guard.alert", alert)


async def evt_guard_status(status: dict) -> None:
    await manager.broadcast("guard.status", status)


async def evt_fix_applied(patch_id: str, file_path: str) -> None:
    await manager.broadcast(
        "fix.applied",
        {
            "patch_id": patch_id,
            "file_path": file_path,
        },
    )


async def evt_status_update(status: dict) -> None:
    await manager.broadcast("status.update", status)
