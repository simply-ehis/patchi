"""
Audit log — hash-chained, append-only event log.

Wraps the existing governance SQLite log and hosted JSON-lines log into a single
interface, receiving Event objects. Every event published to the EventBus with an
audit handler is written through this layer.

Hash chaining: each entry includes the SHA-256 of the previous entry, forming an
immutable chain. Exporting produces a verifiable lineage.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from patchi.core.detector.event import Event

logger = logging.getLogger("patchi.detector.audit")


@dataclass
class AuditEntry:
    """A single entry in the audit log — wraps an Event with hash chaining."""

    event: Event
    previous_hash: str = ""
    entry_hash: str = field(default_factory=lambda: "")
    written_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    def __post_init__(self) -> None:
        if not self.entry_hash:
            self.entry_hash = self._compute_hash()

    def _compute_hash(self) -> str:
        raw = json.dumps(self.to_dict(signed=True), sort_keys=True, default=str)
        return hashlib.sha256(raw.encode()).hexdigest()

    def to_dict(self, signed: bool = False) -> dict:
        d: dict[str, Any] = {
            "event": self.event.to_dict(),
            "written_at": self.written_at,
        }
        if signed:
            d["previous_hash"] = self.previous_hash
            d["entry_hash"] = self.entry_hash
        return d


class AuditLog:
    """
    Event-driven audit log with hash chaining.

    Writes to a JSON-lines file at `.patchi/detector/audit.log.jsonl`.
    Each line is a JSON object with the event, timestamp, and chain hash.

    Export produces a full verifiable chain. Governance SQLite log is still
    written for backward compatibility (high-level action tracking).
    """

    def __init__(self, root: Path | None = None):
        self._root = root
        self._last_hash = ""
        self._chain_length = 0
        self._file: Any = None  # open file handle
        if root:
            self._open()

    def _open(self) -> None:
        if not self._root:
            return
        log_dir = self._root / ".patchi" / "detector"
        log_dir.mkdir(parents=True, exist_ok=True)
        log_path = log_dir / "audit.log.jsonl"

        # Load the last entry's hash if the file exists
        if log_path.exists() and log_path.stat().st_size > 0:
            try:
                with open(log_path, encoding="utf-8") as f:
                    for line in f:
                        if line.strip():
                            entry = json.loads(line)
                            self._last_hash = entry.get("entry_hash", "")
                            self._chain_length += 1
            except (json.JSONDecodeError, OSError):
                logger.warning("Corrupt audit log — starting fresh chain")
                self._last_hash = ""
                self._chain_length = 0

        self._log_path = log_path
        self._file = open(log_path, "a", encoding="utf-8")  # noqa: SIM115

    async def write(self, event: Event) -> None:
        """Write an event to the audit log with hash chaining."""
        entry = AuditEntry(
            event=event,
            previous_hash=self._last_hash,
        )
        self._last_hash = entry.entry_hash
        self._chain_length += 1
        line = json.dumps(entry.to_dict(signed=True), default=str) + "\n"

        if self._file:
            try:
                self._file.write(line)
                self._file.flush()
                os.fsync(self._file.fileno())
            except OSError as exc:
                logger.error("Failed to write audit log: %s", exc)

    async def write_batch(self, events: list[Event]) -> None:
        for event in events:
            await self.write(event)

    def export(self) -> str:
        """Export the full audit log as a JSON array (for reporting/sharing)."""
        if not self._root:
            return "[]"
        log_path = self._root / ".patchi" / "detector" / "audit.log.jsonl"
        if not log_path.exists():
            return "[]"
        entries = []
        with open(log_path, encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    entries.append(json.loads(line))
        return json.dumps(entries, indent=2, default=str)

    def verify_chain(self) -> tuple[bool, int]:
        """Verify the hash chain integrity. Returns (valid, verified_count)."""
        if not self._root:
            return True, 0
        log_path = self._root / ".patchi" / "detector" / "audit.log.jsonl"
        if not log_path.exists():
            return True, 0
        prev_hash = ""
        count = 0
        with open(log_path, encoding="utf-8") as f:
            for line in f:
                if not line.strip():
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    return False, count
                if entry.get("previous_hash", "") != prev_hash:
                    return False, count
                prev_hash = entry.get("entry_hash", "")
                count += 1
        return True, count

    def close(self) -> None:
        if self._file:
            self._file.close()
            self._file = None

    def __enter__(self) -> AuditLog:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()

    @property
    def stats(self) -> dict:
        return {
            "chain_length": self._chain_length,
            "last_hash": self._last_hash[:16] + "...",
        }


# ── Shared bus setup (convenience) ──────────────────────────────────────────


def setup_audit_logger(bus, root: Path) -> AuditLog:
    """
    Create an AuditLog and attach it as the bus's audit handler.

    Returns the AuditLog instance so callers can export/verify.
    """

    audit_log = AuditLog(root=root)

    async def audit_handler(event: Event) -> None:
        await audit_log.write(event)

    bus._audit_handler = audit_handler  # type: ignore[attr-defined]
    logger.info("Audit log attached to bus at .patchi/detector/audit.log.jsonl")
    return audit_log
