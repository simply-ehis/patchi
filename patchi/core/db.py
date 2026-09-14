"""Shared SQLite utilities — busy_timeout + retry/backoff wrapper (Part 8).

Every SQLite connection in Patchi should go through ``open_db`` (or at minimum
set ``PRAGMA busy_timeout``) so that concurrent writers queue instead of
crashing with "database is locked".  ``retry_on_locked`` wraps individual
mutations that may still hit ``OperationalError`` under extreme contention
(e.g. 248 agents dispatching in a single Governor phase) and retries with
exponential backoff.
"""

from __future__ import annotations

import logging
import random
import sqlite3
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any, TypeVar

_T = TypeVar("_T")

_log = logging.getLogger(__name__)

# ── Constants ────────────────────────────────────────────────────────────────

DEFAULT_BUSY_TIMEOUT_MS = 10_000
MAX_RETRIES = 3
INITIAL_BACKOFF_S = 0.05
MAX_BACKOFF_S = 2.0

# SQLite error message substring that indicates a lock contention.
_LOCK_MSG = "database is locked"


# ── Connection helper ────────────────────────────────────────────────────────


def open_db(
    path: str | Path,
    *,
    timeout: float = 10.0,
    busy_timeout_ms: int = DEFAULT_BUSY_TIMEOUT_MS,
    wal: bool = True,
    check_same_thread: bool = True,
) -> sqlite3.Connection:
    """Open a SQLite connection with WAL + busy_timeout pre-configured.

    This is the recommended way to open *any* Patchi database.  It sets
    the two PRAGMAs that prevent "database is locked" under concurrent
    access and returns a ready-to-use connection.
    """
    conn = sqlite3.connect(
        str(path),
        timeout=timeout,
        check_same_thread=check_same_thread,
    )
    if wal:
        conn.execute("PRAGMA journal_mode=WAL")
    conn.execute(f"PRAGMA busy_timeout={busy_timeout_ms}")
    return conn


# ── Retry wrapper ────────────────────────────────────────────────────────────


def retry_on_locked(
    fn: Callable[..., _T],
    *args: Any,
    max_retries: int = MAX_RETRIES,
    initial_backoff: float = INITIAL_BACKOFF_S,
    max_backoff: float = MAX_BACKOFF_S,
    **kwargs: Any,
) -> _T:
    """Call *fn* with retry/backoff on ``sqlite3.OperationalError`` lock hits.

    ``busy_timeout`` handles most contention gracefully.  This wrapper
    catches the rare case where a very long-held lock (or pathological
    timing) still raises ``OperationalError`` even after the timeout.

    Per spec Part 8 §4: if all retries fail, the error is **surfaced** —
    never silently swallowed or logged-and-ignored.
    """
    last_exc: sqlite3.OperationalError | None = None
    backoff = initial_backoff
    for attempt in range(1, max_retries + 1):
        try:
            return fn(*args, **kwargs)
        except sqlite3.OperationalError as exc:
            msg = str(exc).lower()
            if _LOCK_MSG not in msg:
                # Not a lock contention — re-raise immediately.
                raise
            last_exc = exc
            if attempt < max_retries:
                jitter = random.uniform(0, backoff * 0.5)
                sleep_s = min(backoff + jitter, max_backoff)
                _log.warning(
                    "sqlite locked (attempt %d/%d), retrying in %.2fs",
                    attempt,
                    max_retries,
                    sleep_s,
                )
                time.sleep(sleep_s)
                backoff *= 2
            else:
                _log.error(
                    "sqlite locked after %d retries — giving up", max_retries
                )
    # All retries exhausted — surface the error per spec §4.
    raise last_exc  # type: ignore[misc]
