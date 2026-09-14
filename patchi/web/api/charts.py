"""Charts API — data for timeline and trends."""

from __future__ import annotations

import json
import logging
import sqlite3

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

logger = logging.getLogger("patchi.web.api.charts")

router = APIRouter(prefix="/api/charts")


@router.get("/timeline")
async def get_timeline(request: Request) -> JSONResponse:
    root = request.app.state.root
    db_path = root / ".patchi" / "patchi_history.db"

    history = []
    if db_path.exists():
        conn = None
        try:
            conn = sqlite3.connect(str(db_path), timeout=10.0)
            # Part 8: bind busy_timeout so web chart reads queue
            # instead of failing with "database is locked" under scan load.
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA busy_timeout=10000")
            cursor = conn.execute(
                "SELECT severity_breakdown, findings_count FROM scan_history ORDER BY rowid DESC LIMIT 20"
            )
            for row in cursor.fetchall():
                breakdown = json.loads(row[0] or "{}")
                history.append(
                    {
                        "total": row[1],
                        "critical": breakdown.get("critical", 0),
                        "high": breakdown.get("high", 0),
                        "medium": breakdown.get("medium", 0),
                        "low": breakdown.get("low", 0),
                    }
                )
        except Exception as e:
            logger.warning("Failed to fetch chart history: %s", e)
        finally:
            if conn:
                conn.close()

    return JSONResponse({"history": list(reversed(history))})
