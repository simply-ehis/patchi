"""Serve DAST evidence files (screenshots, logs) from .patchi/evidence/dast/."""

from __future__ import annotations

import os
from pathlib import Path

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse

router = APIRouter()


@router.get("/evidence/dast/{filename:path}")
async def serve_dast_evidence(filename: str):
    """Serve a DAST evidence file (screenshot, etc.).

    Path: /evidence/dast/<filename>
    The file must be under the project's .patchi/evidence/dast/ directory.
    """
    # Security: only allow files from .patchi/evidence/dast/
    safe_name = os.path.basename(filename)  # prevent path traversal
    # Walk up to find project root (look for .patchi dir)
    project_root = Path.cwd()
    evidence_path = project_root / ".patchi" / "evidence" / "dast" / safe_name

    if not evidence_path.is_file():
        raise HTTPException(status_code=404, detail="Evidence file not found")

    # Determine media type from extension
    ext = evidence_path.suffix.lower()
    media_types = {
        ".png": "image/png",
        ".jpg": "image/jpeg",
        ".jpeg": "image/jpeg",
        ".gif": "image/gif",
        ".webp": "image/webp",
        ".svg": "image/svg+xml",
        ".txt": "text/plain",
        ".log": "text/plain",
        ".json": "application/json",
    }
    media_type = media_types.get(ext, "application/octet-stream")

    return FileResponse(
        path=str(evidence_path),
        media_type=media_type,
        filename=safe_name,
    )
