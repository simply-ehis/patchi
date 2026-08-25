"""Workflow routes (v1 pages) — linked from the unified v2 nav bar.

The landing page (/) is the v2 Mission Control dashboard
(see routes/dashboard_v2.py) — the single unified UI. The old v1 overview
page was merged into Mission Control and removed.
"""

from __future__ import annotations

import json
from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from starlette.templating import Jinja2Templates as _Jinja2Templates

router = APIRouter()

templates = _Jinja2Templates(directory=str(Path(__file__).parent.parent / "templates"))
templates.env.filters["tojson"] = lambda v: json.dumps(v)
