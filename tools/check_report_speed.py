"""Verify /api/security/report is cached-first and instant on empty cache."""
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi.testclient import TestClient  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent

root = ROOT / ".audit_diag5"
init = root / ".patchi"
if not init.is_dir():
    from patchi.core.config import init_project

    init_project(root)

from patchi.web.app import create_app  # noqa: E402

app = create_app(root)
c = TestClient(app, raise_server_exceptions=False)

t = time.time()
r = c.get("/api/security/report")
dt = time.time() - t
j = r.json()
print(f"empty-cache GET: {r.status_code} in {dt:.1f}s cached={j.get('cached')} findings={j.get('total_findings')}")
assert r.status_code == 200 and dt < 3, f"STILL SLOW: {dt:.1f}s"
assert j.get("cached") is True

import shutil  # noqa: E402

shutil.rmtree(root, ignore_errors=True)
print("REPORT ENDPOINT FIXED")
