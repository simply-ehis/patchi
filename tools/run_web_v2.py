"""Boot the Patchi v2 web app for end-to-end verification.

Usage: python tools/run_web_v2.py [project_root] [port]
Initializes a minimal .patchi project if one doesn't exist at root.
"""

from __future__ import annotations

import sys
from pathlib import Path

import uvicorn


def main() -> None:
    root = Path(sys.argv[1]) if len(sys.argv) > 1 else Path.cwd()
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 1617

    # Ensure an initialized project so config/memory loads succeed
    if not (root / ".patchi").exists():
        from patchi.core.config import init_project

        init_project(root)

    from patchi.web.app import create_app

    app = create_app(root)
    print(f"PATCHI_V2_READY http://127.0.0.1:{port}/v2", flush=True)
    uvicorn.run(app, host="127.0.0.1", port=port, log_level="warning")


if __name__ == "__main__":
    main()
