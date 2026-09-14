"""
AppLauncher — install + start + health + teardown for Playwright/attack.

Detect via FrameworkDetector + project_reader, install if plain, start on free port,
poll GET /health or / 200, log to .patchi/launcher/app.log, atexit teardown.
"""

from __future__ import annotations

import atexit
import logging
import os
import shutil
import socket
import subprocess
import time
from pathlib import Path

from patchi.core.brain.file_corpus import FileCorpus
from patchi.core.brain.framework import FrameworkDetector

_log = logging.getLogger("patchi.testing.launcher")

_PROC: subprocess.Popen | None = None
_PORT: int | None = None


def _free_port() -> int:
    s = socket.socket()
    s.bind(("", 0))
    _, port = s.getsockname()
    s.close()
    return port


def _port_free(port: int) -> bool:
    s = socket.socket()
    try:
        s.bind(("127.0.0.1", port))
        return True
    except OSError:
        return False
    finally:
        s.close()


def _preferred_port(root: Path) -> int | None:
    """Configured port chain: .patchi/config.json → env PORT → package.json dev -p."""
    try:
        from patchi.core.testing._browser import read_web_port

        p = read_web_port(root)
        if p and 1 <= p <= 65535:
            return p
    except Exception as _exc:
        _log.debug("suppressed: %s", _exc)
    try:
        env_p = int(os.environ.get("PORT", ""))
        if 1 <= env_p <= 65535:
            return env_p
    except (TypeError, ValueError):
        pass
    try:
        import json
        import re

        pkg = json.loads((root / "package.json").read_text(encoding="utf-8"))
        dev = (pkg.get("scripts") or {}).get("dev", "")
        m = re.search(r"(?:-p|--port)[= ](\d{2,5})", dev)
        if m and 1 <= int(m.group(1)) <= 65535:
            return int(m.group(1))
    except Exception as _exc:
        _log.debug("suppressed: %s", _exc)
    return None


def _detect_start_cmd(root: Path) -> list[str] | None:
    corpus = FileCorpus(root)
    stack = FrameworkDetector(root, corpus=corpus).detect()
    fws = {f.name.lower() for f in stack.frameworks}
    # package.json scripts
    if (root / "package.json").exists():
        try:
            import json

            pkg = json.loads((root / "package.json").read_text(encoding="utf-8"))
            scripts = pkg.get("scripts", {})
            if "dev" in scripts:
                return ["npm", "run", "dev"]
            if "start" in scripts:
                return ["npm", "start"]
        except Exception as _exc:
            _log.debug("suppressed: %s", _exc)
    if "fastapi" in fws:
        # find app module
        for cand in ["app.main:app", "main:app", "server:app"]:
            return ["uvicorn", cand, "--host", "127.0.0.1", "--port", "{port}"]
    if "flask" in fws:
        return ["flask", "run", "--host=127.0.0.1", "--port={port}"]
    if "django" in fws:
        return ["python", "manage.py", "runserver", "127.0.0.1:{port}"]
    if "next.js" in fws:
        return ["npm", "run", "dev", "--", "-p", "{port}"]
    if "go" in fws and shutil.which("go"):
        return ["go", "run", "."]
    if "rust" in fws and shutil.which("cargo"):
        return ["cargo", "run"]
    return None


def ensure_running(root: Path, config: dict | None = None, extra: dict | None = None) -> str | None:
    global _PROC, _PORT
    from patchi.core.testing._browser import find_server

    # Reuse if already running
    base = find_server(root, config or {}, extra or {})
    if base:
        return base

    if os.environ.get("PATCHI_LAUNCHER_DISABLE") == "1":
        return None

    # Side install check: if node_modules missing and package-lock exists, npm ci already via InstallAgent
    cmd = _detect_start_cmd(root)
    if not cmd or not cmd[0] or not shutil.which(cmd[0]):
        return None

    preferred = _preferred_port(root)
    port = preferred if preferred and _port_free(preferred) else _free_port()
    # replace {port}
    cmd = [str(c).format(port=port) for c in cmd]
    env = os.environ.copy()
    env["PORT"] = str(port)
    env["HOST"] = "127.0.0.1"

    log_dir = root / ".patchi" / "launcher"
    log_dir.mkdir(parents=True, exist_ok=True)
    log_path = log_dir / "app.log"
    try:
        _PROC = subprocess.Popen(
            cmd,
            cwd=str(root),
            env=env,
            stdout=log_path.open("w", encoding="utf-8"),
            stderr=subprocess.STDOUT,
        )
        _PORT = port
        atexit.register(stop)
        # poll health
        import httpx

        url = f"http://127.0.0.1:{port}"
        for _ in range(15):
            time.sleep(2)
            if _PROC.poll() is not None:
                _log.warning("launcher exited early code %s", _PROC.returncode)
                return None
            try:
                resp = httpx.get(f"{url}/health", timeout=2, follow_redirects=True)
                if resp.status_code < 500:
                    return url
            except Exception as _exc:
                _log.debug("suppressed: %s", _exc)
            try:
                resp = httpx.get(url, timeout=2)
                if resp.status_code < 500:
                    return url
            except Exception as _exc:
                _log.debug("suppressed: %s", _exc)
        # fallback: try anyway if process still alive
        if _PROC.poll() is None:
            return url
    except Exception as exc:  # noqa: BLE001
        _log.warning("launcher failed %s: %s", cmd, exc)
    return None


def stop() -> None:
    global _PROC, _PORT
    if _PROC and _PROC.poll() is None:
        try:
            _PROC.terminate()
            _PROC.wait(timeout=5)
        except Exception:
            try:
                _PROC.kill()
            except Exception as _exc:
                _log.debug("suppressed: %s", _exc)
    _PROC = None
    _PORT = None
