"""
Tool Health — three-state probe for external security tooling.

Reconstructed module (referenced by cli/commands/doctor_cmd.py; original
was lost before any commit existed). A tool that is installed but not
runnable must be reported as *broken*, never silently as present-and-fine
or as absent:

    check_tool("bandit") -> {"status": "ok",      "version": "1.7.5", "hint": ""}
                            {"status": "broken",  "version": "",      "hint": "..."}
                            {"status": "missing", "version": "",      "hint": ""}

_TOOLS is the registry of known probeable tools; unknown names fall back
to the caller's own PATH/import check.
"""

from __future__ import annotations

import importlib.util
import logging
import re
import shutil
import subprocess
from pathlib import Path

_log = logging.getLogger("patchi.core.agents.tool_health")

_VERSION_TIMEOUT_S = 10

# Tools this module knows how to probe end-to-end.
_TOOLS = frozenset(
    {
        "bandit",
        "semgrep",
        "codeql",
        "pyre",
        "safety",
        "pip-audit",
        "git",
        "node",
        "npm",
        "ollama",
    }
)

# Per-tool run flags: some tools don't answer `--version` nicely.
_VERSION_ARGS: dict[str, list[str]] = {
    "codeql": ["version"],
    "pyre": ["--version"],
}

# Focused hints when a present tool fails to run.
_BROKEN_HINTS: dict[str, str] = {
    "codeql": "codeql binary missing — install the CodeQL CLI and add it to PATH",
    "pyre": (
        "pyre.bin not runnable on this platform — pyre-check has no Windows"
        " build (Linux/macOS only); use mypy or pyright on Windows"
    ),
}


# ── Unified tool registry (Part 3 §2) ────────────────────────────────────────
# Every external tool any Patchi agent references, in ONE place: how to probe
# it, how to install it, and whether `p doctor --install` may attempt it
# automatically. `auto` is one of "pip" | "npm" | "go" | None (manual only).
# version_args None = presence-only probe (no reliable version flag known).
_TOOL_INFO: dict[str, dict] = {
    # SAST
    "bandit": {
        "kind": "binary",
        "cmd": ["bandit"],
        "version_args": ["--version"],
        "install": "pip install bandit",
        "auto": "pip",
        "group": "sast",
        "desc": "Python security linter",
    },
    "semgrep": {
        "kind": "binary",
        "cmd": ["semgrep"],
        "version_args": ["--version"],
        "install": "pip install semgrep",
        "auto": "pip",
        "group": "sast",
        "desc": "Multi-language SAST scanner",
    },
    "codeql": {
        "kind": "binary",
        "cmd": ["codeql"],
        "version_args": ["version"],
        "install": "Install the CodeQL CLI bundle from github.com/github/codeql-cli-binaries",
        "auto": None,
        "group": "sast",
        "desc": "Semantic code analysis engine",
    },
    "pyre": {
        "kind": "binary",
        "cmd": ["pyre"],
        "version_args": ["--version"],
        "install": "pip install pyre-check",
        "auto": "pip",
        "pkg": "pyre-check",
        "group": "sast",
        "desc": "Python type checker",
    },
    "eslint": {
        "kind": "binary",
        "cmd": ["eslint"],
        "version_args": ["--version"],
        "install": "npm install -g eslint",
        "auto": "npm",
        "pkg": "eslint",
        "group": "sast",
        "desc": "JS/TS linter",
    },
    # Secrets
    "gitleaks": {
        "kind": "binary",
        "cmd": ["gitleaks"],
        "version_args": ["version"],
        "install": "go install github.com/zricethezav/gitleaks/v8@latest (needs Go)",
        "auto": "go",
        "go_pkg": "github.com/zricethezav/gitleaks/v8@latest",
        "group": "secrets",
        "desc": "Secret scanner",
    },
    "shannon": {
        "kind": "binary",
        "cmd": ["shannon"],
        "version_args": None,
        "install": "Install the Shannon entropy CLI for your platform",
        "auto": None,
        "group": "secrets",
        "desc": "Entropy analysis",
    },
    # Supply chain / deps
    "safety": {
        "kind": "binary",
        "cmd": ["safety"],
        "version_args": ["--version"],
        "install": "pip install safety",
        "auto": "pip",
        "group": "supply-chain",
        "desc": "Python dependency vulnerability scanner",
    },
    "pip-audit": {
        "kind": "binary",
        "cmd": ["pip-audit"],
        "version_args": ["--version"],
        "install": "pip install pip-audit",
        "auto": "pip",
        "group": "supply-chain",
        "desc": "Python package auditor",
    },
    "osv-scanner": {
        "kind": "binary",
        "cmd": ["osv-scanner"],
        "version_args": ["--version"],
        "install": "go install github.com/google/osv-scanner/cmd/osv-scanner@latest (needs Go)",
        "auto": "go",
        "go_pkg": "github.com/google/osv-scanner/cmd/osv-scanner@latest",
        "group": "supply-chain",
        "desc": "OSV vulnerability scanner",
    },
    "syft": {
        "kind": "binary",
        "cmd": ["syft"],
        "version_args": ["--version"],
        "install": "Install Syft from github.com/anchore/syft (package manager or script)",
        "auto": None,
        "group": "supply-chain",
        "desc": "SBOM generator",
    },
    "cdxgen": {
        "kind": "binary",
        "cmd": ["cdxgen"],
        "version_args": ["--version"],
        "install": "npm install -g @cyclonedx/cdxgen",
        "auto": "npm",
        "pkg": "@cyclonedx/cdxgen",
        "group": "supply-chain",
        "desc": "SBOM generator",
    },
    "trivy": {
        "kind": "binary",
        "cmd": ["trivy"],
        "version_args": ["--version"],
        "install": "Install Trivy from aquasecurity.github.io/trivy (package manager)",
        "auto": None,
        "group": "supply-chain",
        "desc": "Container/FS vulnerability scanner",
    },
    "grype": {
        "kind": "binary",
        "cmd": ["grype"],
        "version_args": None,
        "install": "Install Grype from github.com/anchore/grype (install script)",
        "auto": None,
        "group": "supply-chain",
        "desc": "Container vulnerability scanner",
    },
    # DAST / dynamic
    "nuclei": {
        "kind": "binary",
        "cmd": ["nuclei"],
        "version_args": ["-version"],
        "install": "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest (needs Go)",
        "auto": "go",
        "go_pkg": "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
        "group": "dast",
        "desc": "Vulnerability scanner (templates)",
    },
    "sqlmap": {
        "kind": "binary",
        "cmd": ["sqlmap"],
        "version_args": ["--version"],
        "install": "pip install sqlmap",
        "auto": "pip",
        "group": "dast",
        "desc": "SQL injection tester",
    },
    "dalfox": {
        "kind": "binary",
        "cmd": ["dalfox"],
        "version_args": ["version"],
        "install": "go install github.com/hahwul/dalfox/v2@latest (needs Go)",
        "auto": "go",
        "go_pkg": "github.com/hahwul/dalfox/v2@latest",
        "group": "dast",
        "desc": "XSS scanner",
    },
    "ffuf": {
        "kind": "binary",
        "cmd": ["ffuf"],
        "version_args": None,
        "install": "go install github.com/ffuf/ffuf/v2@latest (needs Go)",
        "auto": "go",
        "go_pkg": "github.com/ffuf/ffuf/v2@latest",
        "group": "dast",
        "desc": "Web fuzzer",
    },
    "zap": {
        "kind": "binary",
        "cmd": ["zap", "zap.sh"],
        "version_args": None,
        "install": "Download OWASP ZAP (requires Java) from zaproxy.org",
        "auto": None,
        "group": "dast",
        "desc": "Web app security scanner",
    },
    "httpx": {
        "kind": "module",
        "cmd": ["httpx"],
        "version_args": None,
        "install": "pip install httpx",
        "auto": "pip",
        "group": "platform",
        "desc": "Python HTTP client library",
    },
    "playwright": {
        "kind": "playwright",
        "cmd": ["playwright"],
        "version_args": None,
        "install": "pip install playwright && playwright install chromium",
        "auto": "playwright",
        "group": "dast",
        "desc": "Browser automation (+ `playwright install` binaries)",
    },
    # Mutation / misc
    "universalmutator": {
        "kind": "module",
        "cmd": ["universalmutator"],
        "version_args": None,
        "install": "pip install universalmutator",
        "auto": "pip",
        "group": "testing",
        "desc": "Mutation testing",
    },
    "vulture": {
        "kind": "binary",
        "cmd": ["vulture"],
        "version_args": ["--version"],
        "install": "pip install vulture",
        "auto": "pip",
        "group": "sast",
        "desc": "Dead code finder",
    },
    "deadcode": {
        "kind": "binary",
        "cmd": ["deadcode"],
        "version_args": ["--version"],
        "install": "pip install deadcode",
        "auto": "pip",
        "group": "sast",
        "desc": "Dead code detection",
    },
    # Runtimes / platforms (manual install only)
    "git": {
        "kind": "binary",
        "cmd": ["git"],
        "version_args": ["--version"],
        "install": "Install Git from git-scm.com",
        "auto": None,
        "group": "platform",
        "desc": "Version control",
    },
    "node": {
        "kind": "binary",
        "cmd": ["node"],
        "version_args": ["--version"],
        "install": "Install Node.js LTS from nodejs.org",
        "auto": None,
        "group": "platform",
        "desc": "JS runtime",
    },
    "npm": {
        "kind": "binary",
        "cmd": ["npm"],
        "version_args": ["--version"],
        "install": "Ships with Node.js (nodejs.org)",
        "auto": None,
        "group": "platform",
        "desc": "JS package manager",
    },
    "go": {
        "kind": "binary",
        "cmd": ["go"],
        "version_args": ["version"],
        "install": "Install the Go toolchain from go.dev",
        "auto": None,
        "group": "platform",
        "desc": "Go toolchain (builds *_install tools)",
    },
    "cargo": {
        "kind": "binary",
        "cmd": ["cargo"],
        "version_args": ["--version"],
        "install": "Install Rust via rustup.rs",
        "auto": None,
        "group": "platform",
        "desc": "Rust toolchain",
    },
    "java": {
        "kind": "binary",
        "cmd": ["java"],
        "version_args": ["-version"],
        "install": "Install a JDK (e.g. Temurin) for Java-based tools",
        "auto": None,
        "group": "platform",
        "desc": "Java runtime",
    },
    "docker": {
        "kind": "binary",
        "cmd": ["docker"],
        "version_args": ["--version"],
        "install": "Install Docker Desktop from docker.com",
        "auto": None,
        "group": "platform",
        "desc": "Container runtime",
    },
    "ollama": {
        "kind": "binary",
        "cmd": ["ollama"],
        "version_args": ["--version"],
        "install": "Install Ollama from ollama.com for local models",
        "auto": None,
        "group": "ai",
        "desc": "Local model runner",
    },
}

# Keep the legacy frozenset in sync: registry is the source of truth now.
_TOOLS = frozenset(_TOOL_INFO)


def list_tools() -> list[dict]:
    """Every registered tool with its metadata (name, group, desc, install,
    auto, and the machine-usable pkg/go_pkg fields `p doctor --install` uses)."""
    keep = ("group", "desc", "install", "auto", "pkg", "go_pkg")
    return [{"name": name, **{k: v for k, v in info.items() if k in keep}} for name, info in sorted(_TOOL_INFO.items())]


def install_hint(tool: str) -> str:
    """One-line install command/guidance for a tool ("" if unknown)."""
    info = _TOOL_INFO.get(tool, {})
    return str(info.get("install", ""))


def playwright_ready() -> tuple[bool, str]:
    """One check for every Playwright-dependent agent (spec §2.6).

    `pip install playwright` alone is NOT enough — the browser binaries are a
    separate `playwright install` step. Returns (ready, hint). All browser
    agents call this instead of re-deriving their own partial checks, so a
    missing binary set skips with the same message everywhere.
    """
    if importlib.util.find_spec("playwright") is None:
        return (
            False,
            "playwright not installed — pip install playwright && playwright install chromium",
        )
    if not _playwright_browsers_present():
        return (
            False,
            "playwright browser binaries missing — run: playwright install chromium",
        )
    return True, ""


def is_available(tool: str) -> bool:
    """True if the tool probes ok right now. Never raises."""
    try:
        return check_tool(tool).get("status") == "ok"
    except Exception:
        return False


def _playwright_browsers_present() -> bool:
    """Playwright needs binaries beyond the pip package (spec §2.6).

    Browser cache location is per-OS (and honor PLAYWRIGHT_BROWSERS_PATH):
      Windows  %LOCALAPPDATA%\\ms-playwright
      Linux    ~/.cache/ms-playwright
      macOS    ~/Library/Caches/ms-playwright
    """
    import os

    env_path = os.environ.get("PLAYWRIGHT_BROWSERS_PATH")
    if env_path:
        bases = [Path(env_path)]
    else:
        bases = [
            Path.home() / ".cache" / "ms-playwright",  # Linux
            Path.home() / "Library" / "Caches" / "ms-playwright",  # macOS
            Path.home() / "AppData" / "Local" / "ms-playwright",  # Windows
        ]
    for base in bases:
        try:
            if not base.is_dir():
                continue
            if any(p.is_dir() and p.name.startswith("chromium") for p in base.iterdir()):
                return True
        except OSError:
            continue
    return False


def _extract_version(output: str, tool: str) -> str:
    """Pull a plausible version token out of a --version blob."""
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        m = re.search(r"\d+\.\d+(?:\.\d+)?[a-zA-Z0-9.\-]*", line)
        if m:
            return m.group(0)
        # Fall back to first non-empty line, minus the tool name echo
        lowered = line.lower()
        if tool.lower() not in lowered:
            return line[:40]
    return ""


def _broken(tool: str, why: str) -> dict:
    hint = _BROKEN_HINTS.get(tool, why)
    manual = install_hint(tool)
    if manual and manual not in hint:
        hint = f"{hint} — {manual}"
    return {"status": "broken", "version": "", "hint": hint}


def check_tool(tool: str) -> dict:
    """Probe one external tool. Never raises.

    Registry-known tools use their recorded probe (binary/module/playwright);
    unknown names fall back to the legacy PATH + `--version` check.
    """
    info = _TOOL_INFO.get(tool)
    kind = (info or {}).get("kind", "binary")

    if kind == "module":
        mod = (info.get("cmd") or [tool])[0]
        if importlib.util.find_spec(mod) is None:
            return {"status": "missing", "version": "", "hint": install_hint(tool)}
        return {"status": "ok", "version": "", "hint": ""}

    if kind == "playwright":
        if importlib.util.find_spec("playwright") is None:
            return {"status": "missing", "version": "", "hint": install_hint(tool)}
        if not _playwright_browsers_present():
            return {
                "status": "broken",
                "version": "",
                "hint": "playwright installed but browser binaries missing — run: playwright install chromium",
            }
        return {"status": "ok", "version": "", "hint": ""}

    # Binary probe (possibly several candidate names, e.g. zap/zap.sh).
    path = None
    for candidate in (info.get("cmd") if info else [tool]) or [tool]:
        path = shutil.which(candidate)
        if path:
            break
    if path is None:
        return {"status": "missing", "version": "", "hint": install_hint(tool)}

    vargs = None
    if info is not None:
        vargs = info.get("version_args")  # None = presence-only
    else:
        vargs = _VERSION_ARGS.get(tool, ["--version"])
    if vargs is None:
        return {"status": "ok", "version": "", "hint": ""}

    try:
        proc = subprocess.run(  # noqa: S603 — fixed argv, no shell
            [path, *vargs],
            capture_output=True,
            text=True,
            timeout=_VERSION_TIMEOUT_S,
            stdin=subprocess.DEVNULL,  # tools like sqlmap block on stdin otherwise
        )
    except subprocess.TimeoutExpired:
        # A version probe that hangs usually means the tool printed and then
        # waited on stdin (sqlmap on Windows) — the binary itself works.
        return {"status": "ok", "version": "", "hint": ""}
    except OSError as exc:
        return _broken(tool, f"cannot execute {path}: {exc}")

    if proc.returncode != 0:
        return _broken(
            tool,
            f"{tool} exits {proc.returncode} on {vargs[0]} — reinstall or check its runtime deps",
        )

    blob = (proc.stdout or "") + (proc.stderr or "")
    return {
        "status": "ok",
        "version": _extract_version(blob, tool),
        "hint": "",
    }
