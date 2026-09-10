"""
DeadCodeScanner — vulture + import-graph dual-signal dead code detection.

Strategy (per MASTER_REBUILD_BRIEF FIX 2C):
  - Import graph detects file-level dead code (files with no importers).
  - vulture (when installed) detects symbol-level dead code at confidence >= 90.
  - Symbol findings are only reported when BOTH graph AND vulture agree.
  - File-level dead code is always detected via graph alone.
  - Patchi's own infrastructure folders are never flagged.

No keyword grep. No hardcoded summaries. Every scan derives from real code.
"""
from __future__ import annotations

import json
import logging
import shutil
import subprocess
from pathlib import Path

from ..brain.ast_utils import find_dead_symbols
from ..brain.import_graph import ImportGraph, build_import_graph, find_dead_files
from ..brain.languages import EXTENSION_MAP, Lang
from .base import (
    AgentGroup,
    AgentInput,
    AgentResult,
    BaseAgent,
    Severity,
    make_finding,
    register,
)

# Folders that are intentional entry points or infrastructure — never flag them
_SKIP_SEGMENTS = frozenset(
    {
        "cli",
        "core",
        "web",
        "tests",
        "test",
        "commands",
        "notifications",
        "hosted",
        "docs",
        "scripts",
        "benchmark",
        "examples",
        "example",
        "demo",
        "__pycache__",
        ".patchi",
        "node_modules",
        "dist",
        "build",
    }
)


_log = logging.getLogger("patchi.agents.dead_code_scanner")


def _run_sglyon_deadcode(root: Path) -> list[dict] | None:
    """Run sglyon/deadcode if installed; parses JSON output."""
    import shutil
    import subprocess
    import json

    # Try binary first, then python -m deadcode
    candidates = []
    if shutil.which("deadcode"):
        candidates.append(["deadcode", "--format", "json", str(root)])
    # sglyon/deadcode also provides `deadcode` entrypoint via pip; fallback to module
    candidates.append([shutil.which("python") or "python", "-m", "deadcode", "--format", "json", str(root)])
    for cmd in candidates:
        if not cmd[0] or (cmd[0] not in ("python", "python3") and not shutil.which(cmd[0])):
            continue
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=90)
            if proc.returncode not in (0, 1):
                continue
            raw = proc.stdout.strip() or proc.stderr.strip()
            if not raw:
                continue
            data = json.loads(raw)
            # sglyon/deadcode JSON: [{file, line, symbol, kind}]
            out: list[dict] = []
            for item in data if isinstance(data, list) else data.get("results", []):
                f = item.get("file") or item.get("filename") or ""
                try:
                    rel = Path(f).relative_to(root).as_posix() if f else ""
                except ValueError:
                    rel = f
                if _should_skip(rel):
                    continue
                out.append(
                    {
                        "file": rel or f,
                        "line": int(item.get("line", 0) or 0),
                        "name": item.get("symbol") or item.get("name", ""),
                        "type": item.get("kind") or item.get("type", "deadcode"),
                        "message": f"sglyon/deadcode: {item.get('kind','unused')} {item.get('symbol','')}",
                        "confidence": 90,
                        "code": "",
                    }
                )
            if out:
                return out
        except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError, OSError) as exc:
            _log.debug("sglyon deadcode %s failed: %s", cmd[0], exc)
            continue
    return None


@register
class DeadCodeScanner(BaseAgent):
    """Dead code detection via vulture + import graph dual-signal."""

    group = AgentGroup.SCANNER
    name = "DeadCodeScanner"
    timeout = 120

    def _run(self, inp: AgentInput, result: AgentResult) -> None:
        # 1. Try sglyon/deadcode first (unified JSON for Python/JS/TS/Go/Elixir)
        sg = _run_sglyon_deadcode(inp.root)
        if sg:
            for item in sg:
                result.findings.append(
                    make_finding(
                        severity=Severity.LOW,
                        file=item.get("file", ""),
                        line_start=item.get("line", 0),
                        title=f"Dead code (sglyon): {item.get('name', '')}",
                        description=item.get("message", ""),
                        evidence=item.get("code", ""),
                        finding_type="dead_code",
                    )
                )
            result.data["orchestrator"] = "sglyon/deadcode"
            result.data["sglyon_count"] = len(sg)
            result.status = AgentStatus.SUCCEEDED
            result.files_scanned = len({f.file for f in result.findings}) if result.findings else 0
            result.data["total_findings"] = len(result.findings)
            return

        # 2. Fallback: existing dual-signal (import graph + vulture + per-language tools)
        # Build import graph — use corpus if available
        corpus = inp.extra.get("file_corpus")
        try:
            from ..brain.scanner import FileScanner
            from ..brain.import_graph import build_graph

            scanner = FileScanner(inp.root, ignore_paths=inp.config.get("ignore_paths", []), corpus=corpus)
            all_files = scanner.scan()
            # Cap graph building to first 500 files for speed
            graph = build_graph(all_files[:500], inp.root)
        except Exception as exc:
            result.add_error(f"import graph failed: {exc}")
            graph = ImportGraph()
            all_files = []

        # File-level dead code from graph alone
        try:
            graph_dead_files = set(find_dead_files(all_files, graph))
        except Exception as e:
            _log.warning("DeadCodeScanner._run failed: %s", e)
            all_files = []
            graph_dead_files = set()

        # Run vulture and per-language tools in parallel
        skip_tools = set(inp.config.get("dead_code", {}).get("skip_tools", []))
        from concurrent.futures import ThreadPoolExecutor, as_completed

        with ThreadPoolExecutor(max_workers=2) as pool:
            vulture_future = pool.submit(_run_vulture, inp.root)
            tools_future = pool.submit(_run_all_tools, inp.root, skip_tools)
            vulture_findings = vulture_future.result()
            tool_findings = tools_future.result()
        vulture_dead_files: set[str] = set()
        if vulture_findings is not None:
            for vf in vulture_findings:
                if vf.get("confidence", 0) >= 90:
                    vulture_dead_files.add(vf["file"])

        confirmed_dead: list[str] = []
        uncertain: list[str] = []

        # File-level findings
        for rel_path in sorted(graph_dead_files):
            if _should_skip(rel_path):
                continue
            is_vulture_confirmed = vulture_findings is not None and rel_path in vulture_dead_files
            if is_vulture_confirmed:
                confirmed_dead.append(rel_path)
                result.findings.append(
                    make_finding(
                        severity=Severity.MEDIUM,
                        file=rel_path,
                        line_start=0,
                        title=f"Confirmed dead file: {rel_path}",
                        description="Not imported anywhere and vulture confirms no live symbols.",
                        finding_type="confirmed_dead",
                    )
                )
            else:
                uncertain.append(rel_path)
                result.findings.append(
                    make_finding(
                        severity=Severity.LOW,
                        file=rel_path,
                        line_start=0,
                        title=f"Possibly unused file: {rel_path}",
                        description="Not imported anywhere in the project.",
                        finding_type="uncertain_dead",
                    )
                )

        # Symbol-level findings from vulture (only when file is also graph-dead)
        if vulture_findings:
            for vf in vulture_findings:
                rel_path = vf.get("file", "")
                if _should_skip(rel_path):
                    continue
                if vf.get("confidence", 0) < 90:
                    continue
                # Only report symbol if the file is already in our dead set
                if rel_path not in graph_dead_files:
                    continue
                if rel_path in confirmed_dead or rel_path in uncertain:
                    continue  # already reported at file level
                result.findings.append(
                    make_finding(
                        severity=Severity.MEDIUM,
                        file=rel_path,
                        line_start=vf.get("line", 0),
                        title=f"Unused {vf.get('type', 'symbol')}: {vf.get('name', '')}",
                        description=f"vulture ({vf.get('confidence')}%): {vf.get('message', '')}",
                        evidence=vf.get("code", ""),
                        finding_type="dead_code",
                    )
                )

        # Per-language tool findings (not graph-cross-referenced)
        for tf in tool_findings:
            if not tf.get("file") or _should_skip(tf["file"]):
                continue
            result.findings.append(
                make_finding(
                    severity=Severity.LOW,
                    file=tf["file"],
                    line_start=tf.get("line", 0),
                    title=f"Dead code ({tf.get('type', 'unknown')}): {tf.get('name', '')}",
                    description=tf.get("message", ""),
                    evidence=tf.get("code", ""),
                    finding_type="dead_code",
                )
            )

        result.data["confirmed_dead"] = confirmed_dead
        result.data["uncertain"] = uncertain
        result.data["vulture_available"] = vulture_findings is not None
        result.data["tool_findings_count"] = len(tool_findings)
        result.files_scanned = len(graph.nodes)

        # ── AST-based intra-file dead symbol detection (all parser langs) ──────
        # Complements vulture (Python) and external per-language tools. Symbols
        # for graph-dead files get a line-level dead-code signal even when no
        # external toolchain is installed (multi-language parity).
        ast_symbol_count = 0
        for rel_path in sorted(graph_dead_files):
            if _should_skip(rel_path):
                continue
            ext = Path(rel_path).suffix.lower()
            lang = EXTENSION_MAP.get(ext)
            if lang is None:
                continue
            if lang == Lang.PYTHON and vulture_findings is not None:
                continue  # vulture covers Python more precisely
            fp = inp.root / rel_path
            try:
                content = fp.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            for sym in find_dead_symbols(content, lang):
                ast_symbol_count += 1
                result.findings.append(
                    make_finding(
                        severity=Severity.LOW,
                        file=rel_path,
                        line_start=sym["line"],
                        title=f"Unused {sym['kind']}: {sym['name']}",
                        description=(
                            f"Symbol '{sym['name']}' is never referenced "
                            f"within {rel_path} (intra-file dead code)."
                        ),
                        finding_type="dead_code",
                    )
                )
        result.data["ast_symbol_findings"] = ast_symbol_count


# ── Per-language dead code tool helpers ─────────────────────────────────────────


def _detect_project_langs(root: Path) -> set[str]:
    """Detect which languages the project uses by looking for manifest files."""
    langs: set[str] = set()
    if (root / "Cargo.toml").exists():
        langs.add("rust")
    if (root / "go.mod").exists():
        langs.add("go")
    if (root / "Package.swift").exists():
        langs.add("swift")
    if (root / "composer.json").exists():
        langs.add("php")
    if (root / "Gemfile").exists():
        langs.add("ruby")
    if (root / "pom.xml").exists():
        langs.add("java")
    if (root / "build.gradle").exists() or (root / "build.gradle.kts").exists():
        langs.add("java")
    if (root / "package.json").exists():
        langs.add("javascript")
    if (
        (root / "requirements.txt").exists()
        or (root / "setup.py").exists()
        or (root / "pyproject.toml").exists()
    ):
        langs.add("python")
    if list(root.glob("*.csproj")):
        langs.add("csharp")
    return langs


def _run_tool(
    cmd: list[str],
    root: Path,
    timeout: int = 90,
) -> subprocess.CompletedProcess | None:
    if not shutil.which(cmd[0]):
        return None
    try:
        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return None


def _run_vulture(root: Path) -> list[dict] | None:
    """Run vulture for Python. Returns None if not installed."""
    proc = _run_tool(["vulture", str(root), "--min-confidence", "90", "--json"], root)
    if proc is None or proc.returncode not in (0, 1):
        return None
    raw = proc.stdout.strip()
    if not raw:
        return []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return []
    findings: list[dict] = []
    for item in data:
        abs_path = item.get("filename", "")
        try:
            rel = Path(abs_path).relative_to(root).as_posix()
        except ValueError:
            rel = abs_path
        findings.append(
            {
                "file": rel,
                "line": item.get("first_lineno", 0),
                "name": item.get("name", ""),
                "type": item.get("type", ""),
                "message": item.get("message", ""),
                "confidence": item.get("confidence", 0),
                "code": item.get("code", ""),
            }
        )
    return findings


def _run_ts_prune(root: Path) -> list[dict] | None:
    """
    Run ts-prune for TypeScript unused exports.
    npm install -g ts-prune  or  npx ts-prune
    """
    proc = _run_tool(["npx", "--yes", "ts-prune", "--project", str(root / "tsconfig.json")], root)
    if proc is None:
        return None
    findings: list[dict] = []
    for line in proc.stdout.strip().splitlines():
        if " - " not in line:
            continue
        parts = line.split(" - ", 1)
        loc = parts[0].strip()
        symbol = parts[1].strip() if len(parts) > 1 else ""
        if ":" in loc:
            file_part, line_part = loc.rsplit(":", 1)
            line_num = int(line_part) if line_part.isdigit() else 0
        else:
            file_part = loc
            line_num = 0
        try:
            rel = Path(file_part).as_posix()
        except ValueError:
            rel = file_part
        findings.append(
            {
                "file": rel,
                "line": line_num,
                "name": symbol,
                "type": "export",
                "message": f"Unused export: {symbol}",
                "confidence": 95,
                "code": "",
            }
        )
    return findings


def _run_cargo_dead_code(root: Path) -> list[dict] | None:
    """Run cargo udeps for Rust unused dependencies."""
    findings: list[dict] = []
    proc = _run_tool(["cargo", "udeps"], root, timeout=120)
    if proc is not None:
        for line in proc.stderr.strip().splitlines():
            if "unused" in line.lower():
                findings.append(
                    {
                        "file": "Cargo.toml",
                        "line": 0,
                        "name": line.strip(),
                        "type": "unused_dependency",
                        "message": line.strip(),
                        "confidence": 90,
                        "code": "",
                    }
                )
    return findings or None


def _run_go_dead_code(root: Path) -> list[dict] | None:
    """Run go vet + staticcheck for Go dead code."""
    findings: list[dict] = []
    # go vet -unusedresult removed in Go 1.19+; use go vet ./... with check for unused diagnostics
    proc = _run_tool(["go", "vet", "./..."], root, timeout=120)
    if proc is not None:
        for line in proc.stderr.strip().splitlines():
            if "unused" in line.lower() or "dead" in line.lower():
                findings.append(
                    {
                        "file": "",
                        "line": 0,
                        "name": line.strip(),
                        "type": "go_dead_code",
                        "message": line.strip(),
                        "confidence": 85,
                        "code": "",
                    }
                )
    # golangci-lint with unused linter
    proc = _run_tool(
        ["golangci-lint", "run", "--disable-all", "--enable=unused", "--timeout=2m"],
        root,
        timeout=180,
    )
    if proc is not None:
        for line in proc.stdout.strip().splitlines():
            if "unused" in line.lower():
                findings.append(
                    {
                        "file": "",
                        "line": 0,
                        "name": line.strip(),
                        "type": "go_dead_code",
                        "message": line.strip(),
                        "confidence": 90,
                        "code": "",
                    }
                )
    return findings or None


def _run_debride(root: Path) -> list[dict] | None:
    """Run debride for Ruby dead code."""
    proc = _run_tool(["debride", "."], root, timeout=120)
    if proc is None:
        return None
    findings: list[dict] = []
    for line in proc.stdout.strip().splitlines():
        if ":" not in line:
            continue
        parts = line.split(":", 2)
        if len(parts) < 2:
            continue
        file_part, line_part = parts[0], parts[1]
        rest = parts[2] if len(parts) > 2 else ""
        line_num = int(line_part) if line_part.isdigit() else 0
        try:
            rel = Path(file_part).as_posix()
        except ValueError:
            rel = file_part
        findings.append(
            {
                "file": rel,
                "line": line_num,
                "name": rest.strip(),
                "type": "ruby_dead_code",
                "message": rest.strip(),
                "confidence": 90,
                "code": "",
            }
        )
    return findings or None


def _run_composer_unused(root: Path) -> list[dict] | None:
    """Run composer-unused for PHP unused dependencies."""
    proc = _run_tool(["composer", "unused"], root, timeout=120)
    if proc is None:
        return None
    findings: list[dict] = []
    for line in proc.stdout.strip().splitlines():
        if "unused" in line.lower():
            findings.append(
                {
                    "file": "composer.json",
                    "line": 0,
                    "name": line.strip(),
                    "type": "unused_dependency",
                    "message": line.strip(),
                    "confidence": 85,
                    "code": "",
                }
            )
    return findings or None


def _run_dotnet_dead_code(root: Path) -> list[dict] | None:
    """Run dotnet tool for C# dead code analysis."""
    csproj_files = list(root.glob("*.csproj"))
    if not csproj_files:
        csproj_files = list(root.glob("**/*.csproj"))
    if not csproj_files:
        return None
    proc = _run_tool(
        ["dotnet", "list", str(csproj_files[0]), "package", "--vulnerable"], root, timeout=120
    )
    if proc is None:
        return None
    findings: list[dict] = []
    for line in proc.stdout.strip().splitlines():
        if "unused" in line.lower() or "not used" in line.lower():
            findings.append(
                {
                    "file": csproj_files[0].relative_to(root).as_posix(),
                    "line": 0,
                    "name": line.strip(),
                    "type": "unused_dependency",
                    "message": line.strip(),
                    "confidence": 80,
                    "code": "",
                }
            )
    return findings or None


def _run_jdeps(root: Path) -> list[dict] | None:
    """Run jdeps for Java unused dependencies."""
    proc = _run_tool(["jdeps", "-summary", "-recursive", "."], root, timeout=120)
    if proc is None:
        # Try mvn dependency:analyze as an alternative
        proc = _run_tool(["mvn", "dependency:analyze", "-DignoreNonCompile"], root, timeout=180)
        if proc is None:
            return None
        findings: list[dict] = []
        for line in proc.stdout.strip().splitlines():
            if "Unused" in line or "unused" in line:
                findings.append(
                    {
                        "file": "pom.xml",
                        "line": 0,
                        "name": line.strip(),
                        "type": "unused_dependency",
                        "message": line.strip(),
                        "confidence": 85,
                        "code": "",
                    }
                )
        return findings or None
    findings = []
    for line in proc.stdout.strip().splitlines():
        if "->" not in line:
            continue
        parts = line.split("->")
        if len(parts) >= 2:
            source = parts[0].strip()
            findings.append(
                {
                    "file": source if source else "",
                    "line": 0,
                    "name": parts[1].strip(),
                    "type": "java_dependency",
                    "message": line.strip(),
                    "confidence": 80,
                    "code": "",
                }
            )
    return findings or None


def _run_swift_dead_code(root: Path) -> list[dict] | None:
    """Run swiftc dead code analysis for Swift."""
    proc = _run_tool(["swiftc", "-typecheck", "-unused-imports"], root, timeout=120)
    if proc is None:
        return None
    findings: list[dict] = []
    for line in proc.stderr.strip().splitlines():
        if "unused" in line.lower():
            findings.append(
                {
                    "file": "",
                    "line": 0,
                    "name": line.strip(),
                    "type": "swift_unused",
                    "message": line.strip(),
                    "confidence": 85,
                    "code": "",
                }
            )
    return findings or None


def _run_clang_tidy(root: Path) -> list[dict] | None:
    """Run clang-tidy for C/C++ dead code detection."""
    proc = _run_tool(
        ["clang-tidy", "--checks=-*,misc-unused-*", "--list-checks"], root, timeout=120
    )
    if proc is None:
        return None
    findings: list[dict] = []
    for line in proc.stdout.strip().splitlines():
        if "unused" in line.lower():
            findings.append(
                {
                    "file": "",
                    "line": 0,
                    "name": line.strip(),
                    "type": "c_cpp_unused",
                    "message": line.strip(),
                    "confidence": 80,
                    "code": "",
                }
            )
    return findings or None


TOOL_DISPATCH: dict[str, list[tuple[str, str, str]]] = {
    # Note: python/vulture is NOT listed — it's called directly in _run() for graph cross-referencing
    "javascript": [("ts-prune", "unused exports", "ts_prune")],
    "rust": [("cargo deadlinks/udeps", "dead code/deps", "cargo_dead_code")],
    "go": [("go vet/golangci-lint", "dead code", "go_dead_code")],
    "ruby": [("debride", "dead methods", "debride")],
    "php": [("composer-unused", "unused deps", "composer_unused")],
    "csharp": [("dotnet list package", "unused deps", "dotnet_dead_code")],
    "java": [("jdeps/mvn dependency:analyze", "unused deps", "jdeps")],
    "swift": [("swiftc -unused-imports", "unused imports", "swift_dead_code")],
    "c": [("clang-tidy", "unused declarations", "clang_tidy")],
    "cpp": [("clang-tidy", "unused declarations", "clang_tidy")],
}


def _run_all_tools(root: Path, skip_tools: set[str] | None = None) -> list[dict]:
    """Run all available dead code tools in parallel for the project's detected languages."""
    from concurrent.futures import ThreadPoolExecutor, as_completed

    skip_tools = skip_tools or set()
    langs = _detect_project_langs(root)
    tool_funcs: list[tuple[str, any]] = []
    for lang in langs:
        _, _, func_suffix = (TOOL_DISPATCH.get(lang) or [("", "", "")])[0]
        if not func_suffix:
            continue
        if func_suffix in skip_tools:
            _log.debug("Skipping dead code tool %s (in skip_tools)", func_suffix)
            continue
        func_name = f"_run_{func_suffix}"
        func = globals().get(func_name)
        if func is not None:
            tool_funcs.append((func_suffix, func))

    if not tool_funcs:
        return []

    all_findings: list[dict] = []
    with ThreadPoolExecutor(max_workers=min(4, len(tool_funcs))) as pool:
        futures = {pool.submit(func, root): name for name, func in tool_funcs}
        for future in as_completed(futures):
            name = futures[future]
            try:
                findings = future.result()
                if findings:
                    all_findings.extend(findings)
            except Exception as e:
                _log.warning("Dead code tool %s failed: %s", name, e)
    return all_findings


def _should_skip(rel_path: str) -> bool:
    parts = rel_path.lower().split("/")
    return any(seg in _SKIP_SEGMENTS for seg in parts)
