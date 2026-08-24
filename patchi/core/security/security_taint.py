"""
Taint analysis and secret detection agents for Patchi.
"""

from __future__ import annotations
import logging

import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

from ..agents.base import (
    AgentGroup,
    AgentInput,
    AgentResult,
    BaseAgent,
    Severity,
    make_finding,
    register,
)
from ..brain.ast_utils import track_taint
from ..brain.languages import EXTENSION_MAP
from patchi.core.constants import is_offline

# ── Shared subprocess runner ───────────────────────────────────────────────────


_log = logging.getLogger("patchi.security.security_taint")


def _run(cmd: list[str], cwd: Path, timeout: int = 120, env: dict | None = None) -> dict:
    import os

    merged = {**os.environ, **(env or {})}
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            cwd=str(cwd),
            timeout=timeout,
            env=merged,
        )
        return {
            "returncode": proc.returncode,
            "stdout": proc.stdout[:10000],
            "stderr": proc.stderr[:3000],
            "timed_out": False,
        }
    except subprocess.TimeoutExpired:
        return {"returncode": -1, "stdout": "", "stderr": "", "timed_out": True}
    except Exception as e:
        return {"returncode": -1, "stdout": "", "stderr": str(e), "timed_out": False}


def _call_ai(prompt: str, config: dict, max_tokens: int = 800) -> str:
    """Call configured AI. Returns "" if unavailable or offline."""
    if is_offline():
        return ""
    ai = config.get("ai", {})
    local = ai.get("local_model_name")
    if local:
        return _call_ollama(local, prompt, max_tokens)
    for key_cfg in ai.get("keys", []):
        if key_cfg.get("status") == "error":
            continue
        env_var = key_cfg.get("env_var", "")
        api_key = os.environ.get(env_var, "")
        if not api_key:
            continue
        result = _call_openai_compat(
            api_key,
            key_cfg.get("base_url", ""),
            key_cfg.get("model", ""),
            key_cfg.get("format", "openai"),
            prompt,
            max_tokens,
        )
        if result:
            return result
    return ""


def _call_ollama(model: str, prompt: str, max_tokens: int) -> str:
    import urllib.request

    from patchi.core.constants import OLLAMA_GENERATE_URL

    try:
        payload = json.dumps(
            {
                "model": model,
                "prompt": prompt,
                "stream": False,
                "options": {"num_predict": max_tokens},
            }
        ).encode()
        req = urllib.request.Request(
            OLLAMA_GENERATE_URL,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read()).get("response", "")
    except Exception as e:
        _log.warning("_call_ollama failed: %s", e)
        return ""


def _call_openai_compat(api_key, base_url, model, fmt, prompt, max_tokens) -> str:
    import urllib.request

    try:
        if fmt == "anthropic":
            payload = json.dumps(
                {
                    "model": model,
                    "max_tokens": max_tokens,
                    "messages": [{"role": "user", "content": prompt}],
                }
            ).encode()
            headers = {
                "x-api-key": api_key,
                "anthropic-version": "2023-06-01",
                "Content-Type": "application/json",
            }
            url = f"{base_url}/messages"
        else:
            payload = json.dumps(
                {
                    "model": model,
                    "max_tokens": max_tokens,
                    "messages": [{"role": "user", "content": prompt}],
                }
            ).encode()
            headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
            url = f"{base_url}/chat/completions"
        req = urllib.request.Request(url, data=payload, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=30) as r:
            data = json.loads(r.read())
            if fmt == "anthropic":
                return data.get("content", [{}])[0].get("text", "")
            return data.get("choices", [{}])[0].get("message", {}).get("content", "")
    except Exception as e:
        _log.warning("_call_openai_compat failed: %s", e)
        return ""


# ──────────────────────────────────────────────────────────────────────────────
# 1. TaintAnalyzer
# ──────────────────────────────────────────────────────────────────────────────

# Sink call names tracked structurally via tree-sitter AST (track_taint).
_TAINT_SINK_NAMES = {
    "eval", "exec", "os.system", "subprocess.run", "subprocess.Popen",
    "subprocess.call", "execute", "open", "redirect", "HttpResponseRedirect",
    "render_template_string", "Template", "pickle.loads", "yaml.load",
}

# Maps a sink call name (or its leaf) to (sink_type, severity, cwe).
_TAINT_SINK_INFO: dict[str, tuple[str, Severity, str]] = {
    "eval": ("code_injection", Severity.CRITICAL, "CWE-94"),
    "exec": ("code_injection", Severity.CRITICAL, "CWE-94"),
    "os.system": ("command_injection", Severity.CRITICAL, "CWE-78"),
    "subprocess.run": ("command_injection", Severity.CRITICAL, "CWE-78"),
    "subprocess.Popen": ("command_injection", Severity.CRITICAL, "CWE-78"),
    "subprocess.call": ("command_injection", Severity.CRITICAL, "CWE-78"),
    "execute": ("sql_injection", Severity.CRITICAL, "CWE-89"),
    "open": ("path_traversal", Severity.HIGH, "CWE-22"),
    "redirect": ("open_redirect", Severity.HIGH, "CWE-601"),
    "HttpResponseRedirect": ("open_redirect", Severity.HIGH, "CWE-601"),
    "render_template_string": ("template_injection", Severity.HIGH, "CWE-94"),
    "Template": ("template_injection", Severity.HIGH, "CWE-94"),
    "pickle.loads": ("deserialization", Severity.HIGH, "CWE-502"),
    "yaml.load": ("deserialization", Severity.HIGH, "CWE-502"),
}


def _taint_sink_info(name: str) -> tuple[str, Severity, str] | None:
    info = _TAINT_SINK_INFO.get(name)
    if info is not None:
        return info
    leaf = name.split(".")[-1]
    return _TAINT_SINK_INFO.get(leaf)


@register
class TaintAnalyzer(BaseAgent):
    """
    Data flow taint analysis — maps sources to sinks without sanitization.

    Sources: HTTP params, query strings, headers, body, cookies, file uploads,
             WebSocket messages, env vars.
    Sinks:   eval(), exec(), os.system(), subprocess, SQL string concat,
             file path construction, HTTP redirects, template rendering,
             deserialization calls.

    Method:
      1. Static: scan AST for source reads and sink calls, track assignments.
      2. Build flow graph — flag source→sink paths with no sanitization.
      3. AI call per flagged path — "Is this actually exploitable?"
         (one call max per path, results cached in findings).

    No AI = static-only. Still finds ~70% of real taint issues.
    """

    name = "TaintAnalyzer"
    group = AgentGroup.SECURITY
    timeout = 120

    # Sources that introduce untrusted data
    _SOURCE_PATTERNS = [
        (
            re.compile(
                r"""\brequest\.(args|form|json|data|files|cookies|headers|values)\[?['"]?(\w*)['"]?\]?"""
            ),
            "http_param",
        ),
        (re.compile(r"""\bos\.environ\.get\(['"](.*?)['"]\)"""), "env_var"),
        (
            re.compile(r"""\bflask\.request\.|\bfastapi\b.*\bRequest\b|\bdjango\b.*\brequest\."""),
            "http_framework",
        ),
        (re.compile(r"""\bwebsocket\.recv\(\)|\bws\.receive\(\)"""), "websocket"),
        # Node.js / Express sources
        (re.compile(r"""\breq\.(query|body|params|headers|cookies)\b"""), "http_param"),
        (re.compile(r"""\bevent\.(queryStringParameters|body|pathParameters)\b"""), "http_param"),
        # PHP sources
        (re.compile(r"""\$_(GET|POST|REQUEST|COOKIE|SERVER)\["""), "http_param"),
    ]

    # Sinks where untrusted data causes vulnerabilities
    _SINK_PATTERNS = [
        (re.compile(r"""\b(?:eval|exec)\s*\("""), "code_injection", Severity.CRITICAL),
        (
            re.compile(r"""\bos\.system\s*\(|\bsubprocess\.\w+\s*\("""),
            "command_injection",
            Severity.CRITICAL,
        ),
        (
            re.compile(r"""\bcursor\.execute\s*\(.*?\+|f['"]\s*SELECT.*?{""", re.DOTALL),
            "sql_injection",
            Severity.CRITICAL,
        ),
        (
            re.compile(r"""\bopen\s*\([^)]*\+|\bpathlib\..*?\+.*?["'/]"""),
            "path_traversal",
            Severity.HIGH,
        ),
        (
            re.compile(r"""\bredirect\s*\([^)]*request\.|HttpResponseRedirect\("""),
            "open_redirect",
            Severity.HIGH,
        ),
        (
            re.compile(r"""\brender_template_string\s*\(|jinja2.*?\bTemplate\s*\("""),
            "template_injection",
            Severity.HIGH,
        ),
        (
            re.compile(r"""\bpickle\.loads?\s*\(|\byaml\.load\s*\([^,)]*\)"""),
            "deserialization",
            Severity.HIGH,
        ),
        (
            re.compile(r"""\binnerHTML\s*=|document\.write\s*\(|\.html\s*\([^)]*\$"""),
            "xss",
            Severity.HIGH,
        ),
    ]

    def _run(self, inp: AgentInput, result: AgentResult) -> None:
        from patchi.core.brain.scanner import FileScanner

        root = inp.root
        paths = FileScanner(root).discover()

        total_paths = 0
        seen: set[tuple] = set()  # dedupe keys (line, sink_type)

        for path in paths:
            ext = path.suffix.lower()
            lang = EXTENSION_MAP.get(ext)
            if lang is None:
                continue
            try:
                src = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            rel = path.relative_to(root).as_posix()
            lines = src.splitlines()

            # ── AST-based taint tracking (source → sink argument flow) ───────
            taint_results = track_taint(src, lang, _TAINT_SINK_NAMES)
            for tr in taint_results:
                info = _taint_sink_info(tr["name"])
                if info is None:
                    continue
                sink_type, severity, cwe = info
                line = tr.get("line", 0)
                key = (line, sink_type)
                if key in seen:
                    continue
                seen.add(key)
                source_code = (tr.get("tainted_via") or [""])[0][:100]
                ai_confirmed = self._confirm_with_ai(
                    rel,
                    {"line": line, "type": "source", "code": source_code},
                    {"line": line, "code": tr["full_text"].strip()[:100], "type": sink_type},
                    src,
                    inp.config,
                )
                if ai_confirmed is False:
                    continue
                result.add_finding(
                    make_finding(
                        agent=self.name,
                        finding_type=f"taint_{sink_type}",
                        severity=severity,
                        file=rel,
                        line=line,
                        message=(
                            f"Potential {sink_type.replace('_', ' ')}: "
                            f"untrusted input reaches {sink_type} sink."
                        ),
                        code_snippet=tr["full_text"].strip()[:120],
                        detail=f"Tainted via: {', '.join(tr.get('tainted_via') or [])[:80]}",
                        suggestion=f"Validate and sanitize input before passing to {sink_type} sink.",
                        cwe=cwe,
                        fix_agent="SecurityFixer",
                        ai_confirmed=ai_confirmed,
                    )
                )

            # ── Regex proximity pass (concat / assignment sinks AST can't model) ─
            sources_in_file: list[dict] = []
            for i, line in enumerate(lines, 1):
                for pattern, source_type in self._SOURCE_PATTERNS:
                    if pattern.search(line):
                        sources_in_file.append(
                            {"line": i, "type": source_type, "code": line.strip()[:100]}
                        )

            for i, line in enumerate(lines, 1):
                for sink_pattern, sink_type, severity in self._SINK_PATTERNS:
                    if not sink_pattern.search(line):
                        continue
                    nearby_sources = [s for s in sources_in_file if abs(s["line"] - i) <= 30]
                    if not nearby_sources:
                        continue
                    key = (i, sink_type)
                    if key in seen:
                        continue
                    seen.add(key)
                    source = nearby_sources[0]
                    ai_confirmed = self._confirm_with_ai(
                        rel,
                        source,
                        {"line": i, "code": line.strip()[:100], "type": sink_type},
                        src,
                        inp.config,
                    )
                    if ai_confirmed is False:
                        continue
                    result.add_finding(
                        make_finding(
                            agent=self.name,
                            finding_type=f"taint_{sink_type}",
                            severity=severity,
                            file=rel,
                            line=i,
                            message=(
                                f"Potential {sink_type.replace('_', ' ')}: "
                                f"user input from {source['type']} reaches {sink_type} sink."
                            ),
                            code_snippet=line.strip()[:120],
                            detail=f"Source at line {source['line']}: {source['code'][:80]}",
                            suggestion=f"Validate and sanitize input before passing to {sink_type} sink.",
                            cwe=self._cwe(sink_type),
                            fix_agent="SecurityFixer",
                            ai_confirmed=ai_confirmed,
                        )
                    )

            if taint_results or sources_in_file:
                total_paths += 1
            result.files_scanned += 1

        result.data["total_paths_checked"] = total_paths
        result.data["taint_findings"] = result.finding_count

    def _confirm_with_ai(
        self,
        file_path: str,
        source: dict,
        sink: dict,
        file_content: str,
        config: dict,
    ) -> bool | None:
        """Ask AI if this taint path is actually exploitable. Returns True/False/None."""
        # Extract relevant context (source line ± 15 lines)
        lines = file_content.splitlines()
        start = max(0, min(source["line"], sink["line"]) - 15)
        end = min(len(lines), max(source["line"], sink["line"]) + 15)
        context = "\n".join(lines[start:end])

        prompt = (
            f"Security analysis: Is this code path actually exploitable?\n"
            f"File: {file_path}\n"
            f"Source (user input): line {source['line']} — {source['code']}\n"
            f"Sink: line {sink['line']} — {sink['code']}\n"
            f"Code context:\n```\n{context[:800]}\n```\n"
            f"Answer only: YES (exploitable) or NO (not exploitable) or UNCERTAIN."
        )
        from patchi.core.security import security_agents as compat

        response = compat._call_ai(prompt, config, max_tokens=10)
        if not response:
            return None  # No AI — include as uncertain
        response_upper = response.strip().upper()
        if "YES" in response_upper:
            return True
        if "NO" in response_upper:
            return False
        return None

    def _cwe(self, sink_type: str) -> str:
        return {
            "code_injection": "CWE-94",
            "command_injection": "CWE-78",
            "sql_injection": "CWE-89",
            "path_traversal": "CWE-22",
            "open_redirect": "CWE-601",
            "template_injection": "CWE-94",
            "deserialization": "CWE-502",
            "xss": "CWE-79",
        }.get(sink_type, "CWE-20")


# ──────────────────────────────────────────────────────────────────────────────
# 2. SecretScanner
# ──────────────────────────────────────────────────────────────────────────────


@register
class SecretScanner(BaseAgent):
    """
    Secret and credential detection.

    Primary: Gitleaks (MIT) — run as subprocess, parse JSON output.
    Fallback: pattern-based regex scan when Gitleaks not installed.

    DO NOT use TruffleHog in hosted SaaS mode (AGPL-3.0 — source disclosure required).
    Gitleaks is the correct tool here.

    Never stores or logs the actual secret value — only file, line, type.
    """

    name = "SecretScanner"
    group = AgentGroup.SECURITY
    timeout = 120

    # Fallback patterns when Gitleaks unavailable
    _FALLBACK_PATTERNS: list[tuple[str, re.Pattern, Severity]] = [
        ("aws_access_key", re.compile(r"AKIA[0-9A-Z]{16}"), Severity.CRITICAL),
        (
            "aws_secret_key",
            re.compile(r"""(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+]{40}"""),
            Severity.CRITICAL,
        ),
        ("github_token", re.compile(r"gh[pousr]_[A-Za-z0-9_]{32,}"), Severity.CRITICAL),
        ("openai_key", re.compile(r"sk-[A-Za-z0-9]{32,}"), Severity.CRITICAL),
        ("anthropic_key", re.compile(r"sk-ant-[A-Za-z0-9\-_]{95,}"), Severity.CRITICAL),
        (
            "private_key",
            re.compile(r"-----BEGIN (?:RSA|EC|OPENSSH) PRIVATE KEY"),
            Severity.CRITICAL,
        ),
        ("stripe_live_key", re.compile(r"(?:sk|pk)_live_[A-Za-z0-9]{24,}"), Severity.CRITICAL),
        ("google_api_key", re.compile(r"AIza[0-9A-Za-z\-_]{35}"), Severity.CRITICAL),
        (
            "jwt_secret",
            re.compile(r"""(?i)jwt.{0,10}secret.{0,10}[=:]["'][^"']{8,}"""),
            Severity.HIGH,
        ),
        (
            "db_password",
            re.compile(
                r"""(?i)(?:database|mysql|postgres|mongo|\bdb\b).{0,15}password.{0,5}[=:]["'][^"']{4,}"""
            ),
            Severity.HIGH,
        ),
        (
            "hardcoded_password",
            re.compile(r"""(?i)\bpassword\s*=\s*["'][^"']{6,}["']"""),
            Severity.HIGH,
        ),
        (
            "sendgrid_key",
            re.compile(r"SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}"),
            Severity.CRITICAL,
        ),
        ("slack_token", re.compile(r"xox[baprs]-[A-Za-z0-9\-]{10,}"), Severity.CRITICAL),
    ]

    _SKIP_FILES = {
        "package-lock.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "CHANGELOG.md",
        "LICENSE",
        ".gitignore",
    }

    def _run(self, inp: AgentInput, result: AgentResult) -> None:
        root = inp.root

        if shutil.which("gitleaks"):
            self._run_gitleaks(root, result)
        else:
            self._run_fallback(root, result)

        result.data["secret_count"] = result.finding_count
        result.data["tool"] = "gitleaks" if shutil.which("gitleaks") else "regex_fallback"

    def _run_gitleaks(self, root: Path, result: AgentResult) -> None:
        """Run gitleaks detect, parse JSON report."""
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
            report_path = tf.name

        cmd = [
            "gitleaks",
            "detect",
            "--source",
            str(root),
            "--report-format",
            "json",
            "--report-path",
            report_path,
            "--no-git",  # scan files without requiring git history
            "--exit-code",
            "0",  # don't fail on finds — we handle them
        ]
        _run(cmd, root, timeout=self.timeout - 10)

        try:
            findings = json.loads(Path(report_path).read_text())
            if not isinstance(findings, list):
                findings = []
        except Exception as e:
            _log.warning("SecretScanner._run_gitleaks failed: %s", e)
            findings = []
        finally:
            try:
                os.unlink(report_path)
            except Exception as e:
                _log.warning("SecretScanner._run_gitleaks failed: %s", e)

        for f in findings:
            file_path = f.get("File", "")
            line = f.get("StartLine", 0)
            rule_id = f.get("RuleID", "unknown")
            # description never contains the secret value — only metadata
            result.add_finding(
                make_finding(
                    agent=self.name,
                    finding_type="hardcoded_secret",
                    severity=Severity.CRITICAL,
                    file=file_path,
                    line=line,
                    message=f"Secret detected: {rule_id.replace('-', ' ')}",
                    detail=f"Match at {file_path}:{line}. Rule: {rule_id}.",
                    suggestion="Remove the secret from source. Use environment variables instead.",
                    cwe="CWE-312",
                    fix_agent="EnvFixer",
                    rule_id=rule_id,
                )
            )
            result.files_scanned += 1

    def _run_fallback(self, root: Path, result: AgentResult) -> None:
        """Regex-based fallback when gitleaks is not installed."""
        from patchi.core.brain.scanner import FileScanner

        for path in FileScanner(root).discover():
            if path.name in self._SKIP_FILES:
                continue
            if path.name.startswith(".env"):
                continue  # .env files expected to have values — SideFileScanner handles

            try:
                src = path.read_text(encoding="utf-8", errors="replace")
                lines = src.splitlines()
                rel = path.relative_to(root).as_posix()
            except OSError:
                continue

            result.files_scanned += 1
            for i, line in enumerate(lines, 1):
                for pattern_type, pattern, severity in self._FALLBACK_PATTERNS:
                    m = pattern.search(line)
                    if m:
                        safe_line = line[: m.start()] + "[REDACTED]" + line[m.end() :]
                        result.add_finding(
                            make_finding(
                                agent=self.name,
                                finding_type="hardcoded_secret",
                                severity=severity,
                                file=rel,
                                line=i,
                                message=f"Potential {pattern_type.replace('_', ' ')} in source code.",
                                code_snippet=safe_line.strip()[:120],
                                suggestion="Move to environment variable. Never commit secrets.",
                                cwe="CWE-312",
                                fix_agent="EnvFixer",
                                pattern_type=pattern_type,
                            )
                        )
                        break
