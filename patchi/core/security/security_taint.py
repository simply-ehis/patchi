"""
Taint analysis and secret detection agents for Patchi.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from patchi.core.constants import is_offline

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
    "eval",
    "exec",
    "os.system",
    "subprocess.run",
    "subprocess.Popen",
    "subprocess.call",
    "execute",
    "open",
    "redirect",
    "HttpResponseRedirect",
    "render_template_string",
    "Template",
    "pickle.loads",
    "yaml.load",
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
    # Sources that introduce untrusted data - matched against parsed member
    # paths and call sites (member_paths / find_calls), never raw text.
    _REQUEST_ATTRS = {"args", "form", "json", "data", "files", "cookies", "headers", "values"}
    _REQ_ATTRS = {"query", "body", "params", "headers", "cookies"}
    _EVENT_ATTRS = {"queryStringParameters", "body", "pathParameters"}
    _PHP_VARS = ("$_GET", "$_POST", "$_REQUEST", "$_COOKIE", "$_SERVER")
    _SOURCE_CALLS = {"os.environ.get", "websocket.recv", "ws.receive"}
    _SOURCE_CALL_TYPES = {
        "os.environ.get": "env_var",
        "websocket.recv": "websocket",
        "ws.receive": "websocket",
    }

    # Sink call names (full dotted or leaf) shared with the track_taint pass.
    _SINK_CALL_NAMES = {
        "eval", "exec", "os.system", "subprocess.run", "subprocess.Popen",
        "subprocess.call", "execute", "open", "redirect", "HttpResponseRedirect",
        "render_template_string", "Template", "pickle.loads", "pickle.load",
        "yaml.load", "document.write", "html",
    }

    @staticmethod
    def _member_source_kind(dotted: str) -> str | None:
        head, _, rest = dotted.partition(".")
        attr = rest.split(".")[0].split("[")[0]
        if head.lower() == "request" and attr in TaintAnalyzer._REQUEST_ATTRS:
            return "http_param"
        if head.lower() == "req" and attr in TaintAnalyzer._REQ_ATTRS:
            return "http_param"
        if head.lower() == "event" and attr in TaintAnalyzer._EVENT_ATTRS:
            return "http_param"
        if any(dotted.startswith(v) for v in TaintAnalyzer._PHP_VARS):
            return "http_param"
        low = dotted.lower()
        if "flask.request" in low:
            return "http_framework"
        if "fastapi" in low and "request" in low:
            return "http_framework"
        if "django" in low and "request" in low:
            return "http_framework"
        return None

    def _structural_sources(self, content: str, lang) -> list[dict]:
        """Source reads as (line, type, code) from parsed member paths + calls."""
        from patchi.core.brain.ast_utils import find_calls
        from patchi.core.brain.code_query import member_paths

        out: list[dict] = []
        for dotted, line in member_paths(content, lang):
            kind = self._member_source_kind(dotted)
            if kind is not None:
                out.append({"line": line, "type": kind, "code": dotted[:100]})
        for call in find_calls(content, lang, set(self._SOURCE_CALLS)):
            name = str(call.get("name", ""))
            kind = self._SOURCE_CALL_TYPES.get(name)
            if kind:
                line_no = int(call.get("line", 0) or 0)
                out.append({"line": line_no, "type": kind, "code": name[:100]})
        return out

    def _structural_sinks(self, content: str, lang) -> list[dict]:
        """Sink sites as (line, sink_type, severity, cwe) from parsed calls."""
        from patchi.core.brain.ast_utils import find_assignments, find_calls
        from patchi.core.brain.code_query import calls_with_dynamic_arg

        out: list[dict] = []
        try:
            calls = find_calls(content, lang, set(self._SINK_CALL_NAMES))
        except Exception:
            calls = []
        dynamic_lines = set(calls_with_dynamic_arg(content, lang, {"execute", "open"}))
        for call in calls:
            name = str(call.get("name", ""))
            leaf = name.split(".")[-1]
            line = int(call.get("line", 0) or 0)
            if leaf in ("eval", "exec"):
                out.append((line, "code_injection", Severity.CRITICAL, "CWE-94"))
            elif name == "os.system" or name.startswith("subprocess."):
                out.append((line, "command_injection", Severity.CRITICAL, "CWE-78"))
            elif leaf == "execute":
                if line in dynamic_lines:
                    out.append((line, "sql_injection", Severity.CRITICAL, "CWE-89"))
            elif leaf == "open" or "pathlib" in name:
                if line in dynamic_lines:
                    out.append((line, "path_traversal", Severity.HIGH, "CWE-22"))
            elif leaf in ("redirect", "HttpResponseRedirect"):
                out.append((line, "open_redirect", Severity.HIGH, "CWE-601"))
            elif leaf in ("render_template_string", "Template"):
                out.append((line, "template_injection", Severity.HIGH, "CWE-94"))
            elif name in ("pickle.loads", "pickle.load", "yaml.load"):
                out.append((line, "deserialization", Severity.HIGH, "CWE-502"))
            elif name == "document.write":
                out.append((line, "xss", Severity.HIGH, "CWE-79"))
            elif leaf == "html":
                if line in dynamic_lines:
                    out.append((line, "xss", Severity.HIGH, "CWE-79"))
        # innerHTML assignment targets (parsed, not text search)
        try:
            assignments = find_assignments(content, lang)
        except Exception:
            assignments = []
        for assignment in assignments:
            target = str(assignment.get("target", ""))
            if target.endswith(".innerHTML"):
                out.append((int(assignment.get("line", 0) or 0), "xss", Severity.HIGH, "CWE-79"))
        return out

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

            # ── AST-based taint tracking (source → sink argument flow) ──────
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
                    )
                )

            # Structural proximity pass (parsed sources/sinks, 30-line window)
            sources_in_file = self._structural_sources(src, lang)

            for line, sink_type, severity, cwe in self._structural_sinks(src, lang):
                nearby_sources = [s for s in sources_in_file if abs(s["line"] - line) <= 30]
                if not nearby_sources:
                    continue
                key = (line, sink_type)
                if key in seen:
                    continue
                seen.add(key)
                source = nearby_sources[0]
                ai_confirmed = self._confirm_with_ai(
                    rel,
                    source,
                    {"line": line, "code": source["code"], "type": sink_type},
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
                            f"user input from {source['type']} reaches {sink_type} sink."
                        ),
                        code_snippet=source["code"][:120],
                        detail=f"Source at line {source['line']}: {source['code'][:80]}",
                        suggestion=(
                            f"Validate and sanitize input before passing to {sink_type} sink."
                        ),
                        cwe=cwe,
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

    # -- Regex-free fallback detection (AST + entropy + provider prefixes) --
    # Known token formats are matched as EXACT PREFIXES, not regex. Anything
    # without a known prefix must clear a Shannon-entropy + charset-mix bar,
    # and usually also sit in a credential-named assignment, to be flagged.

    _PROVIDER_PREFIXES: tuple[tuple[str, str], ...] = (
        ("AKIA", "aws_access_key"),
        ("sk-ant-", "anthropic_key"),
        ("sk-proj-", "openai_project_key"),
        ("ghp_", "github_pat"),
        ("gho_", "github_oauth"),
        ("ghs_", "github_app_secret"),
        ("ghr_", "github_refresh_token"),
        ("github_pat_", "github_fine_grained_pat"),
        ("xoxb-", "slack_bot_token"),
        ("xoxp-", "slack_user_token"),
        ("xoxa-", "slack_workspace_token"),
        ("xoxs-", "slack_session_token"),
        ("AIza", "google_api_key"),
        ("SG.", "sendgrid_key"),
        ("sk_live_", "stripe_live_key"),
        ("pk_live_", "stripe_publishable_live_key"),
        ("rk_live_", "stripe_restricted_live_key"),
        ("glpat-", "gitlab_pat"),
        ("dop_v1_", "digitalocean_pat"),
        ("shpat_", "shopify_pat"),
        ("npm_", "npm_token"),
        ("pypi-", "pypi_token"),
    )

    _CRED_NAME_TERMS: frozenset = frozenset(
        {
            "api_key",
            "apikey",
            "secret",
            "token",
            "password",
            "passwd",
            "pwd",
            "credential",
            "private_key",
            "access_key",
            "auth_key",
            "client_secret",
            "signing_key",
            "encryption_key",
            "session_key",
            "webhook_secret",
        }
    )

    _PLACEHOLDER_MARKERS: tuple[str, ...] = (
        "changeme",
        "change_me",
        "<your",
        "${",
        "{{",
        "%(",
        "os.environ",
        "getenv",
        "environ[",
        "environ.get",
        "example",
        "placeholder",
        "xxx",
        "...",
        "todo",
        "dummy",
        "sample_",
        "your-",
        "-here",
        "insert_",
        "redacted",
        "[masked]",
        "not_a_real",
        "fake_",
    )

    _TEXT_SUFFIXES = {
        ".py",
        ".js",
        ".ts",
        ".jsx",
        ".tsx",
        ".go",
        ".rs",
        ".java",
        ".kt",
        ".rb",
        ".php",
        ".swift",
        ".dart",
        ".cs",
        ".c",
        ".cpp",
        ".h",
        ".yaml",
        ".yml",
        ".json",
        ".toml",
        ".ini",
        ".cfg",
        ".conf",
        ".properties",
        ".xml",
        ".envrc",
        ".sh",
        ".bash",
        ".ps1",
    }

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
        """Regex-free fallback: AST string literals + entropy + provider prefixes."""
        from patchi.core.brain.scanner import FileScanner

        for path in FileScanner(root).discover():
            if path.suffix.lower() not in self._TEXT_SUFFIXES:
                continue
            if path.name in self._SKIP_FILES:
                continue
            if path.name.startswith(".env"):
                continue  # .env files expected to have values — SideFileScanner handles

            try:
                src = path.read_text(encoding="utf-8", errors="replace")
                rel = path.relative_to(root).as_posix()
            except OSError:
                continue

            result.files_scanned += 1

            if path.suffix.lower() == ".py":
                candidates = extract_py_string_candidates(src)
            else:
                candidates = extract_quoted_candidates(src)

            seen: set[tuple[int, str]] = set()
            for cand in candidates:
                key = (cand.line, cand.value)
                if key in seen:
                    continue
                seen.add(key)

                verdict, label, severity = classify_secret(cand.name, cand.value, self)
                if verdict is None:
                    continue

                redacted = redact(cand.value)
                result.add_finding(
                    make_finding(
                        agent=self.name,
                        finding_type="hardcoded_secret",
                        severity=severity,
                        file=rel,
                        line=cand.line,
                        message=f"Potential {label.replace('_', ' ')} ({verdict}) in source code.",
                        code_snippet=redacted,
                        suggestion="Move to environment variable. Never commit secrets.",
                        cwe="CWE-312",
                        fix_agent="EnvFixer",
                        pattern_type=label,
                        detection=verdict,
                    )
                )

    # ── Regex-free classification helpers (pure string/AST analysis) ────────

    def _match_provider_prefix(self, value: str) -> tuple[str, str] | None:
        lowered = value
        for prefix, label in self._PROVIDER_PREFIXES:
            if lowered.startswith(prefix):
                return prefix, label
        return None

    def _is_placeholder(self, value: str) -> bool:
        low = value.lower()
        for marker in self._PLACEHOLDER_MARKERS:
            if marker in low:
                return True
        # All same character ("AAAA...", "1111...") is never a real secret
        if len(set(value)) <= 2 and len(value) >= 12:
            return True
        return False

    def _is_cred_name(self, name: str) -> bool:
        if not name:
            return False
        normalized = name.lower()
        for sep in ("-", ".", " "):
            normalized = normalized.replace(sep, "_")
        terms = set(normalized.split("_"))
        if not terms.isdisjoint(self._CRED_NAME_TERMS):
            return True
        # Compound forms: apikey, authtoken, clientsecret…
        joined = normalized.replace("_", "")
        return any(
            term.replace("_", "") in joined
            for term in self._CRED_NAME_TERMS
            if "_" in term or len(term) >= 5
        )


def shannon_entropy(value: str) -> float:
    """Shannon entropy in bits per character. 0 = single repeated char."""
    import math

    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for ch in value:
        counts[ch] = counts.get(ch, 0) + 1
    total = float(len(value))
    entropy = 0.0
    for n in counts.values():
        p = n / total
        entropy -= p * math.log2(p)
    return round(entropy, 3)


def charset_mix(value: str) -> int:
    """How many character classes are present: upper, lower, digit, symbol."""
    has_upper = has_lower = has_digit = has_symbol = False
    for ch in value:
        if ch.isupper():
            has_upper = True
        elif ch.islower():
            has_lower = True
        elif ch.isdigit():
            has_digit = True
        else:
            has_symbol = True
    return sum((has_upper, has_lower, has_digit, has_symbol))


def classify_secret(
    name: str, value: str, scanner: SecretScanner
) -> tuple[str | None, str, Severity]:
    """Verdict for one candidate literal.

    Returns (verdict, label, severity); verdict None means clean.
    Order matters: known provider prefixes beat placeholder markers (AWS's own
    documented example keys contain the word "example"), then credential-name
    assignments, then generic blob detection.
    verdict ∈ {"provider-prefix", "credential-assignment", "high-entropy"}
    """
    if not value or len(value) < 8:
        return None, "", Severity.INFO

    # Known formats win unconditionally — even when they contain words like
    # "example" (AWS docs literally publish AKIAIOSFODNN7EXAMPLE).
    provider = scanner._match_provider_prefix(value)
    if provider:
        return "provider-prefix", provider[1], Severity.CRITICAL

    entropy = shannon_entropy(value)
    mix = charset_mix(value)

    # Placeholder markers ("changeme", "<your-...>") only veto weak evidence.
    # A 39-char 3-class string containing the letters "example" is a real
    # credential pattern, not documentation.
    if not (len(value) >= 20 and entropy >= 3.5) and scanner._is_placeholder(value):
        return None, "", Severity.INFO

    cred_name = scanner._is_cred_name(name)

    strong = len(value) >= 20 and entropy >= 3.5 and mix >= 3

    if cred_name and strong:
        return "credential-assignment", name or "credential", Severity.CRITICAL
    if cred_name and len(value) >= 12 and entropy >= 3.0:
        return "credential-assignment", name or "credential", Severity.HIGH

    # Token blobs: hex / base64url runs are usually 2-3 char classes by
    # nature — judge on LENGTH + entropy, not class count.
    blob_like = (
        len(value) >= 32
        and entropy >= 3.0
        and all(ch.isalnum() or ch in "+/=_-" for ch in value)
        and any(ch.isdigit() for ch in value)
        and any(ch.isalpha() for ch in value)
    )
    if blob_like:
        return "high-entropy", "opaque_token_blob", Severity.MEDIUM

    if very_strong_general(value, entropy, mix):
        return "high-entropy", "opaque_high_entropy_value", Severity.MEDIUM
    return None, "", Severity.INFO


def very_strong_general(value: str, entropy: float, mix: int) -> bool:
    return len(value) >= 28 and entropy >= 4.0 and mix == 4


def redact(value: str, keep: int = 4) -> str:
    """Show just enough to identify, never the secret itself."""
    if len(value) <= keep:
        return "[REDACTED]"
    return value[:keep] + "…[REDACTED]"


class StringCandidate:
    """A string literal found in source, with optional assignment target."""

    __slots__ = ("value", "name", "line")

    def __init__(self, value: str, name: str, line: int):
        self.value = value
        self.name = name
        self.line = line


def extract_py_string_candidates(src: str) -> list[StringCandidate]:
    """AST walk collecting string literals bound to names (assignments,
    dict values under string keys) plus bare high-risk constants."""
    import ast as _ast

    from patchi.core.brain.ast_utils.helpers import _py_assign_target_name

    out: list[StringCandidate] = []
    try:
        tree = _ast.parse(src)
    except SyntaxError:
        return out

    def _const_str(node: _ast.AST) -> str | None:
        return (
            node.value if isinstance(node, _ast.Constant) and isinstance(node.value, str) else None
        )

    for node in _ast.walk(tree):
        line = getattr(node, "lineno", 0)
        if isinstance(node, _ast.Assign):
            target = ""
            if node.targets:
                target = _py_assign_target_name(node.targets[0])
            val = _const_str(node.value)
            if val:
                out.append(StringCandidate(val, target, line))
            if isinstance(node.value, _ast.Dict):
                for k, v in zip(node.value.keys, node.value.values, strict=False):
                    sv = _const_str(v)
                    sk = _const_str(k)
                    if sv:
                        out.append(StringCandidate(sv, sk or target, line))
        elif isinstance(node, _ast.AnnAssign):
            target = _py_assign_target_name(node.target)
            val = _const_str(node.value) if node.value else None
            if val:
                out.append(StringCandidate(val, target, line))
        elif isinstance(node, _ast.keyword):
            val = _const_str(node.value)
            if val and node.arg:
                out.append(StringCandidate(val, node.arg, line))
    return out


def extract_quoted_candidates(src: str) -> list[StringCandidate]:
    """Character-scanner for quoted spans in non-Python text (no regex).

    Tracks double/single quote runs, honors backslash escapes, and guesses an
    assignment-ish name from the characters immediately before the quote.
    """
    out: list[StringCandidate] = []
    lines = src.splitlines()
    for lineno, raw in enumerate(lines, 1):
        i = 0
        n = len(raw)
        while i < n:
            ch = raw[i]
            if ch in "\"'":
                quote = ch
                j = i + 1
                buf: list[str] = []
                closed = False
                while j < n:
                    cj = raw[j]
                    if cj == "\\" and j + 1 < n:
                        buf.append(raw[j : j + 2])
                        j += 2
                        continue
                    if cj == quote:
                        closed = True
                        break
                    buf.append(cj)
                    j += 1
                if closed:
                    value = "".join(buf)
                    prefix = raw[max(0, i - 40) : i]
                    name = _guess_name_from_prefix(prefix)
                    out.append(StringCandidate(value, name, lineno))
                    i = j + 1
                    continue
            i += 1
    return out


def _guess_name_from_prefix(prefix: str) -> str:
    """Best-effort identifier before a quote: `name:` / `name=` / `\"name\":`."""
    tail = prefix.rstrip()
    for sep in (":", "="):
        idx = tail.rfind(sep)
        if idx != -1:
            head = tail[:idx].rstrip()
            word_chars = []
            for ch in reversed(head):
                if ch.isalnum() or ch in "_-":
                    word_chars.append(ch)
                else:
                    break
            name = "".join(reversed(word_chars)).strip("\"' ")
            if name:
                return name
    return ""
