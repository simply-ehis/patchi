"""
BusinessLogicAgent — Business logic abuse detection.

Detects:
- Mass assignment / broken object property level mapping
- Excessive data exposure (returning full models)
- Missing pagination on list endpoints
- Missing ownership checks (IDOR)
- Rate limiting missing on mutation endpoints
- Unvalidated business flow state transitions

Structural detections (mass assignment, pagination, state transitions) use
tree-sitter AST (find_calls / find_assignments). Route markers, ownership
checks, and serialization calls use high-quality literal-pattern regex.
Does NOT call AI. Does NOT write to disk. Does NOT touch the queue.
"""

from __future__ import annotations

import re

from ..agents.base import (
    AgentDomain,
    AgentGroup,
    AgentInput,
    AgentResult,
    BaseAgent,
    Finding,
    Severity,
    register,
    safe_rglob,
)
from ..brain.ast_utils import find_assignments, find_calls
from ..brain.languages import EXTENSION_MAP, Lang

# Source extensions to scan (language parity).
_SOURCE_EXTENSIONS = [
    "*.py",
    "*.js",
    "*.jsx",
    "*.ts",
    "*.tsx",
    "*.java",
    "*.rb",
    "*.php",
    "*.go",
    "*.rs",
    "*.cs",
    "*.kt",
    "*.kts",
]

# Path keywords that indicate an API/route file (early-exit gate).
_API_KEYWORDS = [
    "route",
    "view",
    "api",
    "controller",
    "serializer",
    "resource",
    "handler",
    "endpoint",
    "action",
]

# Request-body sources passed directly to model updates (mass assignment).
_REQUEST_BODY_RE = re.compile(r"(?:request\.(?:json|data|form|args)|body)", re.I)
# Model mutation methods that, applied to a request body, are mass assignment.
_MUTATION_CALLS = {"update", "put", "patch", "save"}
# Pagination call names.
_PAGINATION_CALLS = {"limit", "paginate", "offset", "page"}
# Objects whose status/state changes are business-critical.
_STATE_BASES = {"order", "payment", "subscription", "ticket", "workflow"}
# KEEP-AND-HARDEN: State-transition validation — evidence that a state machine or allowed-transitions guard exists —

# absence is MEDIUM, not proof of vuln — never sole verdict source (Part 7 §4)

_STATE_VALIDATION_RE = re.compile(r"(?i)(?:\ballowed\b|\bvalid\b|\btransition\b|state_machine|STATUS_FLOW|\benum\b)")
# Ownership-identifying symbols for IDOR checks, including Patchi's own
# tenant-isolation idiom (with tenant_context(...) + per-project ownership
# comparison) so fixed endpoints stop flagging.
# KEEP-AND-HARDEN: Ownership/IDOR check — evidence that current_user, owner, tenant_context, or user_id comparison

# exists — absence is MEDIUM (15-line window), not proof of IDOR — never sole verdict source (Part 7 §4)

_OWNERSHIP_RE = re.compile(
    r"(?i)(?:current_user|user\.id|\bowner\b|request\.user|\.user_id\s*=|user_id\s*=="
    r"|tenant_context|patch_project|\btenant\b)"
)
# KEEP-AND-HARDEN: Rate-limit decorator — evidence that @ratelimit/@throttle/@limit exists on mutation endpoints —

# absence is LOW, middleware may cover it — never sole verdict source (Part 7 §4)

_RATE_LIMIT_RE = re.compile(r"(?i)@(?:ratelimit|throttle|limit)")


@register
class BusinessLogicAgent(BaseAgent):
    """Detects business logic abuse, mass assignment, IDOR, excessive data exposure."""

    group = AgentGroup.SECURITY
    domain = AgentDomain.SECURITY
    name = "BusinessLogicAgent"
    description = "Business logic abuse: mass assignment, IDOR, excessive data exposure, missing pagination"

    def _run(self, inp: AgentInput, result: AgentResult) -> None:
        route_guard = re.compile(r"(?i)(?:@(?:app\.)?route|def\s+\w+|class\s+\w+[^(]*View|/api/)", re.I)

        for pattern in _SOURCE_EXTENSIONS:
            for fpath in safe_rglob(inp.root, pattern):
                if not fpath.is_file():
                    continue
                rel = fpath.relative_to(inp.root).as_posix()
                ext = fpath.suffix.lower()
                lang = EXTENSION_MAP.get(ext)

                # Skip non-route files early (Part 7: the old code then
                # scanned only the first 1KB yet still emitted verdicts —
                # truncated input must never produce findings).
                if not any(kw in rel.lower() for kw in _API_KEYWORDS):
                    try:
                        first_kb = fpath.read_text(encoding="utf-8", errors="ignore")[:1024]
                    except OSError:
                        continue
                    if not route_guard.search(first_kb):
                        continue
                try:
                    content = fpath.read_text(encoding="utf-8", errors="ignore")
                except OSError:
                    continue

                result.files_scanned += 1
                self._scan_business_logic(content, rel, result, lang)

    def _scan_business_logic(self, content: str, rel: str, result: AgentResult, lang: Lang | None) -> None:
        # ── Mass assignment detection (AST) ───────────────────────────────────
        # Part 7: an update() call fed by request data verdicts only when no
        # field allowlist is visible in the call (only/permit/fillable/
        # guarded/pick). Otherwise it is an unproven guess.
        _ALLOWLIST_RE = re.compile(r"(?i)(?:\bonly\b|permit|fillable|guarded|\bpick\b|\bslice\b|allowed_fields)")
        if lang is not None:
            for call in find_calls(content, lang, _MUTATION_CALLS):
                full = call.get("full_text", "")
                if _REQUEST_BODY_RE.search(full):
                    if _ALLOWLIST_RE.search(full):
                        continue
                    result.add_finding(
                        Finding(
                            agent=self.name,
                            type="mass_assignment",
                            severity=Severity.HIGH,
                            file=rel,
                            line=call.get("line", 0),
                            message="Mass assignment — request body applied directly to model without field whitelist",
                            suggestion="Define an explicit field allowlist and only update whitelisted fields",
                            cwe="CWE-915",
                            extra={"skill": "api-security.skill"},
                        )
                    )

        # ── Excessive data exposure (__dict__, vars(), .to_dict()) ──────────
        # Part 7: serialization without a response sink is MEDIUM only when
        # returned/rendered; internal use demotes to LOW.
        # KEEP-AND-HARDEN: Response sink — evidence that serialization output
        # reaches the HTTP response (not just internal use) — absence demotes
        # to LOW — never sole verdict source (Part 7 §4)
        _RESPONSE_SINK_RE = re.compile(r"(?i)(?:return|response|jsonify|render|send|respond)")
        if any(kw in rel.lower() for kw in _API_KEYWORDS):
            for m in re.finditer(r"(?i)(?:__dict__|vars\s*\(|\.to_dict\s*\(|\.serialize\s*\()", content):
                _line_no = content[: m.start()].count("\n") + 1
                _line_text = content.splitlines()[_line_no - 1] if _line_no <= len(content.splitlines()) else ""
                _sunk = bool(_RESPONSE_SINK_RE.search(_line_text))
                result.add_finding(
                    Finding(
                        agent=self.name,
                        type="excessive_data_exposure",
                        severity=Severity.MEDIUM if _sunk else Severity.LOW,
                        file=rel,
                        line=_line_no,
                        message="Returning full model serialization — may leak sensitive fields"
                        if _sunk
                        else "Full model serialization without visible response sink — verify it is not returned",
                        suggestion="Define explicit response fields; never return __dict__ or vars()",
                        cwe="CWE-200",
                        extra={"skill": "api-security.skill"},
                    )
                )

        # ── Missing pagination on collection endpoints (AST) ──────────────────
        if lang is not None:
            all_calls = find_calls(content, lang, {"all"})
            paginate_calls = find_calls(content, lang, _PAGINATION_CALLS)
            if all_calls and not paginate_calls:
                result.add_finding(
                    Finding(
                        agent=self.name,
                        type="missing_pagination",
                        severity=Severity.LOW,
                        file=rel,
                        line=0,
                        message="Collection endpoint uses .all() without pagination — unbounded resource consumption",
                        suggestion="Add pagination with .paginate() or .limit()/.offset()",
                        cwe="CWE-770",
                        extra={"skill": "api-security.skill"},
                    )
                )

        # ── IDOR — missing ownership check (route marker regex) ───────────────
        for m in re.finditer(
            r"(?i)(?:@(?:app\.)?route|(?:app|router)\.(?:get|post|put|delete|patch))\s*\([^)]*\{(\w+_)?id\}",
            content,
        ):
            line_start = content[: m.start()].count("\n") + 1
            lines = content.splitlines()
            surrounding = "\n".join(lines[line_start : min(line_start + 15, len(lines))])
            if not _OWNERSHIP_RE.search(surrounding):
                # Part 7: a 15-line window cannot see query filters, policies,
                # or decorators elsewhere — absence caps at MEDIUM.
                result.add_finding(
                    Finding(
                        agent=self.name,
                        type="idor_missing_ownership_check",
                        severity=Severity.MEDIUM,
                        file=rel,
                        line=line_start,
                        message="Endpoint with ID parameter and no ownership check visible nearby — "
                        "verify query filters/policies enforce ownership (potential IDOR)",
                        suggestion="Add ownership check: filter query by current_user.id or owner_id",
                        cwe="CWE-862",
                        extra={"skill": "api-security.skill"},
                    )
                )

        # ── Missing rate limiting on mutation endpoints (route marker regex) ──
        for m in re.finditer(r"(?i)(?:@(?:app\.)?route|(?:app|router)\.(?:get|post|put|delete|patch))\s*\(", content):
            line_start = content[: m.start()].count("\n") + 1
            lines = content.splitlines()
            surrounding = "\n".join(lines[max(0, line_start - 3) : min(line_start + 10, len(lines))])
            decorator_line = lines[line_start - 1] if line_start <= len(lines) else ""
            method_line = lines[line_start] if line_start < len(lines) else ""
            if re.search(r"(?i)(?:post|put|delete|patch)", decorator_line[:80]) or re.search(
                r"(?i)(?:post|put|delete|patch)", method_line[:80]
            ):
                if not _RATE_LIMIT_RE.search(surrounding[:200]):
                    result.add_finding(
                        Finding(
                            agent=self.name,
                            type="missing_rate_limit",
                            severity=Severity.LOW,
                            file=rel,
                            line=line_start,
                            message="Mutation endpoint missing rate limiting — potential for abuse",
                            suggestion="Add @ratelimit decorator with appropriate limits",
                            cwe="CWE-799",
                            extra={"skill": "api-security.skill"},
                        )
                    )

        # ── Unvalidated state transitions (AST assignments) ───────────────────
        if lang is not None:
            for asn in find_assignments(content, lang):
                target = asn.get("target", "")
                if "." not in target:
                    continue
                base, _, leaf = target.rpartition(".")
                if leaf in ("status", "state") and base.lower() in _STATE_BASES:
                    line_start = asn.get("line", 0)
                    # Part 7: the old code sliced CHARACTERS with a LINE
                    # number (~20-char window). Use real lines.
                    _all = content.splitlines()
                    ctx = "\n".join(_all[max(0, line_start - 16):min(len(_all), line_start + 5)])
                    if not _STATE_VALIDATION_RE.search(ctx):
                        result.add_finding(
                            Finding(
                                agent=self.name,
                                type="unvalidated_state_transition",
                                severity=Severity.MEDIUM,
                                file=rel,
                                line=line_start,
                                message="Status/state change without transition validation — business logic bypass",
                                suggestion="Validate state transitions against allowed flow matrix",
                                cwe="CWE-284",
                                extra={"skill": "api-security.skill"},
                            )
                        )
