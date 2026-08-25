"""
App Contract builder for Patchi's Brain.

The App Contract is the list of critical flows that must never break.
Every fix checks against this contract before applying.

The contract is built in two layers:
1. Offline (free, no AI): Pattern-based inference from routes, file names, and AST structure.
2. AI-powered: When AI is configured, the LLM synthesises a summary from all AST scanner
   results — file purposes, routes, import graph, dead code, dependencies — producing a
   richer, context-aware contract.

The confirmed contract is stored in Brain memory and never silently overwritten.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from patchi.core.brain.route_mapper import RouteInfo
    from patchi.core.brain.scanner import FileInfo


import logging

_log = logging.getLogger("patchi.brain.contract")

@dataclass
class ContractFlow:
    id: str
    name: str
    description: str
    routes: list[str]
    files: list[str]
    signals: list[str]
    confirmed: bool = False
    user_added: bool = False
    critical: bool = True
    confidence: str = "medium"  # "high" | "medium" | "low"
    suggested: bool = False  # if True, hidden from default confirmation

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "routes": self.routes,
            "files": self.files,
            "signals": self.signals,
            "confirmed": self.confirmed,
            "user_added": self.user_added,
            "critical": self.critical,
            "confidence": self.confidence,
            "suggested": self.suggested,
        }


_ROUTE_TO_FLOW: dict[str, dict] = {
    "dashboard": {"name": "Dashboard Overview", "desc": "Project dashboard with status and health overview.", "signal": "dashboard"},
    "findings": {"name": "Findings Review", "desc": "Browse, filter, and review scan findings.", "signal": "findings"},
    "settings": {"name": "Settings / Configuration", "desc": "View and update project configuration.", "signal": "config"},
    "security": {"name": "Security Scanning", "desc": "Run security scans and view reports.", "signal": "security"},
    "history": {"name": "History & Trends", "desc": "View scan history and health trends.", "signal": "history"},
    "tests": {"name": "Test Management", "desc": "Run, view, and manage test suites.", "signal": "testing"},
    "review": {"name": "Review & Fixes", "desc": "Review proposed fixes and apply or reject patches.", "signal": "fixes"},
    "queue": {"name": "Queue Management", "desc": "View and manage the scan queue.", "signal": "queue"},
    "hosted": {"name": "Hosted Mode", "desc": "Manage hosted mode, tokens, and IP reputation.", "signal": "hosted"},
    "brain": {"name": "Brain & Memory", "desc": "View brain map, memory, import graph, and blast radius.", "signal": "insights"},
    "agents": {"name": "Agent Management", "desc": "View and manage scanner agents.", "signal": "agents"},
    "notifications": {"name": "Notifications", "desc": "Configure and receive notifications and alerts.", "signal": "notifications"},
    "keys": {"name": "Key Management", "desc": "Manage API keys for AI providers.", "signal": "keys"},
}

INFERENCE_RULES: list[tuple[str, str, str, list[str], list[str], list[str]]] = [
    (
        "dashboard-overview",
        "Dashboard Overview",
        "Users can view the main dashboard with project status and health.",
        [r"^/$", r"dashboard", r"status$"],
        [r"dashboard", r"status"],
        ["dashboard"],
    ),
    (
        "findings-review",
        "Findings Review",
        "Users can browse and review scan findings.",
        [r"findings", r"scan/results", r"findings-table"],
        [r"finding", r"result"],
        ["findings"],
    ),
    (
        "settings-config",
        "Settings / Configuration",
        "Users can view and update project configuration.",
        [r"settings", r"config$", r"preferences"],
        [r"settings", r"config"],
        ["config"],
    ),
    (
        "security-scanning",
        "Security Scanning",
        "Run security scans and view reports on the project.",
        [r"security", r"scan", r"guard", r"threats"],
        [r"security", r"scan", r"guard"],
        ["security"],
    ),
    (
        "history-trends",
        "History & Trends",
        "Users can view scan history and health trends over time.",
        [r"history", r"trend", r"health-breakdown"],
        [r"history", r"trend"],
        ["history", "analytics"],
    ),
    (
        "test-management",
        "Test Management",
        "Users can run, view, and manage test suites and agents.",
        [r"tests?", r"test-agents", r"test-agents/status"],
        [r"test", r"unit", r"suite"],
        ["testing"],
    ),
    (
        "review-patches",
        "Review & Fixes",
        "Users can review proposed fixes and apply or reject patches.",
        [r"review", r"fix", r"patch", r"issue"],
        [r"review", r"fix", r"patch"],
        ["fixes"],
    ),
    (
        "queue-management",
        "Queue Management",
        "Users can view and manage the scan queue (pause/resume/clear).",
        [r"queue", r"queue/pause", r"queue/resume", r"queue/clear"],
        [r"queue"],
        ["queue"],
    ),
    (
        "hosted-mode",
        "Hosted Mode Management",
        "Users can manage hosted mode, tokens, and IP reputation.",
        [r"hosted", r"tokens", r"block", r"unblock"],
        [r"hosted", r"token", r"reputation"],
        ["hosted"],
    ),
    (
        "brain-insights",
        "Brain & Memory",
        "Users can view the brain map, memory, import graph, and blast radius.",
        [r"brain", r"memory", r"blast", r"explain"],
        [r"brain", r"memory", r"blast", r"import"],
        ["insights"],
    ),
    (
        "agent-management",
        "Agent Management",
        "Users can view and manage scanner agents and their status.",
        [r"agents", r"model", r"ai"],
        [r"agent", r"scanner"],
        ["agents"],
    ),
    (
        "notifications",
        "Notifications",
        "Users can configure and receive notifications and alerts.",
        [r"notifications?", r"notify"],
        [r"notify", r"notification", r"alert"],
        ["notifications"],
    ),
    (
        "key-management",
        "Key Management",
        "Users can manage API keys for AI providers.",
        [r"keys", r"keys/add", r"keys/remove"],
        [r"key", r"api.key", r"credential"],
        ["keys"],
    ),
]


_KNOWN_PREFIXES = set(_ROUTE_TO_FLOW.keys())


# ── AI contract summariser ─────────────────────────────────────────────────────


def build_ai_contract_summary(
    file_infos: "list[FileInfo]",
    routes: "list[RouteInfo]",
    dead_files: list[str],
    circular_deps: list[Any],
    config: dict | None = None,
) -> str | None:
    """
    When AI is configured, send the full AST scanner results to the LLM
    and get back a plain-English summary of the app's critical flows.

    Returns the AI summary string, or None if no AI is available.
    """
    if not config:
        return None

    ai_config = config.get("ai", {})
    has_keys = bool(ai_config.get("keys")) or bool(ai_config.get("local_model_name"))
    if not has_keys:
        return None

    # Build a compact summary of what the AST scanners found
    file_summaries = []
    for fi in file_infos[:50]:
        funcs = ", ".join(f.name for f in fi.functions[:5])
        classes = ", ".join(c.name for c in fi.classes[:3])
        parts = [fi.path]
        if fi.purpose:
            parts.append(f"({fi.purpose})")
        if funcs:
            parts.append(f"fns: [{funcs}]")
        if classes:
            parts.append(f"cls: [{classes}]")
        file_summaries.append(" ".join(parts))

    route_summaries = [f"{r.method} {r.path}" for r in routes[:30]]

    prompt = (
        "You are analysing a codebase. Below is a structured summary of:\n"
        "- Every source file with its inferred purpose, functions, and classes\n"
        "- Every HTTP route with its method and path\n"
        f"- Dead/unreachable files: {len(dead_files)}\n"
        f"- Circular dependencies: {len(circular_deps)}\n\n"
        "Based on this data, identify the app's critical flows "
        "(login, checkout, admin, API, data submission, etc.) that must never break.\n\n"
        f"=== FILES ({len(file_infos)} total, showing up to 50) ===\n"
        + "\n".join(file_summaries)
        + "\n\n=== ROUTES ===\n"
        + "\n".join(route_summaries)
        + "\n\nRespond with a concise JSON list of critical flows. "
        "Each flow must have: name, description (one sentence), "
        "route_paths (list of matching routes), "
        "and file_paths (list of relevant source files). "
        'Format: [{"name": "User Login", "description": "...", '
        '"route_paths": [...], "file_paths": [...]}]'
    )

    return _call_ai_summary(prompt, config)


def _call_ai_summary(prompt: str, config: dict) -> str | None:
    """Send prompt to the configured AI and return the response."""
    ai_config = config.get("ai", {})

    local_model = ai_config.get("local_model_name")
    if local_model:
        return _call_ollama(local_model, prompt)

    keys = ai_config.get("keys", [])
    for key_cfg in keys:
        if key_cfg.get("status") == "error":
            continue
        import os

        env_var = key_cfg.get("env_var", "")
        api_key = os.environ.get(env_var, "")
        if not api_key:
            continue
        result = _call_openai_compat(
            api_key=api_key,
            base_url=key_cfg.get("base_url", "https://api.openai.com/v1"),
            model=key_cfg.get("model", "gpt-4o-mini"),
            prompt=prompt,
        )
        if result:
            return result
    return None


def _call_ollama(model: str, prompt: str) -> str | None:
    import urllib.request

    from patchi.core.constants import OLLAMA_GENERATE_URL

    try:
        payload = json.dumps(
            {
                "model": model,
                "prompt": prompt,
                "stream": False,
            }
        ).encode()
        req = urllib.request.Request(
            OLLAMA_GENERATE_URL,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read())
            return data.get("response", "")
    except Exception as e:
        _log.warning("_call_ollama failed: %s", e)
        return None


def _call_openai_compat(api_key: str, base_url: str, model: str, prompt: str) -> str | None:
    import urllib.request

    try:
        payload = json.dumps(
            {
                "model": model,
                "max_tokens": 2000,
                "messages": [{"role": "user", "content": prompt}],
            }
        ).encode()
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }
        req = urllib.request.Request(
            f"{base_url}/chat/completions",
            data=payload,
            headers=headers,
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read())
            return data.get("choices", [{}])[0].get("message", {}).get("content", "")
    except Exception as e:
        _log.warning("_call_openai_compat failed: %s", e)
        return None


def parse_ai_contract_response(response: str) -> list[dict] | None:
    """Parse AI response JSON into flow dicts that confirm_flows can use."""
    try:
        data = json.loads(response)
        if isinstance(data, list):
            return data
    except json.JSONDecodeError:
        m = re.search(r"\[.*?\]", response, re.DOTALL)
        if m:
            try:
                return json.loads(m.group())
            except json.JSONDecodeError:
                pass
    return None


# ── Contract builder ───────────────────────────────────────────────────────────


class ContractBuilder:
    """
    Infers the App Contract from routes, AST file info, and optionally AI.

    Two inference paths:
    1. offline inference() — pattern-based, free, no API calls
    2. ai_infer() — sends AST scanner summary to LLM for richer contract

    Usage:
        builder = ContractBuilder(routes, file_infos)
        flows = builder.infer()           # offline, fast
        ai_flows = builder.ai_infer(config)  # AI-powered summary
    """

    def __init__(
        self,
        routes: "list[RouteInfo]",
        file_infos: "list[FileInfo]",
        dead_files: list[str] | None = None,
        circular_deps: list[Any] | None = None,
    ):
        self.routes = routes
        self.file_infos = file_infos
        self.dead_files = dead_files or []
        self.circular_deps = circular_deps or []

    def infer(self) -> list[ContractFlow]:
        """
        Infer contract flows by clustering route paths by their URL prefix.

        Each route is assigned to a cluster based on its first path segment.
        Clusters with at least one route produce a ContractFlow at medium confidence.
        Clusters with routes AND matching file purposes produce high confidence.
        Routes that don't match any known prefix produce a single "Other API" flow.
        """
        from collections import defaultdict

        clusters: dict[str, list[str]] = defaultdict(list)
        unmatched: list[str] = []

        for r in self.routes:
            path = r.path
            segments = [s for s in path.split("/") if s]
            prefix = segments[0] if segments else "root"
            if prefix in _KNOWN_PREFIXES:
                clusters[prefix].append(path)
            else:
                unmatched.append(path)

        found: list[ContractFlow] = []

        for prefix, matched_routes in sorted(clusters.items()):
            meta = _ROUTE_TO_FLOW[prefix]
            flow_id = prefix
            name = meta["name"]
            desc = meta["desc"]
            signal = meta["signal"]

            file_hits = [fi.path for fi in self.file_infos if prefix in fi.path.lower()]
            confidence = "high" if file_hits else "medium"

            found.append(
                ContractFlow(
                    id=flow_id,
                    name=name,
                    description=desc,
                    routes=matched_routes[:5],
                    files=file_hits[:10],
                    signals=[signal],
                    confirmed=False,
                    user_added=False,
                    confidence=confidence,
                    suggested=False,
                )
            )

        if unmatched:
            found.append(
                ContractFlow(
                    id="other-api",
                    name="Other API Endpoints",
                    description="Additional API endpoints that don't fit a named category.",
                    routes=unmatched[:10],
                    files=[],
                    signals=["api"],
                    confirmed=False,
                    user_added=False,
                    confidence="medium",
                    suggested=True,
                )
            )

        return found

    def ai_infer(self, config: dict | None = None) -> list[ContractFlow] | None:
        """
        Use AI to generate a richer contract from AST scanner data.
        Returns AI-inferred flows merged with offline pattern matches,
        or None if AI is not available.
        """
        response = build_ai_contract_summary(
            self.file_infos,
            self.routes,
            self.dead_files,
            self.circular_deps,
            config,
        )
        if not response:
            return None

        ai_flows = parse_ai_contract_response(response)
        if not ai_flows:
            return None

        offline_flows = self.infer()
        {f.id for f in offline_flows}

        merged: list[ContractFlow] = []
        seen_names: set[str] = set()

        for i, af in enumerate(ai_flows):
            name = af.get("name", f"AI Flow {i + 1}")
            key = name.lower().replace(" ", "-")
            if key in seen_names:
                continue
            seen_names.add(key)
            merged.append(
                ContractFlow(
                    id=key,
                    name=name,
                    description=af.get("description", ""),
                    routes=af.get("route_paths", [])[:5],
                    files=af.get("file_paths", [])[:10],
                    signals=["ai-inferred"],
                    confirmed=False,
                    user_added=False,
                )
            )

        # Mark AI-inferred flows with high confidence
        for f in merged:
            if "ai-inferred" in f.signals:
                f.confidence = "high"
                f.suggested = False

        # Merge offline-only flows that AI missed — skip suggested (low confidence)
        for f in offline_flows:
            if f.suggested:
                continue
            key = f.name.lower().replace(" ", "-")
            if key not in seen_names:
                merged.append(f)

        return merged

    def build_confirmation_message(self, flows: list[ContractFlow], all_flows: bool = False) -> str:
        """
        Build the plain-English message Patchi shows the user before confirmation.
        Suggested (low-confidence) flows are excluded from the display unless all_flows=True.
        """
        visible = flows if all_flows else [f for f in flows if not f.suggested]
        hidden_count = len(flows) - len(visible)

        if not visible:
            msg = (
                "I didn't find any obvious critical flows in your project.\n"
                "You can add them manually below."
            )
            if hidden_count:
                msg += (
                    f"\n\n[dim]({hidden_count} low-confidence flow(s) were inferred but hidden — "
                    f"run with --all-flows to see them)[/dim]"
                )
            return msg

        ai_count = sum(1 for f in visible if "ai-inferred" in f.signals)
        len(visible) - ai_count

        names = [f.name for f in visible]
        if len(names) == 1:
            flow_list = names[0]
        elif len(names) == 2:
            flow_list = f"{names[0]} and {names[1]}"
        else:
            flow_list = ", ".join(names[:-1]) + f", and {names[-1]}"

        source_note = ""
        if ai_count > 0:
            source_note = f"\n(Detected via AI analysis of {len(self.file_infos)} files and {len(self.routes)} routes)"
        if hidden_count:
            source_note += (
                f"\n({hidden_count} low-confidence flow(s) hidden — run --all-flows to see)"
            )

        return (
            f"I think your critical flows are: {flow_list}.{source_note}\n"
            f"Does that look right? I'll protect these with every fix I make."
        )


def confirm_flows(
    flows: list[ContractFlow],
    confirmed_ids: set[str],
    user_additions: list[dict] | None = None,
) -> list[ContractFlow]:
    """
    Mark flows as confirmed based on user selection.
    user_additions: list of {name, description, routes, files} dicts for user-added flows.
    Returns the final confirmed contract.
    """
    result: list[ContractFlow] = []

    for flow in flows:
        if flow.id in confirmed_ids:
            flow.confirmed = True
            result.append(flow)

    if user_additions:
        for i, addition in enumerate(user_additions):
            result.append(
                ContractFlow(
                    id=f"user-{i}",
                    name=addition.get("name", f"Custom Flow {i + 1}"),
                    description=addition.get("description", "User-defined critical flow."),
                    routes=addition.get("routes", []),
                    files=addition.get("files", []),
                    signals=["user-defined"],
                    confirmed=True,
                    user_added=True,
                )
            )

    return result


def flows_from_dict(data: list[dict]) -> list[ContractFlow]:
    """Deserialize flows from stored dict (memory)."""
    return [
        ContractFlow(
            id=d["id"],
            name=d["name"],
            description=d["description"],
            routes=d.get("routes", []),
            files=d.get("files", []),
            signals=d.get("signals", []),
            confirmed=d.get("confirmed", False),
            user_added=d.get("user_added", False),
            critical=d.get("critical", True),
            confidence=d.get("confidence", "medium"),
            suggested=d.get("suggested", False),
        )
        for d in data
    ]
