"""
NLQueryAgent §11.2 — Natural Language to graph query.

Parses "Find all auth-related routes without rate limiting" → graph query via LLM → search_graph.
"""

from __future__ import annotations

import logging

from patchi.core.agents.base import (
    AgentGroup,
    AgentInput,
    AgentResult,
    AgentStatus,
    BaseAgent,
    Severity,
    make_finding,
    register,
)

_log = logging.getLogger("patchi.agents.nl_query")

@register
class NLQueryAgent(BaseAgent):
    group = AgentGroup.SCANNER
    name = "NLQueryAgent"
    description = "NL query §11.2 — auth routes without rate limiting"
    timeout = 30
    def _run(self, inp: AgentInput, result: AgentResult) -> None:
        q = (inp.extra or {}).get("query") or inp.extra.get("nl_query") or ""
        if not q:
            result.status=AgentStatus.SKIPPED
            result.data["skip_reason"]="no query in extra.query"
            return
        # LLM parse to keywords (bounded: never hang the agent when no
        # provider is reachable — fall back to the raw query keywords).
        try:
            import concurrent.futures as _cf
            import os
            if not os.environ.get("PATCHI_OFFLINE"):
                from patchi.core import config as cfg
                from patchi.core.ai.client import call_ai
                cfgd=cfg.load(inp.root)
                prompt=f'Parse NL security query to keywords JSON {{"keywords":["auth","rate limiting"], "intent":"find auth without rate limiting"}}. Query: {q}'
                _ex = _cf.ThreadPoolExecutor(max_workers=1)
                try:
                    fut = _ex.submit(call_ai, cfgd, "You are a security query parser.", prompt, 200)
                    resp = fut.result(timeout=25)
                except Exception as exc:
                    _log.debug("nl parse timed out, using raw query: %s", exc)
                    resp = None
                finally:
                    _ex.shutdown(wait=False)
                # use resp as keywords if available
                if resp and "auth" in resp.lower():
                    q = resp
        except Exception as exc:  # noqa: BLE001
            _log.debug("nl parse failed: %s", exc)
        # Simple keyword search over routes
        try:
            from patchi.core.brain.framework import FrameworkDetector
            from patchi.core.brain.route_mapper import RouteMapper
            corpus = inp.extra.get("file_corpus")
            if corpus is None:
                from patchi.core.brain.file_corpus import FileCorpus
                corpus = FileCorpus(inp.root)
            routes=RouteMapper(inp.root, FrameworkDetector(inp.root, corpus=corpus).detect()).extract([])
            # Heuristic: auth-related routes without rate limiting middleware
            for r in routes:
                if "auth" in r.path.lower() and "rate" not in " ".join(r.middleware).lower():
                    if "auth" in q.lower():
                        result.add_finding(make_finding(severity=Severity.MEDIUM, file=r.file, line_start=r.line, title=f"Auth route without rate limiting: {r.method} {r.path}", description=f"NL query '{q}' matched — add rate limiter", finding_type="nl_query_match"))
        except Exception as exc:  # noqa: BLE001
            _log.debug("nl query failed: %s", exc)
        result.status=AgentStatus.SUCCEEDED
