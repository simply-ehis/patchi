"""
Chain-to-Assurance Bridge — feeds exploit chains and intent gaps into
the assurance graph as disproved claims with evidence trails.

Each multi-step chain becomes a claim like "auth bypass leads to data
exfiltration via 4-step chain" with refuting evidence from each step.
Each intent gap becomes a claim like "state-changing route lacks auth"
with refuting evidence from the route analysis.

This lets the assurance page show cross-file attack paths alongside
the invariant-based claims.
"""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path

_log = logging.getLogger("patchi.security.chain_to_assurance")


def feed_chains_to_graph(root: Path) -> int:
    """Load persisted chain/intent data and upsert into the assurance graph.

    Returns the number of claims added/updated.
    """
    ci_path = root / ".patchi" / "chain_intent.json"
    if not ci_path.is_file():
        return 0

    try:
        ci_data = json.loads(ci_path.read_text(encoding="utf-8"))
    except Exception as exc:
        _log.debug("Failed to load chain_intent.json: %s", exc)
        return 0

    chains = ci_data.get("chains", [])
    intent = ci_data.get("intent_report")
    if not chains and not intent:
        return 0

    try:
        from patchi.core.assurance.graph import AssuranceGraph, Evidence
    except ImportError as exc:
        _log.debug("Assurance graph not available: %s", exc)
        return 0

    graph = AssuranceGraph.load(root)
    count = 0

    # ── Chains → Claims ──────────────────────────────────────────────────
    for i, chain in enumerate(chains):
        severity = chain.get("severity", "medium")
        score = chain.get("score", 0)
        steps = chain.get("steps", [])
        narrative = chain.get("narrative", "")

        if len(steps) < 2:
            continue

        claim_id = f"chain-{i+1}-{'-'.join(s.get('type', 'unknown')[:10] for s in steps[:3])}"
        entry_type = steps[0].get("type", "unknown")
        impact_type = steps[-1].get("type", "unknown")

        statement = (
            f"Attack chain: {entry_type} → {impact_type} "
            f"({len(steps)} steps, severity={severity}, score={score:.0f})"
        )

        claim = graph.upsert_claim(
            claim_id=claim_id,
            statement=statement,
            domain="exploit-chain",
            severity_if_disproved=severity,
        )

        # Each step is refuting evidence (the chain proves the path exists)
        for j, step in enumerate(steps):
            # Attach remediation suggestion
            step_type = step.get("type", "")
            try:
                from patchi.core.security.remediation import get_remediation
                rem = get_remediation(step_type)
                fix_hint = rem.action if rem else ""
            except ImportError:
                fix_hint = ""

            ev = Evidence(
                source=f"chain_analyzer.step{j+1}",
                detail=f"[{step.get('role', '?')}] {step.get('type', '?')} @ {step.get('file', '?')}:{step.get('line', '?')}"
                       + (f" → FIX: {fix_hint}" if fix_hint else ""),
                supports=False,  # refuting = vulnerability confirmed
                timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                artifact={
                    "step": j + 1,
                    "role": step.get("role", ""),
                    "agent": step.get("agent", ""),
                    "remediation": fix_hint,
                },
            )
            graph.attach_evidence(claim_id, ev)
            count += 1

        # Narrative evidence
        if narrative:
            ev = Evidence(
                source="chain_analyzer.narrative",
                detail=narrative[:500],
                supports=False,
                timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            )
            graph.attach_evidence(claim_id, ev)
            count += 1

    # ── Intent Gaps → Claims ─────────────────────────────────────────────
    if intent:
        gap_categories = [
            ("unauthenticated_state_changing", "State-changing routes lack authentication", "high"),
            ("admin_without_strict_guard", "Admin routes have no strict auth guard", "high"),
            ("unprotected_among_protected", "Routes unprotected among protected peers", "medium"),
        ]

        for cat_key, description, sev in gap_categories:
            routes = intent.get(cat_key, [])
            if not routes:
                continue

            claim_id = f"intent-gap-{cat_key}"
            statement = f"{description} ({len(routes)} routes)"

            claim = graph.upsert_claim(
                claim_id=claim_id,
                statement=statement,
                domain="intent-gap",
                severity_if_disproved=sev,
            )

            for r in routes:
                method = r.get("method", "?")
                path = r.get("path", "?")
                file_ = r.get("file", "?")
                line = r.get("line", "?")
                has_guard = r.get("has_auth_guard", False)

                ev = Evidence(
                    source="intent_analyzer",
                    detail=f"{method} {path} @ {file_}:{line} (guard={'yes' if has_guard else 'no'})",
                    supports=False,
                    timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    artifact={"route": path, "method": method, "has_guard": has_guard},
                )
                graph.attach_evidence(claim_id, ev)
                count += 1

    # Save
    if count > 0:
        graph.save(root)
        _log.info("Fed %d evidence items into assurance graph (chains=%d, intent gaps=%d)",
                   count, len(chains), len([c for c in gap_categories if intent.get(c[0])]) if intent else 0)

    return count
