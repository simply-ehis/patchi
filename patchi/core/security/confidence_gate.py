"""
Confidence Gate — scores each finding 0.0–1.0 and routes by tier.

HIGH   >= 0.7  -> defend (auto-fix / block)
MEDIUM >= 0.4  -> ai_analyze (Layer 2 AI confirmation)
LOW    <  0.4  -> human_review (if severe) or discard

Scoring factors (additive):
  + method_precision      regex=0.3, AST=0.5, taint/flow=0.7, deterministic=0.9
  + severity_bonus        high=+0.1, critical=+0.2
  + multi_agent_bonus     +0.1 per confirming agent, max +0.3
  + location_precision    exact line=+0.1, within 5 lines=+0.05
  - known_fp_penalty      -0.3 if matches known false-positive pattern
  - ambiguity_penalty     -0.2 if no code snippet or heuristic match

Noise controls (config under ``confidence_gate``):
  min_agents_for_defend   default 1 — findings confirmed by fewer agents are
                          demoted from 'defend' to 'ai_analyze' even at high tier.
  min_agents_to_keep      default 0 (off) — findings confirmed by fewer agents
                          than this are discarded outright regardless of score.
  ai_weight               default 0.0 — blend weight for calibrated AI confidence:
                          final = (1-w)*heuristic_score + w*ai_confidence.
  fp_penalty              default 0.3 — score penalty for known false positives.

False-positive learning loop:
  record_false_positives() persists analyst/AI verdicts to
  .patchi/memory/known_false_positives.json so repeat noise is pre-penalized
  (and, with fp_auto_discard, dropped outright) on every subsequent scan.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from patchi.core.security.gated_finding import GatedFinding, GatedReport
from patchi.core.security.orchestrator import CorrelatedFinding, SecurityReport

_log = logging.getLogger("patchi.confidence_gate")

# ── Method precision lookup ──────────────────────────────────────────────────

_METHOD_PRECISION: dict[str, float] = {
    "regex": 0.3,
    "ast": 0.5,
    "flow": 0.7,
    "deterministic": 0.9,
}

_SEVERITY_BONUS: dict[str, float] = {
    "critical": 0.2,
    "high": 0.1,
    "medium": 0.0,
    "low": 0.0,
    "info": -0.1,
}

_FP_MEMORY_FILE = ".patchi/memory/known_false_positives.json"


class ConfidenceGate:
    """Scores findings and assigns routing tiers."""

    def __init__(self, root: Path, config: dict | None = None):
        self.root = root
        self.config = config or {}
        noise_cfg = self.config.get("confidence_gate", {})
        self.min_agents_for_defend: int = int(noise_cfg.get("min_agents_for_defend", 1))
        self.min_agents_to_keep: int = int(noise_cfg.get("min_agents_to_keep", 0))
        self.ai_weight: float = float(noise_cfg.get("ai_weight", 0.3))  # default 0.3, was 0.0
        self.fp_penalty: float = float(noise_cfg.get("fp_penalty", 0.3))
        self.noise_penalty: float = float(noise_cfg.get("noise_penalty", 0.5))
        self.fp_auto_discard: bool = bool(
            noise_cfg.get("fp_auto_discard", True)
        )  # default True, was False
        self._known_fps: set[tuple] = set()
        self._load_known_fps()
        # Lazy-load AI validator
        self._ai_validator = None

    # ── Known-FP memory ─────────────────────────────────────────────────────

    @property
    def _fp_path(self) -> Path:
        return self.root / _FP_MEMORY_FILE

    def _load_known_fps(self) -> None:
        if not self._fp_path.exists():
            return
        try:
            data = json.loads(self._fp_path.read_text(encoding="utf-8"))
            for entry in data:
                fp_key = (
                    entry.get("file", ""),
                    entry.get("type", ""),
                    entry.get("line", 0),
                )
                self._known_fps.add(fp_key)
        except Exception as exc:  # noqa: BLE001 — corrupt memory = start fresh
            _log.warning("Failed to parse known_false_positives.json: %s", exc)

    def record_false_positives(self, entries: list[dict]) -> int:
        """Persist false-positive verdicts and apply them immediately.

        Each entry needs ``file``, ``type``, ``line``; optional ``reason``
        and ``source`` ("analyst" | "ai") are kept for auditability.
        Returns the number of NEW keys recorded.
        """
        existing: list[dict] = []
        if self._fp_path.exists():
            try:
                existing = json.loads(self._fp_path.read_text(encoding="utf-8"))
            except Exception:  # noqa: BLE001
                existing = []

        seen = {(e.get("file", ""), e.get("type", ""), e.get("line", 0)) for e in existing}
        added = 0
        for entry in entries:
            key = (entry.get("file", ""), entry.get("type", ""), entry.get("line", 0))
            if key in seen or not any(key):
                continue
            seen.add(key)
            existing.append(entry)
            self._known_fps.add(key)
            added += 1

        if added:
            self._fp_path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self._fp_path.with_suffix(".json.tmp")
            tmp.write_text(json.dumps(existing, indent=2), encoding="utf-8")
            tmp.replace(self._fp_path)
            _log.info("Recorded %d new false positive(s)", added)
        return added

    def forget_false_positive(self, file: str, type_: str, line: int) -> bool:
        """Remove one FP verdict (analyst says it was real after all)."""
        key = (file, type_, line)
        if key not in self._known_fps:
            return False
        self._known_fps.discard(key)
        remaining: list[dict] = []
        if self._fp_path.exists():
            try:
                data = json.loads(self._fp_path.read_text(encoding="utf-8"))
                remaining = [
                    e
                    for e in data
                    if (e.get("file", ""), e.get("type", ""), e.get("line", 0)) != key
                ]
            except Exception:  # noqa: BLE001
                remaining = []
        tmp = self._fp_path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(remaining, indent=2), encoding="utf-8")
        tmp.replace(self._fp_path)
        return True

    # ── Gating ──────────────────────────────────────────────────────────────

    def gate(
        self,
        cf: CorrelatedFinding,
        ai_confidence: float | None = None,
    ) -> GatedFinding:
        """Score and route one correlated finding.

        ``ai_confidence`` (0.0–1.0, optional) blends a model verdict into the
        heuristic score using the configured ``ai_weight``.
        """
        score = self._compute_score(cf, ai_confidence=ai_confidence)
        tier = self._assign_tier(score)
        routing = self._assign_routing(tier, cf)
        return GatedFinding(
            finding=cf.finding,
            confidence_score=score,
            confidence_tier=tier,
            routing=routing,
            routing_reason=self._routing_reason(routing, score, cf),
            confirmed_by=cf.confirmed_by,
            composite_score=cf.composite_score,
            owasp_category=cf.owasp_category,
            cwe_ids=cf.cwe_ids,
        )

    def gate_all(
        self,
        report: SecurityReport,
        ai_confidences: list[float] | None = None,
    ) -> GatedReport:
        gated_list = [
            self.gate(
                cf,
                ai_confidence=(
                    ai_confidences[i] if ai_confidences and i < len(ai_confidences) else None
                ),
            )
            for i, cf in enumerate(report.findings)
        ]
        return self._build_report(gated_list)

    def gate_with_ai_validation(
        self,
        report: SecurityReport,
        route_context: dict | None = None,
    ) -> GatedReport:
        """Full harness: score → route → AIConfidenceGate second pass (L2).

        L2 spec: keep deterministic scanners, add AI as second pass ONLY for
        confidence==low AND severity in {high,critical} OR type in {secret, injection, auth}.
        Schema-validated JSON {verdict: confirmed|fp, reason, exploitability 0-1}
        via call_ai_structured:212. Offline → unverified.
        """
        from patchi.core.security.ai_validator import AIValidator

        if self._ai_validator is None:
            self._ai_validator = AIValidator(self.root, self.config)

        # Step 1: Initial gating
        gated = [self.gate(cf) for cf in report.findings]

        # L2 targeted second pass: low confidence + high/critical OR sensitive types
        import os as _os

        if _os.environ.get("PATCHI_OFFLINE"):
            # Offline honors contract — no AI calls, mark as unverified
            for gf in gated:
                if gf.confidence_score < 0.4 or gf.routing == "ai_analyze":
                    gf.routing_reason += " [offline unverified]"
            return self._build_report(gated)

        sensitive_types = ("secret", "injection", "auth", "cred", "token", "password")
        l2_targets: list = []
        for gf in gated:
            is_low = gf.confidence_score < 0.4 or gf.routing in ("ai_analyze", "human_review")
            sev = getattr(gf.finding.severity, "value", str(gf.finding.severity)).lower()
            is_high = sev in ("high", "critical")
            is_sensitive = any(t in (gf.finding.type or "").lower() for t in sensitive_types)
            if (is_low and is_high) or (is_low and is_sensitive) or gf.routing == "ai_analyze":
                # limit tokens: high/critical low OR sensitive types, plus all ai_analyze
                l2_targets.append(gf)
        # cap to bound cost ~10 Findings
        l2_targets = l2_targets[:10]
        if l2_targets:
            _log.info("L2 AIConfidenceGate validating %d findings (low/high+secret/injection/auth) ...", len(l2_targets))
            for gf in l2_targets:
                result = self._ai_validator.validate(gf.finding, route_context=route_context)
                # Schema: is_true_positive + confidence + explanation already
                if result.confidence >= 0.7 and not result.is_true_positive:
                    gf.routing = "discard"
                    gf.routing_reason = f"L2 fp ({result.confidence:.0%}): {result.explanation} [verdict=fp exploitability~{1-result.confidence:.1f}]"
                elif result.confidence >= 0.6 and result.is_true_positive:
                    gf.routing = "defend"
                    gf.routing_reason = f"L2 confirmed ({result.confidence:.0%}): {result.explanation} [exploitability={result.confidence:.1f}]"
                else:
                    gf.routing = "human_review"
                    gf.routing_reason = f"L2 unverified ({result.confidence:.0%}): {result.explanation}"
                ai_w = min(self.ai_weight, 0.5)
                gf.confidence_score = (1.0 - ai_w) * gf.confidence_score + ai_w * (
                    1.0 - result.confidence if not result.is_true_positive else result.confidence
                )

        # Step 3: Auto-learn from discarded findings
        self.learn_from_dismissed(self._build_report(gated))

        return self._build_report(gated)

    def l2_second_pass(self, report: SecurityReport, route_context: dict | None = None) -> GatedReport:
        """Alias for L2 spec naming — explicit entry point."""
        return self.gate_with_ai_validation(report, route_context=route_context)

    def _build_report(self, gated_list: list[GatedFinding]) -> GatedReport:
        stats = {
            "total": len(gated_list),
            "defend": sum(1 for g in gated_list if g.routing == "defend"),
            "ai_analyze": sum(1 for g in gated_list if g.routing == "ai_analyze"),
            "human_review": sum(1 for g in gated_list if g.routing == "human_review"),
            "discarded": sum(1 for g in gated_list if g.routing == "discard"),
        }
        return GatedReport(findings=gated_list, stats=stats)

    def learn_from_dismissed(self, gated: GatedReport) -> int:
        """Auto-record AI-dismissed + discarded findings as known false positives.

        This closes the noise loop: anything the pipeline rejects once is
        pre-penalized (or dropped, with ``fp_auto_discard``) on every future
        scan instead of being re-surfaced thousands of times.
        """
        entries = []
        for gf in gated.discarded:
            f = gf.finding
            entries.append(
                {
                    "file": f.file,
                    "type": f.type,
                    "line": f.line,
                    "reason": gf.routing_reason[:200],
                    "source": "pipeline",
                }
            )
        return self.record_false_positives(entries)

    # ── Scoring internals ───────────────────────────────────────────────────

    def _compute_score(
        self,
        cf: CorrelatedFinding,
        ai_confidence: float | None = None,
    ) -> float:
        score = 0.0
        f = cf.finding

        # 1. Method precision — infer from finding metadata
        method = "regex"
        if f.code_snippet and len(f.code_snippet) > 50:
            method = "flow"
        elif f.cwe and f.cwe.strip():
            method = "ast"
        if cf.composite_score >= 70:
            method = "deterministic"
        score += _METHOD_PRECISION.get(method, 0.3)

        # 2. Severity bonus
        score += _SEVERITY_BONUS.get(
            f.severity.value if hasattr(f.severity, "value") else str(f.severity), 0.0
        )

        # 3. Multi-agent confirmation
        confirm_count = len(cf.confirmed_by)
        score += min(confirm_count * 0.1, 0.3)

        # 4. Location precision
        if f.line > 0:
            score += 0.1

        # 5. Known false-positive penalty
        fp_key = (f.file, f.type, f.line)
        if fp_key in self._known_fps:
            score -= self.fp_penalty

        # 6. Ambiguity penalty
        if not f.code_snippet:
            score -= 0.2

        # 7. Heuristic FP detection — catch common false-positive patterns
        from patchi.core.security.ai_validator import heuristic_pre_filter

        hp = heuristic_pre_filter(f)
        if hp:
            _, penalty = hp
            score -= penalty * 0.5  # partial penalty (full penalty via AIValidator)

        # 8. Noise penalty — findings the NoiseFilter capped (tests,
        #    lockfiles, generated code, docs) carry ``noise_category``.
        #    They may legitimately look dangerous; they must never score
        #    high enough to auto-defend.
        if getattr(f, "noise_category", None):
            score -= self.noise_penalty

        # Clamp heuristic score first…
        score = max(0.0, min(1.0, score))

        # 9. AI confidence calibration (optional): blend model verdict.
        if ai_confidence is not None and self.ai_weight > 0.0:
            w = min(max(self.ai_weight, 0.0), 1.0)
            score = (1.0 - w) * score + w * max(0.0, min(1.0, ai_confidence))

        return max(0.0, min(1.0, score))

    def _assign_tier(self, score: float) -> str:
        if score >= 0.7:
            return "high"
        if score >= 0.4:
            return "medium"
        return "low"

    def _assign_routing(self, tier: str, cf: CorrelatedFinding) -> str:
        confirm_count = len(cf.confirmed_by)
        f = cf.finding

        # Hard consensus floor: too few agents => drop entirely (noise kill).
        if self.min_agents_to_keep > 0 and confirm_count < self.min_agents_to_keep:
            return "discard"

        # Known-FP auto-discard: previously rejected => stay rejected.
        if self.fp_auto_discard:
            fp_key = (f.file, f.type, f.line)
            if fp_key in self._known_fps:
                return "discard"

        if tier == "high":
            # Structural noise block: capped files never auto-defend,
            # no matter how high they score.
            if getattr(cf.finding, "noise_category", None):
                return "ai_analyze"
            # Consensus ceiling: single-agent regex hits can't auto-defend.
            if confirm_count < self.min_agents_for_defend:
                return "ai_analyze"
            return "defend"
        if tier == "medium":
            return "ai_analyze"

        sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
        if sev in ("critical", "high"):
            return "human_review"
        return "discard"

    def _routing_reason(self, routing: str, score: float, cf: CorrelatedFinding) -> str:
        n_agents = len(cf.confirmed_by)
        reasons = {
            "defend": f"High confidence ({score:.2f}) — {n_agents} agent(s) confirmed",
            "ai_analyze": (
                f"Confidence {score:.2f} with {n_agents} agent(s) — needs AI confirmation "
                f"(consensus floor: {self.min_agents_for_defend})"
                if n_agents < self.min_agents_for_defend
                else f"Medium confidence ({score:.2f}) — needs AI confirmation"
            ),
            "human_review": (
                f"Low confidence ({score:.2f}) but severity is "
                f"{cf.finding.severity} — needs human review"
            ),
            "discard": f"Low confidence ({score:.2f}) or below agent consensus — filtered",
        }
        return reasons.get(routing, f"Routed to {routing} (score={score:.2f})")
