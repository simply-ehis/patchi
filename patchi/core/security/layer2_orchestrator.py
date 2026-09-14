"""
Layer 2 AI Orchestrator — confirms medium-confidence findings via LLM.

Design:
  - Batches similar findings (same file + CWE) into single AI calls
  - Rate-limits: max N calls/minute (configurable, default 10)
  - Caches results by (CWE + file + type) hash with 24h TTL
  - Returns structured AIAnalysisResult per input finding

Token optimization:
  - One AI call per batch instead of per-finding
  - Cache avoids re-analyzing identical findings
  - Rate limiting prevents token bursts
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from dataclasses import dataclass
from pathlib import Path

_log = logging.getLogger("patchi.security.layer2_orchestrator")


@dataclass
class AIAnalysisResult:
    """Result from Layer 2 AI analysis."""

    confirmed: bool = False
    summary: str = ""
    fix_code: str = ""
    test_code: str = ""
    confidence_adjustment: float = 0.0
    tokens_used: int = 0
    model: str = ""
    need_human_review: bool = False

    def to_dict(self) -> dict:
        return {
            "confirmed": self.confirmed,
            "summary": self.summary,
            "fix_code": self.fix_code,
            "test_code": self.test_code,
            "confidence_adjustment": self.confidence_adjustment,
            "tokens_used": self.tokens_used,
            "model": self.model,
            "need_human_review": self.need_human_review,
        }


_SYSTEM_PROMPT = """You are Patchi's Layer 2 AI security arbiter — the final
evidence check before a finding is auto-defended or discarded. Your verdicts
directly drive automation, so they must be evidence-based, never vibes.

For EACH finding you must decide: real exploitable issue, or false positive?

CONFIRM only if ALL of these hold:
1. You can quote the exact vulnerable code from the provided snippet as
   `evidence_quote` (verbatim substring). No quote -> no confirmation.
2. You can name the taint SOURCE (where untrusted data enters) and the SINK
   (dangerous operation) and connect them. Pattern-shaped code without an
   attacker-reachable source is NOT confirmed (e.g. test fixtures, sample
   configs, migrations, admin-only CLI scripts).
3. The code path is reachable in this project (not obviously dead code).

DISMISS (confirmed=false) when:
- The match is a test file, fixture, mock, or documentation example.
- A sanitizer/validation neutralizes the flow between source and sink.
- The "vulnerability" requires assumptions the snippet contradicts.
- It matches a known-safe wrapper the project defines.

Tool context: `tool_confidence` values are PRIORS from deterministic tools,
not proof. Multiple agreeing tools raise your prior; a lone regex-tier tool
lowers it. You are the tie-breaker, not an echo.

Output STRICT JSON only (no prose, no markdown fences):
{"findings": [
  {"index": 0,
   "confirmed": false,
   "confidence_adjustment": -0.6,
   "summary": "one sentence verdict with the reason",
   "evidence_quote": "exact line from Code, or empty if dismissed",
   "source_sink_path": "request.args.get -> execute  (or 'none found')",
   "fix_code": "",
   "test_code": "",
   "need_human_review": false}
]}
Rules:
- confidence_adjustment in [-1.0, +1.0]; dismissals usually negative,
  confirmations positive; magnitude = how sure.
- Fixes minimal & secure (parameterized queries, arg lists, no eval).
- Tests must pass without mocking security controls.
- One entry per input finding, same order, same count."""


_CACHE_TTL = 86400  # 24 hours


class Layer2Orchestrator:
    """AI analysis engine for medium-confidence findings."""

    def __init__(self, root: Path, config: dict | None = None):
        self.root = root
        self.config = config or {}
        self._batch_size = self.config.get("pipeline", {}).get("ai_batch_size", 3)
        self._rate_per_min = self.config.get("pipeline", {}).get("ai_rate_per_min", 10)
        self._cache: dict[str, tuple[float, AIAnalysisResult]] = {}
        self._call_timestamps: list[float] = []

    def analyze(self, findings: list) -> list[AIAnalysisResult]:
        """Analyze findings, batching similar ones. Returns one result per input."""
        if not findings:
            return []

        results: list[AIAnalysisResult | None] = [None] * len(findings)
        uncached_indices: list[int] = []

        # Step 1: Check cache
        for i, gf in enumerate(findings):
            key = self._cache_key(gf)
            if key in self._cache:
                ts, cached = self._cache[key]
                if time.time() - ts < _CACHE_TTL:
                    results[i] = cached
                    continue
            uncached_indices.append(i)

        if not uncached_indices:
            return results  # type: ignore

        # Step 2: Build batches from uncached findings
        uncached = [findings[i] for i in uncached_indices]
        batches = self._build_batches(uncached)
        batch_map: dict[int, int] = {}  # finding_index -> batch_index
        for bi, batch in enumerate(batches):
            for gf in batch:
                idx = uncached_indices[uncached.index(gf)]
                batch_map[idx] = bi

        # Step 3: Analyze each batch (one AI call, per-finding verdicts)
        batch_results: list[list[AIAnalysisResult]] = []
        for batch in batches:
            self._throttle_if_needed()
            ai_results = self._analyze_batch(batch)
            batch_results.append(ai_results)

            # Cache per-finding results
            for j, gf in enumerate(batch):
                key = self._cache_key(gf)
                cached_res = ai_results[j] if j < len(ai_results) else ai_results[-1]
                self._cache[key] = (time.time(), cached_res)

        # Step 4: Map batch results back to finding order
        for idx, bi in batch_map.items():
            per_finding = batch_results[bi]
            results[idx] = per_finding[0] if len(per_finding) == 1 else None

        # Positional pass for multi-finding batches: _analyze_batch already
        # returned results aligned to the batch order; recover via batches.
        if any(r is None for r in results):
            for bi, batch in enumerate(batches):
                per_finding = batch_results[bi]
                for j, gf in enumerate(batch):
                    idx = uncached_indices[uncached.index(gf)]
                    if j < len(per_finding):
                        results[idx] = per_finding[j]

        return results  # type: ignore

    def _build_batches(self, findings: list) -> list[list]:
        """Group findings by (file, CWE) to batch into single AI calls."""
        groups: dict[str, list] = {}
        for gf in findings:
            f = gf.finding
            group_key = f"{f.file}||{f.cwe}"
            if group_key not in groups:
                groups[group_key] = []
            groups[group_key].append(gf)

        batches = list(groups.values())
        # Further split if a single group exceeds batch_size
        result: list[list] = []
        for batch in batches:
            for i in range(0, len(batch), self._batch_size):
                result.append(batch[i : i + self._batch_size])
        return result

    def _analyze_batch(self, batch: list) -> list[AIAnalysisResult]:
        """One AI call per batch; returns one verdict per finding, in order."""
        try:
            from patchi.core.ai.client import call_ai_structured
        except ImportError:
            return [self._offline_result(batch)] * len(batch)

        prompt = self._build_prompt(batch)
        try:
            response = call_ai_structured(
                prompt=prompt,
                system=_SYSTEM_PROMPT,
                output_model=dict,
            )
            parsed = (
                self._extract_json(response)
                if isinstance(response, str)
                else (response if isinstance(response, dict) else None)
            )
            if not parsed and isinstance(response, str):
                return [self._offline_result(batch)] * len(batch)
            if parsed is None and isinstance(response, dict):
                parsed = response

            if parsed and isinstance(parsed.get("findings"), list):
                entries = parsed["findings"]
                out: list[AIAnalysisResult] = []
                for _j, entry in enumerate(entries[: len(batch)]):
                    if not isinstance(entry, dict):
                        continue
                    out.append(
                        AIAnalysisResult(
                            confirmed=bool(entry.get("confirmed", False)),
                            summary=str(entry.get("summary", ""))[:300],
                            fix_code=str(entry.get("fix_code", "") or ""),
                            test_code=str(entry.get("test_code", "") or ""),
                            confidence_adjustment=float(entry.get("confidence_adjustment", 0.0) or 0.0),
                            need_human_review=bool(entry.get("need_human_review", False)),
                            tokens_used=int(parsed.get("tokens_used", 0) or 0),
                            model=str(parsed.get("model", "unknown")),
                        )
                    )
                # fill any missing tail positions honestly
                while len(out) < len(batch):
                    out.append(self._offline_result([batch[len(out)]]))
                return out

            # Legacy single-verdict shape: applies to whole batch
            if parsed and "confirmed" in parsed:
                single = AIAnalysisResult(
                    confirmed=bool(parsed.get("confirmed", False)),
                    summary=str(parsed.get("summary", ""))[:300],
                    fix_code=str(parsed.get("fix_code", "") or ""),
                    test_code=str(parsed.get("test_code", "") or ""),
                    confidence_adjustment=float(parsed.get("confidence_adjustment", 0.0) or 0.0),
                    need_human_review=bool(parsed.get("need_human_review", False)),
                    tokens_used=int(parsed.get("tokens_used", 0) or 0),
                    model=str(parsed.get("model", "unknown")),
                )
                return [single] * len(batch)
        except Exception as e:
            _log.warning("Layer2Orchestrator._analyze_batch failed: %s", e)

        return [self._offline_result(batch)] * len(batch)

    def _offline_result(self, batch: list) -> AIAnalysisResult:
        """Default result when AI is unavailable — queue for human review."""
        return AIAnalysisResult(
            confirmed=False,
            summary="AI unavailable — queued for human review",
            need_human_review=True,
            confidence_adjustment=0.0,
        )

    def _build_prompt(self, batch: list) -> str:
        parts = [f"Analyze {len(batch)} security finding(s) from the same context:"]
        for i, gf in enumerate(batch):
            f = gf.finding
            ext = Path(f.file).suffix if f.file else ""
            sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
            # Tool-native confidence priors (bandit/semgrep tiers etc.)
            extra = getattr(f, "extra", {}) or {}
            tool_conf = extra.get("tool_confidence")
            conf_note = (
                f"ToolConfidence: {tool_conf:.2f} (deterministic-tool prior)"
                if isinstance(tool_conf, (int, float))
                else "ToolConfidence: none"
            )
            noise = getattr(f, "noise_category", None)
            noise_note = f"\nNoiseCategory: {noise} (from a low-signal file class)" if noise else ""
            parts.append(
                f"\n--- Finding {i + 1} ---\n"
                f"File: {f.file}:{f.line}\n"
                f"CWE: {f.cwe}\n"
                f"Severity: {sev}\n"
                f"Type: {f.type}\n"
                f"Message: {f.message}\n"
                f"Detail: {getattr(f, 'detail', '')}\n"
                f"Code:\n```{ext}\n{f.code_snippet}\n```\n"
                f"Confirmed by: {', '.join(gf.confirmed_by) or 'single agent'}\n"
                f"{conf_note}{noise_note}\n"
                f"OWASP: {gf.owasp_category}\n"
            )
        parts.append(
            "\nFor EACH finding return a verdict entry with evidence_quote "
            "quoted verbatim from its Code block. JSON only."
        )
        return "\n".join(parts)

    def _extract_json(self, text: str) -> dict | None:
        """Tolerant structured-output parser: bare JSON, fenced, or embedded."""
        if not text:
            return None
        candidate = text.strip()
        # strip markdown fences if present
        if candidate.startswith("```"):
            candidate = candidate.strip("`")
            if candidate.lower().startswith("json"):
                candidate = candidate[4:]
        try:
            parsed = json.loads(candidate)
            return parsed if isinstance(parsed, dict) else None
        except (json.JSONDecodeError, ValueError):
            pass
        # embedded object fallback: first { to matching last }
        start, end = candidate.find("{"), candidate.rfind("}")
        if 0 <= start < end:
            try:
                parsed = json.loads(candidate[start : end + 1])
                return parsed if isinstance(parsed, dict) else None
            except (json.JSONDecodeError, ValueError):
                return None
        return None

    def _throttle_if_needed(self) -> None:
        now = time.time()
        window = 60
        # Remove timestamps older than 60s
        self._call_timestamps = [t for t in self._call_timestamps if now - t < window]
        if len(self._call_timestamps) >= self._rate_per_min:
            sleep_sec = window - (now - self._call_timestamps[0])
            if sleep_sec > 0:
                time.sleep(sleep_sec)
        self._call_timestamps.append(time.time())

    def _cache_key(self, gf) -> str:
        f = gf.finding
        raw = f"{f.file}|{f.line}|{f.type}|{f.cwe}"
        return hashlib.sha256(raw.encode()).hexdigest()
