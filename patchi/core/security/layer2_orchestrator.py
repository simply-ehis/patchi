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


_SYSTEM_PROMPT = """You are Patchi's Layer 2 AI security analyst. Your job is to:
1. Confirm whether each finding is a real, exploitable vulnerability
2. Generate a secure fix for confirmed findings
3. Generate a test case that validates the fix
4. Report confidence adjustment (-1.0 to +1.0) for the finding's score

Rules:
- Be conservative: if unsure, confirmed = false
- Never suggest insecure patterns (no eval, no disabled security)
- Fixes must be minimal and targeted
- Tests must pass without mocking security controls

Output as structured JSON with fields:
- confirmed: bool
- summary: str
- fix_code: str (or empty if not confirmed)
- test_code: str (or empty)
- confidence_adjustment: float (-1.0 to +1.0)
- need_human_review: bool (true if edge case)"""


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

        # Step 3: Analyze each batch
        batch_results: list[AIAnalysisResult] = []
        for batch in batches:
            self._throttle_if_needed()
            ai_result = self._analyze_batch(batch)
            batch_results.append(ai_result)

            # Cache individual results
            for gf in batch:
                key = self._cache_key(gf)
                self._cache[key] = (time.time(), ai_result)

        # Step 4: Map batch results back to finding order
        for idx, bi in batch_map.items():
            results[idx] = batch_results[bi]

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

    def _analyze_batch(self, batch: list) -> AIAnalysisResult:
        """Single AI call for related findings."""
        try:
            from patchi.core.ai.client import call_ai_structured
        except ImportError:
            return self._offline_result(batch)

        prompt = self._build_prompt(batch)
        try:
            response = call_ai_structured(
                prompt=prompt,
                system=_SYSTEM_PROMPT,
                output_model=dict,
            )
            if response and isinstance(response, dict):
                return AIAnalysisResult(
                    confirmed=response.get("confirmed", False),
                    summary=response.get("summary", ""),
                    fix_code=response.get("fix_code", ""),
                    test_code=response.get("test_code", ""),
                    confidence_adjustment=float(response.get("confidence_adjustment", 0.0)),
                    need_human_review=response.get("need_human_review", False),
                    tokens_used=response.get("tokens_used", 0),
                    model=response.get("model", "unknown"),
                )
        except Exception as e:
            _log.warning("Layer2Orchestrator._analyze_batch failed: %s", e)

        return self._offline_result(batch)

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
            parts.append(
                f"\n--- Finding {i + 1} ---\n"
                f"File: {f.file}:{f.line}\n"
                f"CWE: {f.cwe}\n"
                f"Severity: {f.severity.value if hasattr(f.severity, 'value') else f.severity}\n"
                f"Type: {f.type}\n"
                f"Message: {f.message}\n"
                f"Detail: {f.detail}\n"
                f"Code:\n```{ext}\n{f.code_snippet}\n```\n"
                f"Confirmed by: {', '.join(gf.confirmed_by)}\n"
                f"OWASP: {gf.owasp_category}\n"
            )
        parts.append("\nFor each finding, confirm exploitability and generate fix + test.")
        return "\n".join(parts)

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
