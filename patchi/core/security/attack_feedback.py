"""
Attack Feedback — closes the loop between attack outcomes and learning.

When the RedTeamEngine or assurance attackers confirm a vulnerability:
  1. The confirmed payload is added to the fuzz corpus as a high-score entry
  2. False-positive paths are recorded in the ignore_learner
  3. Agent trust scores are updated via the learning brain

This turns every scan into training data for the next scan.
"""

from __future__ import annotations

import logging
import time
from pathlib import Path
from typing import Any

from patchi.core.brain import learning as learn

_log = logging.getLogger("patchi.security.attack_feedback")


def record_confirmed_attack(
    root: Path,
    attack: dict[str, Any],
    *,
    agent_name: str = "red_team",
) -> None:
    """Feed a confirmed attack result into the learning loop.

    ``attack`` is a dict from RedTeamEngine or AttackPlanner with keys:
        hypothesis, payload, endpoint, severity, evidence, tool, success
    """
    payload = attack.get("payload", "")
    endpoint = attack.get("endpoint", "")
    severity = attack.get("severity", "medium")
    evidence = attack.get("evidence", "")

    # --- 1. Fuzz corpus: confirmed payloads are high-value seeds ---
    try:
        from patchi.core.fuzz.corpus import CorpusEntry, FuzzCorpus

        corpus = FuzzCorpus(root)
        label = f"confirmed_{attack.get('tool', 'unknown')}_{endpoint or 'global'}"
        score = {"critical": 1.0, "high": 0.85, "medium": 0.6, "low": 0.4}.get(severity, 0.5)
        corpus.add(
            CorpusEntry(
                label=label[:120],
                value=payload[:500] if payload else evidence[:500],
                strategy="attack_feedback",
                score=score,
            )
        )
        corpus.save()
        _log.info("Fed confirmed attack into corpus: %s (score=%.2f)", label[:60], score)
    except Exception as exc:
        _log.debug("Corpus update failed: %s", exc)

    # --- 2. Learning brain: record acceptance (confirmed = good detection) ---
    finding_type = attack.get("tool", "unknown")
    learn.record_acceptance(finding_type, agent_name, root)
    _log.info("Recorded acceptance for %s via %s", finding_type, agent_name)


def record_false_positive(
    root: Path,
    finding: dict[str, Any],
    *,
    agent_name: str = "unknown",
) -> None:
    """Feed a rejected/false-positive finding into the learning loop.

    Updates the ignore_learner FP stats and records a rejection.
    """
    finding_type = finding.get("control_id", finding.get("type", "unknown"))
    file_path = finding.get("file", "")

    # --- 1. Learning brain: record rejection ---
    learn.record_rejection(finding_type, agent_name, root)

    # --- 2. Ignore learner: record FP for this file/directory ---
    try:
        from patchi.core.security.ignore_learner import IgnoreLearner

        learner = IgnoreLearner(root)
        # Build entries from known FP store
        fp_store = root / ".patchi" / "known_false_positives.json"
        fps: list[dict] = []
        if fp_store.exists():
            import json

            fps = json.loads(fp_store.read_text(encoding="utf-8"))

        # Add this new FP
        fps.append(
            {
                "file": file_path,
                "type": finding_type,
                "timestamp": time.time(),
                "agent": agent_name,
            }
        )
        fp_store.parent.mkdir(parents=True, exist_ok=True)
        import json

        fp_store.write_text(json.dumps(fps[-500:], indent=2), encoding="utf-8")

        # Rebuild learner with updated FP list
        learner.build(known_fps=fps)
        promoted = learner.promote_to_global()
        if promoted:
            _log.info("Promoted %d ignore patterns to global store", promoted)
    except Exception as exc:
        _log.debug("Ignore learner update failed: %s", exc)


def record_fix_outcome(
    root: Path,
    finding_type: str,
    file_path: str,
    fix_strategy: str,
    accepted: bool,
) -> None:
    """Record whether a generated fix was accepted or rejected."""
    if accepted:
        learn.record_fix_pattern(finding_type, file_path, fix_strategy, "accepted", root)
        learn.record_acceptance(finding_type, "auto_fixer", root)
    else:
        learn.record_rejection(finding_type, "auto_fixer", root)
    _log.info(
        "Fix outcome recorded: %s on %s → %s",
        finding_type,
        file_path,
        "accepted" if accepted else "rejected",
    )


def get_learning_summary(root: Path) -> dict:
    """Return the full learning summary for display."""
    return learn.get_summary(root)
