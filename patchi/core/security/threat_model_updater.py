"""
Threat Model Updater — refines threat model from actual scan findings.

After a scan completes, this module:
  1. Boosts scenarios that match confirmed findings
  2. Adds new scenarios for finding types not in the YAML library
  3. Deprioritizes scenarios that produced no findings (false-alarm decay)
  4. Persists the updated model for the next scan cycle

The result is a threat model that adapts to the real risk profile of the
project rather than relying solely on static YAML definitions.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from patchi.core.security.threat_model_generator import (
    AttackScenario,
    ThreatModel,
    ThreatModelGenerator,
)

_log = logging.getLogger("patchi.security.threat_model_updater")

# How much to boost a scenario's score when a finding matches its category
_FINDING_BOOST = 0.15
# Maximum boosted score
_MAX_SCORE = 1.0
# Decay factor for scenarios with zero findings (per scan cycle)
_ZERO_FINDING_DECAY = 0.05


def update_threat_model(
    root: Path,
    findings: list[dict[str, Any]],
) -> ThreatModel:
    """Regenerate the threat model and adjust scores based on scan findings.

    Returns the updated ThreatModel.
    """
    gen = ThreatModelGenerator(root)
    model = gen.generate()

    # Index findings by category
    category_counts: dict[str, int] = {}
    cwe_counts: dict[str, int] = {}
    finding_types: set[str] = set()
    for f in findings:
        cat = _categorize_finding(f)
        category_counts[cat] = category_counts.get(cat, 0) + 1
        cwe = f.get("cwe", "")
        if cwe:
            cwe_counts[cwe] = cwe_counts.get(cwe, 0) + 1
        finding_types.add(f.get("type", f.get("control_id", "")))

    # Boost scenarios matching actual findings
    for scenario in model.scenarios:
        if not scenario.applicable:
            continue
        cat_count = category_counts.get(scenario.category, 0)
        if cat_count > 0:
            boost = min(cat_count * _FINDING_BOOST, _MAX_SCORE - scenario.relevance_score)
            scenario.relevance_score = min(scenario.relevance_score + boost, _MAX_SCORE)
            _log.debug(
                "Boosted %s by %.2f (category=%s, findings=%d)",
                scenario.id,
                boost,
                scenario.category,
                cat_count,
            )
        else:
            # Decay scenarios that produced zero findings
            scenario.relevance_score = max(scenario.relevance_score - _ZERO_FINDING_DECAY, 0.0)

        # Extra boost for CWE matches
        if scenario.cwe and cwe_counts.get(scenario.cwe, 0) > 0:
            scenario.relevance_score = min(scenario.relevance_score + 0.2, _MAX_SCORE)

    # Re-sort by updated relevance
    model.scenarios.sort(key=lambda s: (-s.relevance_score, s.severity))

    # Recompute summaries
    model.applicable_scenarios = sum(1 for s in model.scenarios if s.applicable)
    model.by_severity.clear()
    model.by_category.clear()
    for s in model.scenarios:
        if s.applicable:
            model.by_severity[s.severity] = model.by_severity.get(s.severity, 0) + 1
            model.by_category[s.category] = model.by_category.get(s.category, 0) + 1

    # Add discovered scenarios for finding types not in the YAML library
    _add_discovered_scenarios(model, finding_types, category_counts)

    # Update recommendations
    model.recommendations = _generate_updated_recommendations(model, category_counts)

    # Persist
    tm_path = root / ".patchi" / "threat_model.json"
    tm_path.parent.mkdir(parents=True, exist_ok=True)
    tm_path.write_text(json.dumps(model.to_dict(), indent=2), encoding="utf-8")
    _log.info(
        "Threat model updated: %d scenarios, %d applicable, %d categories",
        model.total_scenarios,
        model.applicable_scenarios,
        len(model.by_category),
    )
    return model


def _categorize_finding(finding: dict[str, Any]) -> str:
    """Map a finding to a threat model category."""
    ftype = (finding.get("type", "") or finding.get("control_id", "")).lower()
    categories = {
        "authentication": ("auth", "login", "session", "password", "jwt", "cookie"),
        "authorization": ("permission", "role", "admin", "access", "privilege"),
        "injection": ("sql", "injection", "command", "eval", "exec", "shell", "xss"),
        "secrets": ("secret", "credential", "api_key", "token", "hardcoded"),
        "crypto": ("hash", "md5", "sha1", "encrypt", "decrypt", "cipher"),
        "configuration": ("config", "debug", "cors", "ssl", "tls", "verbose"),
        "network": ("ssrf", "redirect", "request", "fetch", "url"),
        "dependencies": ("dependency", "vulnerability", "outdated", "cve"),
    }
    for cat, keywords in categories.items():
        if any(kw in ftype for kw in keywords):
            return cat
    return "other"


def _add_discovered_scenarios(
    model: ThreatModel,
    finding_types: set[str],
    category_counts: dict[str, int],
) -> None:
    """Add synthetic scenarios for finding types not covered by YAML library."""
    existing_ids = {s.id for s in model.scenarios}
    discovered = 0

    for ftype in finding_types:
        if not ftype or ftype in existing_ids:
            continue
        cat = _categorize_finding({"type": ftype})
        if cat == "other":
            continue
        # Only add if we have multiple findings of this type
        if category_counts.get(cat, 0) < 2:
            continue
        synthetic_id = f"DISCOVERED-{ftype.upper()[:20]}"
        if synthetic_id in existing_ids:
            continue
        scenario = AttackScenario(
            id=synthetic_id,
            name=f"Discovered: {ftype}",
            category=cat,
            severity="medium",
            cwe="",
            owasp="",
            description=f"Auto-discovered from {category_counts[cat]} scan findings of type '{ftype}'",
            tags=["discovered", "auto"],
            applicable=True,
            relevance_score=min(0.3 + category_counts.get(cat, 0) * 0.05, 0.8),
        )
        model.scenarios.append(scenario)
        existing_ids.add(synthetic_id)
        discovered += 1

    model.total_scenarios += discovered
    if discovered:
        _log.info("Added %d discovered scenarios from scan findings", discovered)


def _generate_updated_recommendations(
    model: ThreatModel,
    category_counts: dict[str, int],
) -> list[str]:
    """Generate recommendations factoring in actual findings."""
    recs = list(model.recommendations)

    # Top-finding categories
    top_cats = sorted(category_counts.items(), key=lambda x: -x[1])[:3]
    for cat, count in top_cats:
        if count >= 3:
            recs.append(f"High volume of {cat} findings ({count}) — prioritize remediation")

    # Categories with no coverage
    covered = set(model.by_category.keys())
    for cat in category_counts:
        if cat not in covered and category_counts[cat] >= 2:
            recs.append(
                f"Add threat scenarios for '{cat}' — {category_counts[cat]} findings detected"
            )

    return recs[:10]
