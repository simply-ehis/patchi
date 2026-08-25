"""
Threat Model Generator — Runtime generator from YAML attack scenarios.

Reads attack scenario YAML files and generates executable threat models
for the current project based on:
- Detected frameworks and patterns
- Route analysis
- Authentication mechanisms
- Data flow patterns

Output: ThreatModel with prioritized attack scenarios for the project.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path

_log = logging.getLogger("patchi.security.threat_model")


@dataclass
class AttackScenario:
    """A single attack scenario from YAML."""

    id: str
    name: str
    category: str
    severity: str
    cwe: str
    owasp: str
    description: str
    prerequisites: list[str] = field(default_factory=list)
    attack_steps: list[dict] = field(default_factory=list)
    detection_signatures: list[str] = field(default_factory=list)
    remediation_playbook: str = ""
    tags: list[str] = field(default_factory=list)
    applicable: bool = False
    relevance_score: float = 0.0


@dataclass
class ThreatModel:
    """Generated threat model for the project."""

    project_root: str
    total_scenarios: int = 0
    applicable_scenarios: int = 0
    scenarios: list[AttackScenario] = field(default_factory=list)
    by_severity: dict[str, int] = field(default_factory=dict)
    by_category: dict[str, int] = field(default_factory=dict)
    recommendations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "project_root": self.project_root,
            "total_scenarios": self.total_scenarios,
            "applicable_scenarios": self.applicable_scenarios,
            "by_severity": self.by_severity,
            "by_category": self.by_category,
            "scenarios": [
                {
                    "id": s.id,
                    "name": s.name,
                    "category": s.category,
                    "severity": s.severity,
                    "cwe": s.cwe,
                    "description": s.description,
                    "applicable": s.applicable,
                    "relevance_score": s.relevance_score,
                    "tags": s.tags,
                }
                for s in self.scenarios
            ],
            "recommendations": self.recommendations,
        }


# ── Category Detection Rules ─────────────────────────────────────────────────

# Maps YAML scenario categories to code signals that indicate applicability
_CATEGORY_SIGNALS: dict[str, list[tuple[str, float]]] = {
    "authentication": [
        ("login", 0.8),
        ("auth", 0.9),
        ("session", 0.7),
        ("jwt", 0.9),
        ("cookie", 0.6),
        ("password", 0.8),
        ("bcrypt", 0.8),
        ("argon2", 0.8),
    ],
    "authorization": [
        ("permission", 0.8),
        ("role", 0.7),
        ("admin", 0.8),
        ("access_control", 0.9),
        ("guard", 0.6),
        ("protect", 0.5),
    ],
    "injection": [
        ("execute", 0.7),
        ("query", 0.6),
        ("raw_sql", 0.9),
        ("cursor", 0.7),
        ("database", 0.5),
        ("orm", 0.4),
        ("subprocess", 0.8),
        ("shell", 0.8),
        ("eval", 0.9),
    ],
    "xss": [
        ("render", 0.5),
        ("template", 0.5),
        ("innerHTML", 0.9),
        ("dangerouslySetInnerHTML", 0.9),
        ("markup", 0.6),
        ("html", 0.4),
        ("response", 0.4),
    ],
    "csrf": [
        ("form", 0.5),
        ("post", 0.4),
        ("state_change", 0.8),
        ("mutate", 0.7),
        ("PUT", 0.6),
        ("DELETE", 0.6),
    ],
    "secrets": [
        ("api_key", 0.9),
        ("secret", 0.8),
        ("token", 0.7),
        ("password", 0.7),
        ("credential", 0.8),
        ("env", 0.5),
    ],
    "dependencies": [
        ("requirements", 0.7),
        ("package.json", 0.7),
        ("Cargo.toml", 0.7),
        ("go.mod", 0.7),
        ("Gemfile", 0.7),
        ("composer.json", 0.7),
    ],
    "configuration": [
        ("config", 0.5),
        ("settings", 0.5),
        ("debug", 0.8),
        ("verbose", 0.6),
        ("cors", 0.8),
        ("ssl", 0.7),
    ],
    "crypto": [
        ("encrypt", 0.8),
        ("decrypt", 0.8),
        ("hash", 0.7),
        ("md5", 0.9),
        ("sha1", 0.8),
        ("aes", 0.7),
        ("rsa", 0.7),
    ],
    "network": [
        ("http", 0.5),
        ("request", 0.4),
        ("fetch", 0.4),
        ("axios", 0.5),
        ("websocket", 0.7),
        ("ssrf", 0.9),
    ],
}


class ThreatModelGenerator:
    """Generates threat models from YAML scenarios + project context."""

    def __init__(self, root: Path):
        self.root = root
        self._scenarios_dir = Path(__file__).parent / "attack_scenarios"

    def generate(self) -> ThreatModel:
        """Generate a threat model for the current project."""
        model = ThreatModel(project_root=str(self.root))

        # Load all YAML scenarios
        all_scenarios = self._load_scenarios()
        model.total_scenarios = len(all_scenarios)

        # Get project context
        project_signals = self._collect_project_signals()

        # Score and filter scenarios
        for scenario in all_scenarios:
            score = self._score_scenario(scenario, project_signals)
            scenario.relevance_score = score
            scenario.applicable = score > 0.1
            model.scenarios.append(scenario)

        # Sort by relevance
        model.scenarios.sort(key=lambda s: (-s.relevance_score, s.severity))

        # Compute summaries
        model.applicable_scenarios = sum(1 for s in model.scenarios if s.applicable)
        for s in model.scenarios:
            if s.applicable:
                model.by_severity[s.severity] = model.by_severity.get(s.severity, 0) + 1
                model.by_category[s.category] = model.by_category.get(s.category, 0) + 1

        # Generate recommendations
        model.recommendations = self._generate_recommendations(model)

        _log.info(
            "Threat model: %d/%d scenarios applicable",
            model.applicable_scenarios,
            model.total_scenarios,
        )
        return model

    def _load_scenarios(self) -> list[AttackScenario]:
        """Load all attack scenarios from YAML files."""
        scenarios = []
        if not self._scenarios_dir.exists():
            return scenarios

        for yaml_file in self._scenarios_dir.glob("*.yaml"):
            try:
                import yaml

                with open(yaml_file, encoding="utf-8") as f:
                    data = yaml.safe_load(f)
                if not data or "scenarios" not in data:
                    continue
                for s in data["scenarios"]:
                    scenarios.append(
                        AttackScenario(
                            id=s.get("id", "unknown"),
                            name=s.get("name", "Unknown"),
                            category=s.get("category", "unknown"),
                            severity=s.get("severity", "medium"),
                            cwe=s.get("cwe", ""),
                            owasp=s.get("owasp", ""),
                            description=s.get("description", ""),
                            prerequisites=s.get("prerequisites", []),
                            attack_steps=s.get("attack_steps", []),
                            detection_signatures=s.get("detection_signatures", []),
                            remediation_playbook=s.get("remediation_playbook", ""),
                            tags=s.get("tags", []),
                        )
                    )
            except Exception as e:
                _log.warning("Failed to load %s: %s", yaml_file.name, e)
        return scenarios

    def _collect_project_signals(self) -> dict[str, float]:
        """Collect signals from the project to determine applicability."""
        signals: dict[str, float] = {}

        # Scan source files for keywords
        source_files = []
        for ext in ("*.py", "*.js", "*.ts", "*.jsx", "*.tsx", "*.go", "*.java", "*.rb"):
            source_files.extend(self.root.rglob(ext))

        # Limit to 500 files for performance
        source_files = source_files[:500]

        # Collect keyword frequency
        keyword_counts: dict[str, int] = {}
        for fp in source_files:
            # Skip vendor/node_modules/venv
            parts = fp.relative_to(self.root).parts
            if any(
                p.startswith(".") or p in ("node_modules", "__pycache__", ".venv", "venv")
                for p in parts
            ):
                continue
            try:
                content = fp.read_text(encoding="utf-8", errors="ignore").lower()
                for _category, kws in _CATEGORY_SIGNALS.items():
                    for kw, _ in kws:
                        if kw.lower() in content:
                            keyword_counts[kw] = keyword_counts.get(kw, 0) + 1
            except Exception:
                pass

        # Convert counts to scores (0-1)
        max_count = max(keyword_counts.values()) if keyword_counts else 1
        for kw, count in keyword_counts.items():
            signals[kw] = min(count / max(max_count, 1), 1.0)

        # Check for dependency files
        dep_files = [
            "requirements.txt",
            "package.json",
            "Cargo.toml",
            "go.mod",
            "Gemfile",
            "composer.json",
            "Pipfile",
        ]
        for df in dep_files:
            if (self.root / df).exists():
                signals[df] = 1.0

        # Check for config files
        config_files = [
            "config.py",
            "settings.py",
            ".env",
            "config.yaml",
            "config.json",
            "application.properties",
        ]
        for cf in config_files:
            if list(self.root.rglob(cf)):
                signals[cf] = 1.0

        return signals

    def _score_scenario(self, scenario: AttackScenario, signals: dict[str, float]) -> float:
        """Score a scenario based on project signals."""
        category_signals = _CATEGORY_SIGNALS.get(scenario.category, [])
        if not category_signals:
            return 0.2  # Default low relevance for unknown categories

        score = 0.0
        for kw, weight in category_signals:
            signal_value = signals.get(kw, 0.0)
            score += signal_value * weight

        # Normalize to 0-1
        max_possible = sum(w for _, w in category_signals)
        if max_possible > 0:
            score = min(score / max_possible, 1.0)

        # Boost for CWE tags matching project patterns
        if scenario.cwe:
            cwe_num = scenario.cwe.replace("CWE-", "")
            # SQL injection CWEs get boost if project uses SQL
            if cwe_num in ("89", "90") and signals.get("execute", 0) > 0.5:
                score = min(score * 1.5, 1.0)
            # XSS CWEs get boost if project renders HTML
            if cwe_num in ("79", "80") and signals.get("render", 0) > 0.3:
                score = min(score * 1.3, 1.0)

        return score

    def _generate_recommendations(self, model: ThreatModel) -> list[str]:
        """Generate security recommendations based on the threat model."""
        recs = []

        # High-severity applicable scenarios
        high_sev = [
            s for s in model.scenarios if s.applicable and s.severity in ("critical", "high")
        ]
        if high_sev:
            recs.append(
                f"Address {len(high_sev)} high/critical scenarios: "
                + ", ".join(s.name for s in high_sev[:3])
            )

        # Category gaps
        if "secrets" in model.by_category:
            recs.append("Review secret management — multiple secret-related scenarios apply")

        if "injection" in model.by_category:
            recs.append("Validate all user inputs — injection scenarios detected")

        if "auth" in str(model.by_category):
            recs.append("Audit authentication flows — auth scenarios are relevant")

        # Dependency warnings
        dep_scenarios = [
            s for s in model.scenarios if s.category == "dependencies" and s.applicable
        ]
        if dep_scenarios:
            recs.append("Run dependency vulnerability scan — project has dependency files")

        return recs
