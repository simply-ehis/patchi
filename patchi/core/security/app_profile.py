"""
App Profile — component-level project profiling with domain scoring.

Detects what kind of project this is (CLI binary, backend API, frontend web,
library, mobile, etc.) and activates/deactivates security domains accordingly.

Three activation states per domain:
  - Active:     Domain applies to this project type
  - N/A:        Domain does not apply (e.g. web-frontend for a CLI tool)
  - Unclear:    Cannot determine — falls to heuristic/AI

Scoring:
  - Only Active domains contribute to the weighted score
  - context_score = Σ(domain_weight × domain_score) / Σ(domain_weight)
  - N/A domains are excluded from both numerator and denominator
"""

from __future__ import annotations
import logging

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from patchi.core.security.domain_loader import Domain, DomainLoader, normalize_component_type


_log = logging.getLogger("patchi.security.app_profile")


class ActivationState(str):
    ACTIVE = "active"
    NA = "n/a"
    UNCLEAR = "unclear"


@dataclass
class DomainActivation:
    domain_id: str
    display_name: str
    state: str  # active | n/a | unclear
    weight: float
    score: float = 0.0
    reason: str = ""

    def to_dict(self) -> dict:
        return {
            "domain_id": self.domain_id,
            "display_name": self.display_name,
            "state": self.state,
            "weight": self.weight,
            "score": round(self.score, 1),
            "reason": self.reason,
        }


@dataclass
class ComponentProfile:
    component_type: str  # cli-binary | backend-api | frontend-web | library | mobile | embedded | unknown
    display_name: str = ""
    frameworks: list[str] = field(default_factory=list)
    languages: list[str] = field(default_factory=list)
    has_database: bool = False
    has_authentication: bool = False
    has_network: bool = False
    has_user_input: bool = False
    is_packaged: bool = False
    detection_signals: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "component_type": self.component_type,
            "display_name": self.display_name,
            "frameworks": self.frameworks,
            "languages": self.languages,
            "has_database": self.has_database,
            "has_authentication": self.has_authentication,
            "has_network": self.has_network,
            "has_user_input": self.has_user_input,
            "is_packaged": self.is_packaged,
        }


_COMPONENT_SIGNALS: dict[str, dict] = {
    "backend-api": {
        "frameworks": {"fastapi", "flask", "django", "express", "koa", "spring", "actix", "rocket", "gin", "echo"},
        "files": {"routes/", "api/", "controllers/", "middleware/", "serializers/"},
        "deps": {"fastapi", "flask", "django", "express", "axios", "rest"},
    },
    "frontend-web": {
        "frameworks": {"react", "vue", "angular", "svelte", "next", "nuxt", "solid"},
        "files": {"components/", "pages/", "views/", "templates/"},
        "deps": {"react", "vue", "angular", "svelte"},
    },
    "cli-binary": {
        "frameworks": {"click", "typer", "argparse", "clap", "cobra", "commander"},
        "files": {"cli/", "commands/"},
        "deps": {"click", "typer", "argparse", "clap"},
    },
    "library": {
        "frameworks": set(),
        "files": {"src/", "lib/"},
        "deps": set(),
    },
    "mobile": {
        "frameworks": {"react-native", "flutter", "swiftui", "jetpack"},
        "files": {"android/", "ios/", "lib/"},
        "deps": {"react-native", "flutter"},
    },
    "embedded": {
        "frameworks": set(),
        "files": {"firmware/", "hal/", "drivers/"},
        "deps": set(),
    },
    "infra": {
        "frameworks": {"docker", "kubernetes", "terraform", "ansible", "pulumi", "helm", "kustomize"},
        "files": {"Dockerfile", "docker-compose", ".github/workflows/", ".gitlab-ci/", "k8s/", "deploy/", "infra/"},
        "deps": {"docker", "docker-compose", "kubernetes", "terraform"},
    },
    "llm-integration": {
        "frameworks": {"langchain", "llamaindex", "openai", "anthropic", "cohere", "transformers"},
        "files": {"llm/", "ai/", "prompts/", "embeddings/", "vector-store/", "agents/"},
        "deps": {"openai", "langchain", "anthropic", "cohere", "transformers"},
    },
}

_COMPONENT_DOMAIN_MAP: dict[str, list[str]] = {
    "backend-api": ["backend-api", "web-frontend"],
    "frontend-web": ["web-frontend"],
    "frontend": ["web-frontend"],
    "cli-binary": [],
    "library": [],
    "mobile": ["web-frontend"],
    "infra": ["cicd-pipeline", "container-infra", "supply-chain-local-tool"],
    "infrastructure": ["cicd-pipeline", "container-infra", "supply-chain-local-tool"],
    "llm-integration": ["llm-integration"],
    "embedded": [],
}


class AppProfileBuilder:
    """Builds an AppProfile from project files and brain data."""

    def __init__(self, root: Path):
        self.root = root

    def build(self, brain: dict | None = None) -> ComponentProfile:
        """Detect component type from project files and brain data."""
        profile = ComponentProfile(component_type="unknown")
        brain = brain or {}

        # Languages from brain
        lang_data = brain.get("languages", {})
        if isinstance(lang_data, dict):
            profile.languages = list(lang_data.keys())
        elif isinstance(lang_data, list):
            profile.languages = [str(lang) for lang in lang_data]

        # Frameworks from brain
        fw_raw = brain.get("frameworks", brain.get("framework", ""))
        if isinstance(fw_raw, list):
            profile.frameworks = [f if isinstance(f, str) else (f.get("name", "") or "") for f in fw_raw]
        elif isinstance(fw_raw, dict):
            profile.frameworks = [fw_raw.get("name", "")] if fw_raw.get("name") else []
        elif isinstance(fw_raw, str):
            profile.frameworks = [fw_raw] if fw_raw else []

        profile.frameworks = [f.lower() for f in profile.frameworks if f]

        # Detection signals from file system
        profile.detection_signals = self._scan_project_files()

        # Component type inference
        profile.component_type = self._infer_component_type(profile)
        profile.display_name = brain.get("project_purpose", brain.get("project_name", "")) or profile.component_type

        profile.has_database = profile.detection_signals.get("has_database", False)
        profile.has_authentication = profile.detection_signals.get("has_authentication", False)
        profile.has_network = profile.detection_signals.get("has_network", False)
        profile.has_user_input = profile.detection_signals.get("has_user_input", False)
        profile.is_packaged = profile.detection_signals.get("is_packaged", False)

        return profile

    def _scan_project_files(self) -> dict[str, Any]:
        """Scan root for file-level signals (fast, no full AST)."""
        signals: dict[str, Any] = {
            "has_database": False,
            "has_authentication": False,
            "has_network": False,
            "has_user_input": False,
            "is_packaged": False,
            "found_dirs": set(),
            "found_deps": set(),
        }

        pyproject = self.root / "pyproject.toml"
        if pyproject.exists():
            signals["is_packaged"] = True
            try:
                content = pyproject.read_text(encoding="utf-8", errors="ignore")
                if "django" in content:
                    signals["found_deps"].add("django")
                if "fastapi" in content:
                    signals["found_deps"].add("fastapi")
                if "click" in content or "typer" in content:
                    signals["found_deps"].add("click")
            except Exception as e:
                _log.warning("AppProfileBuilder._scan_project_files failed: %s", e)

        package = self.root / "package.json"
        if package.exists():
            signals["is_packaged"] = True
            try:
                import json
                data = json.loads(package.read_text(encoding="utf-8", errors="ignore"))
                deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
                signals["found_deps"].update(deps.keys())
            except Exception as e:
                _log.warning("AppProfileBuilder._scan_project_files failed: %s", e)

        # Directory structure scan (limited depth)
        for entry in self.root.iterdir():
            if entry.is_dir() and not entry.name.startswith("."):
                name = entry.name.lower()
                if name in ("routes", "api", "controllers", "middleware"):
                    signals["found_dirs"].add(name)
                    signals["has_network"] = True
                if name in ("components", "pages", "views", "templates"):
                    signals["found_dirs"].add(name)
                    signals["has_user_input"] = True
                if name in ("cli", "commands"):
                    signals["found_dirs"].add(name)
                if name in ("models", "migrations", "db", "database"):
                    signals["found_dirs"].add(name)
                    signals["has_database"] = True
                if name in ("auth", "login", "sessions"):
                    signals["found_dirs"].add(name)
                    signals["has_authentication"] = True

        return signals

    def _infer_component_type(self, profile: ComponentProfile) -> str:
        """Score each component type and return the best match."""
        scores: dict[str, int] = {ct: 0 for ct in _COMPONENT_SIGNALS}
        signals = profile.detection_signals

        for ct, sig in _COMPONENT_SIGNALS.items():
            # Framework matches
            for fw in profile.frameworks:
                if fw in sig.get("frameworks", set()):
                    scores[ct] += 3

            # Directory matches
            for d in signals.get("found_dirs", set()):
                if d + "/" in sig.get("files", set()):
                    scores[ct] += 2

            # Dependency matches
            for dep in signals.get("found_deps", set()):
                if any(k in dep for k in sig.get("deps", set())):
                    scores[ct] += 1

        best = max(scores, key=scores.get)
        return best if scores[best] > 0 else "unknown"


class AppProfileScorer:
    """Computes weighted domain scores from an AppProfile."""

    def __init__(self, root: Path):
        self.root = root
        self._loader = DomainLoader(root)

    def score(
        self, profile: ComponentProfile, existing_scores: dict[str, float] | None = None
    ) -> list[DomainActivation]:
        """Score all domains against the component profile."""
        existing_scores = existing_scores or {}
        domain_ids = self._get_applicable_domains(profile)
        results: list[DomainActivation] = []

        for did in domain_ids:
            domain = self._loader.get_domain(did)
            if not domain:
                continue

            state, reason = self._determine_activation(domain, profile)
            score = existing_scores.get(did, 50.0)

            results.append(DomainActivation(
                domain_id=did,
                display_name=domain.display_name,
                state=state,
                weight=domain.weight,
                score=score if state == ActivationState.ACTIVE else 0.0,
                reason=reason,
            ))

        return results

    def compute_context_score(self, activations: list[DomainActivation]) -> float:
        """Weighted sum of active domain scores."""
        total_weight = 0.0
        weighted_sum = 0.0
        for a in activations:
            if a.state == ActivationState.ACTIVE:
                total_weight += a.weight
                weighted_sum += a.weight * a.score

        if total_weight == 0:
            return 50.0
        return weighted_sum / total_weight

    _TYPE_ALIASES: dict[str, str] = {
        "infrastructure": "infra",
        "frontend": "frontend-web",
        "web-frontend": "frontend-web",
        "backend-api,frontend-web": "backend-api",
    }

    def _normalize_type(self, ct: str) -> str:
        # Delegate to the loader's canonical normalization (same alias table)
        # so scoped loading and applicability checks can never disagree.
        ct = (ct or "").strip().lower()
        if ct in self._TYPE_ALIASES:
            return self._TYPE_ALIASES[ct]
        return normalize_component_type(ct)

    def _get_applicable_domains(self, profile: ComponentProfile) -> list[str]:
        """Return domain IDs that may apply to this component type.

        The loader is scoped to the profile's component type before enumerating,
        so a narrow profile only ever parses the domain files that could match
        (plus the explicit component->domain map entries) instead of the full
        taxonomy.
        """
        profile_type = self._normalize_type(profile.component_type)
        explicit = list(_COMPONENT_DOMAIN_MAP.get(profile.component_type, []))

        # Both axes: component-type match AND explicit domain ids (e.g. a
        # backend-api profile always loads the web-frontend domain).
        self._loader.set_component_scope(
            component_types=[profile.component_type], domain_ids=explicit
        )

        all_domains = self._loader.list_domains()
        for d in all_domains:
            if d not in explicit:
                domain = self._loader.get_domain(d)
                if domain and domain.component_type:
                    comp_types = [self._normalize_type(ct.strip()) for ct in domain.component_type.split(",")]
                    if profile_type in comp_types:
                        explicit.append(d)

        return explicit

    def _determine_activation(
        self, domain: Domain, profile: ComponentProfile
    ) -> tuple[str, str]:
        """Determine if a domain is Active, N/A, or Unclear."""
        sig = domain.activation_signals or {}

        # Check exclusion signals first
        excluded_if = sig.get("excluded_if", [])
        for cond in excluded_if:
            if self._check_signal(cond, profile):
                return ActivationState.NA, f"Excluded by: {cond}"

        # Check required signals
        required_any = sig.get("required_any", [])
        if required_any:
            for cond in required_any:
                if self._check_signal(cond, profile):
                    return ActivationState.ACTIVE, f"Matched: {cond}"
            return ActivationState.UNCLEAR, f"No required signal matched: {required_any}"

        # Check framework match
        fw = sig.get("framework", "")
        if fw and fw.lower() in [f.lower() for f in profile.frameworks]:
            return ActivationState.ACTIVE, f"Framework matched: {fw}"

        # Default: active if component type is relevant (handles comma-separated composite types)
        comp_type = sig.get("component_type", "")
        if comp_type and profile.component_type in [ct.strip() for ct in comp_type.split(",")]:
            return ActivationState.ACTIVE, f"Component type: {comp_type}"

        return ActivationState.UNCLEAR, "No signals matched — unable to determine activation"

    def _check_signal(self, condition: str, profile: ComponentProfile) -> bool:
        """Check a single activation condition string."""
        cond = condition.lower()

        # Framework checks — check if any framework name appears as a keyword in the signal
        for fw in profile.frameworks:
            fw_key = fw.lower().replace("-", "").replace("_", "")
            cond_key = cond.replace("-", "").replace("_", "").replace("(", "").replace(")", "")
            if fw_key in cond_key:
                return True

        # Dependency checks — check known dependency keywords
        for dep in profile.detection_signals.get("found_deps", set()):
            dep_key = dep.lower().replace("-", "").replace("_", "")
            if dep_key in cond:
                return True

        # Component type check
        if profile.component_type in cond:
            return True

        # Directory structure checks
        for d in profile.detection_signals.get("found_dirs", set()):
            if d in cond:
                return True

        # Feature checks
        feature_map = {
            "database": profile.has_database,
            "auth": profile.has_authentication,
            "authentication": profile.has_authentication,
            "network": profile.has_network,
            "user_input": profile.has_user_input,
            "packaged": profile.is_packaged,
        }
        for feature, present in feature_map.items():
            if feature in cond and present:
                return True

        return False
