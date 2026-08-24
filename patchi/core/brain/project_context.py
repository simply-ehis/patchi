"""
Project context for context-aware agent gating.

Central place to determine whether a security agent is relevant
to the project being scanned, based on its inferred domain and purpose.

Usage:
    from patchi.core.brain.project_context import agent_is_relevant
    if not agent_is_relevant(inp):
        self.skip(result, "Not relevant for this project type")
        return result
"""

from __future__ import annotations

_WEB_DOMAINS = {"web-app", "web", "e-commerce", "saas", "social", "cms", "portal"}
_FINANCE_DOMAINS = {"finance", "banking", "fintech", "payments"}
_HEALTHCARE_DOMAINS = {"healthcare", "health", "medical", "hipaa"}
_MOBILE_DOMAINS = {"mobile-app", "android", "ios"}
_DATA_DOMAINS = {"data-pipeline", "etl", "analytics", "data"}

# Domain IDs from the security taxonomy that are web-related
_WEB_DOMAIN_IDS = {"web-frontend", "auth-session"}

# Agents that should only run when the project is a user-facing web app
_WEB_ONLY_AGENTS = {
    "AuthenticationAuditAgent",
    "AuthZAgent",
    "CORS",
    "HeaderAuditAgent",
    "RateLimitAuditor",
}

# Agents that should skip industry-specific rules unless domain matches
_INDUSTRY_AGENTS = {
    "PolicyEngine",
    "ComplianceAgent",
    "PrivacyAgent",
}

# Agents that are universal (run on any project)
_UNIVERSAL_AGENTS = {
    "SecretScanner",
    "EnvScanner",
    "DependencyScanner",
    "CVEMonitorAgent",
    "SupplyChainAgent",
    "PreCheckAgent",
    "IaCScanner",
    "ContainerScanner",
    "SSRFProtection",
    "InjectionAgent",
    "CryptoAgent",
    "NetworkAgent",
    "JWTSecurityAgent",
    "SensitiveDataAgent",
    "MisconfigAgent",
    "TaintAnalyzer",
    "RedTeamAgent",
}


def agent_is_relevant(
    domain: str,
    purpose: str,
    agent_name: str,
    active_domains: list[str] | None = None,
) -> tuple[bool, str]:
    """
    Check whether a security agent is relevant for a project.

    Uses the active security domain IDs from the Brain's context phase
    when available (preferred), falling back to domain/purpose string matching.

    Returns (relevant, reason) where reason is empty if relevant, or explains the skip.
    """
    domain_lower = domain.lower()
    purpose_lower = purpose.lower()
    active = active_domains or []

    # Universal agents always run
    if agent_name in _UNIVERSAL_AGENTS:
        return True, ""

    # Web-only agents skip if no web-related domain is activated
    if agent_name in _WEB_ONLY_AGENTS:
        is_web = bool(set(active) & _WEB_DOMAIN_IDS)
        if not is_web:
            is_web = bool(any(d in domain_lower for d in _WEB_DOMAINS) or "web" in purpose_lower)
        if not is_web:
            return False, f"Project domain is '{domain}' — auth checks not applicable"

    # Industry-specific agents skip unless their domain matches
    if agent_name in _INDUSTRY_AGENTS:
        if not domain_lower and not active:
            return True, ""
        is_finance = any(d in domain_lower for d in _FINANCE_DOMAINS)
        is_health = any(d in domain_lower for d in _HEALTHCARE_DOMAINS)
        if agent_name == "PolicyEngine":
            return True, ""
        if agent_name == "PrivacyAgent":
            if not is_finance and not is_health:
                _has_pii_signals = any(
                    w in purpose_lower for w in ("pii", "gdpr", "ccpa", "privacy", "personal")
                )
                if not _has_pii_signals:
                    return False, f"Project domain is '{domain}' — privacy rules not applicable"

    return True, ""


def domain_has_auth(domain: str, routes: list[str]) -> bool:
    """Quick check if a project likely has authentication based on routes."""
    if domain in _WEB_DOMAINS:
        return True
    auth_keywords = {"login", "signin", "auth", "register", "token"}
    for route in routes:
        for kw in auth_keywords:
            if kw in route.lower():
                return True
    return False