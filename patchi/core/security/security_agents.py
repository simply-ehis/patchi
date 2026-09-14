"""
Security agents for Patchi.

All 54 agents are loaded lazily via _LazyAgent to ensure one failed import
does not crash the entire security module.

Tool wrappers:
  - Bandit     (Apache-2.0)  — pip install bandit
  - Semgrep CE  (LGPL-2.1)  — pip install semgrep
  - Gitleaks    (MIT)        — binary from github.com/gitleaks/gitleaks/releases
  - OSV-Scanner (Apache 2.0) — binary from github.com/google/osv-scanner/releases
  - httpx       (BSD)        — pip install httpx  (for dynamic CORS + header probes)
  - Pysa        (MIT)        — pip install pyre-check fb-sapp
  - CodeQL      (Restricted) — binary from github.com/github/codeql-cli-binaries/releases

DO NOT use TruffleHog in hosted SaaS mode (AGPL-3.0).
Gitleaks is the correct secret scanner here (MIT).
"""

from __future__ import annotations

import importlib
import logging

_log = logging.getLogger("patchi.security.agents")

_AGENT_MODULES: dict[str, str] = {
    "AppMapperAgent": ".app_mapper",
    "AuthenticationAuditAgent": ".auth_audit_agent",
    "AuthZAgent": ".authz_agent",
    "BanditAgent": ".bandit_agent",
    "BlastRadiusAgent": ".blast_radius",
    "BrowserTesterAgent": ".browser_tester",
    "BusinessLogicAgent": ".business_logic_agent",
    "CDNCacheSecurityAgent": ".cdn_cache_agent",
    "CloudWAFDetector": ".cloud_waf_detector",
    "ComplianceAgent": ".compliance_agent",
    "CatchBlockAuditor": ".catch_block_auditor",
    "ConfigAuditAgent": ".security_config",
    "ContainerScannerAgent": ".container_scanner",
    "CORSAuditor": ".security_probe",
    "CodeqlAgent": ".codeql_agent",
    "CryptoAgent": ".crypto_agent",
    "CVEMonitorAgent": ".cve_monitor",
    "DependencyCVEChecker": ".security_probe",
    "DependencyVulnerabilityAgent": ".dependency_vulnerability_agent",
    "DASTAgent": ".dast_agent",
    "DNSSecurityAgent": ".dns_security_agent",
    "EmailAuthenticationAgent": ".email_authentication_agent",
    "EvidenceAgent": ".evidence",
    "FalcoRuntimeAgent": ".falco_runtime_agent",
    "EnvVarValidator": ".env_var_validator",
    "GovernanceAgent": ".governance",
    "HeaderAuditAgent": ".security_config",
    "HistoryAgent": ".history",
    "IaCScannerAgent": ".iac_scanner",
    "InsecureRandomnessAgent": ".insecure_randomness_agent",
    "InjectionAgent": ".injection_agent",
    "SemgrepAgent": ".sast_agent",
    "JWTSecurityAgent": ".jwt_agent",
    "KubernetesAgent": ".kubernetes_agent",
    "LLMSecurityAgent": ".llm_security_agent",
    "MisconfigAgent": ".misconfig_agent",
    "MobileSecurityAgent": ".mobile_security_agent",
    "NetworkAgent": ".network_agent",
    "PlanAuditorAgent": ".plan_auditor",
    "PolicyEngineAgent": ".policy_engine",
    "PreCheckAgent": ".prechecks",
    "PrivacyAgent": ".privacy_agent",
    "PushNotificationAgent": ".push_notification_agent",
    "PysaAgent": ".pysa_agent",
    "RateLimitAuditor": ".security_config",
    "RedTeamAgent": ".red_team_agent",
    "RedTeamEngineAgent": ".red_team_engine",
    "RuntimeValidatorAgent": ".runtime_validator",
    "SamlSSOAgent": ".saml_sso_agent",
    "SecretsRuntimeAgent": ".secrets_runtime_agent",
    "SecretScanner": ".security_taint",
    "SecurityProber": ".security_probe",
    "SensitiveDataAgent": ".sensitive_data_agent",
    "ServiceMeshAgent": ".service_mesh_agent",
    "SessionManagementAgent": ".session_management_agent",
    "SSRFProtectionAgent": ".ssrf_agent",
    "SupplyChainAgent": ".supply_chain",
    "TaintAnalyzer": ".security_taint",
    "WebSocketSecurityAgent": ".websocket_security_agent",
}


class _LazyAgent:
    """Lazily imports and caches a single agent class."""

    def __init__(self, name: str, module_path: str):
        self._name = name
        self._module_path = module_path
        self._cls = None
        self._error = None

    def get(self):
        if self._cls is not None:
            return self._cls
        if self._error is not None:
            return None
        try:
            mod = importlib.import_module(self._module_path, __package__)
            self._cls = getattr(mod, self._name, None)
            if self._cls is None:
                self._error = f"Class {self._name} not found in {self._module_path}"
                _log.warning(self._error)
            return self._cls
        except Exception as e:
            self._error = f"Failed to import {self._name} from {self._module_path}: {e}"
            _log.warning(self._error)
            return None


def _make_proxy(name: str) -> _LazyAgent:
    """Create a lazy proxy and register it in this module's globals."""
    return _LazyAgent(name, _AGENT_MODULES[name])


class _LazyModuleProxy:
    """Module-level __getattr__ that lazily resolves agent imports."""

    def __init__(self):
        self._agents: dict[str, _LazyAgent] = {name: _make_proxy(name) for name in _AGENT_MODULES}

    def __getattr__(self, name: str):
        if name in self._agents:
            cls = self._agents[name].get()
            if cls is None:
                msg = f"Security agent {name} failed to import (see logs)"
                raise ImportError(msg)
            return cls
        msg = f"module {__name__!r} has no attribute {name!r}"
        raise AttributeError(msg)

    def __dir__(self):
        return list(self._agents.keys())


_proxy = _LazyModuleProxy()

__all__ = sorted(_AGENT_MODULES.keys())


def __getattr__(name: str):
    return getattr(_proxy, name)


# ── Eager registration pass ────────────────────────────────────────────────────
# The @register decorators only fire when each agent's module is actually
# imported. Without this pass, `import security_agents` would register ZERO
# agents (the lazy proxy defers everything), so Coordinator.run_group(SECURITY),
# `p security`, and `p agents list security` would silently run nothing.
# Each proxy.get() is individually exception-safe — one broken module logs a
# warning and is skipped, exactly the resilience the lazy design promised.
_registered = 0
_failures = 0
for _agent_name in sorted(_AGENT_MODULES):
    try:
        _cls = _proxy._agents[_agent_name].get()
        if _cls is None:
            _failures += 1
        else:
            _registered += 1
    except Exception as e:  # defensive: never let one agent block the rest
        _failures += 1
        _log.warning("security_agents eager registration failed for %s: %s", _agent_name, e)
if _failures:
    _log.warning(
        "security_agents: registered %d/%d agents (%d failed)",
        _registered,
        len(_AGENT_MODULES),
        _failures,
    )
