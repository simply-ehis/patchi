"""
Dynamic Security Domain Activator v2 — Intelligent, signal-based domain activation.

Replaces static domain loading with adaptive activation based on:
- Code signals (imports, patterns, frameworks)
- Configuration signals (env vars, config files, infra)
- Runtime signals (running services, open ports)
- Historical signals (past findings, incident history)
- Project context (business domain, compliance requirements)

Only activates domains that are actually relevant, reducing scan time and noise.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path

from patchi.core import memory as mem
from patchi.core.brain.scanner import FileInfo
from patchi.core.security.domain_loader import Domain, DomainLoader

_log = logging.getLogger("patchi.security.domain_activator_v2")


@dataclass
class ActivationSignal:
    """A signal that contributes to domain activation."""

    source: str  # "code", "config", "runtime", "history", "context"
    domain: str
    weight: float  # 0.0 - 1.0
    evidence: str  # Human-readable evidence
    metadata: dict = field(default_factory=dict)


@dataclass
class DomainActivationResult:
    """Result of domain activation analysis."""

    activated_domains: list[str]
    signals: list[ActivationSignal]
    domain_scores: dict[str, float]
    skipped_domains: list[str]
    activation_threshold: float


# ── Domain Signal Definitions ────────────────────────────────────────────────

# Each domain has a set of signals that activate it
# Signals are weighted by reliability (higher = more reliable indicator)
DOMAIN_SIGNALS: dict[str, dict[str, list[tuple[str, float, str]]]] = {
    # Injection domains
    "injection-sql": {
        "code": [
            (r"\.execute\s*\([^)]*%[sf]", 0.9, "String formatting in SQL execute"),
            # Any `.execute(...)` / `.executemany(...)` built with `+` string
            # concatenation — catches conn/cursor/session variants alike.
            (
                r"\.execute(?:many)?\s*\([^)]*['\"]\s*\+",
                0.85,
                "String concatenation in SQL execute",
            ),
            (r"cursor\.execute\s*\([^)]*\+", 0.8, "String concatenation in cursor SQL"),
            (r"SELECT.*FROM.*WHERE.*\{", 0.7, "Template-style SQL"),
            (r"f['\"].*SELECT", 0.7, "F-string SQL query"),
            (r"\.raw\s*\([^)]*SELECT", 0.8, "Raw SQL usage"),
        ],
        "config": [
            (r"DATABASE_URL", 0.3, "Database connection configured"),
        ],
    },
    "injection-nosql": {
        "code": [
            (r"\.find\s*\(\s*\{[^}]*\$where", 0.9, "MongoDB $where injection"),
            (r"\.aggregate\s*\([^)]*\$expr", 0.7, "Aggregation with user input"),
            (r"eval\s*\([^)]*db\.", 0.8, "JavaScript eval with DB"),
        ],
    },
    "injection-command": {
        "code": [
            (
                r"subprocess\.(run|call|Popen)\s*\([^)]*shell\s*=\s*True",
                0.9,
                "Shell=True with user input",
            ),
            (r"os\.system\s*\(", 0.95, "os.system usage"),
            (r"os\.popen\s*\(", 0.9, "os.popen usage"),
            (r"commands\.getstatusoutput", 0.8, "commands module usage"),
            (r"shlex\.split\s*\([^)]*input", 0.7, "shlex with user input"),
        ],
    },
    "injection-ldap": {
        "code": [
            (r"ldap3.*\([^)]*\)", 0.6, "LDAP library usage"),
            (r"python-ldap", 0.5, "LDAP import"),
        ],
    },
    "injection-xpath": {
        "code": [
            (r"lxml.*xpath", 0.6, "XPath usage"),
            (r"etree\.XPath", 0.7, "XPath evaluation"),
        ],
    },
    "injection-template": {
        "code": [
            (r"jinja2\.Environment.*autoescape\s*=\s*False", 0.9, "Jinja2 autoescape disabled"),
            (r"render_template_string\s*\(", 0.8, "Flask render_template_string"),
            (r"Template\s*\([^)]*request\.", 0.7, "Template with request data"),
            (r"mustache|handlebars|nunjucks", 0.5, "Template engine usage"),
        ],
    },
    # XSS
    "xss-reflected": {
        "code": [
            (r"request\.(args|query_params|GET)\[", 0.7, "Direct request param usage"),
            (r"HttpResponse\s*\([^)]*request\.", 0.8, "Direct response with request data"),
            (r"res\.send\s*\([^)]*req\.", 0.7, "Express res.send with req data"),
        ],
    },
    "xss-stored": {
        "code": [
            (r"innerHTML\s*=", 0.8, "Direct innerHTML assignment"),
            (r"dangerouslySetInnerHTML", 0.9, "React dangerouslySetInnerHTML"),
            (r"v-html\s*=", 0.8, "Vue v-html directive"),
            (r"\.html\s*\([^)]*user", 0.7, "jQuery .html() with user data"),
        ],
    },
    "xss-dom": {
        "code": [
            (r"document\.write\s*\(", 0.9, "document.write usage"),
            (r"location\.hash", 0.6, "Hash-based routing"),
            (r"eval\s*\([^)]*location", 0.8, "Eval with location"),
        ],
    },
    # Auth & Session
    "authentication": {
        "code": [
            (r"@login_required|@auth_required", 0.8, "Auth decorator usage"),
            (r"passport\.authenticate", 0.8, "Passport.js usage"),
            (r"flask_login|django\.contrib\.auth", 0.7, "Auth framework"),
            (r"bcrypt|argon2|scrypt|PBKDF2", 0.6, "Password hashing"),
            (r"session\[|session\.get\(", 0.7, "Session usage"),
        ],
        "config": [
            (r"SECRET_KEY|JWT_SECRET", 0.5, "Auth secret configured"),
        ],
    },
    "authorization": {
        "code": [
            (r"@permission_required|@role_required", 0.8, "Permission decorators"),
            (r"rbac|acl|casbin", 0.6, "Authorization library"),
            (r"policy\.enforce|can\s*\(", 0.7, "Policy enforcement"),
        ],
    },
    "session-management": {
        "code": [
            (r"session\.cookie_secure\s*=\s*False", 0.8, "Insecure session cookie"),
            (r"session\.cookie_httponly\s*=\s*False", 0.8, "Non-HttpOnly cookie"),
            (r"same_site\s*=\s*['\"]?none", 0.7, "SameSite=None"),
        ],
    },
    "jwt-security": {
        "code": [
            (r"jwt\.encode|jwt\.decode", 0.7, "JWT usage"),
            (r"algorithm\s*=\s*['\"]none['\"]", 0.95, "JWT alg=none"),
            (r"verify\s*=\s*False", 0.9, "JWT verification disabled"),
        ],
    },
    # Secrets
    "secrets-management": {
        "code": [
            (
                r"(api[_-]?key|secret|password|token)\s*=\s*['\"][^'\"]{16,}",
                0.9,
                "Hardcoded secret",
            ),
            (r"os\.environ\[['\"][A-Z_]*KEY", 0.6, "Env var access"),
            (r"vault|keyring|secretsmanager", 0.5, "Secret management lib"),
        ],
        "config": [
            (r"\.env", 0.4, "Env file present"),
        ],
    },
    # Crypto
    "cryptography": {
        "code": [
            (r"Crypto\.Cipher|pycryptodome|cryptography\.hazmat", 0.7, "Crypto library"),
            (r"MD5|SHA1|DES|RC4", 0.8, "Weak algorithm"),
            (r"ECB\s*mode", 0.7, "ECB mode"),
            (r"IV\s*=\s*['\"]0{16}", 0.8, "Static IV"),
        ],
    },
    "tls-ssl": {
        "code": [
            (r"verify\s*=\s*False", 0.8, "SSL verify disabled"),
            (r"ssl\._create_unverified_context", 0.9, "Unverified SSL context"),
            (r"check_hostname\s*=\s*False", 0.8, "Hostname check disabled"),
        ],
        "config": [
            (r"TLS|SSL|HTTPS", 0.4, "TLS config present"),
        ],
    },
    # SSRF
    "ssrf": {
        "code": [
            (r"requests\.(get|post|put|delete)\s*\([^)]*request\.", 0.8, "Request with user URL"),
            (r"urllib\.request\.urlopen\s*\([^)]*input", 0.8, "urlopen with input"),
            (r"httpx\.get\s*\([^)]*user", 0.7, "httpx with user input"),
            (r"fetch\s*\([^)]*input", 0.7, "Fetch with user input"),
        ],
    },
    # Path Traversal
    "path-traversal": {
        "code": [
            (r"open\s*\([^)]*request\.", 0.8, "File open with request"),
            (r"send_file\s*\([^)]*request\.", 0.8, "Flask send_file with request"),
            (r"path\.join\s*\([^)]*\.\.", 0.7, "Path join with traversal"),
            (r"os\.path\.join.*user", 0.7, "Path join with user input"),
        ],
    },
    # Deserialization
    "deserialization": {
        "code": [
            (r"pickle\.loads?\s*\(", 0.95, "Pickle deserialization"),
            (r"marshal\.loads?\s*\(", 0.9, "Marshal deserialization"),
            (r"yaml\.load\s*\([^)]*\)", 0.8, "YAML load without SafeLoader"),
            (r"jsonpickle|dill|cloudpickle", 0.7, "Serialization library"),
            (r"java\.io\.ObjectInputStream", 0.9, "Java deserialization"),
        ],
    },
    # XXE
    "xxe": {
        "code": [
            (r"etree\.parse\s*\([^)]*request", 0.8, "XML parse with request"),
            (r"XMLParser\s*\([^)]*resolve_entities\s*=\s*True", 0.9, "Entity resolution enabled"),
            (
                r"SAXParser.*setFeature.*external-general-entities.*true",
                0.8,
                "SAX external entities",
            ),
        ],
    },
    # CORS
    "cors": {
        "code": [
            (r"CORS\s*\([^)]*origins\s*=\s*['\"]\*['\"]", 0.9, "CORS wildcard origin"),
            (r"Access-Control-Allow-Origin\s*:\s*\*", 0.9, "Wildcard CORS header"),
            (r"cors\.allow_all_origins\s*=\s*True", 0.8, "Allow all origins"),
        ],
    },
    # CSRF
    "csrf": {
        "code": [
            (r"@csrf_exempt", 0.9, "CSRF exemption"),
            (r"csrf\.protect\s*=\s*False", 0.8, "CSRF disabled"),
            (r"WTF_CSRF_ENABLED\s*=\s*False", 0.8, "Flask-WTF CSRF disabled"),
        ],
    },
    # Security Headers
    "security-headers": {
        "code": [
            (r"helmet|secure-headers", 0.5, "Security headers lib"),
            (r"X-Frame-Options|CSP|HSTS", 0.6, "Security header usage"),
        ],
        "config": [
            (r"SECURE_.*_HEADER", 0.5, "Security header config"),
        ],
    },
    # Rate Limiting
    "rate-limiting": {
        "code": [
            (r"flask_limiter|django_ratelimit|express-rate-limit", 0.6, "Rate limit lib"),
            (r"@limiter\.limit|@ratelimit", 0.7, "Rate limit decorator"),
        ],
        "config": [
            (r"RATE_LIMIT|RATELIMIT", 0.4, "Rate limit config"),
        ],
    },
    # Supply Chain
    "supply-chain": {
        "code": [
            (
                r"package\.json|requirements\.txt|pyproject\.toml|Cargo\.toml|go\.mod",
                0.4,
                "Dependency file",
            ),
        ],
        "config": [
            (r"dependabot|renovate|snyk", 0.5, "Dependency bot config"),
        ],
    },
    "dependency-vulnerability": {
        "code": [
            (
                r"package\.json|requirements\.txt|pyproject\.toml|Cargo\.toml|go\.mod",
                0.4,
                "Dependency file",
            ),
        ],
    },
    # Container/Cloud
    "container-security": {
        "code": [
            (r"Dockerfile|docker-compose\.ya?ml", 0.6, "Docker config"),
            (r"FROM\s+\w+:", 0.5, "Base image"),
        ],
    },
    "kubernetes-security": {
        "code": [
            (r"\.ya?ml$", 0.3, "YAML file"),
            (r"apiVersion:|kind: (Deployment|Service|Pod|Ingress)", 0.7, "K8s resource"),
            (r"securityContext|runAsNonRoot|readOnlyRootFilesystem", 0.6, "Security context"),
        ],
    },
    "cloud-security": {
        "code": [
            (r"boto3|google-cloud|azure-mgmt", 0.5, "Cloud SDK"),
            (r"terraform|cloudformation|pulumi", 0.5, "IaC"),
        ],
    },
    # Runtime
    "runtime-protection": {
        "code": [
            (r"falco|sysdig|tracee", 0.6, "Runtime security tool"),
        ],
        "config": [
            (r"falco|runtime", 0.4, "Runtime config"),
        ],
    },
    # Privacy
    "privacy-gdpr": {
        "code": [
            (r"gdpr|personal_data|pii|data_subject", 0.6, "GDPR keywords"),
            (r"anonymize|pseudonymize|consent", 0.6, "Privacy functions"),
        ],
        "config": [
            (r"GDPR|PRIVACY|DATA_PROTECTION", 0.4, "Privacy config"),
        ],
    },
    # Business Logic
    "business-logic": {
        "code": [
            (r"transfer|payment|checkout|order", 0.5, "Financial keywords"),
            (r"workflow|state_machine|saga", 0.5, "Workflow patterns"),
        ],
    },
    # API Security
    "api-security": {
        "code": [
            (r"openapi|swagger|graphql", 0.5, "API schema"),
            (r"rate_limit|throttle|quota", 0.5, "API protection"),
        ],
    },
    # Logging/Audit
    "audit-logging": {
        "code": [
            (r"audit|auditlog|structlog", 0.5, "Audit library"),
            (r"logging\.audit|logger\.audit", 0.6, "Audit logging"),
        ],
    },
}


# ── Signal Extraction ────────────────────────────────────────────────────────


class SignalExtractor:
    """Extracts activation signals from project artifacts."""

    def __init__(self, root: Path):
        self.root = root
        self._code_cache: dict[str, str] = {}

    def extract_all_signals(
        self,
        file_infos: list[FileInfo],
        project_context: dict,
    ) -> list[ActivationSignal]:
        """Extract all signals from code, config, and context."""
        signals = []

        # Code signals
        signals.extend(self._extract_code_signals(file_infos))

        # Config signals
        signals.extend(self._extract_config_signals())

        # Context signals (frameworks, domains, etc.)
        signals.extend(self._extract_context_signals(project_context))

        # History signals (past findings)
        signals.extend(self._extract_history_signals())

        return signals

    def _extract_code_signals(self, file_infos: list[FileInfo]) -> list[ActivationSignal]:
        signals = []

        for fi in file_infos:
            if fi.error:
                continue

            # Get file content (cached)
            content = self._get_file_content(fi.path)
            if not content:
                continue

            content.lower()
            file_path = fi.path

            # Check each domain's code signals
            for domain, signal_defs in DOMAIN_SIGNALS.items():
                code_signals = signal_defs.get("code", [])
                for pattern, weight, description in code_signals:
                    if re.search(pattern, content, re.IGNORECASE):
                        signals.append(
                            ActivationSignal(
                                source="code",
                                domain=domain,
                                weight=weight,
                                evidence=f"{description} in {file_path}",
                                metadata={"file": file_path, "pattern": pattern},
                            )
                        )

        return signals

    def _extract_config_signals(self) -> list[ActivationSignal]:
        signals = []

        # Check common config files
        config_files = [
            ".env",
            "config.yaml",
            "config.yml",
            "settings.py",
            "application.properties",
            "application.yml",
            "docker-compose.yml",
            "docker-compose.yaml",
            "kubernetes/",
            "k8s/",
            "helm/",
            "terraform/",
            ".tf",
            "package.json",
            "requirements.txt",
            "pyproject.toml",
            "Cargo.toml",
            "go.mod",
            "pom.xml",
        ]

        for config_path in config_files:
            full_path = self.root / config_path
            if not full_path.exists():
                # Try glob for directories
                if config_path.endswith("/"):
                    matches = list(self.root.rglob(config_path[:-1] + "/*"))
                    if not matches:
                        continue
                    full_path = matches[0]
                else:
                    continue

            try:
                if full_path.is_file():
                    content = full_path.read_text(encoding="utf-8", errors="ignore")
                else:
                    continue
            except Exception:
                continue

            content.lower()

            for domain, signal_defs in DOMAIN_SIGNALS.items():
                config_signals = signal_defs.get("config", [])
                for pattern, weight, description in config_signals:
                    if re.search(pattern, content, re.IGNORECASE):
                        signals.append(
                            ActivationSignal(
                                source="config",
                                domain=domain,
                                weight=weight,
                                evidence=f"{description} in {config_path}",
                                metadata={"config_file": config_path, "pattern": pattern},
                            )
                        )

        return signals

    def _extract_context_signals(self, project_context: dict) -> list[ActivationSignal]:
        signals = []

        # Framework-based signals
        frameworks = project_context.get("frameworks", [])
        for fw in frameworks:
            fw_name = fw.get("name", "").lower()

            # Framework implies certain domains
            if fw_name in ("django", "flask", "fastapi", "express", "spring", "gin"):
                signals.append(
                    ActivationSignal(
                        source="context",
                        domain="api-security",
                        weight=0.6,
                        evidence=f"Web framework {fw_name} detected",
                    )
                )
                signals.append(
                    ActivationSignal(
                        source="context",
                        domain="authentication",
                        weight=0.5,
                        evidence=f"Web framework {fw_name} typically has auth",
                    )
                )
                signals.append(
                    ActivationSignal(
                        source="context",
                        domain="security-headers",
                        weight=0.4,
                        evidence=f"Web framework {fw_name} needs security headers",
                    )
                )

            if fw_name in ("react", "vue", "svelte", "angular", "next.js", "nuxt"):
                signals.append(
                    ActivationSignal(
                        source="context",
                        domain="xss-dom",
                        weight=0.6,
                        evidence=f"Frontend framework {fw_name} - DOM XSS relevant",
                    )
                )
                signals.append(
                    ActivationSignal(
                        source="context",
                        domain="api-security",
                        weight=0.5,
                        evidence=f"Frontend framework {fw_name} consumes APIs",
                    )
                )

        # Component type signals
        comp_type = project_context.get("component_type", "")
        if comp_type:
            if "frontend" in comp_type:
                signals.append(
                    ActivationSignal(
                        source="context",
                        domain="xss-dom",
                        weight=0.7,
                        evidence="Frontend component type",
                    )
                )
            if "backend" in comp_type or "api" in comp_type:
                signals.append(
                    ActivationSignal(
                        source="context",
                        domain="api-security",
                        weight=0.7,
                        evidence="Backend/API component type",
                    )
                )
            if "mobile" in comp_type:
                signals.append(
                    ActivationSignal(
                        source="context",
                        domain="mobile-security",
                        weight=0.7,
                        evidence="Mobile component type",
                    )
                )
            if "infra" in comp_type or "devops" in comp_type:
                signals.append(
                    ActivationSignal(
                        source="context",
                        domain="container-security",
                        weight=0.6,
                        evidence="Infrastructure component type",
                    )
                )
                signals.append(
                    ActivationSignal(
                        source="context",
                        domain="kubernetes-security",
                        weight=0.5,
                        evidence="Infrastructure component type",
                    )
                )

        # Active security domains from brain
        active_domains = project_context.get("active_security_domains", [])
        for domain in active_domains:
            signals.append(
                ActivationSignal(
                    source="context",
                    domain=domain,
                    weight=0.8,
                    evidence=f"Previously activated domain: {domain}",
                )
            )

        # Deployment model
        deploy_model = project_context.get("deployment_model", "")
        if deploy_model in ("kubernetes", "k8s", "container"):
            signals.append(
                ActivationSignal(
                    source="context",
                    domain="kubernetes-security",
                    weight=0.7,
                    evidence=f"Deployment model: {deploy_model}",
                )
            )
            signals.append(
                ActivationSignal(
                    source="context",
                    domain="container-security",
                    weight=0.7,
                    evidence=f"Deployment model: {deploy_model}",
                )
            )
        elif deploy_model in ("serverless", "lambda", "cloudflare", "vercel"):
            signals.append(
                ActivationSignal(
                    source="context",
                    domain="cloud-security",
                    weight=0.7,
                    evidence=f"Deployment model: {deploy_model}",
                )
            )

        return signals

    def _extract_history_signals(self) -> list[ActivationSignal]:
        signals = []

        # Check past scan results for recurring findings
        scan_results = mem.get_scan_results(self.root)
        domain_finding_counts: dict[str, int] = {}

        for _scanner_name, data in scan_results.items():
            for finding in data.get("findings", []):
                if isinstance(finding, dict):
                    finding_type = finding.get("type", "")
                    # Map finding types to domains
                    domain = self._map_finding_to_domain(finding_type)
                    if domain:
                        domain_finding_counts[domain] = domain_finding_counts.get(domain, 0) + 1

        # If a domain had findings before, it's more likely to be relevant
        for domain, count in domain_finding_counts.items():
            if count >= 2:  # At least 2 historical findings
                signals.append(
                    ActivationSignal(
                        source="history",
                        domain=domain,
                        weight=min(0.3 + count * 0.1, 0.8),
                        evidence=f"{count} historical findings in {domain}",
                        metadata={"historical_count": count},
                    )
                )

        return signals

    def _map_finding_to_domain(self, finding_type: str) -> str | None:
        """Map finding type to security domain."""
        type_lower = finding_type.lower()

        mapping = {
            "sql_injection": "injection-sql",
            "nosql_injection": "injection-nosql",
            "command_injection": "injection-command",
            "ldap_injection": "injection-ldap",
            "xpath_injection": "injection-xpath",
            "template_injection": "injection-template",
            "xss": "xss-reflected",
            "xss_reflected": "xss-reflected",
            "xss_stored": "xss-stored",
            "xss_dom": "xss-dom",
            "csrf": "csrf",
            "cors": "cors",
            "ssrf": "ssrf",
            "path_traversal": "path-traversal",
            "deserialization": "deserialization",
            "xxe": "xxe",
            "jwt": "jwt-security",
            "auth": "authentication",
            "authz": "authorization",
            "session": "session-management",
            "secret": "secrets-management",
            "crypto": "cryptography",
            "tls": "tls-ssl",
            "supply_chain": "supply-chain",
            "dependency": "dependency-vulnerability",
            "container": "container-security",
            "kubernetes": "kubernetes-security",
            "cloud": "cloud-security",
            "runtime": "runtime-protection",
            "privacy": "privacy-gdpr",
            "business_logic": "business-logic",
            "api": "api-security",
            "audit": "audit-logging",
        }

        for key, domain in mapping.items():
            if key in type_lower:
                return domain
        return None

    def _get_file_content(self, file_path: str) -> str | None:
        """Get file content with caching."""
        if file_path in self._code_cache:
            return self._code_cache[file_path]

        full_path = self.root / file_path
        if not full_path.exists():
            return None

        try:
            content = full_path.read_text(encoding="utf-8", errors="ignore")
            # Cache only smaller files to avoid memory issues
            if len(content) < 100_000:
                self._code_cache[file_path] = content
            return content
        except Exception:
            return None


# ── Domain Scoring & Activation ──────────────────────────────────────────────


class DomainActivatorV2:
    """Main domain activation engine."""

    def __init__(
        self,
        root: Path,
        activation_threshold: float = 0.5,
        max_domains: int = 20,
        domain_loader=None,
    ):
        self.root = root
        self.activation_threshold = activation_threshold
        self.max_domains = max_domains
        self.extractor = SignalExtractor(root)
        # Callers that preloaded the taxonomy in the background (CLI/web scan)
        # inject it here so activation never blocks on a cold DomainLoader.
        self.domain_loader = domain_loader or DomainLoader(root)

    def activate_domains(
        self,
        file_infos: list[FileInfo],
        project_context: dict,
        forced_domains: list[str] = None,
    ) -> DomainActivationResult:
        """
        Activate security domains based on extracted signals.

        Args:
            file_infos: Scanned file information
            project_context: Project context from brain
            forced_domains: Domains to force-activate (e.g., from user config)

        Returns:
            DomainActivationResult with activated domains and scoring details
        """
        forced_domains = forced_domains or []

        # Extract all signals
        signals = self.extractor.extract_all_signals(file_infos, project_context)

        # Score each domain
        domain_scores: dict[str, float] = {}
        domain_evidence: dict[str, list[str]] = {}

        for signal in signals:
            domain = signal.domain
            domain_scores[domain] = domain_scores.get(domain, 0) + signal.weight
            if domain not in domain_evidence:
                domain_evidence[domain] = []
            domain_evidence[domain].append(signal.evidence)

        # Add forced domains with high score
        for domain in forced_domains:
            domain_scores[domain] = max(domain_scores.get(domain, 0), 1.0)
            if domain not in domain_evidence:
                domain_evidence[domain] = []
            domain_evidence[domain].append("Forced activation (user/config)")

        # Filter by threshold
        activated = [
            domain for domain, score in domain_scores.items() if score >= self.activation_threshold
        ]

        # Sort by score descending
        activated.sort(key=lambda d: domain_scores[d], reverse=True)

        # Limit to max_domains
        if len(activated) > self.max_domains:
            activated[self.max_domains :]
            activated = activated[: self.max_domains]
        else:
            pass

        # Get all known domains for reporting skipped
        all_known = set(domain_scores.keys())
        all_known.update(self.domain_loader.list_domains())
        skipped_domains = sorted(all_known - set(activated))

        _log.info(f"Activated {len(activated)} domains (threshold={self.activation_threshold})")
        for d in activated:
            _log.debug(f"  {d}: score={domain_scores[d]:.2f}, evidence={domain_evidence[d][:2]}")

        return DomainActivationResult(
            activated_domains=activated,
            signals=signals,
            domain_scores=domain_scores,
            skipped_domains=skipped_domains,
            activation_threshold=self.activation_threshold,
        )

    def get_activated_domain_objects(self, activated_domains: list[str]) -> dict[str, Domain]:
        """Load full Domain objects for activated domains."""
        domains = {}
        for domain_id in activated_domains:
            domain = self.domain_loader.get_domain(domain_id)
            if domain:
                domains[domain_id] = domain
            else:
                _log.warning(f"Activated domain not found in loader: {domain_id}")
        return domains

    def get_relevant_agents(self, activated_domains: list[str]) -> list[str]:
        """Map activated domains to relevant security agents."""
        # Domain -> agent mapping
        domain_agent_map = {
            "injection-sql": ["InjectionAgent", "BanditAgent", "SemgrepAgent"],
            "injection-nosql": ["InjectionAgent", "SemgrepAgent"],
            "injection-command": ["InjectionAgent", "BanditAgent"],
            "injection-ldap": ["InjectionAgent"],
            "injection-xpath": ["InjectionAgent"],
            "injection-template": ["InjectionAgent", "SemgrepAgent"],
            "xss-reflected": ["InjectionAgent", "SemgrepAgent", "BrowserTesterAgent"],
            "xss-stored": ["InjectionAgent", "BrowserTesterAgent"],
            "xss-dom": ["BrowserTesterAgent", "SemgrepAgent"],
            "authentication": [
                "AuthenticationAuditAgent",
                "JWTSecurityAgent",
                "SessionManagementAgent",
            ],
            "authorization": ["AuthZAgent", "BusinessLogicAgent"],
            "session-management": ["SessionManagementAgent", "JWTSecurityAgent"],
            "jwt-security": ["JWTSecurityAgent", "AuthenticationAuditAgent"],
            "secrets-management": ["SecretScanner", "SecretsGuard", "SecretsRuntimeAgent"],
            "cryptography": ["CryptoAgent", "BanditAgent"],
            "tls-ssl": ["CryptoAgent", "HeaderAuditAgent"],
            "ssrf": ["SSRFProtectionAgent", "NetworkAgent"],
            "path-traversal": ["InjectionAgent", "SemgrepAgent"],
            "deserialization": ["InjectionAgent", "BanditAgent", "SemgrepAgent"],
            "xxe": ["InjectionAgent", "SemgrepAgent"],
            "cors": ["CORSAuditor", "SecurityProber"],
            "csrf": ["SecurityProber", "SemgrepAgent"],
            "security-headers": ["HeaderAuditAgent", "SecurityConfigAgent"],
            "rate-limiting": ["RateLimitAuditor", "SecurityConfigAgent"],
            "supply-chain": ["SupplyChainAgent", "DependencyVulnerabilityAgent", "CVEMonitorAgent"],
            "dependency-vulnerability": [
                "DependencyVulnerabilityAgent",
                "CVEMonitorAgent",
                "OSVScannerAgent",
            ],
            "container-security": ["ContainerScannerAgent", "IaCScannerAgent"],
            "kubernetes-security": ["KubernetesAgent", "IaCScannerAgent"],
            "cloud-security": ["IaCScannerAgent", "ConfigAuditAgent"],
            "runtime-protection": ["FalcoRuntimeAgent", "RuntimeValidatorAgent"],
            "privacy-gdpr": ["PrivacyAgent", "SensitiveDataAgent"],
            "business-logic": ["BusinessLogicAgent"],
            "api-security": ["SecurityProber", "APIContractAgent"],
            "audit-logging": ["HistoryAgent", "GovernanceAgent"],
        }

        agents = set()
        for domain in activated_domains:
            agents.update(domain_agent_map.get(domain, []))

        # Always include core agents
        core_agents = ["RedTeamAgent", "PreCheckAgent", "PlanAuditorAgent"]
        agents.update(core_agents)

        return sorted(agents)


# ── Convenience Function ─────────────────────────────────────────────────────


def activate_security_domains(
    root: Path,
    file_infos: list[FileInfo],
    project_context: dict,
    config: dict,
) -> DomainActivationResult:
    """Convenience function for domain activation."""
    # Get activation threshold from config
    threshold = config.get("security", {}).get("domain_activation_threshold", 0.5)
    max_domains = config.get("security", {}).get("max_active_domains", 20)
    forced = config.get("security", {}).get("forced_domains", [])

    activator = DomainActivatorV2(root, threshold, max_domains)
    return activator.activate_domains(file_infos, project_context, forced)
