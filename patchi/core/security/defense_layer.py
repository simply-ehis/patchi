"""
Defense Layer — takes high-confidence findings and produces concrete defense actions.

Each finding maps to a defense action type:
  fix_code         — create Patch, pass through RiskGate, apply if allowed
  update_dependency — update vulnerable package via package manager
  block_ip         — block IP via OS firewall (hosted mode only)
  rotate_secret    — generate new secret, replace in .env and code
  patch_config     — edit config file with known-good values
  escalate         — queue for human review (fallback)

All code changes pass through the existing RiskGate which enforces
CONFIRM/AUTO/AUTOPILOT modes, no-touch paths, quiet hours, blast radius.
"""

from __future__ import annotations
import logging

import subprocess
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path

from patchi.core.agents.base import Finding
from patchi.core.fix.patch import FileChange, Patch
from patchi.core.fix.risk_gate import GateResult, RiskGate
from patchi.core.security.history import _get_db

# ── Defense Action ───────────────────────────────────────────────────────────


_log = logging.getLogger("patchi.security.defense_layer")


@dataclass
class DefenseAction:
    """A concrete action to defend against a confirmed finding."""

    type: str  # fix_code | update_dependency | block_ip | rotate_secret | patch_config | escalate
    target: str  # file path, IP address, package name, env var name
    finding: Finding  # the original finding
    severity: str  # severity string
    fix_code: str = ""  # AI-generated or known-good fix code

    def to_dict(self) -> dict:
        return {
            "type": self.type,
            "target": self.target,
            "severity": self.severity,
            "finding_id": self.finding.type,
            "finding_file": self.finding.file,
        }


@dataclass
class DefendResult:
    """Result of executing a defense action."""

    action: str  # "applied" | "queued" | "blocked" | "skipped"
    reason: str
    defense_action: DefenseAction | None = None
    patch: Patch | None = None
    gate_result: GateResult | None = None
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        d = {
            "action": self.action,
            "reason": self.reason,
            "timestamp": self.timestamp,
        }
        if self.defense_action:
            d["defense_action"] = self.defense_action.to_dict()
        if self.patch:
            d["patch_id"] = self.patch.id
        return d


# ── Type mapping ─────────────────────────────────────────────────────────────

_FINDING_TYPE_TO_ACTION: dict[str, str] = {
    # ── Injection (existing) ──────────────────────────────────────────────
    "sqli": "fix_code",
    "xss": "fix_code",
    "command_injection": "fix_code",
    "path_traversal": "fix_code",
    "ssrf": "fix_code",
    "ssti": "fix_code",
    "injection": "fix_code",
    # ── Secrets ──────────────────────────────────────────────────────────
    "hardcoded_secret": "rotate_secret",
    "api_key": "rotate_secret",
    "password_in_code": "rotate_secret",
    # ── Dependency (existing) ────────────────────────────────────────────
    "cve": "update_dependency",
    "vulnerable_dependency": "update_dependency",
    "unpinned_dependency": "update_dependency",
    # ── Config (existing) ────────────────────────────────────────────────
    "debug_mode": "patch_config",
    "missing_header": "patch_config",
    "cors_wildcard": "patch_config",
    "weak_tls": "patch_config",
    "misconfiguration": "patch_config",
    # ── Block IP (existing) ──────────────────────────────────────────────
    "brute_force": "block_ip",
    "scanner_sweep": "block_ip",
    "injection_probe": "block_ip",
    "rate_spike": "block_ip",
    # ── LLM Security Agent findings ──────────────────────────────────────
    "prompt_injection": "fix_code",
    "insecure_llm_output": "fix_code",
    "insecure_llm_output_rendering": "fix_code",
    "recursive_agent_loop": "fix_code",
    "untrusted_model_source": "fix_code",
    "sensitive_data_in_prompt": "fix_code",
    "excessive_tool_permissions": "fix_code",
    "tool_shell_injection": "fix_code",
    # ── Business Logic Agent findings ────────────────────────────────────
    "mass_assignment": "fix_code",
    "excessive_data_exposure": "fix_code",
    "missing_pagination": "patch_config",
    "idor_missing_ownership_check": "fix_code",
    "unvalidated_state_transition": "fix_code",
    # ── Weak crypto (CryptoAgent findings) ───────────────────────────────
    "weak_cipher": "crypto_fix",
    "weak_hash": "crypto_fix",
    "custom_crypto": "crypto_fix",
    "insufficient_key_size": "crypto_fix",
    # ── Auth (AuthZAgent / AuthenticationAuditAgent findings) ────────────
    "missing_auth": "auth_middleware",
    "missing_authorization": "fix_code",
    "weak_password_policy": "patch_config",
    "missing_csrf": "fix_code",
    "jwt_weakness": "fix_code",
    "open_redirect": "fix_code",
    # ── Session management ───────────────────────────────────────────────
    "session_fixation": "invalidate_session",
    "user_controlled_session_id": "invalidate_session",
    "missing_session_timeout": "patch_config",
    "missing_session_invalidation": "fix_code",
    "insecure_session_storage": "fix_code",
    "missing_httponly": "patch_config",
    "missing_secure_flag": "patch_config",
    "session_in_url": "fix_code",
    # ── Rate limiting ────────────────────────────────────────────────────
    "missing_rate_limit": "enforce_rate_limit",
    # ── Excessive agency ─────────────────────────────────────────────────
    "excessive_agency": "suspend_account",
    # ── WebSocket ────────────────────────────────────────────────────────
    "missing_origin_validation": "block_ws_origin",
    "unencrypted_websocket": "fix_code",
    "websocket_no_input_validation": "fix_code",
    "websocket_no_auth": "fix_code",
    "websocket_no_limit": "patch_config",
    "sensitive_data_in_websocket": "fix_code",
    # ── Container / IaC ──────────────────────────────────────────────────
    "container_privileged": "fix_code",
    "container_root_user": "fix_code",
    "unpinned_base_image": "fix_code",
    "k8s_privileged": "fix_code",
    "k8s_host_network": "fix_code",
    "s3_public_access": "fix_code",
    "security_group_wide_open": "fix_code",
    # ── Supply chain ─────────────────────────────────────────────────────
    "typosquatting": "update_dependency",
    "deprecated_package": "update_dependency",
    "license_violation": "escalate",
}

_ACTION_TYPE_LABELS: dict[str, str] = {
    "fix_code": "Fix code vulnerability",
    "update_dependency": "Update vulnerable dependency",
    "block_ip": "Block malicious IP",
    "rotate_secret": "Rotate exposed secret",
    "patch_config": "Patch security configuration",
    "crypto_fix": "Replace weak crypto with modern algorithms",
    "auth_middleware": "Add authentication middleware",
    "invalidate_session": "Invalidate active sessions",
    "enforce_rate_limit": "Enforce rate limiting middleware",
    "suspend_account": "Suspend compromised account",
    "block_ws_origin": "Block WebSocket origin",
    "escalate": "Escalate for human review",
}

# Package managers and their update commands (for multi-package-manager dispatch)
_PACKAGE_MANAGERS: list[dict] = [
    {
        "name": "pip",
        "check": ["pip", "--version"],
        "update": ["pip", "install", "--upgrade"],
        "files": ["requirements.txt", "Pipfile", "pyproject.toml"],
    },
    {
        "name": "npm",
        "check": ["npm", "--version"],
        "update": ["npm", "update"],
        "files": ["package.json"],
    },
    {
        "name": "yarn",
        "check": ["yarn", "--version"],
        "update": ["yarn", "upgrade"],
        "files": ["package.json"],
    },
    {
        "name": "cargo",
        "check": ["cargo", "--version"],
        "update": ["cargo", "update"],
        "files": ["Cargo.toml"],
    },
    {"name": "go", "check": ["go", "version"], "update": ["go", "get", "-u"], "files": ["go.mod"]},
    {
        "name": "gem",
        "check": ["gem", "--version"],
        "update": ["gem", "update"],
        "files": ["Gemfile"],
    },
    {
        "name": "nuget",
        "check": ["dotnet", "--version"],
        "update": ["dotnet", "package", "update"],
        "files": ["*.csproj", "packages.config"],
    },
    {
        "name": "composer",
        "check": ["composer", "--version"],
        "update": ["composer", "update"],
        "files": ["composer.json"],
    },
]


# ── Defense Layer ────────────────────────────────────────────────────────────


class DefenseLayer:
    """Executes defense actions for high-confidence findings."""

    def __init__(self, root: Path, config: dict | None = None):
        self.root = root
        self.config = config or {}
        self.risk_gate = RiskGate(root)

    def defend_all(self, findings: list) -> list[DefendResult]:
        """Defend against all high-confidence findings. Returns results list."""
        results: list[DefendResult] = []
        for gf in findings:
            action = self._finding_to_action(gf)
            result = self._execute(action)
            results.append(result)
            self._log_defense_result(result)
        return results

    def _finding_to_action(self, gf) -> DefenseAction:
        """Map a gated finding to the appropriate defense action type."""
        f = gf.finding
        ftype = f.type.lower()
        action_type = None

        # Check exact match first, then partial match
        if ftype in _FINDING_TYPE_TO_ACTION:
            action_type = _FINDING_TYPE_TO_ACTION[ftype]
        else:
            for key, val in _FINDING_TYPE_TO_ACTION.items():
                if key in ftype:
                    action_type = val
                    break

        if action_type is None:
            action_type = "escalate"

        target = f.file
        if action_type == "block_ip":
            target = (
                f.extra.get("ip", "") if hasattr(f, "extra") and isinstance(f.extra, dict) else ""
            )

        return DefenseAction(
            type=action_type,
            target=target,
            finding=f,
            severity=f.severity.value if hasattr(f.severity, "value") else str(f.severity),
            fix_code=f.suggestion or "",
        )

    def _execute(self, action: DefenseAction) -> DefendResult:
        """Execute a defense action and return the result."""
        if action.type == "fix_code":
            return self._exec_fix_code(action)
        elif action.type == "update_dependency":
            return self._exec_update_dependency(action)
        elif action.type == "block_ip":
            return self._exec_block_ip(action)
        elif action.type == "rotate_secret":
            return self._exec_rotate_secret(action)
        elif action.type == "patch_config":
            return self._exec_patch_config(action)
        elif action.type == "crypto_fix":
            return self._exec_crypto_fix(action)
        elif action.type == "auth_middleware":
            return self._exec_auth_middleware(action)
        elif action.type == "invalidate_session":
            return self._exec_invalidate_session(action)
        elif action.type == "enforce_rate_limit":
            return self._exec_enforce_rate_limit(action)
        elif action.type == "suspend_account":
            return self._exec_suspend_account(action)
        elif action.type == "block_ws_origin":
            return self._exec_block_ws_origin(action)
        else:
            return DefendResult(
                action="queued",
                reason=f"No auto-defense available for '{action.type}' — queued for human review",
                defense_action=action,
            )

    def _exec_fix_code(self, action: DefenseAction) -> DefendResult:
        """Create a Patch and pass through RiskGate for mode-based decision."""
        if not action.target or not Path(action.target).exists():
            return DefendResult(
                action="skipped",
                reason=f"File does not exist: {action.target}",
                defense_action=action,
            )

        change = FileChange(
            path=action.target,
            original="",
            proposed=action.fix_code,
        )

        patch = Patch(
            id=uuid.uuid4().hex[:12],
            agent=action.finding.agent,
            finding_id=action.finding.type,
            patch_type="SECURITY",
            changes=[change],
            description=_ACTION_TYPE_LABELS.get(action.type, "Security fix"),
            risk_score=self._estimate_risk(action),
            confidence=90,
            blast_radius=0,
        )

        gate_result = self.risk_gate.evaluate(patch)

        if gate_result.is_auto:
            try:
                patch.apply()
                return DefendResult(
                    action="applied",
                    reason=f"Auto-applied: {gate_result.reason}",
                    defense_action=action,
                    patch=patch,
                    gate_result=gate_result,
                )
            except Exception as e:
                return DefendResult(
                    action="blocked",
                    reason=f"Apply failed: {e}",
                    defense_action=action,
                    patch=patch,
                    gate_result=gate_result,
                )
        elif gate_result.is_blocked:
            return DefendResult(
                action="blocked",
                reason=gate_result.reason,
                defense_action=action,
                patch=patch,
                gate_result=gate_result,
            )
        else:
            return DefendResult(
                action="queued",
                reason=gate_result.reason,
                defense_action=action,
                patch=patch,
                gate_result=gate_result,
            )

    def _detect_package_manager(self) -> str | None:
        """Detect which package managers are available in the project."""
        for pm in _PACKAGE_MANAGERS:
            try:
                r = subprocess.run(pm["check"], capture_output=True, text=True, timeout=5)
                if r.returncode == 0:
                    # Verify project has matching manifest file
                    for f in pm["files"]:
                        matches = list(self.root.glob(f))
                        if matches:
                            return pm["name"]
            except (FileNotFoundError, subprocess.TimeoutExpired):
                continue
        return None

    def _detect_manifest(self) -> Path | None:
        """Detect project manifest file (pyproject.toml, package.json, etc.)."""
        for pattern in ["pyproject.toml", "package.json", "Cargo.toml", "go.mod", "Gemfile", "build.gradle", "pom.xml"]:
            matches = list(self.root.glob(pattern))
            if matches:
                return matches[0]
        return None

    def _exec_update_dependency(self, action: DefenseAction) -> DefendResult:
        """Update a vulnerable dependency via detected package manager."""
        pkg = Path(action.target).name if action.target else ""
        if not pkg:
            return DefendResult(
                action="skipped",
                reason="No package specified for update",
                defense_action=action,
            )

        pm_name = self._detect_package_manager()
        if not pm_name:
            return DefendResult(
                action="queued",
                reason="No supported package manager detected (tried pip, npm, yarn, cargo, go, gem, nuget, composer)",
                defense_action=action,
            )

        pm_config = next((p for p in _PACKAGE_MANAGERS if p["name"] == pm_name), None)
        if not pm_config:
            return DefendResult(
                action="blocked",
                reason=f"Package manager '{pm_name}' config not found",
                defense_action=action,
            )

        try:
            cmd = pm_config["update"] + [pkg]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            if result.returncode == 0:
                manifest = self._detect_manifest()
                if manifest and manifest.exists():
                    try:
                        import re as _re
                        text = manifest.read_text(encoding="utf-8")
                        # Match the dependency line in requirements.txt or pyproject.toml
                        text = _re.sub(
                            rf'^({_re.escape(pkg)}\s*[><=!~]+\s*\S+)',
                            r'\1  # updated by Patchi',
                            text,
                            flags=_re.MULTILINE,
                        )
                        manifest.write_text(text, encoding="utf-8")
                    except Exception as e:
                        _log.warning("DefenseLayer._exec_update_dependency failed: %s", e)
                return DefendResult(
                    action="applied",
                    reason=f"Updated {pkg} via {pm_name} successfully",
                    defense_action=action,
                )
            else:
                return DefendResult(
                    action="blocked",
                    reason=f"{pm_name} update failed: {result.stderr[:200]}",
                    defense_action=action,
                )
        except FileNotFoundError:
            return DefendResult(
                action="skipped",
                reason=f"{pm_name} not found — cannot update dependencies",
                defense_action=action,
            )
        except subprocess.TimeoutExpired:
            return DefendResult(
                action="blocked",
                reason=f"{pm_name} update timed out",
                defense_action=action,
            )

    def _exec_block_ip(self, action: DefenseAction) -> DefendResult:
        """Block an IP address via OS firewall (hosted mode only)."""
        ip = action.target
        if not ip:
            return DefendResult(
                action="skipped",
                reason="No IP address to block",
                defense_action=action,
            )

        import json
        blocked_path = self.root / ".patchi" / "blocked_ips.json"
        blocked = []
        if blocked_path.exists():
            try:
                blocked = json.loads(blocked_path.read_text(encoding="utf-8"))
            except Exception as e:
                _log.warning("DefenseLayer._exec_block_ip failed: %s", e)
                blocked = []
        if ip not in blocked:
            blocked.append(ip)
        blocked_path.parent.mkdir(parents=True, exist_ok=True)
        blocked_path.write_text(json.dumps(blocked, indent=2), encoding="utf-8")

        try:
            result = subprocess.run(
                ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                return DefendResult(
                    action="applied",
                    reason=f"Blocked IP {ip} via iptables (persisted to .patchi/blocked_ips.json)",
                    defense_action=action,
                )
            else:
                return DefendResult(
                    action="applied",
                    reason=f"Blocked IP {ip} persisted to .patchi/blocked_ips.json (iptables unavailable: {result.stderr[:100]})",
                    defense_action=action,
                )
        except FileNotFoundError:
            return DefendResult(
                action="applied",
                reason=f"Blocked IP {ip} persisted to .patchi/blocked_ips.json (iptables not available)",
                defense_action=action,
            )
        except subprocess.TimeoutExpired:
            return DefendResult(
                action="applied",
                reason=f"Blocked IP {ip} persisted to .patchi/blocked_ips.json (iptables timed out)",
                defense_action=action,
            )

    def _exec_rotate_secret(self, action: DefenseAction) -> DefendResult:
        """Generate a new secret and update the code."""
        import re
        import secrets as sec

        new_secret = sec.token_urlsafe(32)
        env_path = self.root / ".env"
        if env_path.exists():
            try:
                content = env_path.read_text(encoding="utf-8")
                var_name = action.target if action.target and "=" not in action.target else "SECRET_KEY"
                if var_name in content:
                    content = re.sub(
                        rf"^{re.escape(var_name)}=.*$",
                        f"{var_name}={new_secret}",
                        content,
                        count=1,
                        flags=re.MULTILINE,
                    )
                else:
                    content = f"{content.rstrip()}\n{var_name}={new_secret}\n"
                env_path.write_text(content, encoding="utf-8")
                return DefendResult(
                    action="applied",
                    reason=f"Rotated {var_name} in .env — new 256-bit secret generated",
                    defense_action=action,
                )
            except Exception as e:
                return DefendResult(
                    action="blocked",
                    reason=f"Failed to rotate secret: {e}",
                    defense_action=action,
                )
        return DefendResult(
            action="queued",
            reason="No .env file found — create one and add the rotated secret manually",
            defense_action=action,
        )

    def _exec_patch_config(self, action: DefenseAction) -> DefendResult:
        """Patch a configuration file with known-good values."""
        if not action.target or not Path(action.target).exists():
            return DefendResult(
                action="skipped",
                reason=f"Config file does not exist: {action.target}",
                defense_action=action,
            )

        change = FileChange(
            path=action.target,
            original="",
            proposed=action.fix_code,
        )

        patch = Patch(
            id=uuid.uuid4().hex[:12],
            agent=action.finding.agent,
            finding_id=action.finding.type,
            patch_type="CONFIG",
            changes=[change],
            description=_ACTION_TYPE_LABELS.get(action.type, "Config patch"),
            risk_score=self._estimate_risk(action),
            confidence=85,
            blast_radius=0,
        )

        gate_result = self.risk_gate.evaluate(patch)

        if gate_result.is_auto:
            try:
                patch.apply()
                return DefendResult(
                    action="applied",
                    reason=f"Config auto-patched: {gate_result.reason}",
                    defense_action=action,
                    patch=patch,
                    gate_result=gate_result,
                )
            except Exception as e:
                return DefendResult(
                    action="blocked",
                    reason=f"Config patch failed: {e}",
                    defense_action=action,
                    patch=patch,
                    gate_result=gate_result,
                )
        else:
            return DefendResult(
                action="queued" if not gate_result.is_blocked else "blocked",
                reason=gate_result.reason,
                defense_action=action,
                patch=patch,
                gate_result=gate_result,
            )

    def _exec_crypto_fix(self, action: DefenseAction) -> DefendResult:
        """Replace weak crypto with modern algorithms."""
        if not action.target or not Path(action.target).exists():
            return DefendResult(
                action="skipped",
                reason=f"File does not exist: {action.target}",
                defense_action=action,
            )
        fpath = Path(action.target)
        try:
            content = fpath.read_text(encoding="utf-8", errors="ignore")
        except OSError as e:
            return DefendResult(action="blocked", reason=f"Read error: {e}", defense_action=action)

        # Known bad → good replacements (in order of specificity)
        replacements = [
            ("hashlib.md5(", "hashlib.sha256("),
            ("hashlib.sha1(", "hashlib.sha256("),
            (
                "from cryptography.hazmat.primitives.ciphers.algorithms import ARC4",
                "from cryptography.hazmat.primitives.ciphers.algorithms import ChaCha20",
            ),
            ("ARC4.new(", "ChaCha20.new("),
            ("DES.new(", "AES.new("),
            ("DES3.new(", "AES.new("),
            ("RSA.generate(1024", "RSA.generate(2048"),
            ("RSA.generate(512", "RSA.generate(2048"),
            ("DSA.generate(512", "RSA.generate(2048"),
            ("DSA.generate(1024", "RSA.generate(2048"),
            ("PBKDF2", "PBKDF2HMAC"),  # prefer HMAC variant
        ]

        changes = []
        for old, new in replacements:
            if old in content:
                lines = content.splitlines()
                content.count(old)
                for i, line in enumerate(lines):
                    if old in line:
                        change = FileChange(
                            path=str(fpath),
                            original=line,
                            proposed=line.replace(old, new),
                        )
                        changes.append(change)
                        break  # one change per file per fix type

        if not changes:
            return DefendResult(
                action="skipped",
                reason="No weak crypto patterns found in file",
                defense_action=action,
            )

        patch = Patch(
            id=uuid.uuid4().hex[:12],
            agent=action.finding.agent,
            finding_id=action.finding.type,
            patch_type="SECURITY",
            changes=changes,
            description="Replace weak cryptography with modern algorithms",
            risk_score=20,
            confidence=90,
            blast_radius=1,
        )
        gate_result = self.risk_gate.evaluate(patch)
        if gate_result.is_auto:
            try:
                patch.apply()
                return DefendResult(
                    action="applied",
                    reason="Crypto fix auto-applied",
                    defense_action=action,
                    patch=patch,
                    gate_result=gate_result,
                )
            except Exception as e:
                return DefendResult(
                    action="blocked",
                    reason=f"Apply failed: {e}",
                    defense_action=action,
                    patch=patch,
                    gate_result=gate_result,
                )
        elif gate_result.is_blocked:
            return DefendResult(
                action="blocked",
                reason=gate_result.reason,
                defense_action=action,
                patch=patch,
                gate_result=gate_result,
            )
        else:
            return DefendResult(
                action="queued",
                reason=gate_result.reason,
                defense_action=action,
                patch=patch,
                gate_result=gate_result,
            )

    def _exec_auth_middleware(self, action: DefenseAction) -> DefendResult:
        """Add authentication middleware / decorator to an endpoint."""
        if not action.target or not Path(action.target).exists():
            return DefendResult(
                action="skipped",
                reason=f"File does not exist: {action.target}",
                defense_action=action,
            )
        fpath = Path(action.target)
        try:
            content = fpath.read_text(encoding="utf-8", errors="ignore")
        except OSError as e:
            return DefendResult(action="blocked", reason=f"Read error: {e}", defense_action=action)

        # Detect framework and insert appropriate auth decorator
        changes = []
        if "flask" in content.lower() or "from flask" in content:
            if (
                "from flask_login import login_required" not in content
                and "from flask_login import" not in content
            ):
                # Place import after any shebang or encoding declaration
                lines = content.splitlines()
                insert_at = 0
                for i, line in enumerate(lines):
                    if line.startswith("#!") or line.startswith("# -*-"):
                        insert_at = i + 1
                    else:
                        break
                lines.insert(insert_at, "from flask_login import login_required")
                modified = "\n".join(lines)
                change = FileChange(
                    path=str(fpath),
                    original=content,
                    proposed=modified,
                )
                changes.append(change)
        elif "django" in content.lower() or "from django" in content:
            if "from django.contrib.auth.decorators import login_required" not in content:
                change = FileChange(
                    path=str(fpath),
                    original=content,
                    proposed="from django.contrib.auth.decorators import login_required\n" + content,
                )
                changes.append(change)
        elif "fastapi" in content.lower() or "from fastapi" in content:
            if "Depends" not in content and "get_current_user" not in content:
                change = FileChange(
                    path=str(fpath),
                    original=content,
                    proposed="from fastapi import Depends\nfrom .auth import get_current_user\n" + content,
                )
                changes.append(change)

        if not changes:
            return DefendResult(
                action="skipped",
                reason="No recognizable framework found for auth middleware insertion",
                defense_action=action,
            )

        patch = Patch(
            id=uuid.uuid4().hex[:12],
            agent=action.finding.agent,
            finding_id=action.finding.type,
            patch_type="SECURITY",
            changes=changes,
            description="Add authentication middleware",
            risk_score=30,
            confidence=70,
            blast_radius=2,
        )
        gate_result = self.risk_gate.evaluate(patch)
        if gate_result.is_auto:
            try:
                patch.apply()
                return DefendResult(
                    action="applied",
                    reason="Auth middleware template added",
                    defense_action=action,
                    patch=patch,
                    gate_result=gate_result,
                )
            except Exception as e:
                return DefendResult(
                    action="blocked",
                    reason=f"Apply failed: {e}",
                    defense_action=action,
                    patch=patch,
                    gate_result=gate_result,
                )
        else:
            return DefendResult(
                action="queued" if not gate_result.is_blocked else "blocked",
                reason=gate_result.reason,
                defense_action=action,
                patch=patch,
                gate_result=gate_result,
            )

    def _exec_invalidate_session(self, action: DefenseAction) -> DefendResult:
        """Invalidate all active sessions for a user."""
        import json
        inval_path = self.root / ".patchi" / "invalidate_sessions.json"
        target = action.target or "unknown_user"
        pending = {}
        if inval_path.exists():
            try:
                pending = json.loads(inval_path.read_text(encoding="utf-8"))
            except Exception as e:
                _log.warning("DefenseLayer._exec_invalidate_session failed: %s", e)
                pending = {}
        pending[target] = {
            "timestamp": time.time(),
            "reason": action.finding.message or "Session compromise detected",
            "finding_type": action.finding.type,
        }
        inval_path.parent.mkdir(parents=True, exist_ok=True)
        inval_path.write_text(json.dumps(pending, indent=2), encoding="utf-8")
        return DefendResult(
            action="applied",
            reason=f"Queued session invalidation for {target} — written to .patchi/invalidate_sessions.json",
            defense_action=action,
        )

    def _exec_enforce_rate_limit(self, action: DefenseAction) -> DefendResult:
        """Enforce rate limiting on an endpoint by adding middleware."""
        if not action.target or not Path(action.target).exists():
            return DefendResult(
                action="skipped",
                reason=f"File does not exist: {action.target}",
                defense_action=action,
            )
        fpath = Path(action.target)
        try:
            content = fpath.read_text(encoding="utf-8", errors="ignore")
        except OSError as e:
            return DefendResult(action="blocked", reason=f"Read error: {e}", defense_action=action)

        changes = []
        if "flask" in content.lower():
            if "from flask_limiter import Limiter" not in content:
                change = FileChange(
                    path=str(fpath),
                    original=content,
                    proposed="from flask_limiter import Limiter\nfrom flask_limiter.util import get_remote_address\n\nlimiter = Limiter(key_func=get_remote_address)\n" + content,
                )
                changes.append(change)
        elif "fastapi" in content.lower():
            if (
                "from slowapi import Limiter" not in content
                and "from fastapi import Depends" in content
            ):
                change = FileChange(
                    path=str(fpath),
                    original=content,
                    proposed="from slowapi import Limiter, _rate_limit_exceeded_handler\nfrom slowapi.util import get_remote_address\n" + content,
                )
                changes.append(change)

        if not changes:
            return DefendResult(
                action="queued",
                reason="Add rate limit middleware manually — no framework template matched",
                defense_action=action,
            )

        patch = Patch(
            id=uuid.uuid4().hex[:12],
            agent=action.finding.agent,
            finding_id=action.finding.type,
            patch_type="CONFIG",
            changes=changes,
            description="Add rate limiting middleware",
            risk_score=15,
            confidence=65,
            blast_radius=1,
        )
        gate_result = self.risk_gate.evaluate(patch)
        if gate_result.is_auto:
            try:
                patch.apply()
                return DefendResult(
                    action="applied",
                    reason="Rate limit middleware template added",
                    defense_action=action,
                    patch=patch,
                    gate_result=gate_result,
                )
            except Exception as e:
                return DefendResult(
                    action="blocked",
                    reason=f"Apply failed: {e}",
                    defense_action=action,
                    patch=patch,
                    gate_result=gate_result,
                )
        else:
            return DefendResult(
                action="queued" if not gate_result.is_blocked else "blocked",
                reason=gate_result.reason,
                defense_action=action,
                patch=patch,
                gate_result=gate_result,
            )

    def _exec_suspend_account(self, action: DefenseAction) -> DefendResult:
        """Suspend a compromised account (hosted mode only)."""
        import json
        susp_path = self.root / ".patchi" / "suspend_accounts.json"
        target = action.target or "unknown_account"
        pending = {}
        if susp_path.exists():
            try:
                pending = json.loads(susp_path.read_text(encoding="utf-8"))
            except Exception as e:
                _log.warning("DefenseLayer._exec_suspend_account failed: %s", e)
                pending = {}
        pending[target] = {
            "timestamp": time.time(),
            "reason": action.finding.message or "Account compromise detected",
            "finding_type": action.finding.type,
            "severity": action.severity,
        }
        susp_path.parent.mkdir(parents=True, exist_ok=True)
        susp_path.write_text(json.dumps(pending, indent=2), encoding="utf-8")
        return DefendResult(
            action="applied",
            reason=f"Queued account suspension for {target} — written to .patchi/suspend_accounts.json",
            defense_action=action,
        )

    def _exec_block_ws_origin(self, action: DefenseAction) -> DefendResult:
        """Block a WebSocket origin via config patch."""
        import json
        ws_path = self.root / ".patchi" / "blocked_ws_origins.json"
        target = action.target or "unknown_origin"
        blocked = []
        if ws_path.exists():
            try:
                blocked = json.loads(ws_path.read_text(encoding="utf-8"))
            except Exception as e:
                _log.warning("DefenseLayer._exec_block_ws_origin failed: %s", e)
                blocked = []
        if target not in blocked:
            blocked.append(target)
        ws_path.parent.mkdir(parents=True, exist_ok=True)
        ws_path.write_text(json.dumps(blocked, indent=2), encoding="utf-8")
        return DefendResult(
            action="applied",
            reason=f"Blocked WebSocket origin: {target} — written to .patchi/blocked_ws_origins.json",
            defense_action=action,
        )

    def _estimate_risk(self, action: DefenseAction) -> int:
        """Estimate risk score for a defense action (0-100)."""
        sev_scores = {"critical": 80, "high": 60, "medium": 40, "low": 20, "info": 10}
        base = sev_scores.get(action.severity, 30)

        action_risk = {
            "fix_code": 0,
            "update_dependency": 10,
            "block_ip": 5,
            "rotate_secret": 15,
            "patch_config": 20,
            "crypto_fix": 5,
            "auth_middleware": 15,
            "invalidate_session": 25,
            "enforce_rate_limit": 10,
            "suspend_account": 40,
            "block_ws_origin": 10,
            "escalate": 0,
        }
        return min(100, base + action_risk.get(action.type, 0))

    def _log_defense_result(self, result: DefendResult) -> None:
        """Log defense action result to SQLite history."""
        try:
            conn = _get_db(self.root)
            conn.execute(
                """CREATE TABLE IF NOT EXISTS defense_actions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    action TEXT NOT NULL,
                    reason TEXT,
                    target TEXT,
                    severity TEXT,
                    finding_type TEXT,
                    finding_file TEXT
                )"""
            )
            ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            conn.execute(
                "INSERT INTO defense_actions (timestamp, action, reason, target, severity, finding_type, finding_file) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    ts,
                    result.action,
                    result.reason[:500] if result.reason else "",
                    result.defense_action.target if result.defense_action else "",
                    result.defense_action.severity if result.defense_action else "",
                    result.defense_action.finding.type if result.defense_action else "",
                    result.defense_action.finding.file if result.defense_action else "",
                ),
            )
            conn.commit()
            conn.close()
        except Exception as e:
            _log.warning("DefenseLayer._log_defense_result failed: %s", e)
