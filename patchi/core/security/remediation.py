"""
Auto-Remediation Suggestions — maps finding types to actionable fix guidance.

Each finding type gets:
  - A short fix action (one-liner for the UI)
  - A playbook reference (if available)
  - Code-level fix patterns (for the chain explorer)
  - Severity-adjusted urgency (critical → immediate, info → optional)

This data feeds into:
  1. Chain explorer step cards (inline fix suggestion)
  2. Assurance chain claims (remediation field)
  3. CLI chain output (p chains --fix-hints)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path

_log = logging.getLogger("patchi.security.remediation")


@dataclass
class Remediation:
    """One fix suggestion for a finding type."""

    finding_type: str
    action: str
    code_pattern: str = ""
    playbook_id: str = ""
    reference_url: str = ""
    auto_fixable: bool = False
    risk_level: str = "low"  # low / medium / high (risk of the fix itself)
    lang_patterns: dict[str, str] | None = None  # lang -> code_pattern override

    def for_language(self, lang: str) -> str:
        """Get the code pattern for a specific language, falling back to default."""
        if self.lang_patterns and lang in self.lang_patterns:
            return self.lang_patterns[lang]
        return self.code_pattern


# ── Remediation Database ────────────────────────────────────────────────────

_REMEDIATIONS: dict[str, Remediation] = {
    # Secrets
    "hardcoded_secret": Remediation(
        finding_type="hardcoded_secret",
        action="Move secret to environment variable or secrets manager",
        code_pattern='Use os.environ.get("SECRET_KEY") instead of hardcoded string',
        playbook_id="secrets-runtime-management",
        auto_fixable=True,
    ),
    "weak_hash": Remediation(
        finding_type="weak_hash",
        action="Replace MD5/SHA1 with bcrypt, argon2, or SHA-256+",
        code_pattern="Use bcrypt.checkpw() or hashlib.sha256() instead",
        auto_fixable=True,
    ),
    "hardcoded_password": Remediation(
        finding_type="hardcoded_password",
        action="Remove hardcoded password, use environment variable or vault",
        code_pattern='Replace with os.environ.get("DB_PASSWORD")',
        playbook_id="secrets-runtime-management",
        auto_fixable=True,
    ),
    # Injection
    "sql_injection": Remediation(
        finding_type="sql_injection",
        action="Use parameterized queries or ORM instead of string formatting",
        code_pattern='cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))',
        playbook_id="data-layer",
        auto_fixable=True,
        lang_patterns={
            "go": 'db.QueryRow(ctx, "SELECT * FROM users WHERE id = $1", userID)',
            "java": 'PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id = ?"); ps.setInt(1, userId);',
            "rust": 'sqlx::query!("SELECT * FROM users WHERE id = $1", user_id).fetch_one(&pool)',
            "php": '$stmt = $pdo->prepare("SELECT * FROM users WHERE id = :id"); $stmt->execute(["id" => $userId]);',
            "ruby": "User.where(id: user_id).first  # ActiveRecord sanitizes automatically",
        },
    ),
    "command_injection": Remediation(
        finding_type="command_injection",
        action="Use subprocess.run with list args instead of shell=True",
        code_pattern='subprocess.run(["ls", path], check=False)',
        auto_fixable=True,
        lang_patterns={
            "go": 'exec.Command("ls", path).Output()  # avoid exec.Command("sh", "-c", ...)',
            "java": 'ProcessBuilder pb = new ProcessBuilder("ls", path); pb.start();',
            "rust": 'std::process::Command::new("ls").arg(path).output()',
            "php": '$output = shell_exec("ls " . escapeshellarg($path));',
            "ruby": 'Open3.capture3("ls", path)  # array form avoids shell interpretation',
        },
    ),
    "xss_reflected": Remediation(
        finding_type="xss_reflected",
        action="Escape user input before rendering, use template auto-escaping",
        code_pattern="Use {{ variable | e }} in Jinja2 templates",
        auto_fixable=False,
        lang_patterns={
            "go": "template.HTML(template.HTMLEscapeString(userInput))  // or use html/template auto-escaping",
            "java": '<%= request.getParameter("name") %>  // JSP auto-escapes; use OWASP Encoder for raw',
            "rust": "askama or tera templates auto-escape; avoid Markup::new()",
            "php": 'htmlspecialchars($input, ENT_QUOTES, "UTF-8")',
            "ruby": "ERB::Util.html_escape(user_input)  // or Rails auto-escaping",
        },
    ),
    "path_traversal": Remediation(
        finding_type="path_traversal",
        action="Validate and sanitize file paths, use pathlib.resolve()",
        code_pattern="Path(user_input).resolve().is_relative_to(base_dir)",
        auto_fixable=True,
        lang_patterns={
            "go": "filepath.Clean(path) + must be inside baseDir; check with strings.HasPrefix",
            "java": "Path resolved = Paths.get(baseDir, userInput).normalize(); if (!resolved.startsWith(baseDir)) throw;",
            "rust": "let resolved = std::fs::canonicalize(base_dir.join(&user_input))?; if !resolved.starts_with(&base_dir) { return Err(...); }",
            "php": 'realpath($baseDir . "/" . $userInput) must start with realpath($baseDir)',
            "ruby": "File.expand_path(user_input, base_dir).start_with?(base_dir)",
        },
    ),
    # Auth
    "missing_auth": Remediation(
        finding_type="missing_auth",
        action="Add authentication decorator or middleware to route",
        code_pattern="@require_auth or @login_required",
        playbook_id="auth-session",
        auto_fixable=False,
    ),
    "session_fixation": Remediation(
        finding_type="session_fixation",
        action="Regenerate session ID after login",
        code_pattern="request.session.regenerate() after successful auth",
        playbook_id="auth-session",
    ),
    "weak_password_policy": Remediation(
        finding_type="weak_password_policy",
        action="Enforce minimum length, complexity, and breach-check",
        code_pattern="Use password validation: minlength=12, complexity=True",
        playbook_id="auth-session",
    ),
    # Config
    "debug_enabled": Remediation(
        finding_type="debug_enabled",
        action="Disable debug mode in production, use environment-based config",
        code_pattern='DEBUG = os.environ.get("DEBUG", "false").lower() == "true"',
        auto_fixable=True,
    ),
    "cors_wildcard": Remediation(
        finding_type="cors_wildcard",
        action="Replace CORS wildcard with explicit allowed origins",
        code_pattern="Access-Control-Allow-Origin: https://yourdomain.com",
        playbook_id="cdn-cache-security",
        auto_fixable=True,
    ),
    "missing_security_header": Remediation(
        finding_type="missing_security_header",
        action="Add security headers (HSTS, CSP, X-Frame-Options)",
        code_pattern="Add middleware that sets security response headers",
        playbook_id="cdn-cache-security",
        auto_fixable=True,
    ),
    "missing_hsts": Remediation(
        finding_type="missing_hsts",
        action="Add Strict-Transport-Security header with long max-age",
        code_pattern="Strict-Transport-Security: max-age=31536000; includeSubDomains",
        playbook_id="cdn-cache-security",
    ),
    "missing_csp": Remediation(
        finding_type="missing_csp",
        action="Add Content-Security-Policy header restricting sources",
        code_pattern="Content-Security-Policy: default-src 'self'; script-src 'self'",
        playbook_id="cdn-cache-security",
    ),
    # Crypto
    "weak_crypto": Remediation(
        finding_type="weak_crypto",
        action="Replace deprecated cipher with AES-256-GCM or ChaCha20",
        code_pattern="Use cryptography.hazmat.primitives.ciphers.aead.AESGCM",
        playbook_id="secrets-runtime-management",
        lang_patterns={
            "go": "crypto/aes + crypto/cipher.NewGCM()  // AES-256-GCM",
            "java": 'javax.crypto.Cipher.getInstance("AES/GCM/NoPadding")',
            "rust": "aes_gcm::Aes256Gcm::new(key)  // use aes-gcm crate",
            "php": 'openssl_encrypt($data, "aes-256-gcm", $key, 0, $iv, $tag)',
            "ruby": 'AES-256-GCM via OpenSSL::Cipher.new("aes-256-gcm")',
        },
    ),
    "insecure_random": Remediation(
        finding_type="insecure_random",
        action="Replace random module with secrets for security-sensitive values",
        code_pattern="Use secrets.token_hex(32) instead of random.random()",
        auto_fixable=True,
        lang_patterns={
            "go": "crypto/rand.Read(buf)  // never math/rand for security",
            "java": "java.security.SecureRandom.getInstanceStrong().nextBytes(buf)",
            "rust": "use rand::rngs::OsRng; rand::RngCore::fill_bytes(&mut OsRng, &mut buf)",
            "php": "random_bytes(32)  // never mt_rand or rand()",
            "ruby": "SecureRandom.hex(32)  // never rand() for security",
        },
    ),
    # SSRF / Network
    "ssrf": Remediation(
        finding_type="ssrf",
        action="Validate and allowlist target URLs before making requests",
        code_pattern="Check URL against allowlist before urllib.request.urlopen()",
    ),
    "open_redirect": Remediation(
        finding_type="open_redirect",
        action="Validate redirect target is internal or on allowlist",
        code_pattern="if redirect_url.startswith('/'): return redirect(redirect_url)",
    ),
    # Business logic
    "idor": Remediation(
        finding_type="idor",
        action="Verify requesting user owns the resource (authorization check)",
        code_pattern="if resource.owner_id != current_user.id: abort(403)",
        playbook_id="auth-session",
    ),
    "race_condition": Remediation(
        finding_type="race_condition",
        action="Use database-level locking or atomic operations",
        code_pattern="Use SELECT FOR UPDATE or atomic increment",
    ),
}


# ── Finding Type → Remediation Lookup ───────────────────────────────────────


def _normalize_type(finding_type: str) -> str:
    """Normalize a finding type to a known remediation key."""
    ft = finding_type.lower().strip()
    # Direct match
    if ft in _REMEDIATIONS:
        return ft
    # Substring match
    for key in _REMEDIATIONS:
        if key in ft or ft in key:
            return key
    # Fuzzy: extract core concept
    mappings = {
        "secret": "hardcoded_secret",
        "credential": "hardcoded_secret",
        "password": "hardcoded_password",
        "hash": "weak_hash",
        "sql": "sql_injection",
        "inject": "command_injection",
        "xss": "xss_reflected",
        "traversal": "path_traversal",
        "auth": "missing_auth",
        "session": "session_fixation",
        "debug": "debug_enabled",
        "cors": "cors_wildcard",
        "header": "missing_security_header",
        "hsts": "missing_hsts",
        "csp": "missing_csp",
        "crypto": "weak_crypto",
        "random": "insecure_random",
        "ssrf": "ssrf",
        "redirect": "open_redirect",
        "idor": "idor",
        "race": "race_condition",
    }
    for keyword, mapped in mappings.items():
        if keyword in ft:
            return mapped
    return ft


def get_remediation(finding_type: str) -> Remediation | None:
    """Look up remediation suggestion for a finding type."""
    key = _normalize_type(finding_type)
    return _REMEDIATIONS.get(key)


def get_remediation_confidence(finding_type: str, root: Path | None = None) -> float:
    """Return confidence 0.0-1.0 that this remediation will fix the issue.

    Factors:
      - Historical fix acceptance rate (from attack_feedback learning)
      - Whether the fix is auto_fixable (higher base confidence)
      - Whether we have a language-specific pattern (more precise)
      - Risk level of the fix itself (high risk = lower confidence)
    """
    rem = get_remediation(finding_type)
    if not rem:
        return 0.3  # unknown type = low confidence

    # Base confidence from fix properties
    base = 0.5
    if rem.auto_fixable:
        base += 0.15
    if rem.code_pattern:
        base += 0.05
    if rem.lang_patterns:
        base += 0.05
    risk_penalty = {"low": 0, "medium": 0.1, "high": 0.2}.get(rem.risk_level, 0)
    base -= risk_penalty

    # Historical acceptance rate (if root provided)
    if root:
        try:
            from patchi.core.security.attack_feedback import get_learning_summary

            summary = get_learning_summary(root)
            accepted = summary.get("accepted_fixes", {}).get(finding_type, 0)
            rejected = summary.get("rejected_fixes", {}).get(finding_type, 0)
            total = accepted + rejected
            if total >= 3:
                acceptance_rate = accepted / total
                # Blend: 60% base + 40% historical
                base = 0.6 * base + 0.4 * acceptance_rate
        except Exception as _exc:
            _log.warning('get_remediation_confidence failed: %s', _exc)

    return max(0.1, min(0.95, base))


def get_remediation_for_step(step: dict) -> dict | None:
    """Get remediation for a chain step (dict form from chain.to_dict())."""
    ftype = step.get("type", "")
    rem = get_remediation(ftype)
    if not rem:
        return None
    return {
        "action": rem.action,
        "code_pattern": rem.code_pattern,
        "playbook_id": rem.playbook_id,
        "auto_fixable": rem.auto_fixable,
        "risk_level": rem.risk_level,
    }


def get_remediation_for_chain(chain: dict) -> list[dict | None]:
    """Get remediation for each step in a chain."""
    steps = chain.get("steps", [])
    return [get_remediation_for_step(s) for s in steps]


def load_playbook_fix(playbook_id: str, control_id: str = "") -> str | None:
    """Load the fix strategy from a playbook YAML file."""
    if not playbook_id:
        return None
    pb_path = Path(__file__).parent / "fix-playbooks" / f"{playbook_id}.playbook.yaml"
    if not pb_path.is_file():
        return None
    try:
        import yaml

        data = yaml.safe_load(pb_path.read_text(encoding="utf-8"))
        for pb in data.get("playbooks", []):
            if control_id and pb.get("control_id") != control_id:
                continue
            return pb.get("fix_strategy", "")
        return None
    except Exception as exc:
        _log.debug("Playbook load failed: %s", exc)
        return None
