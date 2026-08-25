"""One-shot patcher: swap SecretScanner regex table for regex-free constants."""
from pathlib import Path

p = Path(__file__).resolve().parent.parent / "patchi" / "core" / "security" / "security_taint.py"
c = p.read_text(encoding="utf-8")

start = c.index("    # Fallback patterns when Gitleaks unavailable")
end = c.index("    _SKIP_FILES")
new_block = '''    # -- Regex-free fallback detection (AST + entropy + provider prefixes) --
    # Known token formats are matched as EXACT PREFIXES, not regex. Anything
    # without a known prefix must clear a Shannon-entropy + charset-mix bar,
    # and usually also sit in a credential-named assignment, to be flagged.

    _PROVIDER_PREFIXES: tuple[tuple[str, str], ...] = (
        ("AKIA", "aws_access_key"),
        ("sk-ant-", "anthropic_key"),
        ("sk-proj-", "openai_project_key"),
        ("ghp_", "github_pat"),
        ("gho_", "github_oauth"),
        ("ghs_", "github_app_secret"),
        ("ghr_", "github_refresh_token"),
        ("github_pat_", "github_fine_grained_pat"),
        ("xoxb-", "slack_bot_token"),
        ("xoxp-", "slack_user_token"),
        ("xoxa-", "slack_workspace_token"),
        ("xoxs-", "slack_session_token"),
        ("AIza", "google_api_key"),
        ("SG.", "sendgrid_key"),
        ("sk_live_", "stripe_live_key"),
        ("pk_live_", "stripe_publishable_live_key"),
        ("rk_live_", "stripe_restricted_live_key"),
        ("glpat-", "gitlab_pat"),
        ("dop_v1_", "digitalocean_pat"),
        ("shpat_", "shopify_pat"),
        ("npm_", "npm_token"),
        ("pypi-", "pypi_token"),
    )

    _CRED_NAME_TERMS: frozenset = frozenset({
        "api_key", "apikey", "secret", "token", "password", "passwd", "pwd",
        "credential", "private_key", "access_key", "auth_key", "client_secret",
        "signing_key", "encryption_key", "session_key", "webhook_secret",
    })

    _PLACEHOLDER_MARKERS: tuple[str, ...] = (
        "changeme", "change_me", "<your", "${", "{{", "%(", "os.environ",
        "getenv", "environ[", "environ.get", "example", "placeholder",
        "xxx", "...", "todo", "dummy", "sample_", "your-", "-here",
        "insert_", "redacted", "[masked]", "not_a_real", "fake_",
    )

    _TEXT_SUFFIXES = {
        ".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".rs", ".java", ".kt",
        ".rb", ".php", ".swift", ".dart", ".cs", ".c", ".cpp", ".h",
        ".yaml", ".yml", ".json", ".toml", ".ini", ".cfg", ".conf",
        ".properties", ".xml", ".envrc", ".sh", ".bash", ".ps1",
    }

'''

assert start != -1 and end != -1 and start < end, "anchor strings not found"
c = c[:start] + new_block + c[end:]
p.write_text(c, encoding="utf-8")
print("pattern table replaced OK")
