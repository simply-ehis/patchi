---
id: secrets-scan-v1
name: Secrets & Credential Scanning
version: 1.0.0
target_agents: [SecretsGuard, SecretScanner, SensitiveDataAgent, EnvKeyAuditAgent]
cwe: [CWE-200, CWE-522, CWE-312, CWE-532, CWE-798]
owasp: [A05:2021, A07:2021, A08:2021]
confidence_boost: 0.15
---

# Secret Scanning Patterns

## High-Signal Regexes (confidence 0.9+)
Matches trigger immediate GatedFinding with tier=defend.

### AWS Keys
```
(?<![A-Za-z0-9/+=])AKIA[0-9A-Z]{16}(?![A-Za-z0-9/+=])
```
→ `secret_type: aws_access_key`, `action: rotate_secret`

### GitHub Tokens
```
gh[pousr]_[A-Za-z0-9_]{36,251}
gh[pousr]_[A-Za-z0-9_]{36,251}(?!')
```
→ `secret_type: github_token`, `action: rotate_secret`

### Generic Private Keys
```
-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----
```
→ `secret_type: private_key`, `action: escalate`

### Slack Webhooks / Tokens
```
https://hooks\.slack\.com/services/T[A-Z0-9]{8,12}/B[A-Z0-9]{8,12}/[A-Za-z0-9]{24}
xox[baprs]-[0-9]{10,14}-[0-9]{10,14}-[A-Za-z0-9]{24}
```
→ `secret_type: slack_token`, `action: rotate_secret`

## Medium-Signal Patterns (confidence 0.6)
Matches trigger GatedFinding with tier=ai_analyze for confirmation.

### Password-Like Variables
```
(?:password|passwd|pwd|secret|token|apikey|api_key)\s*[:=]\s*['\"][^'\"]{6,}['\"]
```
Heuristic checks:
- Value looks random (entropy > 3.5 bits/char) → promote to HIGH
- Value is dictionary word → demote to LOW (likely test/default)
- Key contains `example` or `test` → discard

### JDBC / MongoDB Connection Strings
```
jdbc:(?:mysql|postgresql|sqlserver|oracle)://[^:]+:\d+/[^?\s]+
mongodb(?:\+srv)?://[^:]+:[^@]+@
```
Add `action: rotate_secret` if URI contains credentials (user:pass before @).

### .env / Config File Exposure
File-level check: any `.env` file with world-readable permissions.
→ `action: patch_config` (chmod 600)

## Remediation Templates

### Rotate secret (code fix)
```python
# Old: hardcoded_secret = "AKIA..."
# New: hardcoded_secret = os.environ["AWS_ACCESS_KEY_ID"]
```
Context: Replace string literal with env-var reference; log old value prefix for audit.

### Rotate secret (config fix)
```yaml
# Old: db_password: "super-secret-123"
# New: db_password: ${DB_PASSWORD}
```
Context: Move to secrets manager/env vars; never commit.

## Multi-Agent Cross-Correlation
If `SecretScanner` + `EnvKeyAuditAgent` both flag same file → confidence += 0.2
If `SensitiveDataAgent` also flags it → confidence += 0.15
