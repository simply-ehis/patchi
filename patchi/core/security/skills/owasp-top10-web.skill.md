---
id: owasp-top10-web-v1
name: OWASP Top 10 Web Detection
version: 1.0.0
target_agents: [TaintAnalyzer, MisconfigurationAgent, ClickjackAgent, SQLiDetector, XSSDetector, SSRFDetector, CSRFDetector, OpenRedirectAgent, FileTraversalAgent, SessionManagementAgent]
cwe: [CWE-79, CWE-89, CWE-22, CWE-352, CWE-918, CWE-601, CWE-502, CWE-611, CWE-434, CWE-862]
owasp: [A01:2021, A02:2021, A03:2021, A04:2021, A05:2021, A06:2021, A07:2021, A08:2021]
confidence_boost: 0.1
---

# OWASP Top 10 Detection Patterns

## A01: Broken Access Control (CWE-862)
### Patterns
```
@requires_roles\(|@permission_required|is_authenticated|@login_required
```
**Check**: Present in middleware/auth decorators but missing from view function.
**Severity**: Critical when IDOR pattern detected: `/{id}/` endpoint without ownership check.

**Heuristic**: If route param `{id}` appears in URL pattern but function body lacks `user.id ==` or `owner_id ==` or `request.user ==` → confidence += 0.3

### IDOR Suspect
```regex
/api/(?:users|orders|documents|invoices)/(?:\d+|[a-f0-9]{24})/
```
→ Check if endpoint validates resource ownership. Cross-correlate with AuthSecurityAgent.

## A02: Cryptographic Failures (CWE-312)
### Weak Cipher Detection
```python
# Bad: (any of)
from cryptography.hazmat.primitives.ciphers.algorithms import ARC4

hashlib.md5()
hashlib.sha1()
DES.new(...)
```
→ **action: fix_code** → replace with ChaCha20 / SHA-256 / AES-256-GCM

### HTTP (not HTTPS) Endpoint
```
http://[^h]|http://localhost|://[^/]+:\d+/(?!.*https)
```
→ If in production code (non-localhost, non-loopback) → **action: patch_config**

## A03: Injection (CWE-79, CWE-89, CWE-22)
### XSS — Context-Aware Escaping
```javascript
// DANGEROUS — unescaped user input in HTML
element.innerHTML = userInput
document.write(userInput)
$el.html(userInput)
v-html="userInput"
```
**Fix**: `esc(userInput)` for HTML context, `encUrl()` for URL context, `encJs()` for JS string context.

### SQLi Taint Check
```python
# DANGEROUS — string formatting in query
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
# SAFE:
cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
```
→ **action: fix_code** — convert to parameterized query. Track taint from HTTP params to cursor.execute.

### Command Injection
```python
os.system(f"ping {hostname}")  # BAD
subprocess.run(f"rm {filename}", shell=True)  # BAD
```
→ **action: fix_code** — use shlex.quote() or subprocess with list args.

## A04: Security Misconfiguration
### Debug Enabled in Production
```
DEBUG\s*=\s*True|debug=True|FLASK_DEBUG=1|DJANGO_DEBUG=True
```
→ **action: patch_config** → set to False

### Default Credentials
```regex
admin:admin|root:toor|password:password|admin:password123
```
→ If in config or seed files → **action: escalate**

### CORS Wildcard
```
Access-Control-Allow-Origin:\s*\*
```
→ **action: patch_config** → restrict to specific origins

## A05: Vulnerable & Outdated Components
See `sca-audit.skill.md` for dependency scanning patterns.

## A06: Identification & Authentication Failures
### Weak Password Policy
```regex
min_length.*[0-5]|minimumLength.*[0-5]|MIN_PASSWORD_LENGTH.*[0-5]
```
→ **action: patch_config** → set min_length >= 8

### Session Fixation
```python
# BAD: no session regeneration on login
session["user_id"] = user.id
# GOOD:
session.regenerate()  # or rotate
session["user_id"] = user.id
```
→ **confidence**: 0.7 default, +0.2 if `session_key` or `sid` appears in URL params.

## A07: Integrity Failures
### Unsafe Deserialization
```python
pickle.loads(data)  # BAD
yaml.load(data)  # BAD (without Loader=SafeLoader)
```
→ **action: fix_code** → use safe alternatives (json, or SafeLoader)

## A08: Software & Data Integrity Failures
### Insecure Package Sources
```requirements.txt
--index-url http://  # not https
git+http://
```
→ **action: patch_config** → enforce HTTPS

## Remediation Templates

### SQLi → Parameterized Query
```python
# Before
cursor.execute(f"SELECT * FROM {table} WHERE id = {user_input}")
# After
cursor.execute(f"SELECT * FROM {table} WHERE id = ?", (user_input,))
```

### XSS → Safe Rendering
```javascript
// Before
element.innerHTML = userInput;
// After
element.textContent = userInput;
```
Or use `esc()` helper for HTML-safe interpolation.

## Multi-Agent Cross-Correlation
- `TaintAnalyzer` + `SQLiDetector` both flag same cursor.execute → confidence += 0.25
- `MisconfigurationAgent` + `ClickjackAgent` both on same route → confidence += 0.15
