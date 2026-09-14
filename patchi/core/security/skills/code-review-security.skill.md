---
id: code-review-security-v1
name: Secure Code Review Patterns
version: 1.0.0
target_agents: [TaintAnalyzer, SQLiDetector, XSSDetector, SSRFDetector, CSRFDetector, OpenRedirectAgent, FileTraversalAgent, RFPDetector, InsecureCryptoAgent, InsecureDeserializationAgent, HardcodedSecretAgent, InsecureComparisonAgent, WeakPasswordHasher, FastHTTPAgent, FastAPISecurityAgent, CMDInjectionDetector, LDAPInjectionDetector, NoSQLInjectionDetector, XPathInjectorAgent, SSTIDetector, HeaderInjectionAgent, PrototypePollutionAgent, ZipSlipDetector]
cwe: [CWE-20, CWE-79, CWE-89, CWE-22, CWE-78, CWE-94, CWE-95, CWE-200, CWE-287, CWE-502, CWE-611, CWE-918, CWE-601]
owasp: [A01:2021, A03:2021, A06:2021]
confidence_boost: 0.08
---

# Secure Code Review Detection Patterns

## Injection Variants (Generic)

### Unsafe eval / exec
```python
eval(user_input)  # CWE-95
exec(user_input)  # CWE-95
compile(user_input, ...)  # CWE-94
__import__(user_input)  # CWE-94
```
→ **confidence**: 0.9. **action: fix_code** — replace with safe alternative (ast.literal_eval, dict lookup).

### Template Injection
```python
# Python — any string formatting in template render
render_template_string("Hello " + user_input)   # CWE-94
Template(user_input).render()                   # CWE-94

# JavaScript
eval(`Hello ${userInput}`)                      # CWE-94
```
→ **action: fix_code** — pass variables as template context, never concatenate.

## Path Traversal (CWE-22)

### Unsafe File Operations
```python
open(f"/data/{filename}", "r").read()
shutil.copy(src, f"/uploads/{user_filename}")
```
**Check**: Does `filename` contain `..` or `/`?
**Fix**: 
```python
safe_filename = os.path.basename(filename)
full_path = os.path.normpath(os.path.join("/data", safe_filename))
if not full_path.startswith("/data/"):
    raise SecurityError("Path traversal detected")
```

## SSRF (CWE-918)

### Unsafe URL Fetching
```python
requests.get(url)  # if url is user-controlled
urllib.request.urlopen(url)  # if url is user-controlled
httpx.get(url)  # if url is user-controlled
```
**Heuristic**: Check if URL param resolves to private IP (10.x.x.x, 172.16-31.x.x, 192.168.x.x, 127.x.x.x).
→ **action: block_ip** or escalate.

## Open Redirect (CWE-601)

### Unsafe Redirect
```python
return redirect(request.args.get("next"))
return redirect(request.form["redirect"])
```
**Fix**: Validate against allowlist:
```python
ALLOWED_REDIRECTS = ["/dashboard", "/profile", "/settings"]
if target not in ALLOWED_REDIRECTS:
    target = "/"
return redirect(target)
```

## Weak Cryptography (CWE-326, CWE-327)

### Custom Crypto
```python
# Rolled own encryption
def encrypt(data):
    return "".join(chr(ord(c) ^ 0x42) for c in data)
```
→ **action: fix_code** — use established library (cryptography, PyNaCl).

### Weak Key Size
```python
RSA.generate(1024)  # < 2048
DSA.generate(512)  # < 1024
ecdsa.SigningKey.generate(curve=ecdsa.NIST256p)  # OK
```
→ **action: fix_code** — use minimum key sizes: RSA 2048, DSA 2048, ECDSA P-256.

## Unsafe Deserialization (CWE-502)

### Pickle / YAML / Marshal
```python
pickle.loads(data)
yaml.load(data)  # unsafe without Loader
marshal.loads(data)
shelve.open(filename)
```
→ **confidence**: 0.85 if data comes from user input.
→ **action: fix_code** — use json or yaml.safe_load().

## Log Injection (CWE-532, CWE-117)

### Unescaped Log Input
```python
logging.info(f"User {user_input} logged in")
```
→ If user_input contains newlines or CRLF → log forging possible.
**Fix**: 
```python
safe_input = user_input.replace("\n", "_").replace("\r", "_")
logging.info(f"User {safe_input} logged in")
```

## Comparison Timing Attacks

### Unsafe String Comparison
```python
if user_token == expected_token:        # timing leak
if user_input == stored_secret:         # timing leak
```
→ **action: fix_code**:
```python
import hmac
if hmac.compare_digest(user_token, expected_token):
```

## General Heuristics
- **Taint distance**: Track variable from `request.*` or `user_input` through transformations to dangerous sink. Shorter distance = higher confidence.
- **Input validation**: If no validation between source and sink → confidence += 0.15. `re.match`, `.isdigit()`, or type cast → confidence += 0.1.
- **Encoding**: If encoding/escaping applied between source and sink → confidence -= 0.2.

## Multi-Agent Cross-Correlation
- `TaintAnalyzer` flags taint path + any injection agent confirms → confidence += 0.2
- `InsecureCryptoAgent` + `HardcodedSecretAgent` on same function → confidence += 0.15
- `CMDinjectionDetector` + `TaintAnalyzer` both flag → confidence += 0.25
