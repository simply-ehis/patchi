"""Functional smoke for the regex-free SecretScanner detection core."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from patchi.core.security.security_taint import (
    SecretScanner,
    classify_secret,
    extract_py_string_candidates,
    extract_quoted_candidates,
)

scanner = SecretScanner.__new__(SecretScanner)  # classification helpers only

CASES = [
    # (name, value, expect_verdict_or_None, min_severity)
    ("api_key", "AKIAIOSFODNN7EXAMPLE", "provider-prefix", "critical"),
    (
        "token",
        "sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "provider-prefix",
        "critical",
    ),
    ("slack", "xoxb-FAKE-TOKEN-REPLACED", "provider-prefix", "critical"),
    ("api_key", "wJalrXUtnFEMI-K7MDENGbPxRfiCYEXAMPLEKEY123", "credential-assignment", "critical"),
    ("db_password", "Tr0ub4dor&3CorrectHorse", "credential-assignment", "critical"),
    (
        "config_value",
        "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
        "high-entropy",
        "medium",
    ),
    ("password", "changeme", None, None),
    ("api_key", "<your-api-key-here>", None, None),
    ("note", "aaaaaaaaaaaaaaaaaaaa", None, None),  # repeated char = not a secret
    ("greeting", "hello world", None, None),
]

failures = 0
for name, value, want_verdict, want_sev in CASES:
    verdict, label, severity = classify_secret(name, value, scanner)
    got_sev = severity.value if verdict else None
    ok = verdict == want_verdict and (want_sev is None or got_sev == want_sev)
    status = "PASS" if ok else "FAIL"
    if not ok:
        failures += 1
    print(f"{status}  {name!r:14} -> {verdict}/{got_sev} (want {want_verdict}/{want_sev})")

# AST extraction: python assignments + dict + keyword
src = (
    "API_KEY = 'Zm9vYmFyYmF6cXV1eGZvbyAxMjM0NTY3ODk'\n"
    "cfg = {'client_secret': 'c2VjcmV0dmFsdWV3aXRoZW50cm9weTEyMzQ1Njc4'}\n"
    "connect(api_token='dG9rZW52YWx1ZXdpdGhlbnRyb3B5MTIzNDU2Nzg5MA==')\n"
)
names = {c.name for c in extract_py_string_candidates(src)}
assert {"API_KEY", "client_secret", "api_token"} <= names, f"AST names missing: {names}"
print("PASS  py AST extraction captures assign/dict-key/keyword names")

# Non-python quoted extraction with name guessing
js = "const config = { apiKey: 'Sm9kbmVzc2VjcmV0dmFsdWUxMjM0NTY3ODkw', timeout: 30 };\n"
cands = extract_quoted_candidates(js)
names2 = {c.name for c in cands}
assert any("apikey" in n.lower() or "key" in n.lower() for n in names2), f"name guess failed: {names2}"
print(f"PASS  quoted extractor guesses name from prefix ({names2})")

if failures:
    print(f"SMOKE FAILED: {failures} case(s)")
    sys.exit(1)
print("ALL SECRET SCANNER SMOKE CASES PASS")
