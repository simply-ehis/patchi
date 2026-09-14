# Heuristic & Regex Annihilation Audit (Part 7)

PURPOSE: every regex/keyword heuristic in scope classified KILL / KEEP / KEEP-AND-HARDEN, with fixes applied or justification recorded.
OWNS: Part 7 annihilation pass.
READ-WHEN: touching any scanner verdict, severity, or pattern table.
KEY-FILES: patchi/core/security/secret_evidence.py (shared gates), evals/, tests/test_*_verdicts.py.
INVARIANTS: keyword-only evidence never exceeds MEDIUM without corroboration; placeholders/fixtures never verdict; absence never proves above MEDIUM.
GOTCHAS: Severity is a StrEnum — min()/max() compare alphabetically, caps must be explicit.
UPDATED: 2026-09-12 — initial pass complete, zero open items.

Rule (§0): a heuristic dies unless compulsory. Compulsory ones get (1) a comment
saying why, (2) measurement, (3) never the sole source of a final verdict.

## Fixed (KILL → structural rule or demotion)

### Secrets cluster — shared gates + tiered verdicts
| Site | Was | Now | Measured by |
|---|---|---|---|
| env_scanner SECRET_PATTERNS (generic 40-char, `pwd="x"`, `api_key=`…) | any match → CRITICAL, IGNORECASE | tiered table: structural→CRITICAL / keyword→HIGH, values gated on shared Shannon+placeholder+fixture checks; AKIA case-sensitive; ssh-rsa → INFO; PEM needs body | tests/test_scanners.py (TestEnvScanner), tests/test_secret_evidence.py |
| env_scanner `_has_high_entropy` (diversity ratio) | `hello-world123` passes | real Shannon ≥3.5 via shared helper | same |
| secrets_runtime dup patterns (95/102/107 re-fire 64/59/69) | double/triple CRITICAL per line | deduped canonical table | tests/test_new_security_agents.py |
| secrets_runtime `password="…"` / `secret=` / `token=` → CRITICAL | name+any value | value gate; max HIGH | same |
| secrets_runtime SECRETS-02 env heuristic | secret-ish word on line → MEDIUM | resolved env NAME must be secret-like | code review (no prior test) |
| secrets_runtime SECRETS-03 absence → HIGH | file-local absence | MEDIUM + verify language | code review |
| secrets_runtime SECRETS-05 co-occurrence | coredump word + "secret" word → HIGH | requires gated secret verdict in file | code review |
| secrets_runtime semgrep rule-name substring | "key" in rule name → HIGH | semgrep's own severity mapped | code review |
| sensitive_data keyword→CRITICAL (`pwd="1234"`, `az`+keyword) | name+short value | value gate; keyword tier max HIGH; AKIA case-sensitive; `az` needs separator | tests/test_sensitive_verdicts.py |
| sensitive_data SSN/CC shapes | any match → HIGH | SSA area rules + Luhn + example-domain + fixture exclusion | same |
| sensitive_data URI userinfo double-counted as email | 2 findings | email skips URI lines | same |
| auth_audit session secret / client secret → CRITICAL | name+4/8 chars | value gate; max HIGH | tests/test_auth_verdicts.py |
| auth_audit rate-limit absence → HIGH | file-local absence | MEDIUM + verify | same |
| auth_audit md5 mention → HIGH | substring | call-context rule (HIGH w/ password context, else demoted) | same |
| auth_audit bcrypt-without-salt rule | normal bcrypt usage flagged | deleted (bcrypt manages its own salt) | same |
| crypto weak-hash/encryption bare tokens → HIGH | substring anywhere | call-context rule + demote ladder | tests/test_crypto_verdicts.py |
| crypto hardcoded keys length-only | hex blob length | shared secret gate | same |
| crypto salt absence (single line) → HIGH | line-local absence | MEDIUM + verify; bcrypt rule deleted | same |
| crypto Math.random → HIGH | call presence | HIGH only with secret sink on line, else MEDIUM | same |
| crypto key-size bare numbers | `1024` anywhere | keygen context required, else skip | same |

### Auth/session/contract/claim meaning-guesses
| Site | Was | Now | Measured by |
|---|---|---|---|
| session `token=get_token()` → HIGH session_in_url | assignment shape | URL/query sink required on line | tests/test_new_agents.py (+2 new) |
| session setItem(any) → CRITICAL | no receiver check | localStorage/sessionStorage receiver required for CRITICAL, else MEDIUM | same |
| session cookie flags file-absence → MEDIUM-as-fact | "not set" stated | "not visible in this file — verify" | existing tests |
| websocket ws:// localhost/test | HIGH everywhere | loopback/test skipped | tests/test_websocket_verdicts.py |
| websocket no-auth absence → CRITICAL | 150-char window | HIGH + verify | same |
| websocket handler no-validate → HIGH | "check" suppresses absurdly broad | sink-corroborated HIGH else MEDIUM | same |
| contract `_ROUTE_TO_FLOW` names w/o corroboration | foreign /dashboard inherits ours | table names require file hits; else generic + low | tests/test_contract.py (+3 new) |
| contract `critical=True` default | every guessed flow critical | derived (mutating method / sensitive prefix / entry surface) | same |
| contract dead `INFERENCE_RULES` table | shadowing duplicate | deleted | ruff + suite |
| doc_validator `verified = hits>=1` | one token = proof | route/command/symbol-corroboration rules + reasons | tests/test_doc_claim_agent.py |
| doc_claim_agent fallback/file_match single hit | one weak hit = verified | strong-or-two-weak rule + strength labels | same (+2 new) |
| brain `_infer_purpose` filename-first | stopgap as fact | manifest identity → parsed structure → marked filename-last-resort | spot checks |
| brain `_infer_project_purpose` guess-off-guess | keyword over purposes | manifest-dep classification; filename guesses excluded; explicit unclear | unit checks + Discord spot check (§acceptance) |

### Mechanical (wrong, not philosophical)
| Site | Fix |
|---|---|
| rust_unwrap `\\.expect` triple-escape (never matches) | fixed escape |
| red_team `yaml.load` fires on SafeLoader | negative lookahead |
| mobile AES alternation reports CBC as ECB/HIGH | split ECB/HIGH vs CBC/INFO |
| mobile autoVerify=true flagged MEDIUM | inverted to INFO positive + missing-verify check |
| network `TLSv1` substring matches TLSv1.2 | anchored to 1.0 (`(?![\d._])`); AES-128 dropped (not weak) |
| network http check duplicated without localhost exclusion | deduped to the smarter check |
| authz PHP char-offset window (`content[i-10:i+10]`) | real line window |
| business_logic char-offset window + 1KB truncation verdicts | real line window + full-file scan |
| authz `min()` on StrEnum severities (no-op cap) | explicit cap (caught by own review) |
| cloud_waf inverted geo logic (found ⇒ "missing") | present ⇒ INFO positive |
| cloud_waf per-file DaemonSet/weakness findings | project-once verdicts |
| cloud_waf test payloads → MEDIUM verdicts | INFO inventory |
| cloud `p scan --dast` imported deleted module | (Part 3, rewired to DASTAgent) |
| framework `flask` substring (`deflasker`) | line-anchored package-name match |
| falco per-file DaemonSet absence | project-wide presence check |
| falco `is_k8s` filename-only gate | manifest-content corroboration |
| falco rule-quality keyword absence | `- rule:` block-scoped matching |
| falco missing-rules HIGH | MEDIUM advisory |
| iac NetworkPolicy per-file scope | project-wide manifest check |
| container ENV `KEY=xxx` → CRITICAL | shared gate + `$VAR` indirection skip |
| ui submit/empty-button tag-only verdicts | label/aria/svg association checks |
| ui `props` arg name → MEDIUM | INFO locator |
| llm broken `.*llm\|response\|result` alternation | both-sides-related rewrite |
| llm hub-load HIGH, agency CRITICAL, shell/input unproven | MEDIUM+HIGH splits with corroboration |
| mobile Random() without SecureRandom context | same-file CSPRNG check |
| mobile Bearer-in-URL CRITICAL (brittle regex) | HIGH |
| mobile token-binding/import-name MEDIUMs | LOW + verify |
| prechecks project-count → CRITICAL file="" | per-occurrence file:line HIGH |

## KEEP (locator/inventory, no verdict — reviewed, no change needed)
comment_scanner extraction · test_scanner discovery · side_file_scanner env parsing ·
route_graph_scanner · dependency_scanner/dependency_vulnerability extractors (INFO, OSV verdicts) ·
framework routing hints · route_detector/javascript fallback (absence→None, exemplary) ·
brain RAG tokenizer · contract JSON-extraction fallback · doc_validator claim patterns (finder) ·
ui component/link/template inventory · saml metadata literals (WantAssertionsSigned/SHA-1) ·
iac/docker exact directives · container exact directives · compliance INFO inventory ·
privacy retention INFO · red_team exact dangerous calls/configs · mobile exact manifest flags ·
falco escape IOCs · intent_analyzer AST gaps · domain_activator counts/presence ·
network enforcement-gated redirect check · auth OAuth redirect (hedged MEDIUM) ·
session fixation shape/timeout/logout (hedged) · auth session LOW locators.

## KEEP-AND-HARDEN (compulsory + measured + never sole verdict)
| Site | Why compulsory | Hardening | Measured by |
|---|---|---|---|
| secret_evidence.py gates | no structural proof an opaque string is a key | shared thresholds, placeholders, fixtures | tests/test_secret_evidence.py |
| ConfidenceGate thresholds | cannot AI-verify every finding | eval set 16/16, sabotage-negative | `p eval`, tests/test_eval.py |
| Prefixed tokens (AKIA/ghp/AIza/PEM/URIs) | the token shape IS the structure | case/boundary/body/placeholder hardening | verdict test files |
| PII shapes (SSN/CC/email) | no AST proves an SSN | area rules, Luhn, example exclusion | tests/test_sensitive_verdicts.py |
| ws:// scheme literal | cleartext by scheme | loopback/test exclusion | tests/test_websocket_verdicts.py |
| Exact insecure-config literals (usesCleartextTraffic, privileged:true, default allow, WantAssertionsSigned=false) | the literal IS the misconfiguration | scoping (manifest/project) | agent tests |
| Exact dangerous calls (eval/exec/pickle, DEBUG=True) | call presence IS the vuln shape | SafeLoader/call-context exclusions | tests/test_heuristic_verdicts.py, test_llm_verdicts.py |
| Rust unwrap/clippy output parse | linter fallback | message-format note in code | existing tests |

## Acceptance (§7 in spec numbering: audit table, 32-vs-74, Discord spot check)
- Audit table: this document (zero open rows above).
- 32-vs-74 re-check (measured 2026-09-12 on Patchi's own tree):
  EnvScanner 4 findings (0 critical, 2 high, 3 info-public-key-inventory),
  SensitiveDataAgent 16 (0 critical, 4 high, 9 medium, 3 low).
  The 5704-noise source class (DuplicateScanner) is deleted; the
  secret-keyword→CRITICAL class behind the 29-medium bulk is now gated
  (placeholder/Shannon/fixture/base64-decode/no-space/metachar rules).
  Remaining HIGHs are key-shaped strings in scanner test scripts (accepted
  borderline, documented here). Ground-truth 74 still pending from reporter
  (evals/pending/32-vs-74.md) — but the mechanism that produced the gap is
  closed and measured.
- Discord-bot spot check: synthetic discord.py project classifies
  ["Discord bot"] from manifest deps with no AI (tests/test_project_purpose.py);
  dep-less projects report explicit unclear instead of guessing.
