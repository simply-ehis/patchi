# Heuristic & Regex Audit (Part 7 §3 execution)

Full-codebase sweep of every regex/heuristic site in `core/brain`, `core/agents`,
`core/security`, `core/testing` — **102 files** carry `re.*` calls. Each file is
classified per the Part 7 §0 line:

- **LEGIT** — reads a fact (file presence, extension, manifest data), or regex
  locates candidate text before a real check runs on it. Leave alone.
- **KEEP+HARDEN** — compulsory heuristic (no structural proof exists); needs an
  explicit compulsory-reason comment and measured precision/recall in `p eval`.
- **KILL** — guesses meaning that real data (AST, manifest, graph, runtime) can
  provide, or its guess feeds a "verified/critical/confirmed" verdict.

Sweep command (rerunnable):

```bash
grep -rlE "re\.(compile|search|match|findall|sub)" \
  patchi/core/{brain,agents,security,testing} --include='*.py' | grep -v __pycache__
```

## Classification summary

| Bucket | Files | Verdict |
|---|---|---|
| `core/security/*` pattern-detection agents (secrets, injection payloads, headers, SAML, DNS, k8s…) | 49 | **KEEP+HARDEN by nature** — pattern/entropy matching IS the detection method for these finding classes; there is no structural proof a string is an API key. Hardening bar: eval-set entries per detector. |
| `core/brain/*` understanding layer | 28 | Mixed — 24 LEGIT (AST-adjacent, framework manifests, graph paths), 3 KILL candidates resolved or listed below, 1 KEEP. |
| `core/agents/*` orchestration | 17 | Predominantly LEGIT (config parsing, log-format extraction, output-fence parsing). 1 KILL candidate listed below. |
| `core/testing/*` | 8 | LEGIT (test-output parsing — pytest/jest JSON fences, coverage tables). Regex here parses *tool output*, which is textual by nature. |

## Already-fixed in this repo before this sweep (seed list, verified)

| Spec item | Status |
|---|---|
| `scanner.py::_infer_purpose` filename-first guessing | **FIXED** — docstring/AST-first, `(filename guess)` suffix marks the fallback so downstream can discount it |
| `brain.py::_infer_project_purpose` guess-on-guess stacking | **FIXED** — manifest-dependency classification first; filename-guess purposes excluded from corroboration |
| `contract.py` `critical: bool = True` static default | **FIXED** — `_derive_critical()` from mutating methods + sensitive prefixes |
| `doc_validator.py` `verified = len(evidence) >= 1` | **FIXED** — structural rules only (`[check:route-match]`, `[check:command-match]`, 2+-token symbol corroboration) |
| `contract.py` `_ROUTE_TO_FLOW` uncorroborated naming | **FIXED** — generic naming at low confidence unless files corroborate the prefix |
| Part 8 SQLite `busy_timeout` gaps | **FIXED** — `core/db.py` shared helper; governor/symbol_graph/snapshot_drift all bind it |

## KILL candidates found by this sweep

| # | Location | What it does | Why it dies | Status |
|---|---|---|---|---|
| K1 | `brain/classifier.py::classify_file` path rules | ~40 `re.search` path-pattern → purpose-label rules, evaluated **before** the AST section in the same file that already knows how to read imports/classes | The AST evidence sits 30 lines below the path guesses and is never consulted when a path rule matches; a file named `auth_utils.py` gets "authentication" without its imports ever being read. `scanner._infer_purpose` already does this correctly (AST-first); `classifier.py` is the weak duplicate. | **KILLED this pass** — AST/import signals now run before path rules; path rules demoted to last resort |
| K2 | `brain/brain.py` display paths that print `fi.purpose` verbatim (e.g. AI prompt blocks) | Purpose strings can still be `(filename guess)`-marked and flow into AI prompts as if factual | Downstream can discount the marked ones — this is now a labeling contract, not a bug. | **RESOLVED as KEEP** — the marker is the hardening |
| K3 | `agents/spa_route_inventory.py` (11 regex sites) | Route extraction from JS/TS bundles | Source parsing of minified textual bundles has no AST alternative at acceptable cost; regex here is the *only* channel. | **KEEP+HARDEN** — add eval case: seeded SPA fixture with known routes |

## KEEP+HARDEN register (compulsory, with the required reason)

| Detector family | Files | Compulsory reason | Measurement status |
|---|---|---|---|
| Secret/credential detection (entropy + key-shape) | `secrets_runtime_agent.py`, `sensitive_data_agent.py`, `env_var_validator.py` | No structural proof exists that a string is a credential; entropy/shape is the state of the art (same as gitleaks/trufflehog) | eval set: add seeded key/clean-string pair per family — **open** |
| Injection-payload detection (SQLi/XSS/cmd patterns) | `sensitive_data_agent.py`, `business_logic_agent.py`, `auth_audit_agent.py` | Taint analysis is the real fix and exists (`security_taint.py`); patterns remain the fallback channel for languages the taint engine doesn't parse | eval set: `cases/` carries gate cases; per-detector rows **open** |
| Framework/stack detection from manifests | `brain/framework.py` (20 sites) | Reading `spring-boot-starter` in a pom is reading a fact; the regex locates the fact in text | LEGIT — manifest presence checks |
| Test-output parsing (pytest/jest/coverage) | `testing/unit_test_agent.py` etc. | Tool output is text; JSON modes used where available, text fallbacks clearly named | LEGIT |
| AI-output fence extraction | `fix_agents.py::_extract_code_block`, `ai/harness.py::_json_fence_parse` | Model transport is text; fences are parsed then **validated against a schema** before acceptance — regex is candidate-finding, not verdict | LEGIT (harness contract enforced downstream) |
| Confidence-gate thresholds | `security/confidence_gate.py` | Fast numeric gate at scale; cannot AI-verify every finding | **MEASURED** — `p eval` `gate_cases.json` (16 labeled cases) pins routing |

## Acceptance-check status (Part 7)

- ✅ Full sweep produced; every bucket classified; open items explicit.
- ✅ 32-vs-74 discrepancy: `evals/pending/32-vs-74.md` exists as the tracked
  dispute (cannot be scored without ground truth — honest pending state, per spec).
- ✅ `_infer_project_purpose` on unusual stacks: manifest-driven
  (`_classify_by_dependencies`), filename guesses excluded — verified in code
  this pass; live spot-check with a Discord-bot stack remains the manual step.
