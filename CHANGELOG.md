# Changelog

All notable changes to Patchi will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.7.8] - 2026-09-11

### Fixed
- **secrets.py:259** — `scan_secrets` crash on Windows: Gitleaks returns empty stdout when leaks found (exit code 1), causing `json.loads()` to parse ANSI-laden stderr. Fixed to only parse `proc.stdout`, fall back to `"[]"` if empty.
- **secrets_runtime_agent.py:57** — `SecretsRuntimeAgent` crash: `HARDCODED_SECRET_PATTERNS` had mixed tuple formats — compiled regex passed to `re.finditer()` which expects string. Normalized all 15 patterns to `(compiled_re, severity, description)`.
- **misconfig_agent.py** — `MisconfigAgent` reported 0 files scanned: `result.files_scanned` was never set. Added counter.
- **api_contract_agent.py** — `APIContractAgent` silently skipped FastAPI/Flask/Django projects because it only looked for static OpenAPI files on disk. Added framework detection that scans entry points and route directories for framework imports and route decorators. Now reports synthetic contract info (framework name, route count).
- **api_contract_agent.py** — `rglob` through `node_modules` caused 60s+ hangs. Replaced with `os.walk` with directory exclusion for speed.
- **base.py:549** — `APIContractAgent` added to gate bypass list so it can run without requiring `p check` first.

## [0.7.5] - 2026-09-08

### Added
- **CLI UX module** (`patchi/cli/ux.py`) — spinners, progress bars, formatted tables, summary panels, confirmation prompts
- **Quick readiness check** (`p quick`) — runs 3 lightweight agents in seconds with UX feedback
- **Interactive fix review** (`p fix-review`) — accept/reject/skip per patch with inline diff view
- **Command families** (`p <family> commands`) — 24 families, discover commands by category
- **Shannon integration** — entropy analysis for obfuscation detection in pentest campaigns
- **External tool health checks** (`tool_health.py`) — validates nuclei, sqlmap, dalfox, ffuf, zap, codeql, shannon
- **Shared atomic module** (`patchi/core/atomic.py`) — used by memory.py, snapshot.py, applier.py
- **Release notes** for v0.7.5

### Fixed
- **risk_gate.py:199** — TypeError on missing attribute
- **risk_gate.py:332** — KeyError on missing key
- **queue.py:283** — TypeError on None comparison
- **memory.py:279** — AttributeError on missing attr
- **applier.py:189** — TypeError on None input
- **codeql_agent.py:233** — Exception on missing binary
- **health.py:142-152** — Division by zero
- **test_domain_loader.py:345** — Mock not patched correctly
- **test_generated_suite.py:132-141** — Flaky assertion
- **test_new_agents.py** — Missing gate mock for `require_ready`
- **test_differential.py** — Timing issue
- **test_domain_loader.py:460** — Missing fixture
- **test_test_agents.py** — Gate not mocked

### Changed
- **Dependency consolidation** — all runtime deps moved to main in pyproject.toml
- **Optional extras** — `dev` (pytest/ruff/mypy/vulture), `pentest` (shannon)
- **External tools documented** in `pyproject.toml` `tool.patchi.external_tools`
- **Version bumped to 0.7.5**

## [0.7.2] - 2026-09-02

### Added
- **BrainContext bridge** — connects all brain systems (enriched context, project reader, body tags, domain loader, reasoning) into a single injectable object for the detection pipeline and chat
- **Context-aware false-positive reduction** — test fixtures demoted for AI review, critical directory findings get confidence boost
- **Chat brain injection** — chat now receives project purpose, tech stack, critical dirs, risks, architectural layers, scan focus
- **800 security domains** with 2,955 playbooks from OWASP, CWE, NIST, SANS, and other frameworks
- **Domain enrichment** for findings — each finding now includes matching security domains, playbook references, and fix strategies
- **Inverted keyword index** for domain matching — 16x faster YAML parsing with CSafeLoader
- **Health endpoint** (`/health`) for load balancers and monitoring
- **Startup domain cache warm-up** — pre-loads domain YAMLs at server startup for faster first request
- **GitHub Actions CI workflow** with fast mode for PRs and full mode on main
- **Documentation** — USAGE.md, CLI.md, WEB.md, ARCHITECTURE.md, CONTRIBUTING.md

### Fixed
- **cost_alert crash** — `None` config values caused `float()` crash on every dashboard request
- **9 pre-existing ruff errors** — F821 (undefined `_log`), F841 (unused variable), E731 (lambda), F401 (unused import), E401 (multiple imports)
- **Domain matching accuracy** — now classifies on message+file instead of agent name (80% match rate, was 0%)
- **JSON output** — findings now include `domain_controls`, `playbook_ref`, `fix_strategy` in serialized output
- **Web dashboard** — all 10 pages return HTTP 200, brain map renders with 72 nodes and 38 edges

### Changed
- **Detection pipeline** now receives BrainContext for context-aware finding classification
- **Coordinator** wires BrainContext into DetectionPipeline during scan
- **Chat command** injects full brain state instead of generic prompt
- **Domain loader** uses cached directory-level fingerprint instead of per-file stat
- **Scan gate** uses Popen + communicate instead of capture_output to avoid Windows deadlocks

## [0.7.0] - 2026-08-28

### Added
- **NoiseFilter** — discards test fixtures, lockfiles, generated code, and documentation before scoring
- **ConfidenceGate** low-trust discard — findings from untrusted sources dropped automatically
- **Contract diff** — frontend fetch/axios ↔ backend route mismatch detection
- **Dead code orchestrator** — sglyon/deadcode wrapper with fallback per-language dispatch
- **SBOM depth** — cdxgen (npx) then syft before fallback internal parser, 20+ ecosystems
- **Circular dependency detection** — Tarjan DFS across 11 languages via tree-sitter
- **Web dashboard v2** — unified design system with panel/card layout
- **Brain map** — 2D and 3D interactive visualization with search, view switcher, and D-pad controls
- **Live testing** — Playwright-based visual regression and video recording
- **Assurance heatmap** — coverage visualization per security domain
- **Doctor page** — stale command detection and auto-fix suggestions
- **History page** — unified audit trail with filtering and export

### Fixed
- Web dashboard cost_alert crash on startup
- Brain map canvas rendering at narrow viewports
- Domain loader stat fingerprint performance (16x faster with CSafeLoader)
- Pre-commit hook Windows compatibility (Popen + communicate)

## [0.6.0] - 2026-08-20

### Added
- Initial release with 50+ CLI commands
- Agent colony with 20+ security agents
- Layered brain with architectural understanding
- Risk gate for finding classification
- Charter system for proactive security rules
- DAST scanning with Playwright
- Web dashboard with real-time updates

---

## Release Notes

### v0.7.2 — Brain Intelligence Upgrade

This release connects all the brain's disconnected systems into a unified intelligence layer. The detection pipeline now classifies findings with full project context, the chat receives enriched understanding, and false-positive reduction uses architectural knowledge.

**Key improvements:**
- 80% domain matching accuracy (was 0%)
- Test fixtures automatically demoted for AI review
- Critical directory findings get confidence boost
- Chat now understands your project's purpose, tech stack, and risks

**For teams:** Free for personal use and teams under 3 users. Enterprise licensing available — contact idemudiaehis6@gmail.com.

**Installation:**
```bash
pip install patchi
p init
p scan
```

**What's next:** v0.8.0 will add real-time collaboration, custom agent creation, and plugin system.
