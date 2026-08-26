# Changelog

## [0.6.0] - 2026-08-26

### 🚀 New Features
- **`p dev check`** — 3-gate CI check (ruff + pytest + scan) with JSON output and JUnit parsing
- **`p dev hook --strict`** — Pre-commit hook that blocks commits on lint/test failures
- **`p ask`** — Natural language queries against the layered brain (what changed, what imports, hotspots)
- **`p charter`** — Project guard rails system with NL parser and drift detection
- **`p assure`** — Assurance commands: `--chain-report`, `--run-attackers`, `--run-campaigns`
- **`p chains --fix`** — Auto-apply fixable remediations from exploit chains via RiskGate
- **Multi-language remediation** — Go, Java, Rust, PHP, Ruby patterns for 6 key finding types
- **Remediation confidence scoring** — Based on auto-fix capability, language match, and fix acceptance rates
- **Cost threshold alerts** — Dashboard warning when AI spending exceeds configurable budget

### 🛡️ Security
- **Charter guard rails** — NL parser converts rules into structured guard rails; violations surface as findings
- **Chain explorer cross-linking** — Findings link to exploit chains and vice versa
- **Tenant isolation** — `tenant_context` wraps scan/fix/assurance handlers for per-project isolation
- **API key auth** — CI/CD endpoints require `X-API-Key` header with auto-generated key
- **CI audit script** — Comprehensive `scripts/ci-audit.sh` (agent audit, ruff, mypy, fast tests)

### 🌐 Web UI
- **Fixed scan buttons** — Security scan and report buttons now produce results
- **Scan result refresh** — Findings and severity counts auto-update after scan completes
- **Before/after comparison** — Finding comparison cards for scan diffing
- **Chain claims tab** — Exploit chain visualization with remediation suggestions
- **Charter violations tab** — Displays charter rule violations in findings page

### 🔧 CLI Improvements
- `p dev hook` now shows current mode (strict/warn-only) when installed
- `p scan --quiet` flag added to suppress non-essential output
- Charter violations display in scan output
- Debug adapters (node/python/powershell) return proper responses instead of raising errors
- `tools/run_full_suite.py` for blocking full test suite execution

### 🏗️ Infrastructure
- **Tree-sitter parse cache** shared across agents with bounded memory
- **Lazy torch import** in gnn_models.py (prevents test collection slowdown)
- **ruff format** cleanup across 308 files
- Comprehensive `.gitignore` rules for runtime artifacts
- Debug adapters (node/python/powershell) fixed to return dict instead of NotImplementedError

### 📊 Stats
- 62 CLI commands
- 164+ tests passing
- 40+ security agents
- 14 web route files
- 23 fuzz/attacker/campaign/reliability modules
