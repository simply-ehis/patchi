# Patchi CLI Reference

Complete reference for all 50 registered Patchi commands.

---

## Global Flags

| Flag | Description |
|------|-------------|
| `--version` | Show version |
| `--json` | JSON output |
| `--quiet` | Suppress non-essential output |
| `--verbose` | Extra detail |
| `--no-color` | Disable colored output |
| `--theme {dark,light,mono,highcontrast}` | Color theme |

---

## Project Setup

### `p init`
Initialize Patchi in the current project. Creates `.patchi/` directory with config, memory, and state files.

### `p doctor`
System health check — validates setup, detects stale commands, checks dependencies.

### `p cleanup`
Clean stale `.patchi/` artifacts (JUnit XML, caches, logs, databases).

| Flag | Description |
|------|-------------|
| `--apply` | Actually delete files (default is dry-run) |
| `--all` | Also remove evidence/screenshots |
| `--older-than <duration>` | Only remove files older than this (e.g. `7d`, `24h`, `30m`) |
| `--json` | JSON output for CI integration |

---

## Scanning & Analysis

### `p scan`
Scan the project for security issues and code quality problems.

| Flag | Description |
|------|-------------|
| `--deep` | With LLM analysis on changed files |
| `--offline` | Static analysis only, no AI calls |
| `--json` | JSON output for CI/CD |
| `--changed` | Only scan git-changed files |
| `--force` | Force full re-scan |
| `--with-license` | Include supply-chain license audit |
| `--with-extended` | Include extended findings |
| `--quiet` | Suppress non-essential output |

### `p security`
Run security agents directly.

| Flag | Description |
|------|-------------|
| `--json` | JSON output |
| `--type <type>` | Filter by finding type |

### `p chains`
Show exploit chains and intent gaps from last scan.

| Flag | Description |
|------|-------------|
| `--analyze` | Analyze chains from findings |
| `--fix` | Auto-apply fixable remediations |

### `p findings`
View and manage security findings.

| Flag | Description |
|------|-------------|
| `--json` | JSON output |
| `--severity <level>` | Filter by severity |
| `--type <type>` | Filter by type |

### `p deps`
Supply chain security scan.

| Flag | Description |
|------|-------------|
| `--licenses` | Full license audit (separate from default scan) |

### `p blast`
Blast radius analysis for changed files.

### `p impact`
Show change-impact / blast radius for changed files.

### `p why`
Explain why a file matters in the project context.

---

## Fixing & Patching

### `p fix`
Apply AI-generated fixes (requires scan first).

| Flag | Description |
|------|-------------|
| `--dry-run` | Preview fixes without applying |
| `--all` | Fix all findings |
| `--type <type>` | Fix specific finding type |

### `p auto`
Propose/apply safe fixes for changed files.

### `p patch`
Manage individual patches.

| Subcommand | Description |
|------------|-------------|
| `p patch list` | List all patches |
| `p patch show <id>` | Show diff for a patch |
| `p patch apply <id>` | Apply a pending patch |
| `p patch reject <id>` | Reject a patch |
| `p patch undo` | Undo last applied fix |
| `p patch redo` | Redo last undone fix |
| `p patch rollback <id>` | Roll back to a specific patch |

### `p undo` / `p redo`
Undo/redo applied fixes (compat — prefer `p patch undo/redo`).

### `p rollback`
Roll back to a specific patch (compat — prefer `p patch rollback`).

### `p review`
Review pending changes before applying.

---

## Testing

### `p test`
Run tests.

| Flag | Description |
|------|-------------|
| `--unit` | Unit tests only |
| `--browser` | Browser tests (Playwright) |
| `--stress` | Stress/load tests |
| `--visual` | Visual regression tests |
| `--api` | API tests |
| `--e2e` | End-to-end tests |

### `p verify`
Independently re-run tests+scan and report truth (not self-report).

---

## AI & Chat

### `p chat`
Interactive AI chat with Patchi.

| Flag | Description |
|------|-------------|
| `--stream` | Streaming responses |

### `p ai`
AI configuration and status.

| Subcommand | Description |
|------------|-------------|
| `p ai status` | Show all configured AI keys and status |
| `p ai test` | Send test prompt to active AI provider |
| `p ai add` | Add a new API key interactively |
| `p ai remove <name>` | Remove an API key by name |
| `p ai profiles` | List configured AI provider profiles |

### `p model`
Manage local Ollama model.

| Subcommand | Description |
|------------|-------------|
| `p model set` | Set local model |
| `p model list` | List available local models |
| `p model status` | Show model connection health |

---

## Agents & Profiling

### `p agents`
Inspect and manage agents.

| Subcommand | Description |
|------------|-------------|
| `p agents list` | List agent groups or agents in a group |
| `p agents status` | Show currently active agents |
| `p agents reset` | Reset circuit breaker for an agent |

### `p agent-stats`
Agent profiling stats and learning state.

---

## Brain & Knowledge

### `p brain`
View project purpose, domain, contract flows.

### `p learn`
Learn project conventions and patterns.

### `p plan`
Plan changes before making them.

---

## Memory & Configuration

### `p memory`
View and manage Patchi's memory.

| Subcommand | Description |
|------------|-------------|
| `p memory show <category>` | Show memory for a category |
| `p memory delete <category>` | Clear memory (category or all) |

### `p settings`
View or modify configuration.

| Subcommand | Description |
|------------|-------------|
| `p settings show` | Show current configuration |
| `p settings set <key> <value>` | Set a configuration value |
| `p settings mode` | View or set operating mode |

### `p mode`
View/change scan mode (compat — prefer `p settings mode`).

### `p key`
Manage API keys.

| Subcommand | Description |
|------------|-------------|
| `p key add` | Add an API key (interactive) |
| `p key list` | List all keys with status |
| `p key remove <name>` | Remove a key by nickname |
| `p key test <name>` | Test a key connection |

### `p access`
Manage dev access tokens.

| Subcommand | Description |
|------------|-------------|
| `p access add` | Add a token |
| `p access list` | List all tokens |
| `p access remove` | Remove a token |

---

## Charter & Rules

### `p charter`
Manage project charter and rules.

| Subcommand | Description |
|------------|-------------|
| `p charter set <file>` | Set charter from a file |
| `p charter check` | Check code against charter |
| `p charter hooks` | Manage git hooks |

### `p rules`
View and validate security rule packs.

### `p restrict`
Manage file restrictions.

| Subcommand | Description |
|------------|-------------|
| `p restrict add <path>` | Add path as no-touch zone |
| `p restrict scan-only <path>` | Mark path as scan-only |
| `p restrict sensitive <path>` | Mark path as sensitive |
| `p restrict list` | List all restrictions |
| `p restrict remove <path>` | Remove a restriction |
| `p restrict disable <path>` | Temporarily disable |
| `p restrict enable <path>` | Re-enable |

---

## Notifications & Alerts

### `p notify`
Configure notifications.

| Subcommand | Description |
|------------|-------------|
| `p notify add` | Add a notification channel |
| `p notify test` | Send test alert to all or one channel |

---

## Reporting & Audit

### `p report`
Generate a structured analysis report.

### `p audit`
Full project audit (scan + security + test + report).

### `p assure`
Assurance campaigns — prove properties, record evidence.

| Flag | Description |
|------|-------------|
| `--chain-report` | Show chain-sourced claims separately |
| `--run-attackers` | Run attacker simulations |
| `--run-campaigns` | Run assurance campaigns |

---

## Web & Dashboard

### `p web`
Launch the unified Patchi web UI.

| Flag | Description |
|------|-------------|
| `--port <port>` | Custom port (default: 1612) |
| `--project <path>` | Scan a different project |
| `--open` | Auto-open browser |

---

## Visual Regression

### `p vr`
Visual regression baseline management.

| Subcommand | Description |
|------------|-------------|
| `p vr baseline` | Capture baselines at desktop/tablet/mobile viewports |
| `p vr list` | List baselines with per-viewport counts |
| `p vr compare` | Compare current vs baseline |

---

## Developer Tools

### `p dev`
Developer utilities, testing docs, and diagnostics.

| Subcommand | Description |
|------------|-------------|
| `p dev check` | Run full gate (ruff + pytest + scan) |
| `p dev check --fast` | Run only core tests (~18s) |
| `p dev hook` | Install pre-commit hook |
| `p dev hook --strict` | Install with strict mode |

### `p update`
Check for and apply updates.

### `p watch`
Auto-scan on file saves.

---

## Cross-Repository

### `p cross-repo`
Cross-repository dependency intelligence.

### `p goal`
Autonomous mode — loop the agent pipeline until health target.

---

## Queue Management

### `p queue`
View and control the task queue.

| Subcommand | Description |
|------------|-------------|
| `p queue pause` | Pause queue execution |
| `p queue resume` | Resume queue |
| `p queue skip` | Skip the current active task |
| `p queue mode` | Set queue mode |

---

## Hosted Mode (Experimental)

### `p hosted`
Live monitoring daemon — monitor live apps.

| Subcommand | Description |
|------------|-------------|
| `p hosted start` | Start monitoring |
| `p hosted stop` | Stop monitoring |
| `p hosted daemon` | Start worker with auto-restart + health checks |
| `p hosted status` | Show connection status |
| `p hosted token` | Manage admin tokens |

---

## Git Integration

### `p blame <file>`
Show git blame for a file.

### `p log`
Show git changelog.

---

## Commands Help

### `p command`
List all commands with tags and arguments.

### `p help <command>`
Show help for a specific command.
