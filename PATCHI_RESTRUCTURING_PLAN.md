# Patchi Restructuring Plan — Families with Discovery

## Core Philosophy

**Families, not layers.** Every command is a family. `p <family>` runs the default. `p <family> commands` shows everything in that family. Nothing hidden.

---

## 1. Command Families

| Family | Base Command (runs default) | Discovery (`p <family> commands`) |
|---|---|---|
| **test** | `p test` — run all tests | `p test commands` → unit, e2e, visual, stress, generate, report, config |
| **scan** | `p scan` — full analysis | `p scan commands` → deep, security, structure, since, contract |
| **fix** | `p fix` — propose/apply fixes | `p fix commands` → auto, review, patch, undo, redo, rollback |
| **ready** | `p ready` — ship readiness check | `p ready commands` → quick, ci, json, baseline |
| **web** | `p web` — launch dashboard | `p web commands` → host, port, open, project |
| **status** | `p status` — project health | `p status commands` → doctor, cockpit, trend, heatmap |
| **audit** | `p audit` — full audit | `p audit commands` → quick, plan, intent, html, json |
| **security** | `p security` — security scan | `p security commands` → chains, findings, rules, deps, assure, charter, restrict |
| **config** | `p config` — show settings | `p config commands` → key, model, settings, brain, access, link, notify, rules, plugins |
| **agent** | `p agent` — list agents | `p agent commands` → list, run, stats, reset |
| **git** | `p git` — git integration | `p git commands` → blame, log |
| **maintain** | `p maintain` — maintenance | `p maintain commands` → update, cleanup, doctor |
| **hosted** | `p hosted` — production monitoring | `p hosted commands` → init, worker, daemon, guard, status, logs, token, block |
| **ai** | `p ai` — AI chat & config | `p ai commands` → status, test, add, remove, profiles |
| **report** | `p report` — generate report | `p report commands` → export, weekly |
| **init** | `p init` — project setup | `p init commands` → auto, no-logo |
| **queue** | `p queue` — show queue | `p queue commands` → pause, resume, skip, mode |
| **plan** | `p plan` — plan changes | `p plan commands` → format, missing-import |
| **verify** | `p verify` — independent re-run | — |
| **help** | `p help` — show help | `p help commands` → all, group, json, write-md |

**Plus meta:**
```
p commands                    → lists all families with descriptions
p commands --flat             → alphabetical list of all commands
p commands --search <q>       → search commands by name/description
```

---

## 2. Agent Merges (6 changes, 0 features lost)

| Merge | What Happens |
|---|---|
| **DeadCodeOrchestrator → DeadCodeScanner** | Absorb `sglyon/deadcode` first-attempt into Scanner. Delete Orchestrator file. |
| **SecretsGuard → SecretsRuntimeAgent** | Move `gate_check_proposed_code()` + `scan_code_for_secrets()` into RuntimeAgent. Delete Guard. |
| **DASTScanner → DASTAgent** | Merge endpoint discovery, auth bypass, open redirect into DASTAgent. Delete DASTScanner. |
| **AccessibilityAgent → delete** | Stub (`pass` for axe-core). UIAccessibilityAgent is the real one. |
| **StressTestAgent → wrapper over StressOrchestrator** | Thin BaseAgent wrapper delegating to StressOrchestrator. Delete old implementation. |
| **Duplicate VisualRegressionAgent in screenshot_manager.py** | Rename to `_AsyncVRAgent` (used by LiveTestRunnerV2Agent). |

---

## 3. App Discovery Agent (New)

**File:** `patchi/core/testing/app_discovery_agent.py` — registered as `AppDiscoveryAgent`, group=TEST.

### What It Does

```
AppDiscoveryAgent
├── Detect: framework, project type, start command, health method
├── Launch: web (existing AppLauncher), Electron (`electron .`), Tauri (`cargo tauri dev`),
│         Qt/Tkinter/WPF (python main.py + OS screenshot), CLI tools (subprocess),
│         Go/Rust/Java/C# (go run/cargo run/dotnet run/mvn spring-boot:run),
│         Mobile (ionic/expo/flutter), Workers (celery/sidekiq)
├── Expose: HTTP URL, Process PID, Screenshot capability, Port mapping
└── Verify: HTTP health, TCP probe, Process alive, Screenshot test, Stdout pattern
```

### Frameworks to Support

| Type | Detection | Launch | Health |
|---|---|---|---|
| Web: Node.js/FastAPI/Flask/Django/Next/Go/Rust | ✅ existing | ✅ existing | HTTP |
| Desktop: Electron/Tauri | Detect deps | `electron .` / `cargo tauri dev` | Process + screenshot |
| Desktop: Qt/Tkinter/WPF | Import detection | `python main.py` / `dotnet run` | Process + screenshot |
| CLI tools | Click/argparse/typer | `python -m pkg` | Stdout pattern / exit code |
| Mobile: Ionic/Expo/Flutter | Config detection | `ionic serve` / `expo start` / `flutter run` | HTTP / Process |
| Java/C#/PHP/Ruby | Build files | `mvn`/`gradle`/`dotnet`/`php artisan`/`rails s` | HTTP |
| Workers: Celery/Sidekiq | Deps detection | `celery -A proj worker` / `sidekiq` | Process alive |

### How Visual Tests Use It

```
p test visual
  → AppDiscoveryAgent.run() → detects project, starts it, returns target
  → VisualRegressionAgent.run() → uses HTTP URL or desktop screenshot
  → UIAccessibilityAgent.run() → uses HTTP URL or desktop screenshot
  → UILayoutAgent.run() → uses HTTP URL or desktop screenshot
  → UIButtonAgent.run() → uses HTTP URL or desktop screenshot
```

For desktop apps, visual agents need a screenshot-capture mode (OS-level) instead of Playwright. The AppDiscoveryAgent returns `target_type` ("http" | "desktop" | "cli") so downstream agents know which mode.

---

## 4. Agent Domain Groups (Adds Navigation)

Keep `AgentGroup` for execution mode. Add `AgentDomain` for user-facing organization.

```python
class AgentDomain(Enum):
    TESTING = "testing"           # Does my code work?
    CODE_QUALITY = "code_quality" # Is my code well-structured?
    INTEGRATION = "integration"   # Is everything wired?
    PERFORMANCE = "performance"   # Does it perform?
    SECURITY = "security"         # Are there security holes?
    VISUAL = "visual"             # Does it look right?
    INFRASTRUCTURE = "infrastructure"  # Is the project set up?
```

Each agent gets a `domain` attribute. `list_agents(domain=AgentDomain.TESTING)` returns only testing agents. Web UI shows domain view.

---

## 5. Chain Commands (Intelligent Defaults)

### `p ready` — Ship Readiness (replaces `p check`)

```python
def run_ready(root):
    # 1. Testing
    run_chain([UnitTestAgent, RegressionAgent, FlakeDetectorAgent, CoveragePrioritizerAgent])
    
    # 2. Code Structure
    run_chain([DeadCodeScanner, DuplicateScanner, ResourceLeakAgent, TypeScanner])
    
    # 3. Integration
    run_chain([LinkingAgent, APIContractAgent])
    
    # 4. Performance (if app running)
    if base_url:
        run_chain([StressOrchestrator, MemoryProfilerAgent])
    
    # 5. Security Basics
    run_chain([SecretsRuntimeAgent, DependencyVulnAgent, MisconfigAgent])
    
    # 6. Visual (if app running)
    if base_url:
        run_chain([VisualRegressionAgent, UIAccessibilityAgent])
    
    # Output detailed report
    print_ship_readiness_report(results)
```

### `p test` — Testing Chain

```
p test                    → unit + regression + flake + coverage + contract (+ e2e if app running)
p test unit               → unit only
p test e2e                → e2e + browser
p test visual             → visual + accessibility + layout + button
p test stress             → stress orchestrator
p test generate           → AI generate tests
p test report             → history + trends
p test config             → configure test settings
```

### `p scan` — Analysis Chain

```
p scan                    → brain + deadcode + duplicate + comment + resource + type + secrets + depvuln + misconfig + env
p scan --deep             → + all 45 security agents
p scan security           → security only
p scan structure          → structure only
p scan --since <ref>      → changed files only
```

### `p fix` — Fix Chain

```
p fix                     → propose fixes for findings
p fix auto                → auto-apply safe fixes
p fix review              → interactive review
p fix patch               → patch management
p fix undo/redo/rollback  → patch lifecycle
```

---

## 6. Implementation Phases

### Phase 1: Agent Housekeeping (preserves all features)
1. Merge DeadCodeOrchestrator → DeadCodeScanner
2. Merge SecretsGuard → SecretsRuntimeAgent
3. Merge DASTScanner → DASTAgent
4. Delete AccessibilityAgent (stub)
5. Replace StressTestAgent with wrapper over StressOrchestrator
6. Clean up duplicate VisualRegressionAgent in screenshot_manager.py

### Phase 2: App Discovery Agent
7. Build `AppDiscoveryAgent` with full framework detection
8. Enhance `AppLauncher` with desktop/CLI/mobile support
9. Add screenshot capture for desktop apps (OS-level: `scrot`/PowerShell/screencapture)
10. Add process-alive and stdout health checks
11. Wire into test chain (visual agents use discovery result)

### Phase 3: Domain Groups
12. Add `AgentDomain` enum to `base.py`
13. Add `domain` attribute to all ~126 agents
14. Add `list_agents(domain=...)` support
15. Update `p agent commands` to support domain grouping
16. Update web UI colony view to show domains

### Phase 4: Command Families
17. Restructure CLI registry into family groups
18. Add `p <family> commands` subcommand to each family
19. Add `p commands` (list all families + search)
20. Build `p ready` chain (ship readiness)
21. Build `p quick` chain (fast check)
22. Add subcommands to `p test`, `p scan`, `p fix`, `p audit`, etc.

### Phase 5: Intelligence
23. Smart chain logic (auto-detect what to run based on project type)
24. CI output mode (JUnit XML, GitHub annotations)
25. Baseline tracking (compare across runs)

---

## What the User Sees

```
$ p --help

Families (p <family> runs default, p <family> commands lists all):

  test       Run tests (unit, e2e, visual, stress, generate)
  scan       Analyze code (full, deep, security, structure)
  fix        Propose/apply fixes (auto, review, patch, undo)
  ready      Ship readiness check (test + scan + perf + security)
  web        Launch dashboard
  status     Project health (doctor, cockpit, trend)
  audit      Full audit (quick, plan, html)
  security   Security scan (chains, findings, rules, deps)
  config     Configuration (key, model, settings, brain, access)
  agent      Agent management (list, run, stats)
  git        Git integration (blame, log)
  maintain   Maintenance (update, cleanup, doctor)
  hosted     Production monitoring (worker, daemon, guard)
  ai         AI chat & config (status, test, add)
  report     Generate reports (export, weekly)
  init       Project setup
  queue      Task queue (pause, resume, skip)
  plan       Plan changes
  verify     Independent re-run
  help       Show help

See all: p commands
Search:  p commands --search <query>
```

```
$ p test commands

test          Run all tests (default)
test unit     Unit tests only
test e2e      End-to-end + browser tests
test visual   Visual regression + accessibility + layout
test stress   Load/stress testing
test generate AI-generate tests for untested code
test report   Test history + trends
test config   Configure test settings
```

```
$ p scan commands

scan              Full analysis (default)
scan --deep       Full security suite (45 agents)
scan security     Security-focused scan
scan structure    Code structure analysis
scan --since <ref> Only changed files
```

```
$ p config commands

config            Show settings (default)
config key        API key management (add/list/remove/test)
config model      LLM model (set/list/status)
config settings   View/set configuration
config brain      Brain data management
config access     Dev access tokens
config link       Link frontend + backend
config notify     Notification channels
config rules      Security rule packs
config plugins    Analyzer plugins
config memory     Patchi memory
```

---

## The Pitch

> **Patchi is 126 testing agents organized into 20 families. `p <family>` runs the default. `p <family> commands` shows everything. Nothing hidden. Everything discoverable.**