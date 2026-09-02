# Patchi v2.0 Upgrade Plan — Smart Testing \& Security Platform

## Implementation Status (2026-08-25)

|Component|Status|Where|
|-|-|-|
|Council of Personas (8 personas, deliberation, synthesis, action plans, learning memory)|✅ Done|`patchi/core/brain/council.py`, `patchi/core/brain/personas/`|
|AI Tool Calling (37 tools, schema validation, confirmation gates, audit log)|✅ Done|`patchi/core/ai/tools/`, `patchi/core/ai/tool\\\\\\\_executor.py`|
|Dynamic Security Domain Activation (signal-based scoring, 20+ domains)|✅ Done|`patchi/core/security/domain\\\\\\\_activator\\\\\\\_v2.py`|
|Red Team Engine (YAML attack scenarios: SQLi/XSS/Auth families, safe mode, reporting)|✅ Done|`patchi/core/security/red\\\\\\\_team\\\\\\\_engine.py`, `attack\\\\\\\_scenarios/\\\\\\\*.yaml`|
|Auto-Fixer (playbook matching, patch generation, verification hooks)|✅ Done|`patchi/core/security/auto\\\\\\\_fixer.py`|
|Live Testing v2 (browser pool, stress orchestrator load/spike/soak/breakpoint, screenshots, video)|✅ Done|`patchi/core/testing/live\\\\\\\_v2/`|
|Web Dashboard v2 (mission control, council view, brain map, attack timeline, live tests, command palette, WS streaming)|✅ Done|`patchi/web/routes/dashboard\\\\\\\_v2.py`, `templates\\\\\\\_v2/`, `static/dashboard\\\\\\\_v2.\\\\\\\*`|
|Hosted Mode v2 (overview API, compliance evidence packs, signed webhooks, usage/budget)|✅ Done|`patchi/web/api/hosted\\\\\\\_v2.py`, `patchi/core/hosted/{webhooks,compliance\\\\\\\_report}.py`|
|Agent Audit (registry integrity: all agents instantiate, unique names, metadata, 0 import failures)|✅ Done|`tests/test\\\\\\\_v2\\\\\\\_agent\\\\\\\_audit.py`|
|Pre-existing bug fixes (dotted call names, attribute assignments, missing recheck\_test\_file, tenant mem.init)|✅ Done|see AGENT\_FEEDBACK.md|
|End-to-end verification (real server boot → pages, tools API, hosted APIs, WS handshake)|✅ 13/13|`tools/e2e\\\\\\\_web\\\\\\\_v2.py`|

**Known blocker (environmental):** the packaged security-domain taxonomy in this
checkout is a subset (48 of \~300 YAMLs) so 3 data-integrity tests fail. The code
is correct; the data files need to be restored from the full export. See
AGENT\_FEEDBACK.md ENV-01.

\---

## Executive Summary

Transform Patchi from a static analysis tool into a **fully autonomous, AI-driven testing and security platform** with:

* Council-based decision making (multiple AI personas)
* Tool-calling architecture for all operations
* Live attack simulation with auto-remediation
* Real-time web dashboard with agent observability
* Dynamic security domains that activate on-demand
* Advanced live testing (screenshots, stress tests, browser automation)

\---

## 1\. Brain Architecture Upgrade — Council-Based Intelligence

### 1.1 Multi-Persona Council System

Replace single-brain with a **Council of Specialized Personas**:

|Persona|Role|Specialization|
|-|-|-|
|**Architect**|System design \& structure|Code organization, dependencies, blast radius|
|**Security Officer**|Threat modeling \& defense|Vulnerability detection, attack surfaces, compliance|
|**Test Engineer**|Quality assurance|Test generation, coverage, flakiness, regression|
|**Performance Analyst**|Optimization|Bottlenecks, memory, latency, scalability|
|**DevOps Engineer**|Deployment \& ops|CI/CD, infrastructure, monitoring, secrets|
|**Code Reviewer**|Code quality|Style, patterns, maintainability, docs|
|**Product Owner**|Business logic|Requirements, user flows, acceptance criteria|
|**Incident Responder**|Runtime issues|Crashes, errors, anomalies, root cause|

### 1.2 Council Decision Flow

```
User Request / Event
       ↓
\\\\\\\[Context Enrichment] → Brain provides full project context
       ↓
\\\\\\\[Persona Activation] → Relevant personas selected dynamically
       ↓
\\\\\\\[Parallel Deliberation] → Each persona analyzes independently
       ↓
\\\\\\\[Synthesis] → Council aggregates, debates, reaches consensus
       ↓
\\\\\\\[Action Plan] → Structured tool calls with priorities
       ↓
\\\\\\\[Execution] → Agents execute, report back to Council
       ↓
\\\\\\\[Learning] → Outcomes fed back to improve future decisions
```

### 1.3 Implementation Files

* `patchi/core/brain/council.py` — Council orchestration
* `patchi/core/brain/personas/` — Individual persona implementations
* `patchi/core/brain/synthesis.py` — Consensus building
* `patchi/core/brain/memory.py` — Long-term learning memory

\---

## 2\. AI Tool Calling Architecture

### 2.1 Unified Tool Registry

All operations become **AI-callable tools** with schemas:

```python
# Example tool definition
@tool(
    name="scan\\\\\\\_project",
    description="Full project scan with brain analysis",
    parameters={
        "area": {"type": "string", "description": "Optional subdirectory to scan"},
        "depth": {"type": "integer", "description": "Scan depth limit"}
    }
)
async def scan\\\\\\\_project(root: Path, area: str = None, depth: int = None):
    ...
```

### 2.2 Tool Categories

|Category|Tools|
|-|-|
|**Brain**|`scan`, `explain`, `impact\\\\\\\_analysis`, `why`, `ask`|
|**Security**|`scan\\\\\\\_vulns`, `attack\\\\\\\_simulate`, `red\\\\\\\_team`, `fix\\\\\\\_vuln`, `check\\\\\\\_compliance`|
|**Testing**|`run\\\\\\\_tests`, `generate\\\\\\\_tests`, `stress\\\\\\\_test`, `screenshot`, `browser\\\\\\\_test`, `visual\\\\\\\_regression`|
|**Fix**|`apply\\\\\\\_patch`, `generate\\\\\\\_fix`, `verify\\\\\\\_fix`, `rollback`|
|**Config**|`get\\\\\\\_config`, `set\\\\\\\_config`, `add\\\\\\\_restriction`, `manage\\\\\\\_keys`|
|**Memory**|`get\\\\\\\_brain`, `get\\\\\\\_layers`, `get\\\\\\\_history`, `query\\\\\\\_findings`|
|**Web**|`start\\\\\\\_server`, `get\\\\\\\_dashboard`, `stream\\\\\\\_events`|

### 2.3 Implementation Files

* `patchi/core/ai/tools.py` — Tool definitions \& registry
* `patchi/core/ai/tool\\\\\\\_executor.py` — Execution engine with validation
* `patchi/core/ai/agent\\\\\\\_loop.py` — ReAct-style agent loop
* `patchi/cli/commands/ai\\\\\\\_cmd.py` — CLI integration

\---

## 3\. Dynamic Security Domain System

### 3.1 On-Demand Domain Activation

Domains activate **only when relevant signals detected**:

```python
# Activation signals per domain
DOMAIN\\\\\\\_SIGNALS = {
    "injection": \\\\\\\["sql", "nosql", "orm", "eval", "exec", "user\\\\\\\_input"],
    "authentication": \\\\\\\["login", "password", "oauth", "jwt", "session", "auth"],
    "xss": \\\\\\\["render", "template", "innerHTML", "dangerouslySetInnerHTML"],
    "ssrf": \\\\\\\["fetch", "http", "request", "url", "proxy"],
    "secrets": \\\\\\\["api\\\\\\\_key", "secret", "token", "password", "credential"],
    "runtime": \\\\\\\["docker", "kubernetes", "container", "falco"],
    # ... all 20+ domains
}
```

### 3.2 Domain Lifecycle

1. **Scan** → Brain detects project type, frameworks, imports
2. **Signal Extraction** → Keywords from code, config, dependencies
3. **Domain Matching** → Score each domain against signals
4. **Activation** → Load only domains above threshold
5. **Agent Spawn** → Only relevant security agents run
6. **Deactivation** → Unload after scan (memory efficient)

### 3.3 Implementation Files

* `patchi/core/security/domain\\\\\\\_activator\\\\\\\_v2.py` — New activation logic
* `patchi/core/security/domain\\\\\\\_registry.py` — Domain metadata \& signals
* `patchi/core/security/adaptive\\\\\\\_scanner.py` — Dynamic agent selection

\---

## 4\. Red Team Engine with Auto-Fix

### 4.1 Attack Simulation Framework

```python
class AttackScenario:
    name: str
    category: str  # OWASP Top 10, MITRE ATT\\\\\\\&CK
    prerequisites: list\\\\\\\[str]
    steps: list\\\\\\\[AttackStep]
    expected\\\\\\\_impact: str
    detection\\\\\\\_signatures: list\\\\\\\[str]
    remediation\\\\\\\_playbook: str
```

### 4.2 Attack Categories

|Category|Examples|
|-|-|
|**Injection**|SQLi, NoSQLi, Command, LDAP, Template|
|**Auth**|Bypass, Credential Stuffing, Session Fixation|
|**XSS**|Reflected, Stored, DOM-based, Blind|
|**SSRF**|Internal service access, Cloud metadata|
|**RCE**|Deserialization, Template, File Upload|
|**IDOR**|Parameter manipulation, UUID enumeration|
|**Business Logic**|Race conditions, Workflow bypass|
|**Supply Chain**|Dependency confusion, Typosquatting|

### 4.3 Auto-Fix Integration

Each attack finding → **Auto-generates fix** via:

1. Playbook lookup (deterministic)
2. LLM template fill (context-aware)
3. Verification (re-run attack to confirm fix)
4. PR/Commit creation (if enabled)

### 4.4 Implementation Files

* `patchi/core/security/red\\\\\\\_team\\\\\\\_engine.py` — Core attack orchestrator
* `patchi/core/security/attack\\\\\\\_scenarios/` — YAML scenario library
* `patchi/core/security/auto\\\\\\\_fixer.py` — Fix generation \& verification
* `patchi/core/security/attack\\\\\\\_replayer.py` — Replay attacks post-fix

\---

## 5\. Advanced Live Testing Platform

### 5.1 Browser Automation Suite

```python
class LiveTestCapabilities:
    # Browser control
    navigate(url)
    click(selector)
    type(selector, text)
    wait\\\\\\\_for(selector, condition)
    
    # Observation
    screenshot(full\\\\\\\_page=True, selector=None)
    get\\\\\\\_dom\\\\\\\_snapshot()
    get\\\\\\\_console\\\\\\\_logs()
    get\\\\\\\_network\\\\\\\_logs()
    get\\\\\\\_performance\\\\\\\_metrics()
    
    # Stress
    concurrent\\\\\\\_users(n, duration, ramp\\\\\\\_up)
    spike\\\\\\\_test(multiplier, duration)
    soak\\\\\\\_test(duration)
    
    # Assertion
    assert\\\\\\\_element(selector, condition)
    assert\\\\\\\_network(request\\\\\\\_pattern, response\\\\\\\_condition)
    assert\\\\\\\_performance(metric, threshold)
```

### 5.2 Test Types

|Type|Description|Tools|
|-|-|-|
|**Smoke**|Critical path verification|Playwright, quick checks|
|**Regression**|Visual + functional diff|Screenshot compare, DOM diff|
|**Stress**|Load, spike, soak|k6-style, custom orchestrator|
|**Chaos**|Failure injection|Network latency, errors, crashes|
|**Accessibility**|WCAG 2.1 AA|axe-core, custom rules|
|**Contract**|API schema validation|OpenAPI, GraphQL introspection|

### 5.3 Live Dashboard Integration

* Real-time test execution view
* Screenshot gallery with timeline
* Performance charts (latency, throughput, errors)
* Console/network log streaming
* Test recording (video + HAR)

### 5.4 Implementation Files

* `patchi/core/testing/live\\\\\\\_runner\\\\\\\_v2.py` — Enhanced orchestrator
* `patchi/core/testing/browser\\\\\\\_pool.py` — Browser lifecycle management
* `patchi/core/testing/stress\\\\\\\_orchestrator.py` — Load testing engine
* `patchi/core/testing/screenshot\\\\\\\_manager.py` — Capture \& comparison
* `patchi/core/testing/video\\\\\\\_recorder.py` — Test session recording
* `patchi/web/api/live\\\\\\\_test.py` — WebSocket streaming API

\---

## 6\. Real-Time Web Dashboard

### 6.1 Dashboard Components

```
┌─────────────────────────────────────────────────────────────┐
│  PATCHI v2.0 — Live Mission Control                         │
├──────────────┬──────────────┬──────────────┬────────────────┤
│  BRAIN MAP   │  COUNCIL     │  LIVE TESTS  │  ATTACK SIM    │
│  (interactive)│  DELIBERATION│  (real-time) │  (timeline)    │
├──────────────┼──────────────┼──────────────┼────────────────┤
│  FINDINGS    │  AGENT LOG   │  METRICS     │  CHAT/COMMAND  │
│  (filterable) │  (streaming) │  (charts)    │  (AI tool call)│
└──────────────┴──────────────┴──────────────┴────────────────┘
```

### 6.2 Key Features

* **Brain Map**: Interactive force-directed graph of layers/dependencies
* **Council View**: Real-time persona deliberation with reasoning traces
* **Live Test View**: Browser screen stream, screenshots, console logs
* **Attack Timeline**: Attack → Detection → Fix → Verification flow
* **Agent Stream**: All agent events with expandable details
* **Command Palette**: Natural language → tool calls with preview

### 6.3 Implementation Files

* `patchi/web/app\\\\\\\_v2.py` — New FastAPI app with all endpoints
* `patchi/web/static/dashboard\\\\\\\_v2/` — React/Vanilla JS dashboard
* `patchi/web/ws/events\\\\\\\_v2.py` — Enhanced WebSocket event system
* `patchi/web/api/council.py` — Council deliberation streaming
* `patchi/web/api/live\\\\\\\_test.py` — Live test streaming

\---

## 7\. Enhanced Hosted Mode

### 7.1 Value Proposition

|Feature|Current|v2.0|
|-|-|-|
|**Continuous Guard**|Periodic scan|Real-time interceptor + webhook|
|**Team Dashboard**|Basic|Multi-project, RBAC, SSO|
|**Compliance**|Manual|Automated evidence packs|
|**Supply Chain**|CVE check|SBOM + reachability + auto-PR|
|**Incident Response**|Logs|Timeline + root cause AI|
|**Cost Control**|None|Token budgets, quotas, alerts|

### 7.2 Architecture

```
Hosted Control Plane
       │
       ├── Project 1 (GitHub App) ← Webhook → Scan → PR Comments
       ├── Project 2 (GitLab)     ← Webhook → Scan → Merge Checks
       ├── Project 3 (Self-hosted) ← Agent  → Scan → Dashboard
       └── Project N...
       │
       ├── Shared Brain Cache (cross-project learning)
       ├── Centralized Policy Engine
       ├── Audit Log \\\\\\\& Compliance Reports
       └── Billing \\\\\\\& Usage Analytics
```

### 7.3 Implementation Files

* `patchi/web/api/hosted\\\\\\\_v2.py` — Enhanced hosted API
* `patchi/core/hosted/guard\\\\\\\_service.py` — Background guard daemon
* `patchi/core/hosted/webhook\\\\\\\_handler.py` — GitHub/GitLab/Bitbucket
* `patchi/core/hosted/compliance\\\\\\\_engine.py` — Evidence generation
* `patchi/core/hosted/billing.py` — Usage tracking \& limits

\---

## 8\. Agent Audit \& Improvement

### 8.1 Audit Criteria

Each of the 54+ agents audited for:

* \[ ] **Correctness** — False positive/negative rates
* \[ ] **Performance** — Time complexity, memory usage
* \[ ] **Coverage** — Language/framework support gaps
* \[ ] **Maintainability** — Code quality, test coverage
* \[ ] **Integration** — Proper registration, error handling
* \[ ] **AI Enhancement** — Can benefit from LLM reasoning?

### 8.2 Priority Improvements

|Agent|Issue|Fix|
|-|-|-|
|`RedTeamAgent`|Pattern-only, no exploitation|Full attack simulation|
|`BrowserTestAgent`|Basic navigation only|Full Playwright integration|
|`StressTestAgent`|Synthetic only|Real browser load|
|`SecretScanner`|Regex only|AST + entropy + context|
|`InjectionAgent`|Limited patterns|LLM-assisted variant generation|
|`DependencyVulnerabilityAgent`|CVE list only|Reachability analysis|

### 8.3 New Agents Needed

* `AttackReplayerAgent` — Replay attacks post-fix
* `TestGeneratorAgent` — AI-generated test cases
* `FixVerifierAgent` — Independent fix validation
* `ChaosAgent` — Failure injection testing
* `ComplianceReporterAgent` — Automated evidence packs

\---

## 9\. Implementation Phases

### Phase 1: Foundation (Weeks 1-2)

* \[ ] Council architecture \& persona system
* \[ ] Tool calling framework
* \[ ] Enhanced brain with learning memory
* \[ ] Domain activation v2

### Phase 2: Intelligence (Weeks 3-4)

* \[ ] Red Team Engine with scenarios
* \[ ] Auto-fix generation \& verification
* \[ ] Attack replayer
* \[ ] Council deliberation streaming

### Phase 3: Live Testing (Weeks 5-6)

* \[ ] Browser pool \& orchestration
* \[ ] Screenshot/video capture
* \[ ] Stress/chaos testing engine
* \[ ] Live test WebSocket streaming

### Phase 4: Web Dashboard (Weeks 7-8)

* \[ ] Dashboard v2 with all panels
* \[ ] Real-time event streaming
* \[ ] Command palette (AI tool calls)
* \[ ] Mobile-responsive design

### Phase 5: Hosted \& Polish (Weeks 9-10)

* \[ ] Hosted mode v2
* \[ ] Multi-project dashboard
* \[ ] Compliance automation
* \[ ] Performance optimization
* \[ ] Documentation \& examples

\---

## 10\. Success Criteria

### Technical Metrics

* \[ ] **Scan time**: < 30s for 10k file project (incremental)
* \[ ] **Attack simulation**: 100+ scenarios, < 5 min full run
* \[ ] **Live test**: 50 concurrent browsers, < 2% flake rate
* \[ ] **Dashboard latency**: < 100ms WebSocket event delivery
* \[ ] **Auto-fix rate**: > 70% of findings auto-remediated
* \[ ] **False positive reduction**: > 50% vs v1.0

### Quality Metrics

* \[ ] All agents have > 80% test coverage
* \[ ] Zero critical security findings in Patchi itself
* \[ ] Full offline mode support (no external AI required)
* \[ ] Backward compatible CLI (all v1 commands work)
* \[ ] Comprehensive documentation for all new features

\---

## 11\. Risk Mitigation

|Risk|Likelihood|Impact|Mitigation|
|-|-|-|-|
|Scope creep|High|High|Strict phase gates, MVP per phase|
|AI reliability|Medium|High|Offline fallbacks, confidence thresholds|
|Performance regression|Medium|Medium|Continuous benchmarking in CI|
|Breaking changes|Low|High|Semantic versioning, migration guides|
|Browser instability|Medium|Medium|Pool management, auto-recovery|

\---

## 12\. Immediate Next Steps

1. **Create Council foundation** — `patchi/core/brain/council.py`
2. **Build Tool Registry** — `patchi/core/ai/tools.py`
3. **Implement Domain Activator v2** — Dynamic activation
4. **Prototype Red Team Engine** — 5 core attack scenarios
5. **Set up Live Test infrastructure** — Browser pool + Playwright

\---

*This plan is a living document. Update as implementation reveals new insights.*

