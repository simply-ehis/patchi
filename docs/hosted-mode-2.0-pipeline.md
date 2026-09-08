# Hosted Mode 2.0 — Detection, Classification & Defense Pipeline

> **Status:** Implemented (Phases A–F complete)  
> **Version:** 2.0  
> **Depends on:** Phase 1–5 hardening (contract confidence, project purpose, doc validation, dead code deletion, XSS hardening)

---

## 1. Overview

### 1.1 Purpose

Transform Patchi from a passive security scanner into an **active defense system** that:
- **Detects** all forms of cyber threats across code and runtime
- **Classifies** findings by confidence to eliminate false positives
- **Defends** by automatically fixing code, blocking attacks, rotating secrets, and patching configurations

### 1.2 Three-Layer Architecture

```
REQUEST / CODE
     │
     ▼
┌─────────────────────────────┐
│  LAYER 1: DETECTION         │  ~40 agents, zero AI tokens
│  (36 existing + 4 new)      │
└─────────────┬───────────────┘
              │
              ▼
┌─────────────────────────────┐
│  CORRELATION                │  SecurityOrchestrator (reused)
│  (dedup, score, OWASP map)  │
└─────────────┬───────────────┘
              │
              ▼
┌─────────────────────────────┐
│  CONFIDENCE GATE            │  Scores 0.0–1.0, routes per tier
│  HIGH ≥ 0.7  → DEFEND       │
│  MEDIUM ≥ 0.4 → AI ANALYZE  │
│  LOW   < 0.4 → HUMAN REVIEW │
└─────────────┬───────────────┘
              │
      ┌───────┴───────┐
      │               │
      ▼               ▼
┌────────────┐ ┌────────────────┐
│ DEFEND     │ │ L2 AI ORCH     │  Confirms medium-confidence
│ (auto)     │ │ (token cost)   │  findings, generates fixes
└──────┬─────┘ └───────┬────────┘
       │               │ (confirmed)
       └───────┬───────┘
               ▼
┌─────────────────────────────┐
│  DEFENSE LAYER              │  Produces concrete actions:
│  RiskGate + Mode            │    fix_code | block_ip | rotate_key
│  (reused from fix/risk_gate)│    update_dep | patch_config
└─────────────┬───────────────┘
              │
      ┌───────┴───────┐
      ▼               ▼
┌──────────┐   ┌──────────┐
│ APPLIED  │   │ QUEUED   │  (per user mode: CONFIRM/AUTO/AUTOPILOT)
└──────────┘   └──────────┘
```

---

## 2. Layer 1: Detection Agents

### 2.1 Existing (36 agents — reused as-is)

| Group | Count | Agents |
|---|---|---|
| SCANNER | 11 | CoreScanner, SideFileScanner, UIScanner, DependencyScanner, TestScanner, DeadCodeScanner, EnvScanner, RouteGraphScanner, TypeScanner, CommentScanner, DuplicateScanner |
| SECURITY | 30 | TaintAnalyzer, SecretScanner, ConfigAuditAgent, HeaderAuditAgent, RateLimitAuditor, CORSAuditor, DependencyCVEChecker, MisconfigAgent, JWTSecurityAgent, SensitiveDataAgent, AuthenticationAuditAgent, SSRFProtectionAgent, InjectionAgent, AuthZAgent, CryptoAgent, NetworkAgent, PrivacyAgent, DependencyVulnerabilityAgent, ComplianceAgent, SecretsGuard, SupplyChainAgent, IaCScannerAgent, ContainerScannerAgent, PolicyEngineAgent, CVEMonitorAgent, RedTeamAgent, PreCheckAgent, RuntimeValidatorAgent, AppMapperAgent, BrowserTesterAgent |
| GUARD | 4 | GovernanceAgent, HistoryAgent, BlastRadiusAgent, PlanAuditorAgent |
| PROBER | 1 | SecurityProber (dev-mode only) |

### 2.2 New (4 agents)

| Agent | File | Threat Domain | Detection Method |
|---|---|---|---|
| **LLMSecurityAgent** | `patchi/core/security/agents/llm_security_agent.py` | Prompt injection, tool over-permissioning, data exfiltration via AI, MCP misconfig | Regex + AST: user input -> LLM calls, unused dangerous tools, LLM output with secrets |
| **BusinessLogicAgent** | `patchi/core/security/agents/business_logic_agent.py` | Race conditions, mass assignment, rate limit bypass, price manipulation | AST: TOCTOU patterns, `**kwargs`/`update()`, unprotected POST routes |
| **SessionManagementAgent** | `patchi/core/security/agents/session_mgmt_agent.py` | Session fixation, improper timeout, token leakage, concurrent session issues | Regex + config audit: `session_id` from URL params, missing expiration config, token in logs |
| **WebSocketSecurityAgent** | `patchi/core/security/agents/websocket_agent.py` | WS message injection, missing origin validation, WS DoS, unencrypted WS | Regex + route graph: `ws://` URLs, missing origin check on `@app.websocket`, missing WS rate limiting |

All new agents follow the existing pattern:
- `@register` decorator, `group = AgentGroup.SECURITY`
- Deterministic only (regex + AST, zero AI calls)
- Produce `Finding` objects via standard `make_finding()` helper

---

## 3. Data Types (`patchi/core/security/gated_finding.py`)

```python
@dataclass
class GatedFinding:
    finding: Finding
    confidence_score: float       # 0.0-1.0
    confidence_tier: str          # "high" | "medium" | "low"
    routing: str                  # "defend" | "ai_analyze" | "human_review" | "discard"
    routing_reason: str
    confirmed_by: list[str]
    composite_score: float
    owasp_category: str
    cwe_ids: list[str]

@dataclass
class GatedReport:
    findings: list[GatedFinding]
    stats: dict
```

---

## 4. ConfidenceGate (`patchi/core/security/confidence_gate.py`)

### Scoring Formula

```
confidence = 0.0
+ method_precision       regex=0.3, AST=0.5, taint_flow=0.7, deterministic=0.9
+ severity_bonus         high=+0.1, critical=+0.2
+ multi_agent_bonus      +0.1 per confirming agent, max +0.3
+ location_precision      exact line=+0.1, within 5 lines=+0.05
- known_fp_penalty       -0.3 if matches known false-positive pattern
- ambiguity_penalty      -0.2 if no code snippet / heuristic match
= final (clamped to [0.0, 1.0])
```

### Tier Routing

| Score Range | Tier | Routing | Action |
|---|---|---|---|
| >= 0.7 | HIGH | `defend` | Pass directly to Defense Layer |
| >= 0.4 | MEDIUM | `ai_analyze` | Layer 2 AI confirms + generates fix |
| 0.0-0.39 | LOW | `human_review` | Queue for user (if severe) or discard |
| 0.0 (known FP) | ZERO | `discard` | Silently filtered |

---

## 5. DetectionPipeline (`patchi/core/security/detection_pipeline.py`)

Orchestrates: CorrelatedFinding[] -> ConfidenceGate -> GatedFinding[] -> Layer2Orchestrator (for medium) -> GatedReport.

---

## 6. Layer 2 AI Orchestrator (`patchi/core/security/layer2_orchestrator.py`)

- Batches similar findings (same file + CWE) into single AI calls
- Rate limits: max 10 calls/minute
- Caches results by (CWE + file + type) hash with 24h TTL
- Produces: confirmed (bool), summary, fix_code, test_code, confidence_adjustment

---

## 7. Defense Layer (`patchi/core/security/defense_layer.py`)

### Defense Actions

| Type | Target | Method |
|---|---|---|
| `fix_code` | File path | Creates Patch -> RiskGate -> apply |
| `update_dependency` | Package name | `pip install --upgrade` / `npm update` |
| `block_ip` | IP address | `iptables -A INPUT -s IP -j DROP` |
| `rotate_secret` | Env var name | Generate + replace in .env + code |
| `patch_config` | Config file | Edit config with known-good values |
| `escalate` | Finding ID | Queue for human review |

All code changes pass through **existing RiskGate** which enforces CONFIRM/AUTO/AUTOPILOT modes, no-touch paths, quiet hours, and blast radius checks.

---

## 8. Integration

Added to `Coordinator.run_group(SECURITY)` after `SecurityOrchestrator.correlate()`:

```python
if self.config.get("pipeline", {}).get("enabled", False):
    pipeline = DetectionPipeline(self.root, self.config)
    gated = pipeline.process(self.last_security_report)
    defense = DefenseLayer(self.root, self.config)
    results = defense.defend_all(gated.defend)
```

---

## 9. Files

| File | Lines | Status |
|---|---|---|---|
| `patchi/core/security/gated_finding.py` | 60 | New |
| `patchi/core/security/confidence_gate.py` | 120 | New |
| `patchi/core/security/detection_pipeline.py` | 100 | New |
| `patchi/core/security/layer2_orchestrator.py` | 200 | New |
| `patchi/core/security/defense_layer.py` | 520 | Expanded (12 action types, 71 finding mappings, 8 pkg managers) |
| `patchi/core/security/llm_security_agent.py` | 190 | New (LLM prompt injection detection) |
| `patchi/core/security/business_logic_agent.py` | 170 | New (business logic abuse) |
| `patchi/core/security/session_management_agent.py` | 170 | New (session management) |
| `patchi/core/security/websocket_security_agent.py` | 140 | New (WebSocket security) |
| `patchi/core/security/request_interceptor.py` | 220 | New (runtime request interceptor) |
| `patchi/core/security/scheduler.py` | 230 | New (background scan scheduler) |
| `patchi/core/security/defectdojo.py` | 210 | New (optional DefectDojo reporter) |
| `patchi/core/security/skills/*.skill.md` | 8 files | New (SecOpsAgentKit adaptations) |
| `patchi/core/agents/base.py` | +50 | Modified (auto skill loading) |
| `patchi/core/agents/coordinator.py` | +15 | Modified (pipeline wiring) |

---

## 10. Reused (No Changes)

RiskGate, Mode enum, SecurityOrchestrator, BlastRadiusAgent, GovernanceAgent, HistoryAgent, BrainLearning, patchi_apply_gate, patchi_policy_gate.

---

## 11. Token Impact

| Scenario | AI Calls | Tokens |
|---|---|---|
| Typical scan (50 findings) | ~15 | ~60K |
| Heavy scan (150 findings) | ~45 | ~180K |
| Without pipeline (AI on all) | 150 | ~600K |
| **Savings** | **70-90%** | |
