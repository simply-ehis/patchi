# Patchi — Builder Brief
### Open-Source Autonomous Test, Scan, Defend & Monitor Agent
Version 0.1 · Draft for architecture review

---

## 1. Vision & Scope

Patchi is an **open-source, self-hostable security agent system** for solo/small-team developers. It has four pillars:

| Pillar | Status | Powered by |
|---|---|---|
| **Test** | Working (CLI) | Existing tester code |
| **Scan** | Working (CLI) | Existing scanner code |
| **Defend** | Target of this brief | New — specialist agents |
| **Monitor** | Target of this brief | New — always-on detector |

The bottleneck is **hosted mode**: turning Patchi from "a CLI you run" into "a defender that lives alongside your app, watches it continuously, and reacts." This brief specs that system end-to-end, on the assumption that everything is open source and every deployment shape is self-hostable — there is no proprietary SaaS-only path.

**Guiding constraint for every design decision below:** bank on existing open-source security tooling as the detection/enforcement substrate; Patchi's own code should mostly be the *orchestration layer* (routing, agent logic, UX) — not reinvented WAFs, IDS engines, or scanners. This keeps Patchi thin, auditable, and trustworthy, which matters enormously for a tool people give production access to.

---

## 2. Deployment Shapes (one core, three faces)

This is the part that needs to be nailed down early because it drives the whole architecture: **Patchi Core must be deployment-agnostic.** Build one engine, then three thin adapters around it.

```
                         ┌─────────────────────┐
                         │     PATCHI CORE      │
                         │  (detector + agents  │
                         │   + policy engine)   │
                         └──────────┬───────────┘
                                    │
          ┌─────────────────────┬──┴────────────────────┐
          │                     │                        │
   ┌──────▼──────┐     ┌────────▼────────┐     ┌─────────▼─────────┐
   │  EMBEDDED    │     │   STANDALONE     │     │  GITHUB APP/BOT   │
   │  (in-process │     │   (sidecar /     │     │  (repo + PR level)│
   │   SDK/agent) │     │   separate       │     │                    │
   │              │     │   deployment)    │     │                    │
   └──────────────┘     └──────────────────┘     └────────────────────┘
```

### 2a. Embedded mode
A lightweight SDK/middleware dropped into the host app (Express/Next/Fastify middleware, Python WSGI/ASGI wrapper, etc.). Runs in-process, taps request/response lifecycle directly. Lowest latency, lowest infra overhead — ideal for the solo-dev target user who doesn't want to run a second service.

- Ships as an npm/pip package.
- Talks to Patchi Core over a local Unix socket or embedded worker thread — not a network hop.
- Config lives in `patchi.config.yml` at repo root.

### 2b. Standalone / sidecar mode
Patchi Core runs as its own deployable unit (Docker container / binary), sitting in front of or beside the target app — reverse-proxy style for web traffic, plus log/metric shipping for runtime signals. This is "real" self-hosted defender mode:

- `docker-compose up` should be the entire onboarding experience.
- Ingests: reverse-proxied HTTP traffic, app logs (shipped via Vector/Fluent Bit), and optionally host/container syscalls (via Falco).
- Exposes a local dashboard (the "node view" you mentioned) and a control API.
- This is the mode where the always-on detector + full agent roster make the most sense, since it has the broadest visibility.

### 2c. GitHub App/bot mode
Shifts left — operates on the *repo*, not the *runtime*. Installed as a GitHub App:

- Runs scan/test agents on PR open/push (via GitHub Actions or a webhook-triggered worker).
- Posts findings as PR review comments, with severity labels and suggested fixes.
- Can gate merges (required check) once confidence is high enough.
- The bot identity should be distinct from the runtime defender identity in logs/audit trails, even though they share Patchi Core — a compromised bot token and a compromised runtime agent are different blast radii, and your permission model needs to reflect that (see §6).

**Design rule:** all three modes emit events into the same internal event schema and route through the same detector → dispatcher → agent pipeline. The only thing that changes is where events come from and where actions land (block a request vs. comment on a PR vs. rotate a secret).

---

## 3. Core Architecture

```
 ┌────────────┐      ┌───────────────────┐      ┌──────────────────┐
 │  SIGNAL     │      │   ALWAYS-ON        │      │   DISPATCHER /    │
 │  SOURCES    │─────▶│   DETECTOR         │─────▶│   CLASSIFIER      │
 │ (traffic,   │      │  (Sigma rules +    │      │ (maps signal →    │
 │ logs, CVEs, │      │   anomaly scoring) │      │  ATT&CK technique │
 │ syscalls,   │      │                    │      │  → agent)         │
 │ PR diffs)   │      └────────────────────┘      └─────────┬────────┘
 └────────────┘                                              │
                                                               ▼
                                          ┌────────────────────────────────┐
                                          │      SPECIALIST AGENTS          │
                                          │  (scoped tools + policy limits) │
                                          └────────────────────────────────┘
                                                               │
                                                               ▼
                                          ┌────────────────────────────────┐
                                          │   ACTION / RESPONSE LAYER       │
                                          │ (block, patch, alert, rotate,   │
                                          │  comment-on-PR, rollback)       │
                                          └────────────────────────────────┘
                                                               │
                                                               ▼
                                          ┌────────────────────────────────┐
                                          │   AUDIT LOG (immutable,          │
                                          │   append-only, exportable)       │
                                          └────────────────────────────────┘
```

### 3.1 Signal sources
- HTTP request/response stream (embedded/standalone modes)
- Application + access logs
- Host/container syscalls (Falco, optional — standalone mode only)
- Dependency manifests (`package.json`, `requirements.txt`, lockfiles) — repo mode
- Git diffs / PR content — repo mode
- Secret-scan sweep results

### 3.2 Always-on detector
This is the piece worth being most disciplined about, because false positives will kill trust with solo devs faster than anything else.

- **Rule engine:** adopt **Sigma** as the detection-rule format. Write/curate rules once, they compile to whatever backend you run underneath (see §4). This also means the open-source community's existing Sigma rule corpus is usable on day one.
- **Anomaly layer:** a lightweight statistical baseline (request rate, error rate, payload-size distributions per route) sitting on top of the rule engine, to catch things signatures miss. Keep this simple initially — z-score/EWMA on a handful of features beats an undertrained ML model.
- **Output:** every detection event carries a normalized envelope:

```json
{
  "event_id": "uuid",
  "source": "embedded|standalone|github",
  "technique_id": "T1190",         // MITRE ATT&CK
  "confidence": 0.82,
  "raw_signal": { ... },
  "suggested_agent": "injection-agent",
  "timestamp": "..."
}
```

### 3.3 Dispatcher / classifier
Thin routing layer. Given a `technique_id` + confidence, maps to the correct specialist agent, and decides urgency (sync block vs. async investigate). This is also where you enforce rate-limiting on agent invocation — an attacker who can trigger unlimited agent wake-ups is a resource-exhaustion vector against *you*.

### 3.4 Specialist agents (roster)
Anchor each agent to MITRE ATT&CK tactic coverage rather than an ad hoc taxonomy — this gives shared vocabulary and lets you map OSS tool output directly onto agent responsibilities.

| Agent | Handles | Primary OSS backbone |
|---|---|---|
| **Injection Agent** | SQLi, XSS, command/path injection | OWASP CRS (via Coraza/ModSecurity) |
| **Auth Agent** | Brute force, credential stuffing, session/token abuse | Custom rules on Wazuh + rate data |
| **Dependency Agent** | Vulnerable/typosquat packages, CVEs | OSV-Scanner, Trivy, Grype |
| **Secrets Agent** | Leaked keys/tokens in code, logs, configs | Gitleaks, TruffleHog |
| **Network Agent** | Volumetric/DDoS, protocol anomalies | Suricata / Zeek |
| **Runtime Agent** | Container escape, anomalous process behavior | Falco (standalone mode only) |
| **Triage/Anomaly Agent** | Catch-all statistical outliers, unclassified signals | Detector's own anomaly layer |

Each agent gets a **narrow, explicit toolset** — the injection agent can push a WAF rule change; it cannot rotate secrets or touch CI config. This containment is a security requirement, not a nice-to-have (see §6).

### 3.5 Action/response layer
Concrete outputs per mode:

- Embedded/standalone: block/challenge request, apply hot WAF rule, throttle IP, rotate a flagged secret, trigger rollback hook.
- GitHub mode: PR comment with finding + suggested diff, required-check failure, auto-opened issue for confirmed CVEs.

### 3.6 Audit log
Append-only, exportable (JSON Lines to start). Every detection, every agent action, every human override gets logged. This is non-negotiable for a tool people are trusting with autonomous defensive actions — you want to be able to answer "what did Patchi do and why" after the fact, always.

---

## 4. OSS Foundations to Bank On

Building the detection/enforcement substrate from scratch is the wrong use of your time and it's also a security liability (untested homegrown WAF logic vs. rules battle-tested across thousands of deployments). Wrap, don't rebuild.

| Layer | Tool | Role in Patchi |
|---|---|---|
| SIEM / host detection backbone | **Wazuh** | Log ingestion, rule evaluation engine, agent-based host monitoring |
| Detection rule format | **Sigma** | Portable rule definitions, compiled to Wazuh/Elastic/etc. |
| Runtime/container security | **Falco** (CNCF) | eBPF syscall monitoring — Runtime Agent's eyes |
| Network IDS | **Suricata** / **Zeek** | Protocol + signature-level network detection |
| WAF | **OWASP CRS** on **Coraza** (Go, embeddable) | Injection Agent's enforcement arm |
| Dependency/SCA | **OSV-Scanner**, **Trivy**, **Grype** | Dependency Agent's scan source |
| Secrets scanning | **Gitleaks**, **TruffleHog** | Secrets Agent's scan source |
| SAST | **Semgrep** | Repo-mode static analysis, custom rule support |
| DAST | **OWASP ZAP**, **Nuclei** | Doubles as scan tool AND attack-sim source (§5) |
| Log shipping | **Vector** or **Fluent Bit** | Feeds standalone-mode detector |

License check before you lock these in: Coraza is Apache 2.0, Wazuh is GPL-2.0, Falco is Apache 2.0, Suricata is GPL-2.0, Semgrep's core engine is LGPL 2.1 (rules are mixed licensing — check individual rule packs). Since Patchi itself is going fully open source, audit each dependency's license against whatever license you pick for Patchi (MIT/Apache-2.0 recommended for max adoption) before shipping — GPL components you *invoke as a separate process* are generally fine; ones you'd statically link are not.

---

## 5. Attack Simulation & Validation Framework

This is what proves the detector→dispatcher→agent loop actually works, not just that individual tools work in isolation. Treat it as a permanent regression suite, not a one-time exercise.

### 5.1 Target ranges
Stand up deliberately vulnerable apps as permanent test fixtures:
- **OWASP Juice Shop** — modern web app vulnerabilities, great for the Injection/Auth agents
- **DVWA** / **WebGoat** — classic vuln classes, good baseline coverage
- Spin these up in an isolated Docker network — never expose them beyond the test harness.

### 5.2 Attack simulation tooling
| Tool | Use |
|---|---|
| **Atomic Red Team** (MITRE) | Library of small, discrete tests mapped 1:1 to ATT&CK technique IDs — perfect pairing with your agent roster. Run a technique, assert the *correct* agent woke up. |
| **Caldera** (MITRE) | Multi-step adversary emulation, for testing chained-attack scenarios once atomic tests pass |
| **Nuclei** | Templated attack payloads against Juice Shop/DVWA — also doubles as your DAST tool |
| **Stratus Red Team** | Cloud-specific technique emulation — bring in once standalone mode has cloud deployment targets |

### 5.3 The test loop (this is your CI for the security product itself)
1. Deploy Patchi (whichever mode you're testing) in front of the target range.
2. Fire an Atomic Red Team test with a known `technique_id`.
3. Assert, in order: (a) detector fired an event, (b) `technique_id` classification was correct, (c) the correct specialist agent was dispatched, (d) the agent's action landed within an acceptable latency budget, (e) the audit log recorded all of it correctly.
4. Track **detection rate**, **false-positive rate**, **mean time to dispatch**, and **mean time to action** as first-class metrics — put them on a dashboard, publish them in the repo README. For an open-source security tool, these numbers *are* your credibility.
5. Run the full atomic suite on every Patchi Core release as a gating CI job, not just ad hoc.

### 5.4 Success bar before "full pro"
Don't move to the fuller specialist-agent buildout until the atomic-test suite is green against Juice Shop for at least the Injection, Auth, Dependency, and Secrets agents, with a documented false-positive rate. That's the concrete, boring, unglamorous milestone that de-risks everything after it.

---

## 6. Security-of-the-Security-Tool (non-negotiables)

A tool that scans, defends, and takes autonomous action on someone's production app is an extremely high-value target itself. Bake these in from day one, not retrofitted later:

- **Least-privilege agents.** Each specialist agent gets an explicit, minimal tool list. No agent gets blanket shell/filesystem/network access "just in case."
- **Human-in-the-loop by default for destructive actions.** Auto-block/throttle is fine to run autonomously; secret rotation, rollback, and merge-blocking should default to "propose + confirm" until a project opts into full autonomy per action type.
- **Signed, versioned rule updates.** If Sigma rules/WAF rules auto-update from a community feed, sign them and pin versions — don't let Patchi silently pull and execute unvetted rule changes.
- **Separate credentials per deployment mode.** GitHub App token, standalone-mode API key, and embedded-mode local socket auth should never share scope.
- **Immutable audit trail**, exportable, tamper-evident (hash-chain the log entries at minimum).
- **Self-scan Patchi with Patchi.** Dogfood the Dependency and Secrets agents against Patchi's own repo in CI.

---

## 7. Suggested Build Sequence

1. **Event schema + audit log** — the unglamorous foundation everything else writes to.
2. **Detector v1**: wrap Wazuh + a curated Sigma rule subset, standalone mode only, no agents yet — just correct alerting.
3. **Dispatcher + one agent** (Injection Agent, backed by Coraza/OWASP CRS) — prove the full pipe end-to-end.
4. **Atomic Red Team harness against Juice Shop** — validate step 3 before building agent #2.
5. **Remaining agents**, one at a time, each gated by its own atomic-test pass.
6. **Embedded mode SDK** — once standalone mode's core is stable, extract the thin adapter.
7. **GitHub App/bot** — repo-mode adapter reusing the same dispatcher + Dependency/Secrets agents (lowest-risk agents to run unattended on PRs).
8. **Public metrics dashboard** (detection rate, FP rate, MTTD/MTTA) as part of the OSS repo — this is your trust signal to the community.

---

## 8. Open Questions to Resolve Before Coding

- License choice for Patchi itself (MIT vs Apache-2.0 vs AGPL — AGPL worth considering if you want to discourage closed-source SaaS forks of a hosted-mode competitor).
- Where does agent "reasoning" run — local LLM call, hosted API, or pluggable (bring-your-own-model)? This affects both cost and how comfortable people feel self-hosting.
- Config format and precedence across the three modes (single `patchi.config.yml` schema shared everywhere, mode-specific overrides).
- Governance model for community-contributed Sigma rules/agent definitions once this is public.

---

*This brief covers Defend + Monitor architecture and the OSS/testing foundation. Test + Scan CLI internals are assumed stable and out of scope here.*
