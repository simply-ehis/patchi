# Patchi — Master Plan
### Consolidated Architecture, Security & Scoring Strategy
Draft v0.1 · Living document

---

## 0. What Patchi Is

An open-source, self-hostable defender agent system for solo devs. Four pillars: **Test**, **Scan** (working, CLI-driven), **Defend**, **Monitor** (target of this plan). Everything below assumes full open source, self-hostable in every mode, and callable as an MCP tool by other agents (not itself a coding agent like Claude Code — a defender that other tools invoke).

Core principle running through every section: **bank on existing open-source security tooling as the substrate; Patchi's own code is the orchestration layer** — routing, classification, agent logic, UX. Don't rebuild WAFs, IDS engines, or standards bodies' work.

---

## 1. Deployment Shapes

One core engine, three adapters — never three separate products.

```
                         ┌─────────────────────┐
                         │     PATCHI CORE      │
                         │  (detector + agents  │
                         │   + policy engine)   │
                         └──────────┬───────────┘
          ┌─────────────────────┬──┴────────────────────┐
   ┌──────▼──────┐     ┌────────▼────────┐     ┌─────────▼─────────┐
   │  EMBEDDED    │     │   STANDALONE     │     │  GITHUB APP/BOT   │
   │  (in-process │     │   (sidecar,      │     │  (repo + PR level)│
   │   SDK)       │     │   self-hosted)   │     │                    │
   └──────────────┘     └──────────────────┘     └────────────────────┘
```

- **Embedded** — npm/pip package, middleware-style, talks to Core over local socket/thread. Lowest overhead, ideal default for solo devs.
- **Standalone/sidecar** — Docker/binary deployment, reverse-proxy + log/syscall ingestion. `docker-compose up` is the onboarding bar. This is where the full detector + agent roster has the broadest visibility.
- **GitHub App/bot** — repo-level, PR/CI-triggered. Distinct credential scope from runtime modes. Comments on PRs, can gate merges once trusted.

All three emit into the same internal event schema and route through the same detector → dispatcher → agent pipeline; only signal sources and action targets differ.

---

## 2. Core Architecture

```
 SIGNAL SOURCES ──▶ ALWAYS-ON DETECTOR ──▶ DISPATCHER/CLASSIFIER ──▶ SPECIALIST AGENTS ──▶ ACTION LAYER ──▶ AUDIT LOG
```

**Signal sources:** HTTP traffic, app/access logs, host/container syscalls (Falco, standalone only), dependency manifests, git diffs/PRs, secret-scan sweeps.

**Always-on detector:**
- Rule engine on **Sigma** (portable rule format, compiles to Wazuh/Elastic/etc., reuses community rule corpus).
- Lightweight anomaly layer on top (z-score/EWMA over request rate, error rate, payload-size distributions) — start simple, avoid undertrained ML.
- Every event normalized to an envelope: `event_id`, `source`, `technique_id` (MITRE ATT&CK), `confidence`, `raw_signal`, `suggested_agent`, `timestamp`.

**Dispatcher/classifier:** routes `technique_id` + confidence to the right agent, sets urgency (sync block vs async investigate), rate-limits agent invocation (prevents resource-exhaustion via forced wake-ups).

**Specialist agent roster** (anchored to MITRE ATT&CK tactics, narrow scoped toolsets):

| Agent | Handles | OSS backbone |
|---|---|---|
| Injection Agent | SQLi, XSS, command/path injection | OWASP CRS via Coraza/ModSecurity |
| Auth Agent | Brute force, credential stuffing, session/token abuse | Wazuh + custom rules |
| Dependency Agent | Vulnerable/typosquat packages, CVEs | OSV-Scanner, Trivy, Grype |
| Secrets Agent | Leaked keys/tokens | Gitleaks, TruffleHog |
| Network Agent | Volumetric/DDoS, protocol anomalies | Suricata / Zeek |
| Runtime Agent | Container escape, anomalous process behavior | Falco (standalone only) |
| Triage/Anomaly Agent | Unclassified statistical outliers | Detector's own anomaly layer |

**Action layer:** block/challenge/throttle/rotate/rollback (runtime modes); PR comment/required-check-fail/auto-issue (repo mode).

**Audit log:** append-only, hash-chained, exportable. Every detection, action, and human override logged — this is what makes autonomous action defensible after the fact.

---

## 3. OSS Foundations

| Layer | Tool | Role |
|---|---|---|
| SIEM/host detection backbone | Wazuh | Log ingestion + rule engine |
| Detection rule format | Sigma | Portable rules across backends |
| Runtime/container security | Falco (CNCF) | eBPF syscall monitoring |
| Network IDS | Suricata / Zeek | Protocol + signature detection |
| WAF | OWASP CRS on Coraza | Injection Agent's enforcement arm |
| Dependency/SCA | OSV-Scanner, Trivy, Grype | Dependency Agent's scan source |
| Secrets scanning | Gitleaks, TruffleHog | Secrets Agent's scan source |
| SAST | Semgrep | Repo-mode static analysis |
| DAST | OWASP ZAP, Nuclei | Scan tool + attack-sim source |
| Log shipping | Vector / Fluent Bit | Feeds standalone detector |

**License check before locking in:** audit each dependency (Coraza Apache-2.0, Wazuh GPL-2.0, Falco Apache-2.0, Suricata GPL-2.0, Semgrep core LGPL-2.1) against Patchi's own chosen license. Invoking GPL tools as separate processes is generally fine; static-linking is not — confirm with a lawyer/FSF guidance before shipping, not assumed here.

---

## 4. Attack Simulation & Validation

Permanent regression suite, not a one-time exercise.

**Target ranges:** OWASP Juice Shop, DVWA, WebGoat — isolated Docker network, never exposed beyond the test harness.

**Simulation tooling:**
| Tool | Use |
|---|---|
| Atomic Red Team (MITRE) | Discrete tests mapped 1:1 to ATT&CK technique IDs — pairs directly with the agent roster |
| Caldera (MITRE) | Multi-step adversary emulation for chained scenarios |
| Nuclei | Templated payloads; doubles as DAST tool |
| Stratus Red Team | Cloud-specific technique emulation (bring in once standalone mode targets cloud) |

**The test loop (CI for the security product itself):**
1. Deploy Patchi in front of the target range.
2. Fire an Atomic Red Team test with a known `technique_id`.
3. Assert in order: detector fired → classification correct → correct agent dispatched → action landed within latency budget → audit log correct.
4. Track detection rate, false-positive rate, mean time to dispatch, mean time to action as first-class published metrics.
5. Run the full atomic suite as a gating CI job on every Patchi Core release.

**Success bar before "full pro":** atomic suite green against Juice Shop for at least Injection, Auth, Dependency, and Secrets agents, with a documented false-positive rate.

---

## 5. Security-of-the-Security-Tool (closing the "0 score, local tool" gap)

The original bug: scoring a local CLI as "0 security" with no suggestions was two separate failures wearing one symptom — (a) real local-mode risks weren't being checked at all, and (b) inapplicable backend/network checks were dragging the score down for no reason. Section 5 fixes (a); Section 7 fixes (b).

**Supply chain integrity**
- Lockfile pinning, no floating semver ranges in Patchi's own deps
- No unaudited `postinstall` scripts
- Signed/provenance releases (SLSA, `npm provenance`, GPG-signed tags)
- Own dependency tree run through the Dependency Agent every release

**Local execution safety**
- Sandbox any dynamic loading of plugins/rules/custom scan definitions — a malicious rule file or `.patchirc` shouldn't get code execution just from `patchi scan`
- If scanning ever executes the *target repo's* code (tests, build scripts) to analyze it, that's an untrusted-execution boundary — isolate it (restricted subprocess, not `require()`)

**Secrets handling**
- Hosted-mode API keys in OS keychain (keytar/libsecret), not plaintext config
- No `.env` content ever logged or telemetry-reported, even in debug mode

**Update mechanism**
- Auto-update verifies signatures before replacing the binary

**Hosted mode guards itself too:**
- Hosted infra (dispatcher, agent runtime, API surface) runs behind the same detect/defend pipeline as any customer app — scoped as its own protected instance with its own audit trail.
- Meta-layer needs a separate operational watcher (heartbeat/dead-man's switch) — who alerts you if the dispatcher hangs or the audit log stops writing is a basic-ops question, invisible until it's the reason an incident was missed.

---

## 6. Scan/Detect/Fix/Suggest/Improve — Full Checklist

**Layer 1 — Structural/hygiene** (existing): broken imports, dead code, duplicate code, unused exports, circular deps, type mismatches.

**Layer 2 — Security** (existing): injection classes, hardcoded secrets, dependency CVEs, insecure defaults, auth flaws.

**Layer 3 — Silent/logical bugs** (the gap): bugs that don't look like errors, only appear behaviorally.

| Technique | Catches | Why it works |
|---|---|---|
| Mutation testing (Stryker, mutmut) | Tests that pass but verify nothing | Breaks code in small ways, checks if tests notice — surviving mutants = effectively untested paths |
| Property-based testing (fast-check, Hypothesis) | Unthought-of edge cases | Generates inputs against invariants instead of hand-picked examples |
| Combinatorial/pairwise testing | Combo bugs (flag A + config B + state C only) | Systematically tests interaction pairs/triples, not flags in isolation |
| Taint/dataflow analysis (CodeQL, Semgrep dataflow) | Silent failures — unvalidated input reaching a sink functions later | Tracks value flow across function boundaries, not just syntax |
| Golden/snapshot + semantic diffing | "Looks perfect but output quietly changed" | Structural diff catches behaviorally-different output that string diff misses |
| Runtime invariant assertions | Silent state corruption | Pre/post-condition checks in debug/canary builds surface violations that never throw in prod |
| Chaos/fault injection | Combo bugs under failure conditions (timeout + retry + partial write) | Deliberately injects latency/failure, watches for silent inconsistency |

**The iterative fix loop** needs a composite scoring function per candidate, not "first thing that compiles":
1. Passes existing test suite
2. Passes mutation-tested subset for the affected file(s)
3. Reduces blast radius vs. previous candidate
4. Introduces no new Layer 1/2 findings on the diff

Rank candidates on this composite score; keep generating until a candidate clears all four or a max-iteration budget is hit.

---

## 7. Blast Radius — Computation

Two distinct things needed: theoretical (static graph) and real (production-weighted) blast radius.

**Step 1 — Symbol-level dependency graph, not file-level.** Track which specific symbol changed (function signature, exported constant, config key, type shape), then which symbols reference it. File-level granularity is too coarse for "changed one word in a key file."

**Step 2 — Both directions.**
- Downstream: everything transitively depending on the changed symbol (BFS on reversed depends-on edges) — "who breaks."
- Upstream: what the changed symbol itself depends on — useful for root-cause diagnosis of a detected bug.

**Step 3 — Weight the graph, don't just count nodes.**
- Test coverage per affected node (uncovered + affected = highest real risk)
- Runtime traffic (via OpenTelemetry tracing from monitor mode) — theoretically-affected but zero-traffic-in-30-days nodes are lower real risk than the static graph implies
- Criticality tags (auth/payment/data-write weighted higher than a logging helper)

**Step 4 — Compute twice: damage graph (buggy commit) and repair graph (fix commit).** Diff the two. Reveals what the bug broke, what the fix repairs, and whether the fix ripples into new territory the bug never touched — feeds directly into the fix-scoring loop in Section 6.

**Step 5 — Visualize as an overlay on the existing node-view UI.** Red = broken (damage graph), amber = affected but untested, green = covered and passing, animated diff between damage-graph and repair-graph on a proposed fix. A before/after blast-radius diff, not just a static import map — this is a genuine differentiator since most tools in this space stop at static graphs.

---

## 8. Context-Aware Security Scoring

**The core fix:** don't score every app against every domain's controls. Classify which domains apply, then score only those. A CLI with no server shouldn't be judged against backend auth controls, and getting a 0 there isn't a real finding — it's a wrong question.

**Why hybrid, not pure-AI or pure-static:**
| Approach | Problem |
|---|---|
| Static exhaustive list per domain | Goes stale, misses new domains |
| Search/ask fresh every scan | Non-deterministic, unauditable |
| Pure AI-suggested defense list | Confidently invents plausible-but-ungrounded requirements |

**Resolution:** versioned, source-of-truth taxonomy (stable, auditable, community-reviewable) + an AI/heuristic classifier that only decides *which taxonomy branches apply*. The AI routes; it never invents requirements.

**Pipeline:**
```
SIGNALS ──▶ CONTEXT CLASSIFIER ──▶ APP PROFILE ──▶ DOMAIN ACTIVATION ──▶ SCORING
```

1. **Signals:** presence/absence of network listeners, HTTP routes, auth/session code, DB/ORM, CLI vs server entrypoint, frontend framework with no backend calls, mobile manifests, IaC/Dockerfiles, CI/CD config, payment/PII handling, LLM/API-key usage. Mostly already gathered by Patchi's context engine for other purposes.

2. **App Profile:** a *set* of components, each tagged with active domains — not one label for the whole repo. E.g. Patchi's CLI binary → Local Tool/Supply Chain active, Backend API n/a; Patchi's hosted dispatcher → Backend API + Auth + Network active; Patchi's web UI → Frontend Web active, Backend API n/a (it's a client). Score components separately, then roll up.

3. **Domain taxonomy — anchored to existing standards, not invented:**
   - OWASP ASVS (general web app controls)
   - OWASP API Security Top 10 (backend/API domain)
   - OWASP Top 10 for LLM Applications (relevant for Patchi's own brain and for LLM-integrated apps it scans)
   - OWASP Mobile Top 10
   - CIS Docker/Kubernetes Benchmarks
   - OWASP Top 10 CI/CD Security Risks
   - SLSA framework (supply chain / local tool domain)

4. **Domain activation — three states, not two:**
   - **Active** — signals confirm applicability, score it
   - **Not applicable** — signals confirm it doesn't apply, shown explicitly as N/A (not silently omitted, not counted as failure)
   - **Unclear** — ambiguous signals, flag one clarifying question rather than guess

5. **Scoring — weighted only over active domains:**
```
context_score = Σ(domain_weight × domain_score) / Σ(domain_weight)   [active domains only]
```
   N/A domains contribute to neither numerator nor denominator. Surface the full breakdown, not just one number — e.g. "Supply Chain: 40/100, Local Execution Safety: 20/100, Backend Auth: N/A, Frontend Web: N/A."

**Drift handling:** re-classify only when the signal set changes meaningfully (new server entrypoint appears, auth library imported) — not every scan, to avoid score jitter. Version the taxonomy itself (semver) so any score is reproducible from `(commit, taxonomy_version, activated_domains)`.

### Taxonomy schema (per domain record)

```yaml
domain_id: "supply-chain-local-tool"
version: "1.0.0"
display_name: "Local Tool Supply Chain Security"
source_standard: "SLSA v1.0 (adapted)"
component_type: "cli"            # cli | backend-api | frontend-web | mobile | infra | llm-integration
weight: 0.9

activation_signals:
  required_any:
    - signal: "has_package_manifest"
    - signal: "is_installable_binary"
  excluded_if:
    - signal: "no_execution_entrypoint"

controls:
  - control_id: "SC-01"
    name: "Dependency pinning"
    description: "Lockfile present, no floating semver ranges in direct deps"
    severity: "high"
    check_method: "static"           # static | dynamic | manual-review
    detector: "lockfile-analyzer"
    remediation_ref: "docs/remediations/SC-01.md"
  - control_id: "SC-02"
    name: "Postinstall script audit"
    severity: "critical"
    check_method: "static"
    detector: "npm-script-scanner"
  - control_id: "SC-03"
    name: "Release provenance"
    severity: "medium"
    check_method: "manual-review"

deprecated_by: null
last_reviewed: "2026-07-03"
```

Design notes: `excluded_if` is as important as `required_any` (turns missing checks into honest N/A, not silent zero); `check_method: manual-review` keeps automation-maturity honest instead of faking a pass/fail; `detector` is a pointer so scanners can be swapped without touching the standard mapping; per-domain versioning lets fast-moving domains (LLM security) update independently of the whole taxonomy.

---

## 9. Security-of-the-Security-Tool — Least Privilege & Trust

- Each specialist agent gets an explicit, minimal tool list — no blanket shell/filesystem/network access "just in case."
- Human-in-the-loop by default for destructive actions (secret rotation, rollback, merge-blocking default to propose+confirm; auto-block/throttle can run autonomously).
- Signed, versioned rule updates — no silent pulling and executing of unvetted community rule changes.
- Separate credentials per deployment mode (GitHub App token / standalone API key / embedded local socket auth never share scope).
- Immutable, hash-chained, exportable audit trail.
- Dogfooding: self-scan Patchi with Patchi's own Dependency and Secrets agents in CI.

---

## 10. Differentiator Upgrades

### CLI-only
- **Provenance-signed scan reports** — local signature/hash chain so a report can't be silently altered before being pasted into a PR or compliance doc.
- **Offline-first taxonomy bundling** — signed local taxonomy bundle, versioned independently of the binary; full context-aware scoring with zero network calls.
- **"Explain my score like I'm new here" mode** — plain-language walkthrough of why each domain activated or didn't, for devs without security-standards literacy.

### Hosted-only
- **Runtime-weighted blast radius as a first-class dashboard surface** — "this CVE is in a path hit 40k times/day" vs. "hit 0 times in 30 days," built on data the always-on detector already collects.
- **Fix-confidence scoring shown as iteration history**, not a one-shot result — "3 candidates evaluated, this one chosen because it reduced blast radius by 80% and introduced 0 new findings."
- **Cross-repo/cross-project context memory** — a secret leaked in repo A that's reused in repo B's config gets flagged as cross-project blast radius, something single-repo tools can't see.

### Both
- **N/A as a first-class, visually distinct score state** everywhere (CLI + dashboard) — directly fixes the original "0 score, no suggestions" frustration.
- **Self-scan as a published, live badge** — Patchi scored against its own context-aware taxonomy, shown in the repo README per release, verifiable not asserted.
- **Community-extensible, versioned taxonomy** (Sigma-rules-style ecosystem for domain-applicability logic) — lets the community contribute new domain records (IoT firmware, browser extensions, etc.), turning context-awareness into an ecosystem rather than a single feature.

---

## 11. Suggested Build Sequence

1. Event schema + audit log (foundation everything writes to)
2. Detector v1 — Wazuh + curated Sigma subset, standalone mode, alerting only, no agents yet
3. Dispatcher + one agent (Injection Agent via Coraza/OWASP CRS) — prove the pipe end-to-end
4. Atomic Red Team harness against Juice Shop — validate step 3 before agent #2
5. Remaining agents, one at a time, each gated by its own atomic-test pass
6. Local-mode security checklist (Section 5) implemented and self-scanned
7. Context taxonomy v1 — start with the Local Tool Supply Chain domain fully populated as a template, then expand
8. Classifier + domain-activation scoring wired into existing scan output
9. Embedded mode SDK extracted from standalone core
10. GitHub App/bot adapter — reuse dispatcher + lowest-risk agents (Dependency, Secrets) for unattended PR operation
11. Public metrics + self-scan badge live in the OSS repo

---

## 12. Open Questions

- License choice for Patchi (MIT/Apache-2.0 vs AGPL — AGPL worth weighing for deterring closed-source hosted forks)
- Where agent "reasoning" runs — local LLM, hosted API, or pluggable/bring-your-own-model
- Unified config schema/precedence across the three deployment modes
- Governance model for community-contributed Sigma rules and taxonomy domain records once public

---

### Appendix A: Build Sequence vs. Current Codebase (as of 2026-07-03)

| Build Step | Status | Notes |
|---|---|---|
| 1. Event schema + audit log | **NOT STARTED** | Log exists (governance + hosted), but no formal event schema |
| 2. Detector v1 (Wazuh + Sigma) | **NOT STARTED** | Agent roster exists but no always-on detector pipeline |
| 3. Dispatcher + Injection Agent | **PARTIAL** | Injection Agent exists, no event dispatcher |
| 4. Atomic Red Team harness | **NOT STARTED** | No test ranges or CI harness |
| 5. Remaining agents | **7/8 DONE** | Missing Triage Agent |
| 6. Local-mode security checklist | **NOT STARTED** | No sandboxing, no update mechanism, no OS keychain |
| 7. Context taxonomy v1 | **NOT STARTED** | No domain taxonomy or scoring pipeline |
| 8. Classifier + domain scoring | **NOT STARTED** | Only file-purpose classifier exists |
| 9. Embedded mode SDK | **NOT STARTED** | Monolithic CLI only |
| 10. GitHub App adapter | **NOT STARTED** | No adapter code |
| 11. Public metrics + badge | **NOT STARTED** | No badge system |

---

*This document consolidates the hosted architecture brief, the self-scan/validation checklist, the blast-radius model, and the context-aware scoring design discussed to date. Test + Scan CLI internals are assumed stable and out of scope.*