# STRIDE Threat Model — Patchi Vulnerability Scanner

## Overview
This document identifies security threats across the Patchi vulnerability scanning pipeline and documents corresponding mitigations. Threats are classified per the STRIDE framework (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege).

---

## Threat Table

| ID | Category | Affected Component | Threat Description | Likelihood | Impact | Mitigation |
|----|---|---|---|---|---|---|
| S-1 | **Spoofing** | Auth/Session | An attacker submits malicious code under a forged identity to trigger false vulnerability reports. | Medium | Medium | - All scan requests authenticated via JWT bearer tokens<br>- Session binding to user account; findings scoped to caller<br>- Rate limiting per user/IP (configurable via governor) |
| S-2 | **Spoofing** | Model Input | Crafted CPG/graph inputs designed to cause model inference crashes or out-of-bounds behavior. | Medium | High | - Process isolation (`RunMode.PROCESS`) ensures native crashes do not affect scanner master process<br>- Input validation: node/edge count caps enforced at `graph_to_tensors`<br>- Model trust gate: untrusted models (no `.trained` marker) refuse to emit findings |
| S-3 | **Tampering** | Model File | An adversary replaces the ONNX classifier model with a tampered version to alter findings. | Medium | High | - SHA-256 checksum sidecar (`<model>.sha256`) verified on session load<br>- Model load path rejects mismatched checksums with clear skip reason<br>- `allow_untrained` flag only bypasses marker check for smoke-testing, never disables checksum |
| S-4 | **Tampering** | CPG Extraction | Malformed or obfuscated source code produces corrupted CPGs, leading to downstream failures. | Low | Medium | - CPG extractor validates node/edge invariants before classification<br>- Fallback to heuristic rules when CPG is malformed (VulnerabilityClassifier)<br>- Graceful degradation: if GNN model unavailable, heuristic detector operates independently |
| S-5 | **Repudiation** | Audit Logging | A scan completes but no audit trail exists, enabling denial of scan occurrence. | Low | Medium | - Every `p scan` execution writes a JSON log entry to `.patchi/scan_history/`<br>- Log includes: timestamp, model version hash, finding count, agent participation<br>- Immutable append-only format; entries signed with HMAC when possible |
| S-5 (revised) | **Repudiation** | Daemon Scheduler | Scan scheduler daemon runs without visible audit trail. | Medium | Medium | - ScanScheduler exposes `get_results()` returning structured data<br>- Every result includes agent, severity, and trust gate status<br>- Worksheet traces per-task (see `worksheets/`) maintain execution lineage |
| I-1 | **Information Disclosure** | Model Details | ONNX model architecture, class catalog, or weight details leaked via error messages. | Low | Low | - Error messages generic; no model-internal data exposed<br>- `--verbose` flag for development only; hidden in production<br>- Model checksums do not reveal architecture details |
| I-2 | **Information Disclosure** | Source Code | Scanned source code or extracted findings leaked in API responses or logs. | Medium | High | - `p scan --offline --json` produces machine-readable output; no PII by default<br>- Findings tagged with CWE identifiers only, no raw code stored long-term<br>- Config `redact_sources=true` strips code snippets from reports<br>- Scanner operates in offline mode by default; no external API calls required |
| I-3 | **Information Disclosure** | Dependency Versions | Transitive dependency versions (including vulnerable ones) exposed via error output. | Low | Medium | - Dependency versions logged at INFO level only<br>- `pip-audit` integration optional; disabled by default<br>- Supply-chain SBOM generation opt-in only |
| D-1 | **Denial of Service** | Model Inference | GNN model inference hangs or crashes the scanner process. | High | High | - **Process isolation**: `RunMode.PROCESS` spawns separate Python process for GNN inference;<br>  native crashes (OOM, SIGSEGV) cannot kill master scanner<br>- Timeout enforced via `subprocess.run(timeout=...)` on tracer runs<br>- Circuit breaker: if model raises 3 consecutive exceptions, auto-disable until restart |
| D-2 | **Denial of Service** | Config Flood | Malformed config overwhelms ScanScheduler interval parsing or resource allocation. | Medium | Medium | - Config parsing validated against schema before loading<br>- Interval values bounded: `min(1s, max(24h, parsed_value))`<br>- Invalid config falls back to safe defaults with clear log warning |
| D-3 | **Denial of Service** | File System | Disk exhaustion during scan result serialization or trace output. | Low | Medium | - Output directed to `.patchi/output/` with size quotas (configurable)<br>- Trace reports capped at 10,000 calls; older entries purged<br>- `--offline` mode avoids network-bound operations that could stall |
| E-1 | **Elevation of Privilege** | Findings Severity | Findings escalated beyond their warranted severity (e.g., low → critical). | Medium | High | - **Trust gate**: untrained/models without `.trained` marker capped at MEDIUM severity<br>- CWE-mapped findings include severity override flag "review before acting"<br>- Human-in-the-loop: all findings above LOW require manual approval before triage |
| E-2 | **Elevation of Privilege** | Agent Access | Security agents (Pysa, CodeQL) given excessive filesystem or network access. | Medium | High | - Agents run in sandboxed subprocess with path restrictions<br>- No outbound network calls by default; all fetches opt-in<br>- Capability matrix per-agent registered in `security_agents.py` with minimal required permissions |
| E-3 | **Elevation of Privilege** | Model Weights | Untrained model weights used to fabricate vulnerability findings. | Medium | High | - **Honesty gate**: models without `.trained` marker produce zero findings; clear skip reason logged<br>- `.trained` sidecar file required for trust; SHA-256 checksum verified<br>- `allow_untrained` flag only for development smoke-testing; caps findings at INFO/LOW |

---

## Trust Gate Details (E-3 Slice 3)

The honesty gate is the central defense-in-depth mechanism for threat E-3 and D-3:

| Condition | Model Status | Findings Behavior |
|---|---|---|
| No model file found | `available=False` | Zero findings; skip reason "model not found" |
| Model without `.trained` marker | `available=True` (if `allow_untrained=True`) | Zero findings; skip reason "UNTRAINED — honesty gate active" |
| Model with `.trained` marker + valid SHA-256 | `available=True` | Findings emitted, capped at MEDIUM severity, tagged "review before acting" |
| Model with `.trained` marker + checksum mismatch | `available=False` | Blocked with "checksum mismatch" skip reason |

---

## Recommended Additional Mitigations

| Priority | Measure | Effort | Description |
|---|---|---|---|
| High | Add binary-signing of ONNX models (RSA/ECDSA) | Medium | Replaces SHA-256 sidecar with public-key verification; prevents even modified-sidecar attacks |
| Medium | Implement request signing for `p scan` CLI | Low | JWT request signing ensures only authorized users trigger scans |
| Medium | Add memory sandbox (ulimit/vulcan) for model process | High | Hard limits on RSS/Heap for the GNN inference process |
| Low | Audit logging format standardization | Low | JSON schema for all scan logs; enables SIEM integration |
| Low | TLS for any future API endpoints | Low | If network features added, enforce TLS 1.3+ |

---

## Threat Model Maintenance

- **Review cycle**: Every new agent, model, or CLI flag requires a STRIDE review.
- **New threat reporting**: Use the `bin/agent_review.ps1` cross-model review pipeline to surface AI‑smell–type findings.
- **Documentation**: Updates to this file must accompany any structural change (new module, new agent, new CLI command).