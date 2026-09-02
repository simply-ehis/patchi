# Patchi v0.7.2 — Brain Intelligence Upgrade

🧠 **The brain is now connected.** All disconnected systems are wired into a unified intelligence layer.

## What's New

### BrainContext Bridge
The biggest change: all brain systems (enriched context, project reader, body tags, domain loader, reasoning) are now connected through a single `BrainContext` object. This means:

- **Detection pipeline** classifies findings with full project context
- **Chat** receives enriched understanding of your codebase
- **False-positive reduction** uses architectural knowledge to demote test fixtures and boost critical findings

### 800 Security Domains
Expanded from 48 to 800 security domains covering OWASP, CWE, NIST, SANS, and more. Each domain includes:
- Controls with severity ratings
- Playbooks with fix strategies
- Keyword matching for finding classification

### Context-Aware Finding Classification
Findings are now enriched with:
- **Domain matches** — which security domains apply
- **Project relevance** — critical directories get confidence boost
- **Test fixture detection** — test files automatically demoted for AI review
- **Fix strategies** — playbook references for remediation

## Installation

```bash
pip install patchi
p init
p scan
```

## Quick Start

```bash
# Scan your project
p scan

# Start the web dashboard
p web

# Ask the brain about your codebase
p chat "What are the main security risks in this project?"

# Run the full dev check gate
p dev check --fast
```

## What's Fixed

- cost_alert crash on dashboard startup
- 9 pre-existing ruff errors (F821, F841, E731, F401, E401)
- Domain matching accuracy (80% now, was 0%)
- JSON output includes domain_controls, playbook_ref, fix_strategy
- All 10 web pages return HTTP 200
- Brain map renders with 72 nodes and 38 edges

## What's Changed

- Detection pipeline receives BrainContext for context-aware classification
- Coordinator wires BrainContext into DetectionPipeline during scan
- Chat command injects full brain state instead of generic prompt
- Domain loader uses cached directory-level fingerprint (16x faster)
- Scan gate uses Popen + communicate to avoid Windows deadlocks

## Breaking Changes

None. This is a backwards-compatible release.

## License

Patchi Freemium — Free for personal use and teams under 3 users.
Enterprise licensing available — contact idemudiaehis6@gmail.com.

## What's Next (v0.8.0)

- Real-time collaboration
- Custom agent creation
- Plugin system
- AI-powered code review

---

**Full changelog:** [CHANGELOG.md](CHANGELOG.md)

**Documentation:** [docs/CLI.md](docs/CLI.md) | [docs/WEB.md](docs/WEB.md) | [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)

**Contributing:** [CONTRIBUTING.md](CONTRIBUTING.md)

**Support:** Open an issue or contact idemudiaehis6@gmail.com
