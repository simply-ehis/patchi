# Delegation Brief — Patchi Security Domain Reset

## Mission

Rebuild Patchi's security domain taxonomy from scratch, sourced directly from
established open-source security standards. For **every** standard you use,
produce two matching artifacts per domain:

1. A **domain file** (`domains/{domain_id}.yaml`) — the control taxonomy
2. A **fix-playbook file** (`fix-playbooks/{domain_id}.playbook.yaml`) — how to
   remediate every control in that domain

Do **not** produce a third "plain playbook" file — Patchi's loader only reads
`domains/` and `fix-playbooks/`; a third directory would be dead weight.

---

## Step 0 — License check, before writing anything

For every standard you're about to use, confirm it is safe to derive
structured content from, and note the license alongside the source. As a
starting point (verify current terms yourself before relying on this list):

**Generally safe (open license, built for reuse):**
- OWASP family — ASVS, Top 10, API Security Top 10, Mobile Application
  Security Testing Guide, Cheat Sheet Series, SAMM (CC-BY-SA 4.0 — attribution
  + share-alike required)
- CWE / CAPEC (MITRE) — free to use with attribution
- MITRE ATT&CK — free to use with attribution
- NIST publications (e.g. SP 800-63, SP 800-53) — US government work,
  public domain in the US

**Verify carefully before using — do not assume:**
- CIS Benchmarks — downloadable free, but redistribution/derivative terms are
  more restrictive than OWASP/NIST; check the current license before deriving
  a domain from one
- Any paid/proprietary standard (ISO 27001/27002, PCI-DSS) — these are sold
  documents, not open source; skip them unless you've independently confirmed
  a specific derivative use is permitted

If a standard's license is unclear or restrictive, skip it and note why,
rather than guessing.

---

## Step 1 — Sourcing rigor (non-negotiable, matches existing domains)

Every existing domain file in this codebase opens with a block like this —
match it exactly:

```yaml
# SOURCE VERIFICATION NOTE:
#   Source standard: OWASP ASVS 5.0.0 (released 2025-05-30, confirmed current).
#   Confidence: HIGH. Every req_id/description/level below was extracted
#   directly from the official machine-readable CSV at the v5.0.0 git tag:
#   https://raw.githubusercontent.com/OWASP/ASVS/v5.0.0/...
#   Descriptions below are reworded, not verbatim, per copyright policy;
#   original requirement text belongs to [standard owner], licensed [license].
```

Requirements:
- Cite the **exact version** of the standard and confirm it's current, not a
  stale cached memory of an older edition
- Pull from the **official machine-readable source** where one exists (CSV,
  JSON, structured export), not a paraphrase of a paraphrase
- **Reword every description** — never copy clause text verbatim. This is a
  hard requirement, not a style preference
- Cite the license and the owner explicitly

---

## Step 2 — Exact schema (copied directly from `domain_loader.py` — must match byte-for-byte on field names)

### `domains/{domain_id}.yaml`

```yaml
domain_id: "kebab-case-id"          # becomes both filenames — see naming rule below
version: "1.0.0"
display_name: "Human Readable Name"
source_standard: "Exact standard name + version + chapter/section"
component_type: "backend-api,frontend-web"   # comma-separated; whatever actually applies
weight: 0.9                          # 0.0-1.0, how central this domain is

activation_signals:
  required_any:
    - signal: "concrete, detectable signal — a real package name, a real route
               pattern, a real code construct. Not vague ('uses authentication')."
  excluded_if:
    - signal: "the negation of the above, so domains don't activate on nothing"

controls:
  - control_id: "DOMAINPREFIX-01"     # short prefix + zero-padded number
    name: "Short imperative name"
    description: "Reworded (not verbatim) explanation of the requirement"
    source_clause: "Exact standard + clause number, e.g. 'ASVS 5.0.0 V6.1.1'"
    severity: "critical|high|medium|low"
    check_method: "static|dynamic|manual"
    detector: "which tool/agent would actually catch this, if known"
    remediation_ref: "pointer to more detail, if any"
```

### `fix-playbooks/{domain_id}.playbook.yaml`

```yaml
playbooks:
  - control_id: "DOMAINPREFIX-01"     # must match a real control_id above
    playbook_version: "1.0.0"
    fix_strategy: "deterministic-autofix" | "llm-template-fill" | "manual-only"
    deterministic_tool: "the actual tool/command, or null"
    llm_fix_template: "full instruction text for an LLM to generate the fix, or null"
    verification_checks:
      - "concrete, re-runnable check — 'rerun X tool and confirm Y', not vague"
    blast_radius_notes: "what this fix touches / how contained it is"
    human_review_required: true|false
```

**Be honest about the `fix_strategy` distribution.** Don't default everything
to `manual-only` — that's the failure mode we're specifically trying to avoid
this time. For each control, actually think through: can this be fixed by a
deterministic tool/codemod? If yes, `deterministic-autofix` and name the real
tool. Can an LLM fix it given a good template? If yes, `llm-template-fill` and
write the **actual template text** (see `AUTHSESS-06` in the existing
`fix-playbooks/auth-session.playbook.yaml` for the bar — a real, usable
instruction, not a placeholder path). Only fall back to `manual-only` when a
control genuinely can't be automated (e.g. "write documentation," "get legal
sign-off").

---

## Step 3 — Naming rule (fixes a real bug from last time)

`domain_id` **must** be identical to both filenames:
- `domains/{domain_id}.yaml`
- `fix-playbooks/{domain_id}.playbook.yaml`

No exceptions, no near-matches. A previous batch had domain/playbook filename
drift that made automated coverage-auditing produce false "missing" results —
this rule exists specifically to prevent a repeat.

---

## Step 4 — Deliverable format

Package output as:
```
domain-reset-delivery/
  domains/
    {domain_id}.yaml   (one per domain)
  fix-playbooks/
    {domain_id}.playbook.yaml   (one per domain, matching filename)
  MANIFEST.md   (list every domain produced, its source standard + version,
                 total control count, and fix_strategy distribution counts)
```

The existing 49 domains in this codebase are being handled separately by the
project owner and will be merged in afterward — don't try to reconcile with
them, just build clean, well-sourced new content against the schema above.
