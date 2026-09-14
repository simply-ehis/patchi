---
id: sca-audit-v1
name: Software Composition Analysis
version: 1.0.0
target_agents: [DependencyCVEChecker, DependencyVulnerabilityAgent, SBOMAgent, ConfigAuditAgent]
cwe: [CWE-937, CWE-1035, CWE-1104, CWE-829]
owasp: [A06:2021, A08:2021]
confidence_boost: 0.1
---

# SCA Detection Patterns

## Dependency File Discovery
Check all supported manifest files in project root and subdirectories:
- `requirements.txt`, `Pipfile`, `poetry.lock`, `pyproject.toml`
- `package.json`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`
- `Gemfile`, `Gemfile.lock`
- `pom.xml`, `build.gradle`, `gradle.lockfile`
- `go.mod`, `go.sum`
- `Cargo.toml`, `Cargo.lock`
- `composer.json`, `composer.lock`
- `nuget.config`, `paket.lock`

## Known Vulnerability Indicators

### Pinned Versions With Known CVEs
```requirements.txt
Django==3.2.18  # check against NVD/CVE database
flask==1.0.0
requests==2.28.0
```
**Check**: For each pinned version, cross-reference with CVE list.
**Severity**: Critical if version is in CVE database with CVSS >= 9.0.

### Unpinned / Range Versions
```requirements.txt
Django>=3.2,<4.0  # may pull vulnerable subversions
requests>=2.0.0
```
**Risk**: Resolution may pull version with known CVE. Suggest lock file.

### Deprecated / Archived Packages
```package.json
"jquery": "^1.12.0"   # deprecated, no security patches
"lodash": "^3.10.0"   # old major version
```
**Check**: Package is past EOL or archived on npm/PyPI.
→ **action: fix_code** — update to latest maintained version.

### Known Malicious Package Names
Typo-squatting detection:
```regex
requets|requrests|requeests|pip instal|lodash|loadsh|mocha|mochajs|nodemodules
```
Also check for unicode homoglyph attacks in package names.

## Dependency Tree Depth
**Rule**: Flag dependencies with >5 transitive dependency levels — increased supply chain risk surface.

## Lock File Integrity
**Rule**: If `package.json` exists but `package-lock.json`/`yarn.lock` missing → confidence 0.4.
Suggest generating lockfile for reproducible builds.

## License Compliance
**Rule**: If dependency uses GPL/AGPL license and project is MIT/Apache/BSL → **action: escalate**.

## Remediation Templates

### Update Pinned Version
```python
# Before
requests==2.28.0  # CVE-2023-32681 (CVSS 7.5)
# After
requests==2.31.0  # patched
```

### Switch to Actively Maintained Alternative
```python
# Before
deprecated - package == 0.1  # archived 2022
# After
actively - maintained - package == 2.0
```

## CVE Data Sources (reference only)
Patterns target known CVE-* prefixes. For full CVE matching, integrate:
- OSV.dev API: `https://api.osv.dev/v1/query`
- NVD API: `https://services.nvd.nist.gov/rest/json/cves/2.0`

## Multi-Agent Cross-Correlation
- `DependencyCVEChecker` + `SBOMAgent` overlapping CVE → confidence += 0.2
- `DependencyVulnerabilityAgent` confirms exploitable CVE in runtime code → confidence += 0.3
- Multiple manifest files with same vulnerable dep → confidence += 0.15
