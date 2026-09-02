"""
Domain Loader — loads security domain taxonomies and fix playbooks.

Domains are YAML files under domains/ defining control requirements
(e.g. OWASP ASVS chapters mapped to Patchi controls). Fix playbooks
under fix-playbooks/ define how to remediate each control.

Usage:
    loader = DomainLoader(root)
    domain = loader.get_domain("web-frontend")
    for ctrl in domain.controls:
        playbook = loader.get_playbook(ctrl.control_id)
"""

from __future__ import annotations

import hashlib
import logging
import os
import pickle
import re
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

_log = logging.getLogger("patchi.security.domain_loader")

# Bump when the pickled payload shape changes (new dataclass field, schema
# semantics, etc.) so stale caches from older code are ignored, not mis-read.
# Content edits to the YAML and edits to this module both invalidate the cache
# automatically via the fingerprint; this constant is the manual escape hatch.
_CACHE_VERSION = 1

# ── Component-type scoping ────────────────────────────────────────────────────
# Canonical aliases shared with AppProfileScorer so a scan target's component
# type (e.g. "frontend-web") matches domain files that declare "frontend" or
# "web-frontend". Keep in sync with the top-level component_type in the YAMLs.
_COMPONENT_ALIASES = {
    "infrastructure": "infra",
    "frontend": "frontend-web",
    "web-frontend": "frontend-web",
}


def normalize_component_type(ct) -> str:
    """Canonicalize a component-type token (case/alias-insensitive)."""
    key = (ct or "").strip().lower()
    return _COMPONENT_ALIASES.get(key, key)


# Cheap top-level key scan: only lines starting at column 0 count, so nested
# (indented) keys and inline mentions are ignored. Used to build the domain
# index without paying for a full YAML parse of every file.
_INDEX_RE = re.compile(r'^(domain_id|component_type):\s*"?([^"#\n]+?)"?\s*$', re.MULTILINE)


def _cache_dir() -> Path:
    """Per-user cache directory shared across processes and projects.

    The domain taxonomy ships with the installed package, so one cache entry
    serves every scanned project on this machine. Never written into the
    scanned project (which may be read-only or a third-party checkout).
    """
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA") or tempfile.gettempdir()
    else:
        base = os.environ.get("XDG_CACHE_HOME") or str(Path.home() / ".cache")
    return Path(base) / "patchi" / "domain-cache"


# Module-level stat cache: {dir_path_str: (mtime, file_mtimes_dict)}
_stat_cache: dict[str, tuple[float, dict[str, float]]] = {}


def _stat_fingerprint(domains_dir: Path, playbooks_dir: Path) -> str:
    """Fast fingerprint with per-file stat caching.

    First call stats all files (O(n)). Subsequent calls reuse cached stats
    and only re-stat files whose parent directory mtime changed — making
    repeated calls O(1) when nothing changed, and O(changed) otherwise.
    """
    parts: list[str] = []
    for d in (domains_dir, playbooks_dir):
        if not d.is_dir():
            parts.append(f"{d.name}:0:0")
            continue
        try:
            dir_mtime = d.stat().st_mtime
        except OSError:
            parts.append(f"{d.name}:0:0")
            continue

        cache_key = str(d)
        cached = _stat_cache.get(cache_key)
        if cached and cached[0] == dir_mtime:
            # Directory didn't change — reuse cached file mtimes
            file_mtimes = cached[1]
        else:
            # Directory changed — re-stat all files
            file_mtimes = {}
            for f in d.glob("*.yaml"):
                try:
                    file_mtimes[f.name] = f.stat().st_mtime
                except OSError:
                    pass
            _stat_cache[cache_key] = (dir_mtime, file_mtimes)

        count = len(file_mtimes)
        mtime_sum = sum(file_mtimes.values())
        parts.append(f"{d.name}:{count}:{mtime_sum:.6f}")

    return "|".join(parts) if parts else "empty"

def _content_fingerprint(domains_dir: Path, playbooks_dir: Path) -> str:
    """Authoritative cache key: dir paths + name + full bytes of every YAML.

    Content-hashed so a data edit can never silently serve a stale cache,
    regardless of filesystem timestamp granularity (NTFS stores 100ns ticks,
    so mtime-only keys can miss quick edits). The loader module's own
    mtime/size is mixed in, so code changes that alter how objects are built
    invalidate the cache automatically too.
    """
    h = hashlib.sha256()
    for d in (domains_dir, playbooks_dir):
        try:
            h.update(str(d.resolve()).encode("utf-8", "replace"))
        except OSError:
            pass
        if not d.is_dir():
            continue
        for f in sorted(d.glob("*.yaml")):
            try:
                h.update(f.name.encode("utf-8", "replace"))
                h.update(f.read_bytes())
            except OSError:
                continue
    try:
        st = Path(__file__).stat()
        h.update(b"|loader:")
        h.update(str(st.st_mtime_ns).encode("ascii"))
        h.update(str(st.st_size).encode("ascii"))
    except OSError:
        pass
    return h.hexdigest()[:24]


def _cache_path(fingerprint: str) -> Path:
    return _cache_dir() / f"v{_CACHE_VERSION}_{fingerprint}.pkl"


def _load_cached(fingerprint: str):
    """Load (domains, playbooks) from the on-disk cache, or None on any miss.

    The pickled payload is the built Domain/FixPlaybook objects, so a cache
    hit skips both YAML parsing AND object construction (~17s -> <0.1s).
    Shape- and type-checked so a truncated, corrupt, or wrong-schema payload
    (e.g. pickled by older code) falls back to a fresh parse instead of
    being served.
    """
    try:
        path = _cache_path(fingerprint)
        if not path.is_file():
            return None
        with open(path, "rb") as fh:
            domains, playbooks = pickle.load(fh)
        if not isinstance(domains, dict) or not isinstance(playbooks, dict):
            return None
        if not all(isinstance(d, Domain) for d in domains.values()):
            return None
        if not all(isinstance(p, FixPlaybook) for p in playbooks.values()):
            return None
        for d in domains.values():
            if not all(isinstance(c, DomainControl) for c in d.controls):
                return None
        return domains, playbooks
    except Exception as e:  # noqa: BLE001 — cache is best-effort
        _log.debug("DomainLoader cache load failed: %s", e)
        return None


def _purge_stale_caches(d: Path, keep_fingerprint: str) -> None:
    """Drop cache files older than a week so the dir can't grow unbounded.

    Age-based only: never delete files with a different (possibly still
    active) fingerprint, which may belong to another project or process.
    """
    cutoff = time.time() - 7 * 24 * 3600
    try:
        target = _cache_path(keep_fingerprint)
        # Final cache files (v<ver>_<fp>.pkl) and orphaned temp files left by
        # writers killed between mkstemp and os.replace (.tmp_<fp>_*.pkl).
        for old in list(d.glob(f"v{_CACHE_VERSION}_*.pkl")) + list(d.glob(".tmp_*.pkl")):
            if old == target:
                continue
            try:
                if old.stat().st_mtime < cutoff:
                    old.unlink(missing_ok=True)
            except OSError:
                pass
    except Exception as _exc:  # noqa: BLE001
        _log.debug('_purge_stale_caches skipped: %s', _exc)


def _save_cached(fingerprint: str, domains: dict, playbooks: dict) -> None:
    """Atomically write the cache (unique temp file + rename); never raise."""
    try:
        d = _cache_dir()
        d.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(prefix=f".tmp_{fingerprint}_", suffix=".pkl", dir=d)
        try:
            with os.fdopen(fd, "wb") as fh:
                pickle.dump((domains, playbooks), fh, protocol=pickle.HIGHEST_PROTOCOL)
            os.replace(tmp, _cache_path(fingerprint))
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
        _purge_stale_caches(d, fingerprint)
    except Exception as e:  # noqa: BLE001
        _log.debug("DomainLoader cache write failed: %s", e)


@dataclass
class DomainControl:
    control_id: str
    name: str
    description: str
    source_clause: str
    severity: str
    check_method: str
    detector: str
    remediation_ref: str
    raw: dict = field(default_factory=dict)


@dataclass
class Domain:
    domain_id: str
    version: str
    display_name: str
    source_standard: str
    component_type: str
    weight: float
    activation_signals: dict
    controls: list[DomainControl]
    raw: dict = field(default_factory=dict)


@dataclass
class FixPlaybook:
    control_id: str
    playbook_version: str
    fix_strategy: str
    deterministic_tool: str | None
    llm_fix_template: str | None
    verification_checks: list[str]
    blast_radius_notes: str
    human_review_required: bool
    raw: dict = field(default_factory=dict)


def _try_load_yaml(path: Path) -> dict | None:
    if not path.exists():
        return None
    try:
        import yaml
        try:
            Loader = yaml.CSafeLoader  # type: ignore[attr-defined]
        except AttributeError:
            Loader = yaml.SafeLoader
        with open(path, encoding="utf-8") as f:
            return yaml.load(f, Loader=Loader)
    except ImportError:
        try:
            import json
            with open(path, encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            import logging
            logging.getLogger("patchi.security.domain_loader").warning(
                "Failed to parse %s: %s", path, e
            )
            return None
    except Exception as e:
        import logging
        logging.getLogger("patchi.security.domain_loader").warning(
            "Failed to parse %s: %s", path, e
        )
        return None

def _to_float(value, default: float = 0.5) -> float:
    """Coerce a YAML value to float, never raising on malformed data."""
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _to_bool(value, default: bool = True) -> bool:
    """Lenient bool coercion: accepts bools and common string spellings.

    ``bool("false")`` is ``True`` in Python, which would silently invert
    intent for hand-written YAML, so string values are parsed explicitly.
    """
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        return value.strip().lower() in {"true", "yes", "y", "1", "on"}
    if value is None:
        return default
    return default


def _to_str_list(value) -> list:
    """Coerce to a list of strings; a bare string becomes a single item."""
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return [str(v) for v in value]
    return [str(value)]


class DomainLoader:
    """Loads domain taxonomies and fix playbooks from YAML files."""

    def __init__(self, root: Path, component_types=None, domain_ids=None):
        self._root = root
        self._domains_dir = root / "patchi" / "core" / "security" / "domains"
        self._playbooks_dir = root / "patchi" / "core" / "security" / "fix-playbooks"
        self._fallback_dirs()
        self._domains: dict[str, Domain] = {}
        self._playbooks: dict[str, FixPlaybook] = {}
        self._loaded = False
        self._last_stat: str = ""
        self._last_fingerprint: str = ""
        self._index: dict | None = None
        self._scope_types: set[str] | None = None
        self._scope_ids: set[str] | None = None
        if component_types is not None or domain_ids is not None:
            self.set_component_scope(component_types, domain_ids)

    def set_component_scope(self, component_types=None, domain_ids=None) -> None:
        """Restrict loading to a subset of the taxonomy.

        ``component_types`` (str or iterable) loads only domain files whose
        top-level component_type matches (aliases normalized, so "frontend"
        matches a "frontend-web" scope). ``domain_ids`` additionally forces
        specific domains to load regardless of their declared type — used by
        AppProfileScorer for its explicit component->domain map (e.g. a
        backend-api profile always loads the web-frontend domain). Pass
        None/None (or an empty list — treated the same as None) to restore
        full-taxonomy loading (the default).
        """
        if component_types is None and domain_ids is None:
            self._scope_types = None
            self._scope_ids = None
        else:
            types: set[str] = set()
            if component_types:
                if isinstance(component_types, str):
                    component_types = [component_types]
                for ct in component_types:
                    types.add(normalize_component_type(ct))
            self._scope_types = types
            self._scope_ids = set(domain_ids or [])
        # Any previously loaded subset is stale.
        self._domains = {}
        self._playbooks = {}
        self._loaded = False

    def _is_scoped(self) -> bool:
        return bool(self._scope_types or self._scope_ids)

    def _build_index(self) -> dict:
        """Map domain_id -> {path, types} with a regex scan, no YAML parse.

        ``types`` is the set of normalized component types, or None when the
        top-level component_type could not be extracted (the file is then
        parsed and authoritatively filtered during a scoped load). The index
        is cached in-process, but invalidated whenever the stat signature of
        the data directories changes — including for callers that only ask
        for the index (``index_component_types``) without ever loading.
        """
        stat_fp = _stat_fingerprint(self._domains_dir, self._playbooks_dir)
        if self._index is not None and stat_fp == self._index.get("_stat"):
            return self._index
        index: dict = {}
        if self._domains_dir.exists():
            for fpath in sorted(self._domains_dir.glob("*.yaml")):
                try:
                    text = fpath.read_text(encoding="utf-8")
                except OSError:
                    continue
                fields: dict[str, str] = {}
                for m in _INDEX_RE.finditer(text):
                    key, val = m.group(1), m.group(2).strip()
                    if key not in fields:
                        fields[key] = val
                did = fields.get("domain_id")
                if not did:
                    continue
                raw = fields.get("component_type")
                types = None
                if raw:
                    types = {normalize_component_type(t) for t in raw.split(",")}
                index[did] = {"path": fpath, "types": types}
        index["_stat"] = stat_fp
        self._index = index
        return index

    def index_component_types(self, domain_id: str) -> frozenset:
        """Normalized component types of a domain, from the cheap index.

        Never parses YAML — safe to call on a loader with no scope. The index
        is refreshed automatically if the data files change.
        """
        entry = self._build_index().get(domain_id)
        if not entry or not entry["types"]:
            return frozenset()
        return frozenset(entry["types"])

    def _fallback_dirs(self):
        pkg = Path(__file__).parent
        if not self._domains_dir.exists():
            self._domains_dir = pkg / "domains"
        if not self._playbooks_dir.exists():
            self._playbooks_dir = pkg / "fix-playbooks"

    def _dirs_changed(self, content: bool = True) -> bool:
        """True if the data changed since the last load.

        The stat-only signature is the cheap trigger; only when it fires do we
        pay for a full content hash, which is immune to timestamp-granularity
        races (NTFS stores 100ns ticks). The content fingerprint doubles as
        the on-disk cache key. ``content=False`` skips the hash entirely —
        used by scoped loads, which bypass the on-disk cache and only need
        in-process change detection. Residual limitation: an edit landing
        within the same stat signature (same 100ns tick AND same size) goes
        unnoticed for the remainder of this process — fresh processes always
        recompute the content hash, so the on-disk cache can never go stale.
        """
        stat_fp = _stat_fingerprint(self._domains_dir, self._playbooks_dir)
        if stat_fp == self._last_stat:
            return False
        if not content:
            self._last_stat = stat_fp
            self._last_fingerprint = ""
            return True
        content_fp = _content_fingerprint(self._domains_dir, self._playbooks_dir)
        changed = content_fp != self._last_fingerprint
        self._last_stat = stat_fp
        self._last_fingerprint = content_fp
        return changed

    def _load_all(self):
        if self._is_scoped():
            self._load_scoped()
            return
        if self._loaded:
            if not self._dirs_changed():
                return
        else:
            # First load: initialize fingerprint tracking so the cache key is
            # set before we probe the on-disk cache. Force the content hash
            # even if a scoped load already set a stat signature — the scoped
            # path intentionally skips content hashing, and the cache key must
            # never be the empty sentinel.
            stat_fp = _stat_fingerprint(self._domains_dir, self._playbooks_dir)
            if stat_fp != self._last_stat or not self._last_fingerprint:
                self._last_fingerprint = _content_fingerprint(
                    self._domains_dir, self._playbooks_dir
                )
                self._last_stat = stat_fp
            self._loaded = True

        # Fast path: reuse the shared on-disk cache keyed by content fingerprint.
        fingerprint = self._last_fingerprint
        cached = _load_cached(fingerprint)
        if cached is not None:
            self._domains, self._playbooks = cached
            return

        if self._domains_dir.exists():
            for fpath in sorted(self._domains_dir.glob("*.yaml")):
                domain = self._parse_domain_file(fpath)
                if domain is not None:
                    self._domains[domain.domain_id] = domain

        if self._playbooks_dir.exists():
            for fpath in sorted(self._playbooks_dir.glob("*.yaml")):
                self._playbooks.update(self._parse_playbook_file(fpath))

        # Persist the freshly built objects so the next process starts fast.
        _save_cached(fingerprint, self._domains, self._playbooks)

    def _load_scoped(self):
        """Load only the domains relevant to the active component scope.

        The cheap regex index picks the candidate files (component_type match
        and/or explicit domain ids) before any YAML parse, so a narrow scan
        (e.g. frontend-web: ~13 of 334 files) never builds the full taxonomy.
        The on-disk cache is intentionally bypassed: it stores the whole
        taxonomy, and reading it would defeat the purpose of a scoped load.
        """
        if self._loaded:
            if not self._dirs_changed(content=False):
                return
            # Data changed — the cached index may reference stale paths/types.
            self._index = None
        else:
            self._dirs_changed(content=False)
            self._loaded = True

        scope_types = self._scope_types or set()
        scope_ids = self._scope_ids or set()
        index = self._build_index()

        domains: dict[str, Domain] = {}
        playbooks: dict[str, FixPlaybook] = {}
        for did, entry in index.items():
            if did == "_stat":
                continue  # internal cache sentinel, not a domain
            if did in scope_ids:
                pass  # explicitly requested regardless of declared type
            elif entry["types"] is not None and not (entry["types"] & scope_types):
                continue  # cheap index says this file can't match — skip
            # Parse the file; the parsed component_type is authoritative
            # (guards against a regex miss or an unusual file layout).
            domain = self._parse_domain_file(entry["path"])
            if domain is None:
                continue
            if did not in scope_ids:
                parsed_types = {
                    normalize_component_type(t)
                    for t in str(domain.component_type).split(",")
                    if t.strip()
                }
                if not (parsed_types & scope_types):
                    continue
            domains[domain.domain_id] = domain
            pb_path = self._playbooks_dir / f"{entry['path'].stem}.playbook.yaml"
            if pb_path.exists():
                playbooks.update(self._parse_playbook_file(pb_path))

        self._domains = domains
        self._playbooks = playbooks

    def _parse_domain_file(self, fpath: Path) -> Domain | None:
        """Build a Domain from one YAML file, or None if it isn't one."""
        data = _try_load_yaml(fpath)
        if not data or "domain_id" not in data:
            return None
        controls: list[DomainControl] = []
        for c in data.get("controls", []):
            if not isinstance(c, dict):
                _log.warning(
                    "DomainLoader: skipping non-dict control in %s",
                    fpath.name,
                )
                continue
            cid = c.get("control_id")
            name = c.get("name")
            if not isinstance(cid, str) or not cid or not isinstance(name, str) or not name:
                _log.warning(
                    "DomainLoader: skipping control without control_id/name in %s (keys=%s)",
                    fpath.name,
                    sorted(c)[:8],
                )
                continue
            controls.append(
                DomainControl(
                    control_id=cid,
                    name=name,
                    description=str(c.get("description", "")),
                    source_clause=str(c.get("source_clause", "")),
                    severity=str(c.get("severity", "medium")),
                    check_method=str(c.get("check_method", "static")),
                    detector=str(c.get("detector", "")),
                    remediation_ref=str(c.get("remediation_ref", "")),
                    raw=c,
                )
            )
        did = data.get("domain_id")
        if not isinstance(did, str) or not did:
            return None
        return Domain(
            domain_id=did,
            version=str(data.get("version", "1.0.0")),
            display_name=str(data.get("display_name", did)),
            source_standard=str(data.get("source_standard", "")),
            component_type=str(data.get("component_type", "")),
            weight=_to_float(data.get("weight"), 0.5),
            activation_signals=data.get("activation_signals", {}) or {},
            controls=controls,
            raw=data,
        )

    def _parse_playbook_file(self, fpath: Path) -> dict[str, FixPlaybook]:
        """Build {control_id: FixPlaybook} from one fix-playbook YAML file."""
        result: dict[str, FixPlaybook] = {}
        data = _try_load_yaml(fpath)
        if not data or "playbooks" not in data:
            return result
        for pb in data["playbooks"]:
            if not isinstance(pb, dict):
                _log.warning(
                    "DomainLoader: skipping non-dict playbook entry in %s",
                    fpath.name,
                )
                continue
            cid = pb.get("control_id")
            if not isinstance(cid, str) or not cid:
                # Also accept the legacy playbook_id key so a malformed or
                # older-format file degrades gracefully instead of crashing
                # the whole scan pipeline (see tools/fix_playbooks.py).
                cid = pb.get("playbook_id")
            if not isinstance(cid, str) or not cid:
                _log.warning(
                    "DomainLoader: skipping playbook entry without control_id in %s (keys=%s)",
                    fpath.name,
                    sorted(pb)[:8],
                )
                continue
            # Legacy schema support: remediation_steps/verification map onto
            # the canonical llm_fix_template/verification_checks fields.
            llm_template = pb.get("llm_fix_template")
            legacy_steps = isinstance(pb.get("remediation_steps"), list)
            if not llm_template and legacy_steps:
                steps = pb["remediation_steps"]
                parts = [f"{i + 1}. {s}" for i, s in enumerate(steps) if isinstance(s, str)]
                notes = pb.get("implementation_notes")
                if isinstance(notes, list):
                    parts.append("Implementation notes: " + " ".join(str(n) for n in notes))
                if parts:
                    llm_template = "\n".join(parts)
            verification = pb.get("verification_checks")
            if not verification and pb.get("verification") is not None:
                verification = pb["verification"]
            fix_strategy = str(pb.get("fix_strategy") or "")
            if not fix_strategy:
                # Entries written in the legacy remediation_steps schema are
                # LLM-fixable by construction — don't fall back to manual-only.
                fix_strategy = "llm-template-fill" if legacy_steps else "manual-only"
            result[cid] = FixPlaybook(
                control_id=cid,
                playbook_version=str(pb.get("playbook_version", "1.0.0")),
                fix_strategy=fix_strategy,
                deterministic_tool=pb.get("deterministic_tool"),
                llm_fix_template=llm_template if isinstance(llm_template, str) else None,
                verification_checks=_to_str_list(verification),
                blast_radius_notes=str(pb.get("blast_radius_notes", "")),
                human_review_required=_to_bool(pb.get("human_review_required"), True),
                raw=pb,
            )
        return result

    def list_domains(self) -> list[str]:
        self._load_all()
        return list(self._domains.keys())

    def get_domain(self, domain_id: str) -> Domain | None:
        self._load_all()
        return self._domains.get(domain_id)

    def find_control(self, control_id: str) -> DomainControl | None:
        """Find a control by id in the loaded domains.

        On a scoped loader this only searches the loaded (in-scope) domains —
        controls belonging to out-of-scope domains return None, by design, so
        a narrow scan never materializes the rest of the taxonomy.
        """
        self._load_all()
        for domain in self._domains.values():
            for ctrl in domain.controls:
                if ctrl.control_id == control_id:
                    return ctrl
        return None

    def get_playbook(self, control_id: str) -> FixPlaybook | None:
        """Get the fix playbook for a control.

        On a scoped loader only playbooks for loaded (in-scope) domains are
        available; out-of-scope controls return None by design.
        """
        self._load_all()
        return self._playbooks.get(control_id)

    def _build_keyword_index(self) -> dict[str, list[tuple[str, DomainControl, Domain]]]:
        """Pre-build inverted index: keyword -> [(domain_id, control, domain)].

        Called once after loading; makes match_finding_to_controls O(k) per
        finding instead of O(domains * controls).
        """
        if hasattr(self, "_kw_index") and self._kw_index is not None:
            return self._kw_index
        kws = self._domain_keywords()
        index: dict[str, list[tuple[str, DomainControl, Domain]]] = {}
        for domain in self._domains.values():
            for ctrl in domain.controls:
                # Index keywords from control name + description
                ctrl_text = (ctrl.name + " " + ctrl.description).lower()
                ctrl_domains = self._classify_domains(ctrl_text)
                for kw_set_name in ctrl_domains:
                    if kw_set_name not in index:
                        index[kw_set_name] = []
                    index[kw_set_name].append((domain.domain_id, ctrl, domain))
        self._kw_index = index
        return index

    @staticmethod
    def _domain_keywords() -> dict[str, set[str]]:
        return {
            # ── Injection & Input ──────────────────────────────────────────
            "injection": {
                "sql", "nosql", "ldap", "command", "orm", "eval",
                "deserialization", "hql", "injection", "template injection",
                "xpath", "csv injection", "log injection", "header injection",
            },
            "xss": {
                "xss", "cross-site", "cross site", "script injection",
                "dom xss", "reflected xss", "stored xss", "self-xss",
            },
            "sqli": {"sql injection", "sqli", "blind sql", "union select", "stacked query"},
            "ssrf": {
                "ssrf", "server-side request forgery",
                "server side request forgery", "url fetch",
            },
            "xxe": {"xxe", "xml external", "xml entity", "xml parser", "dtd"},
            "rce": {"rce", "remote code", "code execution", "code injection", "command injection", "os command", "exec", "passthru", "system("},
            "path_traversal": {
                "path traversal", "directory traversal", "path injection",
                "file inclusion", "local file", "lfi", "rfi", "dot dot slash",
            },
            "open_redirect": {
                "open redirect", "url redirect", "redirect injection",
                "unvalidated redirect", "302 redirect", "location header",
            },
            # ── Authentication & Session ───────────────────────────────────
            "authentication": {
                "auth", "authentication", "login", "password", "oauth",
                "session", "token", "jwt", "sso", "identity",
                "authenticate", "mfa", "totp", "2fa", "biometric",
                "credential stuffing", "brute force", "account lockout",
            },
            "session": {
                "session", "cookie", "session fixation", "session hijack",
                "session timeout", "session token", "httpOnly", "secure flag",
            },
            "authorization": {
                "authorization", "privilege", "role", "permission", "rbac",
                "abac", "access control", "idor", "broken function",
                "privilege escalation", "elevation of privilege",
            },
            # ── Cryptography ──────────────────────────────────────────────
            "cryptography": {
                "crypto", "encryption", "cipher", "hash", "tls", "ssl",
                "certificate", "cryptographic", "key management",
                "key exchange", "digital signature", "hmac", "aes", "rsa",
                "pbkdf2", "bcrypt", "argon2", "scrypt", "nonce", "iv",
                "quantum", "post-quantum", "ecc", "diffie",
            },
            # ── Web & Frontend ────────────────────────────────────────────
            "cors": {"cors", "cross-origin", "cross origin", "wildcard origin", "access-control-allow"},
            "csrf": {"csrf", "xsrf", "cross-site request", "cross site request", "request forgery", "anti-forgery"},
            "clickjacking": {"clickjack", "frame injection", "x-frame-options", "frame-ancestors"},
            "security_headers": {
                "security header", "content-security-policy", "csp",
                "strict-transport", "hsts", "x-content-type", "x-xss-protection",
                "permissions-policy", "referrer-policy", "feature-policy",
            },
            # ── Data & Privacy ────────────────────────────────────────────
            "sensitive_data": {
                "sensitive data", "pii", "personal information",
                "secret exposure", "credential leakage", "data leak",
                "data breach", "data exposure", "data classification",
            },
            "secrets": {
                "secret", "hardcoded", "credential", "api key",
                "token exposure", "password in code", "secret scanning",
                "private key", "secret key", "connection string",
            },
            # ── Dependencies & Supply Chain ───────────────────────────────
            "dependency": {
                "dependency", "cve", "supply chain", "third party",
                "vulnerable package", "sbom", "outdated", "unmaintained",
            },
            "supply_chain": {
                "supply chain", "dependency confusion", "malicious package",
                "typosquatting", "artifact signing", "provenance",
            },
            # ── Infrastructure & Config ───────────────────────────────────
            "misconfiguration": {
                "misconfig", "security header", "hardening",
                "insecure default", "security config", "missing header",
                "debug mode", "verbose error", "default credential",
            },
            # ── Secrets & Hardcoded Credentials ────────────────────────────
            "hardcoded_secret": {
                "hardcoded", "secret", "credential", "api key", "private key",
                "password in code", "token exposure", "connection string",
                "secret key", "auth token", "bearer token", "access key",
            },
            "hardcoded_key": {
                "hardcoded key", "hardcoded secret", "hardcoded password",
                "hardcoded credential", "hardcoded token",
            },
            # ── Authentication & Access ──────────────────────────────────
            "auth_bypass": {
                "authentication bypass", "auth bypass", "login bypass",
                "without authentication", "no auth", "unauthenticated",
                "missing auth", "missing authentication",
            },
            "missing_auth": {
                "without authentication", "no auth", "unauthenticated",
                "missing auth", "missing authentication", "missing authorization",
            },
            # ── Debug & Config ───────────────────────────────────────────
            "debug_mode": {
                "debug mode", "debug=true", "debug on", "verbose error",
                "stack trace", "exposed error", "error details",
                "traceback", "exception detail", "internal error",
            },
            "insecure_config": {
                "insecure default", "default credential", "default password",
                "insecure configuration", "security misconfiguration",
                "missing security header", "open port", "exposed service",
            },
            # ── Type Safety & Quality ────────────────────────────────────
            "type_safety": {
                "type annotation", "type hint", "missing type",
                "untyped", "any type", "type error", "type safety",
            },
            # ── Technical Debt ───────────────────────────────────────────
            "technical_debt": {
                "todo", "fixme", "hack", "workaround", "bug",
                "technical debt", "deprecated", "legacy", "temporary",
            },
            "dos": {"dos", "denial of service", "rate limit", "resource exhaustion", "ddos", "throttle", "backlog"},
            "runtime": {"runtime", "container", "kubernetes", "docker", "orchestration", "falco", "pod", "node"},
            "network": {"network", "firewall", "dns", "tcp", "port", "egress", "ingress", "proxy", "vpn", "tls termination"},
            # ── Cloud ─────────────────────────────────────────────────────
            "cloud_aws": {"aws", "s3", "ec2", "lambda", "iam", "cloudtrail", "kms", "rds", "ecs", "fargate", "sqs", "sns"},
            "cloud_azure": {"azure", "blob storage", "key vault", "active directory", "arm template", "devops"},
            "cloud_gcp": {"gcp", "gce", "gcs", "bigquery", "cloud functions", "gke", "secret manager", "cloud run"},
            # ── Container & Orchestration ──────────────────────────────────
            "container": {
                "container", "dockerfile", "image", "layer", "registry",
                "privileged", "root user", "capabilities", "seccomp",
                "apparmor", "selinux", "read-only fs",
            },
            "kubernetes": {
                "kubernetes", "k8s", "pod", "deployment", "service",
                "ingress", "rbac", "networkpolicy", "podsecurity",
                "etcd", "apiserver", "admission controller", "helm",
            },
            # ── CI/CD & DevOps ────────────────────────────────────────────
            "cicd": {
                "ci/cd", "pipeline", "github actions", "gitlab ci",
                "jenkins", "build", "deploy", "artifact", "workflow",
                "runner", "secret scanning", "cache poisoning",
            },
            # ── API Security ──────────────────────────────────────────────
            "api_security": {
                "api", "rest", "graphql", "grpc", "webhook",
                "rate limit", "pagination", "versioning", "content negotiation",
                "idempotency", "hateoas", "swagger", "openapi",
            },
            # ── Database ──────────────────────────────────────────────────
            "database": {
                "database", "db", "mysql", "postgres", "postgresql",
                "mongodb", "redis", "elasticsearch", "cassandra",
                "sqlite", "oracle", "sql server", "stored procedure",
                "query", "connection pool", "row level security",
            },
            # ── Mobile ────────────────────────────────────────────────────
            "mobile": {
                "mobile", "android", "ios", "swift", "kotlin",
                "react native", "flutter", "xamarin", "ionic",
                "keychain", "keystore", "deep link", "intent",
                "webview", "biometric", "jailbreak", "root detection",
            },
            # ── Desktop ───────────────────────────────────────────────────
            "desktop": {
                "electron", "tauri", "nwjs", "desktop",
                "browser extension", "chrome extension", "firefox extension",
            },
            # ── Languages & Frameworks ────────────────────────────────────
            "python": {"python", "django", "flask", "fastapi", "pylint", "bandit", "pip", "pyproject"},
            "javascript": {"javascript", "nodejs", "node.js", "express", "npm", "package.json", "nextjs", "nuxt", "remix", "astro", "qwik", "svelte"},
            "java": {"java", "spring", "tomcat", "maven", "gradle", "jvm", "jndi", "jsp", "jackson"},
            "dotnet": {".net", "c#", "asp.net", "blazor", "nuget", "razor", "viewstate", "entity framework"},
            "go": {"golang", "goroutine", "net/http", "gin framework", "echo framework", "fiber framework"},
            "rust": {"rust", "cargo", "crate", "unsafe", "rustc", "tokio", "serde"},
            "ruby": {"ruby", "rails", "rubygems", "bundler", "erb", "devise", "activerecord"},
            "php": {"php", "laravel", "symfony", "composer", "wordpres", "drupal", "twig", "blade"},
            "c_cpp": {"c++", "c language", "gcc", "clang", "buffer overflow", "format string", "malloc", "free"},
            # ── Compliance ────────────────────────────────────────────────
            "compliance": {"compliance", "regulatory", "gdpr", "hipaa", "pci", "sox", "audit", "soc2", "iso27001"},
            "privacy": {"privacy", "consent", "data retention", "anonymization", "pseudonymization", "cookie consent", "tracking", "fingerprinting"},
            # ── Fraud & Business Logic ────────────────────────────────────
            "fraud": {"fraud", "bot", "scraping", "account takeover", "credential stuffing", "payment fraud", "coupon abuse", "referral abuse"},
            "business_logic": {"business logic", "price manipulation", "race condition", "workflow bypass", "amount tampering", "state confusion", "toctou"},
            # ── Incident Response & Monitoring ─────────────────────────────
            "incident": {"incident", "breach", "forensic", "containment", "recovery", "escalation", "alert"},
            "monitoring": {"monitoring", "logging", "audit log", "siem", "detection", "alerting", "telemetry"},
            # ── Threat Modeling ───────────────────────────────────────────
            "threat_model": {"threat model", "stride", "attack surface", "abuse case", "risk assessment", "mitigation tracking"},
            # ── IaC & Cloud Config ────────────────────────────────────────
            "terraform": {"terraform", "tf state", "tfvars", "provider", "module", "hcl"},
            "ansible": {"ansible", "playbook", "vault", "role", "galaxy", "inventory"},
            "helm": {"helm", "chart", "values.yaml", "template", "release"},
            # ── IoT & Edge ────────────────────────────────────────────────
            "iot": {"iot", "mqtt", "coap", "embedded", "firmware", "sensor", "actuator", "gateway"},
            "edge": {"edge", "cdn", "worker", "service worker", "cache api", "push notification"},
            # ── AI/ML ─────────────────────────────────────────────────────
            "ai_ml": {"artificial intelligence", "machine learning", "llm", "neural network", "model training", "inference", "prompt injection", "rag", "vector database", "embedding", "fine-tune", "fine-tuning", "transformer"},
            # ── Web3 & Blockchain ─────────────────────────────────────────
            "web3": {"web3", "smart contract", "blockchain", "ethereum", "defi", "nft", "token", "oracle", "flash loan", "mev"},
            # ── Game Security ─────────────────────────────────────────────
            "game": {"game", "cheat", "speed hack", "item duplication", "memory corruption", "anticheat"},
            # ── Post-Quantum ──────────────────────────────────────────────
            "quantum": {"quantum", "post-quantum", "lattice", "kyber", "dilithium", "nist pqc"},
            # ── Zero Trust ────────────────────────────────────────────────
            "zero_trust": {"zero trust", "never trust", "verify every", "microsegment", "least privilege"},
        }

    def _classify_domains(self, text: str) -> set[str]:
        """Classify text into security domains based on keyword sets."""
        text_lower = text.lower().replace("_", " ").replace("-", " ")
        matched = set()
        for domain, kws in self._domain_keywords().items():
            for kw in kws:
                if kw in text_lower:
                    matched.add(domain)
                    break
        return matched

    def match_finding_to_controls(
        self, finding_type: str, file_path: str, message: str
    ) -> list[DomainControl]:
        """Match a finding to domain controls using a pre-built keyword index.

        O(k) per finding where k = number of matching keywords.
        """
        self._load_all()
        idx = self._build_keyword_index()

        combined = f"{message} {file_path} {finding_type}"
        finding_domains = self._classify_domains(combined)
        if not finding_domains:
            return []

        candidates = {}
        for kw_set in finding_domains:
            for domain_id, ctrl, domain in idx.get(kw_set, []):
                key = ctrl.control_id
                if key not in candidates:
                    candidates[key] = [0, ctrl, domain]
                candidates[key][0] += 1

        scored = []
        for key, entry in candidates.items():
            overlap_count, ctrl, domain = entry
            score = overlap_count * 2
            if message and ctrl.name:
                ctrl_words = [w for w in ctrl.name.lower().split() if len(w) > 3]
                if ctrl_words and any(w in message.lower() for w in ctrl_words):
                    score += 3
            if file_path:
                dw = domain.domain_id.replace("-", " ").split()
                if any(w in file_path.lower() for w in dw if len(w) > 3):
                    score += 2
            if score >= 4:
                scored.append((score, ctrl))

        scored.sort(key=lambda x: (-x[0], x[1].severity != "critical"))
        return [ctrl for _, ctrl in scored[:5]]

