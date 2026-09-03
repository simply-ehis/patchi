"""Tests for the incremental BrainWatcher (Phase 1)."""

from pathlib import Path

from patchi.core.brain.brain_watcher import (
    BrainWatcher,
    ChangeSet,
    affected_layers,
    build_or_update,
    clear_stale,
    diff_snapshots,
    file_snapshot,
    mark_layers_stale,
    update_layers,
)
from patchi.core.brain.layered_brain import build_layers


class _FI:
    """Minimal FileInfo stand-in for the layer builder."""

    def __init__(self, path, language="python", funcs=(), classes=()):
        self.path = path
        self.language = language
        self.functions = [type("F", (), {"name": n})() for n in funcs]
        self.classes = [type("C", (), {"name": n})() for n in classes]
        self.imports = []
        self.exports = []
        self.is_entry_point = False


class _Graph:
    def __init__(self, edges):
        self.edges = edges


def _fi_map():
    return [
        _FI("auth/login.py", funcs=("do_login",)),
        _FI("auth/session.py", funcs=("make_token",)),
        _FI("api/routes.py", funcs=("get_user",)),
        _FI("data/models.py", funcs=("User",)),
    ]


def test_diff_snapshots():
    old = {"a.py": "h1", "b.py": "h2"}
    new = {"a.py": "h1", "b.py": "hX", "c.py": "h3"}
    cs = diff_snapshots(old, new)
    assert cs.changed == {"b.py"}
    assert cs.added == {"c.py"}
    assert cs.removed == set()


def test_change_set_helpers():
    cs = ChangeSet(changed={"a.py"}, added={"b.py"}, removed={"c.py"})
    assert cs.any
    assert cs.all_paths == {"a.py", "b.py", "c.py"}


def test_affected_layers_walks_parent_chain():
    layers = build_layers(_fi_map(), _Graph({}), [], None)
    # auth/login.py changed → module "auth", subsystem "auth", project
    cs = ChangeSet(changed={"auth/login.py"})
    names = affected_layers(cs, layers)
    assert "auth" in names            # module
    assert "auth" in names            # subsystem (same name here)
    assert "__project__" in names     # project ancestor


def test_update_layers_reuses_unchanged_module():
    old = build_layers(_fi_map(), _Graph({}), [], None)
    old_auth = old["auth"]  # subsystem layer object

    # Only api/routes.py changes its public API.
    new_fis = [
        _FI("auth/login.py", funcs=("do_login",)),
        _FI("auth/session.py", funcs=("make_token",)),
        _FI("api/routes.py", funcs=("get_user", "new_endpoint")),
        _FI("data/models.py", funcs=("User",)),
    ]
    cs = ChangeSet(changed={"api/routes.py"})
    new_layers, rebuilt = update_layers(old, new_fis, _Graph({}), [], None, changes=cs)

    # Unchanged module "auth" keeps the exact cached object (no re-summarise).
    assert new_layers["auth"] is old_auth
    # Changed module + its subsystem + project are rebuilt.
    assert "api" in rebuilt
    assert "__project__" in rebuilt
    # The auth subsystem summary is unchanged (reused).
    assert new_layers["auth"].summary == old_auth.summary


def test_update_layers_module_summary_updates_on_change():
    old = build_layers(_fi_map(), _Graph({}), [], None)
    new_fis = [
        _FI("auth/login.py", funcs=("do_login", "logout")),
        _FI("auth/session.py", funcs=("make_token",)),
        _FI("api/routes.py", funcs=("get_user",)),
        _FI("data/models.py", funcs=("User",)),
    ]
    cs = ChangeSet(changed={"auth/login.py"})
    new_layers, rebuilt = update_layers(old, new_fis, _Graph({}), [], None, changes=cs)
    assert "auth" in rebuilt
    assert "logout" in new_layers["auth"].public_api
    assert "logout" not in old["auth"].public_api


def test_mark_and_clear_stale():
    layers = build_layers(_fi_map(), _Graph({}), [], None)
    mark_layers_stale(layers, ["api", "__project__"])
    assert layers["api"].stale is True
    assert layers["auth"].stale is False
    clear_stale(layers)
    assert all(not lay.stale for lay in layers.values())


def _write_fis(tmp_path: Path, content_map: dict[str, str]) -> list:
    fis = []
    for rel, content in content_map.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
        funcs = ("get_user",) if "routes" in rel else ("do_login",)
        if "extra" in content:
            funcs = ("get_user", "extra")
        fis.append(_FI(rel, funcs=funcs))
    return fis


def test_build_or_update_noop_when_unchanged(tmp_path):
    content = {
        "auth/login.py": "a",
        "auth/session.py": "b",
        "api/routes.py": "c",
        "data/models.py": "d",
    }
    old_fis = _write_fis(tmp_path, content)
    old = build_layers(old_fis, _Graph({}), [], None)
    snap = file_snapshot(old_fis, tmp_path)
    # Re-read the same files → identical snapshot → true no-op.
    layers, rebuilt, changes = build_or_update(
        old, old_fis, _Graph({}), [], None, old_snapshot=snap, root=tmp_path
    )
    assert layers is old
    assert rebuilt == []
    assert changes.any is False


def test_build_or_update_rebuilds_on_change(tmp_path):
    content = {
        "auth/login.py": "a",
        "auth/session.py": "b",
        "api/routes.py": "c",
        "data/models.py": "d",
    }
    old_fis = _write_fis(tmp_path, content)
    old = build_layers(old_fis, _Graph({}), [], None)
    snap = file_snapshot(old_fis, tmp_path)
    # Change one file's content.
    (tmp_path / "api/routes.py").write_text("c2 extra")
    new_fis = _write_fis(tmp_path, {**content, "api/routes.py": "c2 extra"})
    layers, rebuilt, changes = build_or_update(
        old, new_fis, _Graph({}), [], None, old_snapshot=snap, root=tmp_path
    )
    assert "api" in rebuilt
    assert changes.changed == {"api/routes.py"}


def test_file_snapshot_and_watcher(tmp_path):
    f = tmp_path / "a.py"
    f.write_text("print('hi')\n")
    fis = [_FI("a.py")]
    snap1 = file_snapshot(fis, tmp_path)
    assert snap1["a.py"]

    # Watcher round-trips through memory (save_layers creates the dir).
    w = BrainWatcher(tmp_path)
    w.save_snapshot(snap1)
    loaded = w.load_snapshot()
    assert loaded["a.py"] == snap1["a.py"]

    # Change the file → snapshot differs → affected marks the module stale.
    f.write_text("print('bye')\n")
    snap2 = file_snapshot(fis, tmp_path)
    cs = w.diff(snap1, snap2)
    assert cs.changed == {"a.py"}
