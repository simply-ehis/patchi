"""Machine-pure --json output for p fix / p impact / p blast (Part 3 §2).

The contract for every JSON-mode command: stdout parses as exactly one JSON
value — no human UI before it, no Rich soft-wrapping inside it.
"""

import io
import json

import pytest

from patchi.cli.console import con, muted_console, print_json

# ── The console helpers themselves ────────────────────────────────────────────


def test_print_json_is_byte_pure_and_not_rich_wrapped(capsys):
    """A >80-char string value must survive on one line (Rich would wrap it)."""
    long_value = "x" * 300
    print_json({"value": long_value})
    raw = capsys.readouterr().out
    doc = json.loads(raw)  # raises if wrapped/corrupted
    assert doc["value"] == long_value
    longest = max(len(line) for line in raw.splitlines())
    assert longest > 200, "print_json must not soft-wrap long values"


def test_muted_console_captures_con_prints(capsys):
    with muted_console():
        con.print("human UI that must not reach stdout")
    assert capsys.readouterr().out == ""


def test_muted_console_restores_sysstdout_follow_state():
    """Regression: swapping the `file` property pins the console to a stream
    that later closes ("I/O operation on closed file" for the whole test
    batch). The underlying _file (None = follow sys.stdout) must round-trip."""
    original = con._file
    with muted_console():
        assert isinstance(con._file, io.StringIO)
    assert con._file is original


def test_muted_console_restores_after_exception():
    original = con._file
    with pytest.raises(RuntimeError), muted_console():
        con.print("swallowed")
        raise RuntimeError("boom")
    assert con._file is original
    # the console still works afterwards (no exception raised)
    con.print("still alive")


# ── p fix --json ──────────────────────────────────────────────────────────────


def _fake_finding(fix_agent="SecurityFixer", file="src/app.py", sev="high"):
    return {
        "type": "sql_injection",
        "file": file,
        "severity": sev,
        "message": "textbook",
        "fix_agent": fix_agent,
    }


def test_fix_json_no_findings_is_a_document_not_silence(monkeypatch, tmp_path, capsys):
    from patchi.cli.commands import fix_cmd
    from patchi.core import memory as mem

    monkeypatch.setattr(mem, "get_brain", lambda root: {"contract_locked": True})
    monkeypatch.setattr(mem, "get_scan_results", lambda root: {})
    fix_cmd.run(root=tmp_path, json_output=True)
    doc = json.loads(capsys.readouterr().out)
    assert doc["ok"] is True
    assert doc["applied"] == 0 and doc["queued"] == 0 and doc["blocked"] == 0
    assert "note" in doc


def test_fix_json_dry_run_reports_gate_actions(monkeypatch, tmp_path, capsys):
    from patchi.cli.commands import fix_cmd
    from patchi.core import memory as mem
    from patchi.core.fix.patch import Patch, PatchState

    monkeypatch.setattr(mem, "get_brain", lambda root: {"contract_locked": True})
    monkeypatch.setattr(
        mem, "get_scan_results",
        lambda root: {"Agent": {"findings": [_fake_finding()]}},
    )

    def fake_agents(findings, root, quiet=False):
        return [
            Patch(id="p1", description="d1", risk_score=10, confidence=90, state=PatchState.PROPOSED),
            Patch(id="p2", description="d2", risk_score=99, confidence=50, state=PatchState.PROPOSED),
        ]

    monkeypatch.setattr(fix_cmd, "_run_fix_agents", fake_agents)
    fix_cmd.run(root=tmp_path, dry_run=True, json_output=True)
    doc = json.loads(capsys.readouterr().out)
    assert doc["ok"] is True and doc["dry_run"] is True and doc["fixable"] == 1
    actions = {p["id"]: p["action"] for p in doc["patches"]}
    assert set(actions.values()) <= {"auto-apply", "queue", "blocked"}
    assert len(doc["patches"]) == 2
    assert all("risk_score" in p for p in doc["patches"])


def test_fix_json_patch_record_shape(monkeypatch, tmp_path, capsys):
    """The applied path's per-patch record carries the CI-relevant fields."""
    from patchi.cli.commands.fix_cmd import _patch_json
    from patchi.core.fix.patch import Patch, PatchState

    patch = Patch(
        id="p9",
        description="tighten",
        risk_score=22,
        confidence=80,
        state=PatchState.PENDING,
    )
    rec = _patch_json(patch, [])
    assert rec == {
        "id": "p9",
        "files": [],
        "risk_score": 22,
        "confidence": 80,
        "description": "tighten",
        "state": "pending",
        "blocked_reason": "",
    }


def test_fix_json_review_prompt_is_skipped(monkeypatch, tmp_path, capsys):
    """JSON mode must never reach the interactive confirm (CI would hang)."""
    from patchi.cli.commands import fix_cmd
    from patchi.core import memory as mem

    called = {"prompt": False}
    monkeypatch.setattr(mem, "get_brain", lambda root: {"contract_locked": True})
    monkeypatch.setattr(mem, "get_scan_results", lambda root: {})

    import patchi.cli.ux as ux

    real_confirm = ux.confirm

    def spy(*a, **k):
        called["prompt"] = True
        return real_confirm(*a, **k)

    monkeypatch.setattr(ux, "confirm", spy)
    fix_cmd.run(root=tmp_path, json_output=True)
    assert called["prompt"] is False


# ── p impact / p blast --json ─────────────────────────────────────────────────


def test_impact_json_document_shape(monkeypatch, tmp_path, capsys):
    from patchi.cli.commands import reason_cmd
    from patchi.core.brain.reasoning import ReasoningEngine

    class FakeAnalysis:
        summary = "1 file(s) changed"
        affected_layers = ["agents"]
        impacted_layers = ["web"]

    monkeypatch.setattr(ReasoningEngine, "impact_analysis", lambda self, files: FakeAnalysis())
    reason_cmd.run_impact(files=["a.py"], json_output=True, root=tmp_path)
    doc = json.loads(capsys.readouterr().out)
    assert doc["files"] == ["a.py"]
    assert doc["affected_layers"] == ["agents"]
    assert doc["impacted_layers"] == ["web"]


def test_blast_all_json_document_shape(tmp_path, capsys):
    from patchi.cli.commands import reason_cmd
    from patchi.core.brain.import_graph import ImportGraph

    graph = ImportGraph()
    for m in ("a.py", "b.py", "c.py"):
        graph.nodes.add(m)
    graph.add_edge("a.py", "b.py")
    graph.add_edge("b.py", "c.py")

    monkeypatched = reason_cmd._show_all_blast_radii(graph, tmp_path, json_output=True)
    _ = monkeypatched  # direct call; returns None, emits document
    doc = json.loads(capsys.readouterr().out)
    entries = {e["file"]: e for e in doc["blast_radii"]}
    assert entries["a.py"]["total_affected"] == 0  # nothing imports a.py
    assert entries["c.py"]["total_affected"] == 2  # a->b->c chain reaches c
    assert entries["c.py"]["direct"] == 1


def test_impact_json_error_paths_emit_documents(monkeypatch, tmp_path, capsys):
    from patchi.cli.commands import reason_cmd

    # no files given
    reason_cmd.run_impact(files=None, json_output=True, root=tmp_path)
    doc = json.loads(capsys.readouterr().out)
    assert "error" in doc

    # --all with no graph data
    monkeypatch.setattr(
        reason_cmd, "_build_graph",
        lambda root: __import__("patchi.core.brain.import_graph", fromlist=["ImportGraph"]).ImportGraph(),
    )
    reason_cmd.run_impact(files=None, show_all=True, json_output=True, root=tmp_path)
    doc = json.loads(capsys.readouterr().out)
    assert "error" in doc and "p scan" in doc["error"]
