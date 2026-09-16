"""Onboarding-banner stdout discipline on un-inited projects.

The pre-dispatch "Welcome to Patchi!" banner used to print on stdout for
every command on a project without a completed ``p init`` — polluting
machine-consumed output (status panels shifted, governance/CI surfaces
prefixed with human text) the same way it once polluted ``--json`` and the
update notice (both fixed earlier under the machine-pure contract).

The contract, enforced from ``main``'s onboarding block:

- suppressed from stdout when ``--json`` / ``<cmd> --json`` (top-level
  ``json`` or subcommand ``json_output``), ``--quiet``, or the command is a
  machine-stdout surface even in human mode (status/why/impact/blast/
  findings/trend/doctor/memory/governance/ready)
- in those modes a one-line nudge goes to **stderr** instead (dropped
  entirely under ``--quiet``: "errors only" means errors only)
- interactive human commands (scan, init-less chat, governance humans… —
  anything not in the machine set, not quiet/json) still get the friendly
  banner on stdout

These tests drive ``main.main`` end-to-end through its real arg parsing
with a stubbed registry dispatch (no project scan needed) and a tmp root
whose config says onboarding is incomplete.
"""

from __future__ import annotations

import sys

import pytest

from patchi.cli import main as cli_main


@pytest.fixture()
def uninited(tmp_path, monkeypatch):
    """A project root that exists but never completed onboarding."""
    from patchi.core import config as cfg

    monkeypatch.setattr(cfg, "find_project_root", lambda: tmp_path)
    monkeypatch.setattr(cfg, "load", lambda root: {"onboarding_complete": False})
    return tmp_path


def _run_main(argv, monkeypatch, capsys, capture=None):
    """Run main() with the given argv, dispatch stubbed out.

    ``capture`` (optional dict) receives the parsed args namespace the
    stubbed dispatch was handed — use it to assert on argparse results.
    """
    import patchi.cli.framework as fw

    captured = capture if capture is not None else {}

    def fake_dispatch(commands, args):
        captured["args"] = args
        return None, True

    monkeypatch.setattr(fw, "dispatch", fake_dispatch)
    monkeypatch.setattr(sys, "argv", ["patchi"] + argv)
    monkeypatch.setattr(
        "patchi.cli.commands.update_cmd.auto_check_background", lambda: None, raising=False
    )
    rc = cli_main.main()
    return rc, captured


# ── machine-stdout commands: banner must stay off stdout ────────────────────


@pytest.mark.parametrize(
    "argv",
    [
        ["status"],
        ["why", "app.py"],
        ["impact", "app.py"],
        ["blast", "app.py"],
        ["findings"],
        ["trend"],
        ["doctor"],
        ["memory"],
        ["governance", "actions"],
        ["governance", "policy"],
        ["ready"],
    ],
    ids=lambda a: " ".join(a),
)
def test_banner_absent_from_stdout_on_machine_commands(uninited, monkeypatch, capsys, argv):
    _run_main(argv, monkeypatch, capsys)
    out = capsys.readouterr().out
    assert "Welcome to Patchi" not in out, f"banner polluted stdout of `p {' '.join(argv)}`"


# ── stderr nudge replaces it (so humans piping output still get told) ───────


@pytest.mark.parametrize(
    "argv",
    [
        ["status"],
        ["governance", "actions"],
        ["ready"],
        ["findings"],
    ],
    ids=lambda a: " ".join(a),
)
def test_stderr_nudge_present_for_machine_commands(uninited, monkeypatch, capsys, argv):
    _run_main(argv, monkeypatch, capsys)
    err = capsys.readouterr().err
    assert "Onboarding incomplete" in err and "p init" in err


def test_stderr_nudge_dropped_under_quiet(uninited, monkeypatch, capsys):
    """--quiet means errors only — no nudge anywhere."""
    _run_main(["--quiet", "status"], monkeypatch, capsys)
    cap = capsys.readouterr()
    assert "Onboarding" not in cap.err
    assert "Welcome to Patchi" not in cap.out


# ── --json stays byte-pure (the original contract, still enforced) ──────────


@pytest.mark.parametrize("argv", [["--json", "status"], ["status", "--json"]])
def test_banner_absent_in_json_modes(uninited, monkeypatch, capsys, argv):
    _run_main(argv, monkeypatch, capsys)
    cap = capsys.readouterr()  # single read — readouterr drains the capture
    assert "Welcome to Patchi" not in cap.out
    assert "Onboarding incomplete" in cap.err  # stderr nudge still informs humans


# ── interactive humans still get the friendly banner ────────────────────────


def test_banner_still_shown_for_humans(uninited, monkeypatch, capsys):
    _run_main(["scan"], monkeypatch, capsys)
    out = capsys.readouterr().out
    assert "Welcome to Patchi" in out


def test_banner_shown_for_chat(uninited, monkeypatch, capsys):
    _run_main(["chat"], monkeypatch, capsys)
    out = capsys.readouterr().out
    assert "Welcome to Patchi" in out


def test_no_banner_when_onboarding_complete(tmp_path, monkeypatch, capsys):
    from patchi.core import config as cfg

    monkeypatch.setattr(cfg, "find_project_root", lambda: tmp_path)
    monkeypatch.setattr(cfg, "load", lambda root: {"onboarding_complete": True})
    _run_main(["status"], monkeypatch, capsys)
    cap = capsys.readouterr()
    assert "Welcome to Patchi" not in cap.out
    assert "Onboarding incomplete" not in cap.err


def test_no_banner_without_project_root(monkeypatch, capsys):
    from patchi.core import config as cfg

    monkeypatch.setattr(cfg, "find_project_root", lambda: None)
    _run_main(["status"], monkeypatch, capsys)
    cap = capsys.readouterr()
    assert "Welcome to Patchi" not in cap.out
    assert "Onboarding incomplete" not in cap.err


# ── global --json bridges into json_output commands ──────────────────────────


def test_top_level_json_bridges_to_json_output(uninited, monkeypatch, capsys):
    """`p --json status` must reach the handler: the subparser's json_output
    default would otherwise mask the top-level flag (pre-existing bug where
    only `p status --json` produced JSON). Asserts end-to-end through real
    main() via the args the stubbed dispatch receives."""
    captured: dict = {}
    _run_main(["--json", "status"], monkeypatch, capsys, capture=captured)
    assert captured["args"].json_output is True


def test_subcommand_json_form_still_works(uninited, monkeypatch, capsys):
    captured: dict = {}
    _run_main(["status", "--json"], monkeypatch, capsys, capture=captured)
    assert captured["args"].json_output is True


def test_bridge_does_not_fire_without_json(uninited, monkeypatch, capsys):
    captured: dict = {}
    _run_main(["status"], monkeypatch, capsys, capture=captured)
    assert captured["args"].json_output is False
    assert captured["args"].json is False
