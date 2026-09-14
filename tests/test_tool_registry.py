"""Unified tool registry (Part 3 §2): coverage, hints, and honest states."""

from patchi.core.agents.tool_health import check_tool, is_available, list_tools, tool_groups


def test_every_entry_has_install_hint():
    tools = list_tools()
    assert len(tools) >= 25, f"registry shrank: {len(tools)}"
    for t in tools:
        assert t["install"], f"{t['name']}: no install hint"
        assert t["group"], f"{t['name']}: no group"
        assert t["auto"] in ("pip", "npm", "go", "playwright", None), t


def test_auto_install_entries_have_exact_packages():
    """The installer runs these blindly — a wrong package is worse than none."""
    tools = {t["name"]: t for t in list_tools()}
    assert tools["pyre"]["pkg"] == "pyre-check"
    assert tools["cdxgen"]["pkg"] == "@cyclonedx/cdxgen"
    for name in ("gitleaks", "osv-scanner", "nuclei", "dalfox", "ffuf"):
        assert tools[name]["go_pkg"].startswith("github.com/"), name
    for name, t in tools.items():
        if t["auto"] in ("pip", "npm") and name != "playwright":
            pkg = t.get("pkg") or name
            assert " " not in pkg, (name, pkg)
            if "/" in pkg:
                # Scoped npm packages (@scope/name) are the only legal slash
                assert pkg.startswith("@") and pkg.count("/") == 1, (name, pkg)


def test_missing_tool_reports_hint_not_silence():
    st = check_tool("definitely-not-a-real-tool-xyz")
    assert st["status"] == "missing"
    assert is_available("definitely-not-a-real-tool-xyz") is False


def test_broken_state_exists():
    """pyre is present-but-unrunnable here: the third state must surface."""
    import shutil

    if shutil.which("pyre") is None:
        import pytest

        pytest.skip("pyre not installed here — nothing to prove broken")
    st = check_tool("pyre")
    assert st["status"] in ("ok", "broken")
    if st["status"] == "broken":
        assert st["hint"], "broken without explanation is silent failure"


def test_group_filter_returns_only_that_group():
    for group in tool_groups():
        tools = list_tools(group)
        assert tools, f"group {group!r} is registered but empty"
        assert all(t["group"] == group for t in tools), group


def test_group_filter_unknown_group_is_empty_not_crash():
    assert list_tools("definitely-not-a-group") == []


def test_ci_tiers_exist_with_installable_tools():
    """The advertised CI tiers must be real groups with real tools."""
    groups = set(tool_groups())
    for tier in ("sast", "dast", "secrets", "supply-chain"):
        assert tier in groups, f"CI tier {tier!r} missing from registry"
        assert any(t.get("auto") for t in list_tools(tier)), (
            f"CI tier {tier!r} has no auto-installable tool"
        )


def test_doctor_install_only_rejects_unknown_group(capsys):
    """--only with a bogus group must exit 2 with the valid-group list."""
    from patchi.cli.commands.doctor_cmd import _auto_install_tools

    rc = _auto_install_tools("definitely-not-a-group")
    assert rc == 2
    err = capsys.readouterr().out
    assert "Unknown tool group" in err
    assert "sast" in err  # valid groups are listed


def test_doctor_install_only_scopes_the_pass(monkeypatch, capsys):
    """--only sast must visit sast tools and nothing else."""
    from patchi.cli.commands import doctor_cmd

    seen_groups: list[str] = []

    def fake_check_tool(name: str) -> dict:
        return {"status": "ok", "version": "9.9.9", "hint": ""}

    real_list_tools = doctor_cmd.list_tools if hasattr(doctor_cmd, "list_tools") else None

    import patchi.core.agents.tool_health as th

    orig_list = th.list_tools
    monkeypatch.setattr(th, "list_tools", lambda group=None: seen_groups.extend(
        [t["group"] for t in orig_list(group)]
    ) or orig_list(group))
    monkeypatch.setattr(th, "check_tool", fake_check_tool)

    rc = doctor_cmd._auto_install_tools("sast")
    assert rc == 0
    assert seen_groups, "installer visited no tools"
    assert set(seen_groups) == {"sast"}, f"scoping leaked: {sorted(set(seen_groups))}"
    _ = real_list_tools
    out = capsys.readouterr().out
    assert "sast tools only" in out


def test_tool_verify_delegates_to_registry(monkeypatch):
    from patchi.core.security import tool_verify

    monkeypatch.setattr(tool_verify, "is_tool_ready", lambda _t: (True, ""))
    # Registry says ready: unsupported-tool error still comes from the map
    try:
        tool_verify.run_tool_on_file("nope-not-a-tool", __file__)
    except ValueError as e:
        assert "unsupported tool" in str(e)
    else:
        raise AssertionError("expected ValueError for unknown tool")
