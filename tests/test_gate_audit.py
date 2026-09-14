"""P-Check gate audit, locked as regression (spec §7).

Proves, on every run:
1. Every SECURITY name in the base gate list resolves (no typo-ghosts like
   the `DastAgent` vs `DASTAgent` miss that left dynamic testing ungated).
2. The exemption set is exactly the documented static-only agents — any
   addition fails here and forces a documented review.
3. AttackAgent (live Metasploit prober) is gated, not exempt.
4. Pure-live agents idle without P-Check instead of probing blind.
5. Mixed agents (CORSAuditor) keep static findings while the live step
   self-blocks with a recorded reason.
"""

import tempfile
from pathlib import Path

from patchi.core.agents.base import (
    AgentGroup,
    AgentInput,
    discover_agent_modules,
    get_agent,
    list_agents,
)

def _inp(root: Path) -> AgentInput:
    return AgentInput(root=root, scope=[], brain={}, config={})


def _tmp_root() -> Path:
    t = Path(tempfile.mkdtemp())
    (t / ".patchi").mkdir(exist_ok=True)
    return t


def test_security_gate_names_all_resolve():
    discover_agent_modules()
    from patchi.core.agents import base as _base
    import inspect

    src = inspect.getsource(_base.BaseAgent.run)
    # Extract the quoted names in the needs_gate tuple
    import re

    names = set(re.findall(r'"([A-Za-z]+Agent)"', src.split("needs_gate = ")[1].split(")")[0]))
    assert "DASTAgent" in names, "DASTAgent must be in the gate list"
    assert "DastAgent" not in names, "ghost typo name must not be in the gate list"
    for name in names:
        assert get_agent(name) is not None, f"gated name does not resolve: {name}"


def test_exemption_set_is_exact():
    discover_agent_modules()
    from patchi.core.agents import base as _base
    import inspect

    src = inspect.getsource(_base.BaseAgent.run)
    m = __import__("re").search(r"self\.name not in \((.*?)\)", src, __import__("re").DOTALL)
    assert m, "exemption tuple not found in BaseAgent.run"
    exempt = set(__import__("re").findall(r'"([A-Za-z]+Agent)"', m.group(1)))
    assert exempt == {"PreCheckAgent", "UnitTestAgent", "RegressionAgent", "APIContractAgent"}, exempt


def test_attack_agent_gated_without_pcheck():
    discover_agent_modules()
    from patchi.core.agents.attack_agent import AttackAgent

    res = AttackAgent().run(_inp(_tmp_root()))
    assert res.data.get("gate_blocked") is True


def test_dast_agent_gated_without_pcheck():
    discover_agent_modules()
    from patchi.core.agents.base import AgentGroup as _G

    cls = get_agent("DASTAgent")
    assert cls is not None
    assert cls.group == _G.SECURITY or cls.group == _G.TEST
    res = cls().run(_inp(_tmp_root()))
    assert res.data.get("gate_blocked") is True, res.data


def test_cors_auditor_static_survives_live_block(monkeypatch):
    discover_agent_modules()
    cls = get_agent("CORSAuditor")
    assert cls is not None
    # Pin online so the test exercises the P-Check gate, not the offline skip
    monkeypatch.setattr("patchi.core.security.security_probe.is_offline", lambda: False)
    root = _tmp_root()
    (root / "app.py").write_text(
        "from fastapi.middleware.cors import CORSMiddleware\n"
        'app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True)\n',
        encoding="utf-8",
    )
    res = cls().run(_inp(root))
    assert res.data.get("gate_blocked") is not True  # static path runs
    assert res.data.get("live_probe_blocked") is True  # live step self-blocks
    assert res.finding_count >= 1  # static CORS findings kept


def test_test_group_agents_either_run_or_gate():
    """Every TEST agent either is exempt (static) or gate-blocks idle."""
    discover_agent_modules()
    exempt = {"PreCheckAgent", "UnitTestAgent", "RegressionAgent", "APIContractAgent"}
    root = _tmp_root()
    offenders = []
    for cls in list_agents():
        if getattr(cls, "group", None) is not AgentGroup.TEST:
            continue
        if cls.name in exempt:
            continue
        try:
            res = cls().run(_inp(root))
        except Exception:
            continue  # crash = caught elsewhere; this test is about bypass
        ran_live = res.data.get("live_probe") is True
        blocked = res.data.get("gate_blocked") is True
        skipped = str(res.status.value).lower() == "skipped"
        if ran_live and not blocked:
            offenders.append(cls.name)
        elif not blocked and not skipped and not ran_live:
            # Ran fully without gate and without P-Check: only acceptable
            # for agents that never touch live targets. Flag for review.
            offenders.append(f"{cls.name} (ran ungated)")
    assert not offenders, f"agents bypassing the gate: {offenders}"
