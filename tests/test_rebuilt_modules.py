"""Tests for the rebuilt modules: defenders, fuzz, reliability, attackers, campaigns."""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from patchi.core.assurance.graph import AssuranceGraph

# ── Defenders ────────────────────────────────────────────────────────────────


class TestDefenderRegistry:
    def test_all_adapters_registered(self):
        from patchi.core.security.defenders import ADAPTER_REGISTRY

        expected = {
            "fix_code", "update_dependency", "block_ip", "rotate_secret",
            "patch_config", "crypto_fix", "auth_middleware",
            "invalidate_session", "enforce_rate_limit", "suspend_account",
            "block_ws_origin",
        }
        assert expected == set(ADAPTER_REGISTRY.keys())

    def test_get_adapter_returns_correct_class(self):
        from patchi.core.security.defenders import get_adapter
        from patchi.core.security.defenders.block_ip import BlockIpAdapter
        from patchi.core.security.defenders.fix_code import FixCodeAdapter

        adapter = get_adapter("fix_code", root=Path("."), risk_gate=None)
        assert isinstance(adapter, FixCodeAdapter)

        adapter = get_adapter("block_ip", root=Path("."), risk_gate=None)
        assert isinstance(adapter, BlockIpAdapter)

    def test_fallback_adapter_for_unknown_type(self):
        from patchi.core.security.defenders import get_adapter

        adapter = get_adapter("totally_unknown_type", root=Path("."), risk_gate=None)
        assert adapter.action_type == "totally_unknown_type"

    def test_defense_layer_delegates(self):
        from patchi.core.security.defense_layer import DefenseLayer

        dl = DefenseLayer(root=Path("."))
        assert hasattr(dl, "defend_all")
        assert hasattr(dl, "_execute")


# ── Fuzz ─────────────────────────────────────────────────────────────────────


class TestInputFuzzer:
    def test_fuzz_string_generates_variants(self):
        from patchi.core.fuzz import InputFuzzer

        f = InputFuzzer(seed=42)
        results = f.fuzz_string("hello", count=15)
        assert len(results) == 15
        assert any(r.strategy == "injection" for r in results)
        assert any(r.strategy == "boundary" for r in results)

    def test_fuzz_numeric_generates_variants(self):
        from patchi.core.fuzz import InputFuzzer

        f = InputFuzzer(seed=42)
        results = f.fuzz_numeric(42)
        assert len(results) == 10
        values = {r.value for r in results}
        assert 0 in values
        assert -1 in values

    def test_fuzz_dict_adds_extra_keys(self):
        from patchi.core.fuzz import InputFuzzer

        f = InputFuzzer(seed=42)
        results = f.fuzz_dict({"name": "test"})
        assert len(results) >= 4
        admin_key = [r for r in results if "admin_key" in r.label]
        assert len(admin_key) == 1
        assert admin_key[0].value.get("admin") is True


class TestSequenceFuzzer:
    def test_pairwise_permutations(self):
        from patchi.core.fuzz import SequenceFuzzer

        sf = SequenceFuzzer()
        ops = [{"method": "GET", "path": "/a"}, {"method": "POST", "path": "/b"}]
        results = sf.generate(ops)
        assert len(results) >= 2
        labels = {r.label for r in results}
        assert any("reversed" in lbl for lbl in labels)

    def test_replay_sequences(self):
        from patchi.core.fuzz import SequenceFuzzer

        sf = SequenceFuzzer()
        ops = [{"method": "POST", "path": "/api/transfer"}]
        results = sf.generate(ops)
        assert any(r.strategy == "replay" for r in results)


class TestStateFuzzer:
    def test_illegal_transitions(self):
        from patchi.core.fuzz import StateFuzzer

        sf = StateFuzzer()
        sf.load_from_dict({
            "transitions": [
                {"from_state": "anon", "to_state": "auth", "action": "login"},
                {"from_state": "auth", "to_state": "admin", "action": "escalate"},
            ]
        })
        results = sf.generate()
        illegal = [r for r in results if r.strategy == "illegal"]
        assert len(illegal) > 0

    def test_replay_attacks(self):
        from patchi.core.fuzz import StateFuzzer

        sf = StateFuzzer()
        sf.load_from_dict({
            "transitions": [
                {"from_state": "a", "to_state": "b", "action": "go"},
            ]
        })
        results = sf.generate()
        replay = [r for r in results if r.strategy == "replay"]
        assert len(replay) > 0


class TestFuzzCorpus:
    def test_add_and_retrieve(self):
        from patchi.core.fuzz.corpus import CorpusEntry, FuzzCorpus

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            corpus = FuzzCorpus(root)
            corpus.add(CorpusEntry(label="test1", value="hello", strategy="boundary", score=0.8))
            corpus.add(CorpusEntry(label="test2", value="world", strategy="injection", score=0.3))
            assert len(corpus) == 2

            interesting = corpus.get_interesting(min_score=0.5)
            assert len(interesting) == 1
            assert interesting[0].label == "test1"

            # Test persistence
            corpus.save()
            corpus2 = FuzzCorpus(root)
            assert len(corpus2) == 2


# ── Reliability ──────────────────────────────────────────────────────────────


class TestFaultInjector:
    def test_scan_file_finds_issues(self):
        from patchi.core.reliability import FaultInjector

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "test.py").write_text(
                'import requests\n'
                'requests.get("http://example.com")\n'
                'json.loads(data)\n'
            )
            fi = FaultInjector(root)
            results = fi.scan_file(root / "test.py")
            types = {r.fault_type for r in results}
            assert "network" in types or "disk" in types


class TestIdempotencyAnalyzer:
    def test_finds_append_issues(self):
        from patchi.core.reliability import IdempotencyAnalyzer

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "test.py").write_text("items.append(new_item)\n")
            ia = IdempotencyAnalyzer(root)
            results = ia.scan_file(root / "test.py")
            assert len(results) >= 1
            assert results[0].issue_type == "append_without_check"


class TestChaosScenario:
    def test_general_experiments(self):
        from patchi.core.reliability import ChaosScenario

        cs = ChaosScenario(Path("."))
        experiments = cs.analyze()
        assert len(experiments) >= 3
        names = {e.name for e in experiments}
        assert "disk_full_on_scan" in names


class TestRecoveryAnalyzer:
    def test_general_gaps(self):
        from patchi.core.reliability import RecoveryAnalyzer

        ra = RecoveryAnalyzer(Path("."))
        gaps = ra.analyze()
        assert isinstance(gaps, list)


# ── Attackers ────────────────────────────────────────────────────────────────


class TestAttackPlanner:
    def test_empty_graph_no_hypotheses(self):
        from patchi.core.attackers import AttackPlanner

        g = AssuranceGraph()
        planner = AttackPlanner(g)
        plan = planner.plan()
        assert plan.total_score == 0.0

    def test_plan_with_claims(self):
        from patchi.core.attackers import AttackPlanner

        g = AssuranceGraph()
        g.upsert_claim(
            "auth-endpoints",
            "All endpoints require authentication",
            domain="auth",
        )
        # Leave verdict as UNPROVEN (no evidence) so attackers hypothesize
        planner = AttackPlanner(g)
        plan = planner.plan()
        assert len(plan.hypotheses) > 0

    def test_run_all_empty(self):
        from patchi.core.attackers import AttackPlanner

        g = AssuranceGraph()
        planner = AttackPlanner(g)
        results = planner.run_all()
        assert results == []


# ── Campaigns ────────────────────────────────────────────────────────────────


class TestCampaignOrchestrator:
    def test_run_all_empty_graph(self):
        from patchi.core.campaigns import CampaignOrchestrator

        g = AssuranceGraph()
        orch = CampaignOrchestrator(g)
        result = orch.run_all()
        assert len(result.campaigns) == 2
        assert result.total_findings >= 0

    def test_run_specific_campaign(self):
        from patchi.core.campaigns import CampaignOrchestrator

        g = AssuranceGraph()
        orch = CampaignOrchestrator(g)
        result = orch.run_campaign("state_transitions")
        assert result.name == "state_transitions"

    def test_unknown_campaign_raises(self):
        from patchi.core.campaigns import CampaignOrchestrator

        g = AssuranceGraph()
        orch = CampaignOrchestrator(g)
        with pytest.raises(ValueError, match="Unknown campaign"):
            orch.run_campaign("nonexistent")


class TestStateTransitionCampaign:
    def test_discovers_states(self):
        from patchi.core.campaigns import StateTransitionCampaign

        g = AssuranceGraph()
        c = StateTransitionCampaign(g)
        steps = c.run()
        names = {s.name for s in steps}
        assert "discover_states" in names
        assert "test_illegal_sequences" in names


class TestDataFlowAbuseCampaign:
    def test_runs_all_steps(self):
        from patchi.core.campaigns import DataFlowAbuseCampaign

        g = AssuranceGraph()
        c = DataFlowAbuseCampaign(g)
        steps = c.run()
        assert len(steps) == 6
