"""Unit tests for patchi.core.brain.contract"""
from __future__ import annotations

import unittest

from patchi.core.brain.contract import (
    ContractBuilder,
    ContractFlow,
    confirm_flows,
    flows_from_dict,
)
from patchi.core.brain.languages import Lang
from patchi.core.brain.route_mapper import RouteInfo
from patchi.core.brain.scanner import FileInfo


def _make_route(path: str, method: str = "GET") -> RouteInfo:
    return RouteInfo(method=method, path=path, handler="handler", file="routes.py", line=1)


def _make_file(path: str) -> FileInfo:
    return FileInfo(path=path, language=Lang.PYTHON, size_bytes=100, lines=10)


class TestContractInference(unittest.TestCase):
    def test_infers_known_prefix(self):
        routes = [_make_route("/settings"), _make_route("/keys/add")]
        files = []
        builder = ContractBuilder(routes, files)
        flows = builder.infer()
        flow_ids = {f.id for f in flows}
        self.assertIn("settings", flow_ids)
        self.assertIn("keys", flow_ids)

    def test_unknown_prefix_becomes_other_api(self):
        routes = [_make_route("/api/custom")]
        builder = ContractBuilder(routes, [])
        flows = builder.infer()
        flow_ids = {f.id for f in flows}
        self.assertIn("other-api", flow_ids)

    def test_unmatched_routes_are_suggested(self):
        routes = [_make_route("/unknown/endpoint")]
        builder = ContractBuilder(routes, [])
        flows = builder.infer()
        for f in flows:
            if f.id == "other-api":
                self.assertTrue(f.suggested)

    def test_no_flows_for_empty_project(self):
        builder = ContractBuilder([], [])
        flows = builder.infer()
        self.assertEqual(flows, [])

    def test_inferred_flows_are_unconfirmed(self):
        routes = [_make_route("/settings")]
        builder = ContractBuilder(routes, [])
        flows = builder.infer()
        for flow in flows:
            self.assertFalse(flow.confirmed)

    def test_no_duplicate_flow_ids(self):
        routes = [_make_route("/settings"), _make_route("/security/scan"), _make_route("/security/full-scan")]
        builder = ContractBuilder(routes, [])
        flows = builder.infer()
        ids = [f.id for f in flows]
        self.assertEqual(len(ids), len(set(ids)))

    def test_confirmation_message_single_flow(self):
        routes = [_make_route("/settings")]
        builder = ContractBuilder(routes, [])
        flows = builder.infer()
        msg = builder.build_confirmation_message(flows)
        # Part 7: uncorroborated prefixes get generic names, never the
        # dashboard-specific table labels.
        self.assertIn("Settings Endpoints", msg)
        self.assertNotIn("Settings / Configuration", msg)
        self.assertIn("protect", msg)

    def test_corroborated_prefix_uses_table_name(self):
        routes = [_make_route("/settings")]
        files = [_make_file("src/settings.py")]
        builder = ContractBuilder(routes, files)
        flows = builder.infer()
        names = [f.name for f in flows]
        self.assertIn("Settings / Configuration", names)

    def test_critical_derived_not_defaulted(self):
        # GET-only, non-sensitive prefix: not critical.
        routes = [_make_route("/about")]
        flows = ContractBuilder(routes, []).infer()
        self.assertFalse(any(f.critical for f in flows))
        # Mutating method: critical by structure.
        routes = [_make_route("/items", method="POST")]
        flows = ContractBuilder(routes, []).infer()
        self.assertTrue(any(f.critical for f in flows))
        # Sensitive prefix: critical even when read-only.
        routes = [_make_route("/login")]
        flows = ContractBuilder(routes, []).infer()
        self.assertTrue(any(f.critical for f in flows))

    def test_confirmation_message_multiple_flows(self):
        routes = [_make_route("/settings"), _make_route("/security/scan")]
        builder = ContractBuilder(routes, [])
        flows = builder.infer()
        msg = builder.build_confirmation_message(flows)
        self.assertIn("and", msg)

    def test_confirmation_message_empty(self):
        builder = ContractBuilder([], [])
        msg = builder.build_confirmation_message([])
        self.assertIn("didn't find", msg)


class TestConfirmFlows(unittest.TestCase):
    def _make_flow(self, flow_id: str) -> ContractFlow:
        return ContractFlow(
            id=flow_id,
            name=flow_id.title(),
            description="Test flow.",
            routes=[],
            files=[],
            signals=[],
        )

    def test_confirm_selected_flows(self):
        flows = [self._make_flow("settings"), self._make_flow("keys")]
        confirmed = confirm_flows(flows, confirmed_ids={"settings"})
        self.assertEqual(len(confirmed), 1)
        self.assertTrue(confirmed[0].confirmed)
        self.assertEqual(confirmed[0].id, "settings")

    def test_unselected_flows_not_included(self):
        flows = [self._make_flow("settings"), self._make_flow("keys")]
        confirmed = confirm_flows(flows, confirmed_ids={"settings"})
        ids = {f.id for f in confirmed}
        self.assertNotIn("keys", ids)

    def test_user_additions(self):
        flows = []
        additions = [{"name": "Custom Export", "description": "Users can export data."}]
        confirmed = confirm_flows(flows, confirmed_ids=set(), user_additions=additions)
        self.assertEqual(len(confirmed), 1)
        self.assertTrue(confirmed[0].user_added)
        self.assertEqual(confirmed[0].name, "Custom Export")

    def test_confirm_all_flows(self):
        flows = [
            self._make_flow("settings"),
            self._make_flow("keys"),
            self._make_flow("security"),
        ]
        confirmed = confirm_flows(flows, confirmed_ids={"settings", "keys", "security"})
        self.assertEqual(len(confirmed), 3)
        self.assertTrue(all(f.confirmed for f in confirmed))


class TestFlowsSerialization(unittest.TestCase):
    def test_to_dict_and_back(self):
        flow = ContractFlow(
            id="settings",
            name="Settings / Configuration",
            description="Users can view and update project configuration.",
            routes=["/settings"],
            files=["src/routes/settings.py"],
            signals=["config"],
            confirmed=True,
            user_added=False,
        )
        d = flow.to_dict()
        restored = flows_from_dict([d])
        self.assertEqual(len(restored), 1)
        r = restored[0]
        self.assertEqual(r.id, "settings")
        self.assertEqual(r.name, "Settings / Configuration")
        self.assertTrue(r.confirmed)
        self.assertEqual(r.routes, ["/settings"])

    def test_empty_list(self):
        result = flows_from_dict([])
        self.assertEqual(result, [])


if __name__ == "__main__":
    unittest.main()
