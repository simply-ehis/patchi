"""Dart type checker — uses tree-sitter."""

from __future__ import annotations

from typing import Any

from ..languages import Lang, get_parser
from .base import BaseTypeChecker, _node_text, make_finding


import logging
_log = logging.getLogger("patchi.brain.dart")

class DartTypeChecker(BaseTypeChecker):
    language = "dart"

    def check(self, source: str, file_path: str) -> list[dict]:
        findings: list[dict] = []
        parser = get_parser(Lang.DART)
        if parser is None:
            return findings
        try:
            tree = parser.parse(source.encode("utf-8"))
            self._walk(tree.root_node, source, file_path, findings)
        except Exception as e:
            _log.warning("DartTypeChecker.check failed: %s", e)
        return findings

    def _walk(self, node: Any, source: str, file_path: str, findings: list[dict]) -> None:
        ntype = node.type
        if ntype in ("method_declaration", "function_declaration"):
            line = node.start_point[0] + 1
            name = _node_text(source, self._child_by_type(node, "identifier")) if self._child_by_type(node, "identifier") else ""
            return_type = self._child_by_type(node, "type_identifier") or self._child_by_type(node, "generic_type")
            if return_type and _node_text(source, return_type) == "dynamic":
                findings.append(make_finding(
                    finding_type="dynamic_type",
                    file=file_path, line=line,
                    title="Function returns 'dynamic'",
                    description=f"Function '{name}' returns 'dynamic' — prefer a specific type for sound null safety",
                    severity="medium",
                ))
        for child in node.children:
            self._walk(child, source, file_path, findings)

    def _child_by_type(self, node: Any, ntype: str) -> Any | None:
        for child in node.children:
            if child.type == ntype:
                return child
        return None
