"""Go type checker — uses tree-sitter."""

from __future__ import annotations

import logging
from typing import Any

from ..languages import Lang, get_parser
from .base import BaseTypeChecker, _node_text, make_finding

_log = logging.getLogger("patchi.brain.go")

class GoTypeChecker(BaseTypeChecker):
    language = "go"

    def check(self, source: str, file_path: str) -> list[dict]:
        findings: list[dict] = []
        parser = get_parser(Lang.GO)
        if parser is None:
            return findings
        try:
            tree = parser.parse(source.encode("utf-8"))
            self._walk(tree.root_node, source, file_path, findings)
        except Exception as e:
            _log.warning("GoTypeChecker.check failed: %s", e)
        return findings

    def _walk(self, node: Any, source: str, file_path: str, findings: list[dict]) -> None:
        ntype = node.type
        if ntype == "function_declaration":
            line = node.start_point[0] + 1
            name_node = self._child_by_type(node, "identifier")
            name = _node_text(source, name_node) if name_node else ""
            result = self._child_by_type(node, "result")
            if result is not None:
                for child in result.children:
                    if child.type == "type_identifier" and _node_text(source, child) == "interface{}":
                        findings.append(make_finding(
                            finding_type="empty_interface",
                            file=file_path, line=line,
                            title="Function returns 'interface{}'",
                            description=f"Function '{name}' returns empty interface — consider a concrete type",
                            evidence=f"{name}: interface{{}}",
                            severity="medium",
                        ))
                        break
            params = self._child_by_type(node, "parameter_list")
            if params:
                for child in params.children:
                    if child.type == "parameter_declaration":
                        ptype = self._child_by_type(child, "type_identifier") or self._child_by_type(child, "pointer_type") or self._child_by_type(child, "generic_type")
                        if ptype and _node_text(source, ptype) == "interface{}":
                            findings.append(make_finding(
                                finding_type="empty_interface",
                                file=file_path, line=line,
                                title="Parameter is 'interface{}'",
                                description=f"Parameter in '{name}' is empty interface — consider a concrete type",
                                severity="medium",
                            ))
        for child in node.children:
            self._walk(child, source, file_path, findings)

    def _child_by_type(self, node: Any, ntype: str) -> Any | None:
        for child in node.children:
            if child.type == ntype:
                return child
        return None
