"""PHP type checker — uses tree-sitter."""

from __future__ import annotations

import logging
from typing import Any

from ..languages import Lang, get_parser
from .base import BaseTypeChecker, _node_text, make_finding

_log = logging.getLogger("patchi.brain.php")

class PHPTypeChecker(BaseTypeChecker):
    language = "php"

    def check(self, source: str, file_path: str) -> list[dict]:
        findings: list[dict] = []
        parser = get_parser(Lang.PHP)
        if parser is None:
            return findings
        try:
            tree = parser.parse(source.encode("utf-8"))
            self._walk(tree.root_node, source, file_path, findings)
        except Exception as e:
            _log.warning("PHPTypeChecker.check failed: %s", e)
        return findings

    def _walk(self, node: Any, source: str, file_path: str, findings: list[dict]) -> None:
        ntype = node.type
        if ntype in ("function_definition", "method_declaration"):
            line = node.start_point[0] + 1
            name = _node_text(source, self._child_by_type(node, "name")) if self._child_by_type(node, "name") else ""
            return_type = self._child_by_type(node, "primitive_type") or self._child_by_type(node, "named_type") or self._child_by_type(node, "nullable_type")
            if return_type is None:
                findings.append(make_finding(
                    finding_type="missing_return_type",
                    file=file_path, line=line,
                    title="Missing return type hint",
                    description=f"Function '{name}' is missing a PHP return type hint",
                    evidence=f"function {name}()",
                    severity="low",
                ))
            # Check param type hints
            params = self._child_by_type(node, "formal_parameters")
            if params:
                for child in params.children:
                    if child.type == "simple_parameter":
                        ptype = self._child_by_type(child, "primitive_type") or self._child_by_type(child, "named_type") or self._child_by_type(child, "nullable_type")
                        if ptype is None:
                            param_name = _node_text(source, self._child_by_type(child, "variable_name")) if self._child_by_type(child, "variable_name") else "?"
                            findings.append(make_finding(
                                finding_type="missing_param_type",
                                file=file_path, line=line,
                                title="Missing parameter type hint",
                                description=f"Parameter '{param_name}' in '{name}' missing type hint",
                                severity="low",
                            ))
        for child in node.children:
            self._walk(child, source, file_path, findings)

    def _child_by_type(self, node: Any, ntype: str) -> Any | None:
        for child in node.children:
            if child.type == ntype:
                return child
        return None
