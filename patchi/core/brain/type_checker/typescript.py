"""TypeScript type checker — uses tree-sitter AST instead of regex."""

from __future__ import annotations

from typing import Any

from ..languages import Lang, get_parser
from .base import BaseTypeChecker, _node_text, make_finding


import logging
_log = logging.getLogger("patchi.brain.typescript")

class TypeScriptChecker(BaseTypeChecker):
    language = "typescript"

    def check(self, source: str, file_path: str) -> list[dict]:
        findings: list[dict] = []
        parser = get_parser(Lang.TYPESCRIPT)
        if parser is None:
            return findings

        try:
            tree = parser.parse(source.encode("utf-8"))
            buf = source.encode("utf-8")
            self._walk(tree.root_node, buf, source, file_path, findings)
        except Exception as e:
            _log.warning("TypeScriptChecker.check failed: %s", e)

        return findings

    def _walk(self, node: Any, buf: bytes, source: str, file_path: str, findings: list[dict]) -> None:
        ntype = node.type

        if ntype in ("function_declaration", "method_definition"):
            self._check_function(node, buf, source, file_path, findings)
            return
        elif ntype == "arrow_function":
            self._check_arrow_function(node, buf, source, file_path, findings)
            return
        elif ntype == "variable_declarator":
            self._check_variable(node, buf, source, file_path, findings)
        elif ntype == "required_parameter":
            self._check_parameter(node, buf, source, file_path, findings)
        elif ntype == "export_statement":
            for child in node.named_children if hasattr(node, "named_children") else node.children:
                self._walk(child, buf, source, file_path, findings)
            return
        elif ntype == "as_expression":
            self._check_as_cast(node, buf, source, file_path, findings)
        elif ntype == "comment":
            self._check_comment(node, buf, source, file_path, findings)
            return

        for child in node.named_children if hasattr(node, "named_children") else node.children:
            self._walk(child, buf, source, file_path, findings)

    def _check_function(self, node: Any, buf: bytes, source: str, file_path: str, findings: list[dict]) -> None:
        line = node.start_point[0] + 1

        # Check return type annotation
        return_type = self._child_by_field(node, "return_type")
        name = self._child_text_by_field(node, "name", buf) or "anonymous"

        if return_type is None and name != "constructor":
            body_text = _node_text(source, node)
            if "=>" not in body_text:
                findings.append(make_finding(
                    finding_type="missing_return_type",
                    file=file_path, line=line,
                    title="Missing return type on function",
                    description=f"Function '{name}' is missing an explicit return type annotation",
                    evidence=f"function {name}",
                    severity="low",
                ))
        elif return_type is not None:
            # return_type is a type_annotation node — look inside for "any"
            inner = self._find_predefined_type(return_type)
            if inner == "any":
                findings.append(make_finding(
                    finding_type="explicit_any",
                    file=file_path, line=line,
                    title="Function returns 'any'",
                    description=f"Function '{name}' returns 'any' type",
                    evidence=f"function {name}: any",
                    severity="medium",
                ))

        # Check parameters for 'any'
        params = self._child_by_field(node, "parameters")
        if params:
            self._check_parameter_list(params, buf, source, file_path, findings)

    def _check_arrow_function(self, node: Any, buf: bytes, source: str, file_path: str, findings: list[dict]) -> None:
        line = node.start_point[0] + 1

        return_type = self._child_by_field(node, "return_type")
        if return_type is None:
            parent = getattr(node, "parent", None)
            if parent and parent.type == "variable_declarator":
                name_node = self._child_by_field(parent, "name")
                name = _node_text(source, name_node) if name_node else "anonymous"
                findings.append(make_finding(
                    finding_type="missing_return_type",
                    file=file_path, line=line,
                    title="Missing return type on arrow function",
                    description=f"Arrow function '{name}' is missing explicit return type",
                    evidence=f"const {name} = ... =>",
                    severity="low",
                ))
        elif return_type is not None:
            inner = self._find_predefined_type(return_type)
            if inner == "any":
                findings.append(make_finding(
                    finding_type="explicit_any",
                    file=file_path, line=line,
                    title="Arrow function returns 'any'",
                    description="Arrow function returns 'any' type",
                    severity="medium",
                ))

        params = self._child_by_field(node, "parameters")
        if params:
            self._check_parameter_list(params, buf, source, file_path, findings)

    def _check_variable(self, node: Any, buf: bytes, source: str, file_path: str, findings: list[dict]) -> None:
        line = node.start_point[0] + 1
        name_node = self._child_by_field(node, "name")
        name = _node_text(source, name_node) if name_node else ""

        # Check if variable has a type annotation
        type_node = self._child_by_field(node, "type")
        if type_node is None:
            value_node = self._child_by_field(node, "value")
            if value_node and value_node.type not in ("arrow_function", "function", "object", "array"):
                findings.append(make_finding(
                    finding_type="missing_type",
                    file=file_path, line=line,
                    title="Missing type annotation on variable",
                    description=f"Variable '{name}' is missing explicit type annotation",
                    evidence=f"{name} = ...",
                    severity="low",
                ))
        elif type_node is not None:
            inner = self._find_predefined_type(type_node)
            if inner == "any":
                findings.append(make_finding(
                    finding_type="explicit_any",
                    file=file_path, line=line,
                    title="Variable typed as 'any'",
                    description=f"Variable '{name}' is explicitly typed as 'any'",
                    evidence=f"{name}: any",
                    severity="medium",
                ))

    def _check_parameter(self, node: Any, buf: bytes, source: str, file_path: str, findings: list[dict]) -> None:
        line = node.start_point[0] + 1
        name_node = self._child_by_field(node, "name")
        name = _node_text(source, name_node) if name_node else ""

        type_node = self._child_by_field(node, "type")
        if type_node is not None:
            inner = self._find_predefined_type(type_node)
            if inner == "any":
                findings.append(make_finding(
                    finding_type="explicit_any",
                    file=file_path, line=line,
                    title="Parameter typed as 'any'",
                    description=f"Parameter '{name}' is typed as 'any'",
                    evidence=f"{name}: any",
                    severity="medium",
                ))

    def _check_parameter_list(self, params_node: Any, buf: bytes, source: str, file_path: str, findings: list[dict]) -> None:
        for child in params_node.named_children if hasattr(params_node, "named_children") else params_node.children:
            if child.type == "required_parameter":
                self._check_parameter(child, buf, source, file_path, findings)
            elif child.type == "optional_parameter":
                self._check_parameter(child, buf, source, file_path, findings)

    def _find_predefined_type(self, type_ann: Any) -> str:
        """Look inside a type_annotation node for a predefined_type like 'any'."""
        for child in type_ann.children if hasattr(type_ann, "children") else []:
            if child.type == "predefined_type":
                try:
                    raw = child.text
                    if isinstance(raw, bytes):
                        return raw.decode("utf-8", errors="replace")
                    return str(raw)
                except Exception as e:
                    _log.warning("TypeScriptChecker._find_predefined_type failed: %s", e)
        return ""

    def _child_by_field(self, node: Any, field: str) -> Any | None:
        if hasattr(node, "child_by_field_name"):
            return node.child_by_field_name(field)
        return None

    def _child_text_by_field(self, node: Any, field: str, buf: bytes) -> str:
        child = self._child_by_field(node, field)
        if child:
            try:
                return buf[child.start_byte : child.end_byte].decode("utf-8", errors="replace")
            except Exception as e:
                _log.warning("TypeScriptChecker._child_text_by_field failed: %s", e)
        return ""

    def _check_as_cast(self, node: Any, buf: bytes, source: str, file_path: str, findings: list[dict]) -> None:
        line = node.start_point[0] + 1
        type_node = self._child_by_field(node, "type")
        type_name = "unknown"
        if type_node:
            type_name = _node_text(source, type_node)[:50]
        findings.append(make_finding(
            finding_type="unsafe_cast",
            file=file_path, line=line,
            title="Unsafe type cast",
            description=f"Using 'as' type assertion to '{type_name}'",
            evidence=f"as {type_name}",
            severity="medium",
        ))

    def _check_comment(self, node: Any, buf: bytes, source: str, file_path: str, findings: list[dict]) -> None:
        line = node.start_point[0] + 1
        text = _node_text(source, node)
        if "@ts-ignore" in text:
            findings.append(make_finding(
                finding_type="ts_ignore",
                file=file_path, line=line,
                title="@ts-ignore suppression",
                description="TypeScript compiler error suppressed with @ts-ignore",
                evidence=text.strip(),
                severity="medium",
            ))
        elif "@ts-expect-error" in text:
            findings.append(make_finding(
                finding_type="ts_ignore",
                file=file_path, line=line,
                title="@ts-expect-error suppression",
                description="TypeScript compiler error suppressed with @ts-expect-error",
                evidence=text.strip(),
                severity="medium",
            ))
