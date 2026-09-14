"""Python type checker — uses stdlib ast."""

from __future__ import annotations

import ast

from .base import BaseTypeChecker, make_finding


class PythonTypeChecker(BaseTypeChecker):
    language = "python"

    def check(self, source: str, file_path: str) -> list[dict]:
        findings: list[dict] = []
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return findings

        lines = source.split("\n")
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self._check_function_def(node, lines, file_path, findings)
            elif isinstance(node, ast.AnnAssign):
                self._check_annotation(node, lines, file_path, findings)

        return findings

    def _check_function_def(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        lines: list[str],
        file_path: str,
        findings: list[dict],
    ) -> None:
        line = node.lineno

        # Missing return type annotation
        if node.returns is None:
            if node.name not in ("__init__", "__new__", "__post_init__"):
                findings.append(
                    make_finding(
                        finding_type="missing_return_type",
                        file=file_path,
                        line=line,
                        title="Missing return type annotation",
                        description=f"Function '{node.name}' is missing a return type annotation",
                        evidence=f"def {node.name}",
                        severity="low",
                    )
                )

        # Parameters without type annotations
        for arg in node.args.args:
            if arg.arg == "self":
                continue
            if arg.annotation is None:
                findings.append(
                    make_finding(
                        finding_type="missing_param_type",
                        file=file_path,
                        line=line,
                        title="Missing parameter type annotation",
                        description=f"Parameter '{arg.arg}' in function '{node.name}' is missing a type annotation",
                        evidence=f"{arg.arg}: ?",
                        severity="low",
                    )
                )

    def _check_annotation(self, node: ast.AnnAssign, lines: list[str], file_path: str, findings: list[dict]) -> None:
        line = node.lineno
        ann = node.annotation
        if isinstance(ann, ast.Name) and ann.id == "Any":
            target = ast.unparse(node.target) if hasattr(ast, "unparse") else ""
            findings.append(
                make_finding(
                    finding_type="explicit_any",
                    file=file_path,
                    line=line,
                    title="Variable typed as 'Any'",
                    description=f"Variable '{target}' is typed as 'Any' (bypasses type checking)",
                    evidence=f"{target}: Any",
                    severity="medium",
                )
            )
