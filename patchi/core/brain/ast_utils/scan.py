"""
AST scanning utilities for Patchi.
Provides tree-sitter based code scanning capabilities.
"""

import logging
from pathlib import Path
from typing import Any, Dict

logger = logging.getLogger(__name__)


def _slice(node: Any, source: str) -> str:
    """Extract source code slice for a tree-sitter node."""
    try:
        return source[node.start_byte:node.end_byte]
    except Exception:
        return ""


def scan_python(
    source: str,
    file_path: Path,
) -> Dict[str, Any]:
    """
    Scan Python source code and extract structured information.
    
    Returns a dictionary with:
    - functions: list of function definitions
    - classes: list of class definitions
    - imports: list of imports
    - calls: function/method calls
    """
    try:
        import ast
    except ImportError:
        logger.warning("ast module not available")
        return {"functions": [], "classes": [], "imports": [], "calls": []}

    try:
        tree = ast.parse(source)
    except SyntaxError as e:
        logger.warning(f"Syntax error in {file_path}: {e}")
        return {"functions": [], "classes": [], "imports": [], "calls": []}

    functions = []
    classes = []
    imports = []
    calls = []

    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            functions.append({
                "name": node.name,
                "line": node.lineno,
                "end_line": getattr(node, 'end_lineno', node.lineno),
                "args": [a.arg for a in node.args.args],
                "returns": ast.unparse(node.returns) if node.returns else None,
            })
        elif isinstance(node, ast.ClassDef):
            classes.append({
                "name": node.name,
                "line": node.lineno,
                "end_line": getattr(node, 'end_lineno', node.lineno),
                "bases": [ast.unparse(b) for b in node.bases],
            })
        elif isinstance(node, ast.Import):
            for alias in node.names:
                imports.append({
                    "name": alias.name,
                    "alias": alias.asname,
                    "line": node.lineno,
                })
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                imports.append({
                    "name": f"{node.module}.{alias.name}" if node.module else alias.name,
                    "alias": alias.asname,
                    "line": node.lineno,
                })
        elif isinstance(node, ast.Call):
            func_name = ""
            if isinstance(node.func, ast.Name):
                func_name = node.func.id
            elif isinstance(node.func, ast.Attribute):
                func_name = node.func.attr
            calls.append({
                "function": func_name,
                "line": node.lineno,
            })

    return {
        "functions": functions,
        "classes": classes,
        "imports": imports,
        "calls": calls,
    }


def scan_generic(source: str, file_path: Path) -> Dict[str, Any]:
    """
    Generic scanner for non-Python files.
    Returns basic structural information.
    """
    return {
        "functions": [],
        "classes": [],
        "imports": [],
        "calls": [],
    }


def scan_file(file_path: Path) -> Dict[str, Any]:
    """
    Scan a file and return structured information.
    """
    try:
        source = file_path.read_text(encoding="utf-8", errors="ignore")
    except Exception as e:
        logger.warning(f"Failed to read {file_path}: {e}")
        return {"functions": [], "classes": [], "imports": [], "calls": []}

    suffix = file_path.suffix.lower()
    if suffix == ".py":
        return scan_python(source, file_path)
    else:
        return scan_generic(source, file_path)


def scan_python_file(file_path: Path) -> Dict[str, Any]:
    """Convenience function to scan a Python file."""
    return scan_python(file_path.read_text(encoding="utf-8"), file_path)
