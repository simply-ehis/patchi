"""Mutation testing infrastructure — kills weak tests by mutating AST nodes.

Parses Python source with ast.parse, applies single-point mutations via
ast.NodeTransformer subclasses, writes each mutant to a temp file, runs pytest
against it, and reports whether the test suite caught the mutation (killed) or
not (survived).

Usage (programmatic):
    tester = MutationTester(project_root)
    mutants = tester.generate_mutants(file_path)
    results = [tester.run_tests_for_mutant(m) for m in mutants]
    score = tester.score(mutants, results)

CLI:
    p eval mut --file <path> [--max N] [--timeout S]
"""

from __future__ import annotations

import ast
import copy
import dataclasses
import os
import subprocess
import sys
import tempfile
from pathlib import Path

# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class Mutant:
    """A single point mutation applied to source code."""

    original_line: int
    mutated_code: str
    operator_name: str
    line_number: int
    description: str = ""


@dataclasses.dataclass(frozen=True)
class MutationResult:
    """Outcome of running the test suite against one mutant."""

    mutant: Mutant
    killed: bool
    test_returncode: int
    test_output: str
    duration_s: float


@dataclasses.dataclass(frozen=True)
class MutationScore:
    """Aggregate score across a set of mutants."""

    total: int
    killed: int
    survived: int
    errors: int
    kill_rate: float
    results: list[MutationResult]


# ---------------------------------------------------------------------------
# AST helpers
# ---------------------------------------------------------------------------

# Binary operators that have a natural inversion.
_OPPOSITE_BINOP: dict[type[ast.operator], type[ast.operator]] = {
    ast.Eq: ast.NotEq,
    ast.NotEq: ast.Eq,
    ast.Lt: ast.GtE,
    ast.GtE: ast.Lt,
    ast.LtE: ast.Gt,
    ast.Gt: ast.LtE,
    ast.Add: ast.Sub,
    ast.Sub: ast.Add,
    ast.Mult: ast.Div,
    ast.Div: ast.Mult,
    ast.FloorDiv: ast.Mult,
    ast.Mod: ast.Add,
    ast.Pow: ast.Mult,
    ast.LShift: ast.RShift,
    ast.RShift: ast.LShift,
    ast.BitAnd: ast.BitOr,
    ast.BitOr: ast.BitAnd,
    ast.BitXor: ast.BitAnd,
}

# Unary operators that have a natural inversion.
_OPPOSITE_UNARYOP: dict[type[ast.unaryop], type[ast.unaryop]] = {
    ast.Not: ast.Not,
    ast.USub: ast.UAdd,
    ast.UAdd: ast.USub,
    ast.Invert: ast.Invert,
}


def _is_safe_to_mutate(node: ast.AST) -> bool:
    """Return True if the node is safe to mutate (not import/class/__init__)."""
    if isinstance(node, (ast.Import, ast.ImportFrom)):
        return False
    if isinstance(node, ast.ClassDef):
        return False
    if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
        if node.name == "__init__":
            return False
    return True


def _line_of(node: ast.AST) -> int:
    return getattr(node, "lineno", 0)


# ---------------------------------------------------------------------------
# Mutation operators (each is a NodeTransformer that yields one mutation)
# ---------------------------------------------------------------------------


class _NegateCondition(ast.NodeTransformer):
    """Flip ``if x:`` to ``if not x:`` and ``while x:`` to ``while not x:``."""

    def __init__(self) -> None:
        self.mutation: Mutant | None = None
        self._applied = False

    def visit_If(self, node: ast.If) -> ast.If:
        if self._applied:
            return node
        if not _is_safe_to_mutate(node):
            return node
        # Don't negate if the test is already a Not.
        if isinstance(node.test, ast.UnaryOp) and isinstance(node.test.op, ast.Not):
            return node
        self._applied = True
        new_test = ast.UnaryOp(op=ast.Not(), operand=node.test)
        ast.copy_location(new_test, node.test)
        node.test = new_test
        self.mutation = Mutant(
            original_line=_line_of(node),
            mutated_code="",
            operator_name="negate_condition",
            line_number=_line_of(node),
            description="Flipped condition with Not",
        )
        return node

    def visit_While(self, node: ast.While) -> ast.While:
        if self._applied:
            return node
        if not _is_safe_to_mutate(node):
            return node
        if isinstance(node.test, ast.UnaryOp) and isinstance(node.test.op, ast.Not):
            return node
        self._applied = True
        new_test = ast.UnaryOp(op=ast.Not(), operand=node.test)
        ast.copy_location(new_test, node.test)
        node.test = new_test
        self.mutation = Mutant(
            original_line=_line_of(node),
            mutated_code="",
            operator_name="negate_condition",
            line_number=_line_of(node),
            description="Flipped while condition with Not",
        )
        return node


class _SwapOperators(ast.NodeTransformer):
    """Swap comparison and arithmetic operators to their opposites."""

    def __init__(self) -> None:
        self.mutation: Mutant | None = None
        self._applied = False

    def visit_Compare(self, node: ast.Compare) -> ast.Compare:
        if self._applied:
            return node
        if not _is_safe_to_mutate(node):
            return node
        for i, op in enumerate(node.ops):
            opp = _OPPOSITE_BINOP.get(type(op))
            if opp is not None:
                self._applied = True
                node.ops[i] = opp()
                self.mutation = Mutant(
                    original_line=_line_of(node),
                    mutated_code="",
                    operator_name="swap_operators",
                    line_number=_line_of(node),
                    description=f"Swapped {type(op).__name__} -> {opp.__name__}",
                )
                break
        return node

    def visit_BinOp(self, node: ast.BinOp) -> ast.BinOp:
        if self._applied:
            return node
        if not _is_safe_to_mutate(node):
            return node
        opp = _OPPOSITE_BINOP.get(type(node.op))
        if opp is not None:
            self._applied = True
            node.op = opp()
            self.mutation = Mutant(
                original_line=_line_of(node),
                mutated_code="",
                operator_name="swap_operators",
                line_number=_line_of(node),
                description=f"Swapped {type(node.op).__name__} -> {opp.__name__}",
            )
        return node


class _RemoveStatement(ast.NodeTransformer):
    """Remove a return statement or a bare expression that is a function call.

    Uses generic_visit to walk the entire tree depth-first. When it finds a
    body list (list of ast.stmt), it scans for the first removable node and
    drops it in place. Only one node is removed per mutant.
    """

    def __init__(self) -> None:
        self.mutation: Mutant | None = None
        self._applied = False

    def _is_removable(self, node: ast.stmt) -> bool:
        if not _is_safe_to_mutate(node):
            return False
        if isinstance(node, ast.Return):
            return True
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
            return True
        return False

    def generic_visit(self, node: ast.AST) -> ast.AST:
        for field, value in ast.iter_fields(node):
            if isinstance(value, list) and value and isinstance(value[0], ast.stmt):
                self._mutate_body_inplace(value)
                # Recurse into each stmt even after mutation attempt.
                for i, item in enumerate(value):
                    if isinstance(item, ast.AST):
                        value[i] = self.generic_visit(item)
            elif isinstance(value, list):
                for i, item in enumerate(value):
                    if isinstance(item, ast.AST):
                        value[i] = self.generic_visit(item)
            elif isinstance(value, ast.AST):
                setattr(node, field, self.generic_visit(value))
        return node

    def _mutate_body_inplace(self, body: list[ast.stmt]) -> None:
        if self._applied:
            return
        for i, stmt in enumerate(body):
            if self._is_removable(stmt):
                self._applied = True
                desc = (
                    "Removed return statement"
                    if isinstance(stmt, ast.Return)
                    else "Removed function call expression"
                )
                self.mutation = Mutant(
                    original_line=_line_of(stmt),
                    mutated_code="",
                    operator_name="remove_statement",
                    line_number=_line_of(stmt),
                    description=desc,
                )
                body.pop(i)
                return


class _ChangeConstant(ast.NodeTransformer):
    """Change a numeric literal (1->0, 2->1, ...) or string literal."""

    def __init__(self) -> None:
        self.mutation: Mutant | None = None
        self._applied = False

    def visit_Constant(self, node: ast.Constant) -> ast.Constant:
        if self._applied:
            return node
        if not _is_safe_to_mutate(node):
            return node
        if isinstance(node.value, bool):
            # Flip booleans.
            self._applied = True
            node.value = not node.value
            self.mutation = Mutant(
                original_line=_line_of(node),
                mutated_code="",
                operator_name="change_constant",
                line_number=_line_of(node),
                description=f"Flipped bool {not node.value} -> {node.value}",
            )
        elif isinstance(node.value, int) and not isinstance(node.value, bool):
            self._applied = True
            old = node.value
            node.value = 0 if old != 0 else 1
            self.mutation = Mutant(
                original_line=_line_of(node),
                mutated_code="",
                operator_name="change_constant",
                line_number=_line_of(node),
                description=f"Changed int {old} -> {node.value}",
            )
        elif isinstance(node.value, float):
            self._applied = True
            old = node.value
            node.value = 0.0 if old != 0.0 else 1.0
            self.mutation = Mutant(
                original_line=_line_of(node),
                mutated_code="",
                operator_name="change_constant",
                line_number=_line_of(node),
                description=f"Changed float {old} -> {node.value}",
            )
        elif isinstance(node.value, str):
            self._applied = True
            old = node.value
            node.value = "mutated" if old != "mutated" else ""
            self.mutation = Mutant(
                original_line=_line_of(node),
                mutated_code="",
                operator_name="change_constant",
                line_number=_line_of(node),
                description=f"Changed string {old!r} -> {node.value!r}",
            )
        else:
            return node
        return node


class _SwapArguments(ast.NodeTransformer):
    """Swap the first two arguments of a function call (if >= 2 args)."""

    def __init__(self) -> None:
        self.mutation: Mutant | None = None
        self._applied = False

    def visit_Call(self, node: ast.Call) -> ast.Call:
        if self._applied:
            return node
        if not _is_safe_to_mutate(node):
            return node
        # Only swap positional args (not keyword args).
        if len(node.args) < 2:
            return node
        self._applied = True
        node.args[0], node.args[1] = node.args[1], node.args[0]
        self.mutation = Mutant(
            original_line=_line_of(node),
            mutated_code="",
            operator_name="swap_arguments",
            line_number=_line_of(node),
            description="Swapped first two call arguments",
        )
        return node


# ---------------------------------------------------------------------------
# All operators in application order
# ---------------------------------------------------------------------------

_MUTATION_OPERATORS: list[type[ast.NodeTransformer]] = [
    _NegateCondition,
    _SwapOperators,
    _RemoveStatement,
    _ChangeConstant,
    _SwapArguments,
]


# ---------------------------------------------------------------------------
# MutationTester
# ---------------------------------------------------------------------------


class MutationTester:
    """Generate mutants from a Python source file and test them."""

    def __init__(self, root: Path) -> None:
        self.root = Path(root)

    # ── generate mutants ──────────────────────────────────────────────────

    def generate_mutants(self, file_path: Path, max_mutants: int = 10) -> list[Mutant]:
        """Parse *file_path* with AST, apply each operator once, return up to
        *max_mutants* Mutant objects (not yet tested — mutated_code is empty
        until run_tests_for_mutant fills it)."""
        file_path = Path(file_path)
        source = file_path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(file_path))

        mutants: list[Mutant] = []
        for op_cls in _MUTATION_OPERATORS:
            if len(mutants) >= max_mutants:
                break
            transformer = op_cls()
            mutated_tree = copy.deepcopy(tree)
            new_tree = transformer.visit(mutated_tree)
            if transformer.mutation is None:
                continue
            # Fix missing line numbers.
            ast.fix_missing_locations(new_tree)
            mutated_source = ast.unparse(new_tree)
            mutant = Mutant(
                original_line=transformer.mutation.original_line,
                mutated_code=mutated_source,
                operator_name=transformer.mutation.operator_name,
                line_number=transformer.mutation.line_number,
                description=transformer.mutation.description,
            )
            mutants.append(mutant)
        return mutants[:max_mutants]

    # ── run tests for a single mutant ─────────────────────────────────────

    def run_tests_for_mutant(
        self,
        mutant: Mutant,
        timeout: float = 30.0,
        test_path: Path | None = None,
    ) -> MutationResult:
        """Write *mutant.mutated_code* to a temp file, run pytest, return
        whether the test suite caught the mutation."""
        with tempfile.TemporaryDirectory(prefix="patchi_mut_") as tmpdir:
            mut_file = Path(tmpdir) / "mutated_target.py"
            mut_file.write_text(mutant.mutated_code, encoding="utf-8")

            # Build the pytest command.  If test_path is given, run only that
            # file against the mutant.  Otherwise run the full test suite.
            cmd: list[str] = [sys.executable, "-m", "pytest", str(mut_file), "-x", "-q"]
            if test_path is not None:
                # Re-run tests from the original project, but with the mutant
                # on sys.path so imports resolve against the mutated code.
                cmd = [
                    sys.executable,
                    "-m",
                    "pytest",
                    str(test_path),
                    "-x",
                    "-q",
                ]

            env = os.environ.copy()
            # Prepend the temp dir so `import mutated_target` resolves.
            env["PYTHONPATH"] = f"{tmpdir}{os.pathsep}{env.get('PYTHONPATH', '')}"

            import time as _time

            t0 = _time.monotonic()
            try:
                proc = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                    env=env,
                    cwd=str(self.root),
                )
                duration = _time.monotonic() - t0
                tests_passed = proc.returncode == 0
                return MutationResult(
                    mutant=mutant,
                    killed=tests_passed,
                    test_returncode=proc.returncode,
                    test_output=proc.stdout + proc.stderr,
                    duration_s=round(duration, 3),
                )
            except subprocess.TimeoutExpired:
                duration = _time.monotonic() - t0
                return MutationResult(
                    mutant=mutant,
                    killed=True,
                    test_returncode=-1,
                    test_output=f"TIMEOUT after {timeout}s",
                    duration_s=round(duration, 3),
                )
            except Exception as exc:
                duration = _time.monotonic() - t0
                return MutationResult(
                    mutant=mutant,
                    killed=False,
                    test_returncode=-2,
                    test_output=f"ERROR: {exc}",
                    duration_s=round(duration, 3),
                )

    # ── score ─────────────────────────────────────────────────────────────

    @staticmethod
    def score(
        mutants: list[Mutant],
        results: list[MutationResult],
    ) -> MutationScore:
        """Compute the mutation score from generated mutants and their results."""
        total = len(results)
        killed = sum(1 for r in results if r.killed)
        survived = sum(1 for r in results if not r.killed and r.test_returncode >= 0)
        errors = total - killed - survived
        kill_rate = killed / total if total else 0.0
        return MutationScore(
            total=total,
            killed=killed,
            survived=survived,
            errors=errors,
            kill_rate=round(kill_rate, 4),
            results=results,
        )


# ---------------------------------------------------------------------------
# CLI entry point — p eval mut
# ---------------------------------------------------------------------------


def run_cli(file: str, max_mutants: int = 10, timeout: float = 30.0) -> int:
    """CLI handler for ``p eval mut --file <path>``."""
    from patchi.cli.console import con
    from patchi.core.config import require_project_root

    root = require_project_root()
    file_path = Path(file).resolve()
    if not file_path.exists():
        con.print(f"[red]File not found:[/red] {file_path}")
        return 1

    tester = MutationTester(root)
    con.print(f"[bold]Generating mutants for[/bold] {file_path.name} (max {max_mutants})")

    mutants = tester.generate_mutants(file_path, max_mutants=max_mutants)
    if not mutants:
        con.print("[yellow]No mutants generated — file may have no eligible nodes.[/yellow]")
        return 0

    con.print(f"[bold]{len(mutants)} mutant(s) generated. Running tests...[/bold]\n")

    results: list[MutationResult] = []
    for i, mutant in enumerate(mutants, 1):
        con.print(
            f"  [{i}/{len(mutants)}] {mutant.operator_name} @ line {mutant.line_number} — {mutant.description}"
        )
        result = tester.run_tests_for_mutant(mutant, timeout=timeout)
        results.append(result)
        mark = "[red]SURVIVED[/red]" if not result.killed else "[green]KILLED[/green]"
        con.print(f"       {mark}  ({result.duration_s:.1f}s)\n")

    score = tester.score(mutants, results)
    con.print("[bold]═══ Mutation Score ═══[/bold]")
    con.print(f"  Total:     {score.total}")
    con.print(f"  Killed:    {score.killed}")
    con.print(f"  Survived:  {score.survived}")
    con.print(f"  Errors:    {score.errors}")
    con.print(f"  Kill rate: {score.kill_rate:.1%}")

    if score.survived > 0:
        con.print("\n[bold yellow]Survived mutants:[/bold yellow]")
        for r in results:
            if not r.killed:
                con.print(
                    f"  [yellow]✗[/yellow] {r.mutant.operator_name} @ line {r.mutant.line_number}"
                )

    return 0 if score.kill_rate >= 0.8 else 1
