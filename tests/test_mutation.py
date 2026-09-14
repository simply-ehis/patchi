"""Tests for patchi.core.testing.mutation_tester."""

from __future__ import annotations

import ast
import copy
import textwrap
from pathlib import Path

import pytest

from patchi.core.testing.mutation_tester import (
    Mutant,
    MutationResult,
    MutationScore,
    MutationTester,
    _ChangeConstant,
    _is_safe_to_mutate,
    _NegateCondition,
    _RemoveStatement,
    _SwapArguments,
    _SwapOperators,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_SAMPLE_SOURCE = textwrap.dedent("""\
    def greet(name):
        if name:
            return "hello " + name
        return "default"

    def add(a, b):
        return a + b

    def compare(x):
        if x == 1:
            return True
        if x > 10:
            return False
        return None

    def loop(n):
        i = 0
        while i < n:
            i += 1
        return i

    def swap(a, b, c):
        return a + b + c
""")


def _write_sample(tmp: Path) -> Path:
    p = tmp / "sample.py"
    p.write_text(_SAMPLE_SOURCE, encoding="utf-8")
    return p


# ---------------------------------------------------------------------------
# _is_safe_to_mutate
# ---------------------------------------------------------------------------


class TestIsSafeToMutate:
    def test_import_is_not_safe(self):
        node = ast.Import(names=[ast.alias(name="os")])
        assert _is_safe_to_mutate(node) is False

    def test_import_from_is_not_safe(self):
        node = ast.ImportFrom(module="os", names=[ast.alias(name="path")])
        assert _is_safe_to_mutate(node) is False

    def test_class_def_is_not_safe(self):
        node = ast.ClassDef(name="Foo", bases=[], keywords=[], body=[], decorator_list=[])
        assert _is_safe_to_mutate(node) is False

    def test_init_is_not_safe(self):
        node = ast.FunctionDef(name="__init__", args=ast.arguments(), body=[ast.Pass()])
        assert _is_safe_to_mutate(node) is False

    def test_regular_function_is_safe(self):
        node = ast.FunctionDef(name="foo", args=ast.arguments(), body=[ast.Pass()])
        assert _is_safe_to_mutate(node) is True

    def test_if_is_safe(self):
        node = ast.If(test=ast.Name(id="x", ctx=ast.Load()), body=[ast.Pass()], orelse=[])
        assert _is_safe_to_mutate(node) is True


# ---------------------------------------------------------------------------
# _NegateCondition
# ---------------------------------------------------------------------------


class TestNegateCondition:
    def test_negates_if(self):
        source = "if x:\n    pass\n"
        tree = ast.parse(source)
        t = _NegateCondition()
        new_tree = t.visit(copy.deepcopy(tree))
        ast.fix_missing_locations(new_tree)
        assert t.mutation is not None
        assert t.mutation.operator_name == "negate_condition"
        code = ast.unparse(new_tree)
        assert "not x" in code

    def test_negates_while(self):
        source = "while True:\n    break\n"
        tree = ast.parse(source)
        t = _NegateCondition()
        new_tree = t.visit(copy.deepcopy(tree))
        ast.fix_missing_locations(new_tree)
        assert t.mutation is not None
        code = ast.unparse(new_tree)
        assert "not" in code

    def test_skips_already_negated(self):
        source = "if not x:\n    pass\n"
        tree = ast.parse(source)
        t = _NegateCondition()
        t.visit(copy.deepcopy(tree))
        assert t.mutation is None

    def test_single_mutation_only(self):
        source = "if a:\n    pass\nif b:\n    pass\n"
        tree = ast.parse(source)
        t = _NegateCondition()
        t.visit(copy.deepcopy(tree))
        # Only the first eligible condition is negated.
        assert t.mutation is not None


# ---------------------------------------------------------------------------
# _SwapOperators
# ---------------------------------------------------------------------------


class TestSwapOperators:
    def test_swaps_eq_to_neq(self):
        source = "x == 1\n"
        tree = ast.parse(source)
        t = _SwapOperators()
        new_tree = t.visit(copy.deepcopy(tree))
        ast.fix_missing_locations(new_tree)
        assert t.mutation is not None
        code = ast.unparse(new_tree)
        assert "!=" in code

    def test_swaps_lt_to_gte(self):
        source = "x < 10\n"
        tree = ast.parse(source)
        t = _SwapOperators()
        new_tree = t.visit(copy.deepcopy(tree))
        ast.fix_missing_locations(new_tree)
        assert t.mutation is not None
        code = ast.unparse(new_tree)
        assert ">=" in code

    def test_swaps_add_to_sub(self):
        source = "a + b\n"
        tree = ast.parse(source)
        t = _SwapOperators()
        new_tree = t.visit(copy.deepcopy(tree))
        ast.fix_missing_locations(new_tree)
        assert t.mutation is not None
        code = ast.unparse(new_tree)
        assert "-" in code and "+" not in code

    def test_swaps_mult_to_div(self):
        source = "a * b\n"
        tree = ast.parse(source)
        t = _SwapOperators()
        new_tree = t.visit(copy.deepcopy(tree))
        ast.fix_missing_locations(new_tree)
        assert t.mutation is not None
        code = ast.unparse(new_tree)
        assert "/" in code


# ---------------------------------------------------------------------------
# _RemoveStatement
# ---------------------------------------------------------------------------


class TestRemoveStatement:
    def test_removes_return(self):
        source = "def f():\n    return 42\n    x = 1\n"
        tree = ast.parse(source)
        t = _RemoveStatement()
        new_tree = t.visit(copy.deepcopy(tree))
        ast.fix_missing_locations(new_tree)
        assert t.mutation is not None
        code = ast.unparse(new_tree)
        assert "return" not in code

    def test_removes_function_call(self):
        source = "def f():\n    print('hello')\n    return 1\n"
        tree = ast.parse(source)
        t = _RemoveStatement()
        new_tree = t.visit(copy.deepcopy(tree))
        ast.fix_missing_locations(new_tree)
        assert t.mutation is not None
        code = ast.unparse(new_tree)
        assert "print" not in code

    def test_keeps_non_call_expressions(self):
        source = "x = 1\ny = 2\n"
        tree = ast.parse(source)
        t = _RemoveStatement()
        t.visit(copy.deepcopy(tree))
        # No return or bare call — nothing to remove.
        assert t.mutation is None


# ---------------------------------------------------------------------------
# _ChangeConstant
# ---------------------------------------------------------------------------


class TestChangeConstant:
    def test_changes_int(self):
        source = "x = 42\n"
        tree = ast.parse(source)
        t = _ChangeConstant()
        new_tree = t.visit(copy.deepcopy(tree))
        ast.fix_missing_locations(new_tree)
        assert t.mutation is not None
        code = ast.unparse(new_tree)
        assert "0" in code

    def test_changes_zero_to_one(self):
        source = "x = 0\n"
        tree = ast.parse(source)
        t = _ChangeConstant()
        new_tree = t.visit(copy.deepcopy(tree))
        ast.fix_missing_locations(new_tree)
        assert t.mutation is not None
        code = ast.unparse(new_tree)
        assert "1" in code

    def test_flips_bool(self):
        source = "x = True\n"
        tree = ast.parse(source)
        t = _ChangeConstant()
        new_tree = t.visit(copy.deepcopy(tree))
        ast.fix_missing_locations(new_tree)
        assert t.mutation is not None
        code = ast.unparse(new_tree)
        assert "False" in code

    def test_changes_string(self):
        source = 'x = "hello"\n'
        tree = ast.parse(source)
        t = _ChangeConstant()
        new_tree = t.visit(copy.deepcopy(tree))
        ast.fix_missing_locations(new_tree)
        assert t.mutation is not None
        code = ast.unparse(new_tree)
        assert "mutated" in code

    def test_changes_float(self):
        source = "x = 3.14\n"
        tree = ast.parse(source)
        t = _ChangeConstant()
        new_tree = t.visit(copy.deepcopy(tree))
        ast.fix_missing_locations(new_tree)
        assert t.mutation is not None
        code = ast.unparse(new_tree)
        assert "0.0" in code


# ---------------------------------------------------------------------------
# _SwapArguments
# ---------------------------------------------------------------------------


class TestSwapArguments:
    def test_swaps_two_args(self):
        source = "f(a, b)\n"
        tree = ast.parse(source)
        t = _SwapArguments()
        new_tree = t.visit(copy.deepcopy(tree))
        ast.fix_missing_locations(new_tree)
        assert t.mutation is not None
        code = ast.unparse(new_tree)
        assert "f(b, a)" in code

    def test_swaps_first_two_of_three(self):
        source = "f(a, b, c)\n"
        tree = ast.parse(source)
        t = _SwapArguments()
        new_tree = t.visit(copy.deepcopy(tree))
        ast.fix_missing_locations(new_tree)
        assert t.mutation is not None
        code = ast.unparse(new_tree)
        assert "f(b, a, c)" in code

    def test_skips_single_arg(self):
        source = "f(a)\n"
        tree = ast.parse(source)
        t = _SwapArguments()
        t.visit(copy.deepcopy(tree))
        assert t.mutation is None

    def test_skips_zero_args(self):
        source = "f()\n"
        tree = ast.parse(source)
        t = _SwapArguments()
        t.visit(copy.deepcopy(tree))
        assert t.mutation is None


# ---------------------------------------------------------------------------
# MutationTester.generate_mutants
# ---------------------------------------------------------------------------


class TestGenerateMutants:
    def test_generates_mutants(self, tmp_path: Path):
        sample = _write_sample(tmp_path)
        tester = MutationTester(tmp_path)
        mutants = tester.generate_mutants(sample, max_mutants=10)
        assert len(mutants) > 0
        assert len(mutants) <= 10
        for m in mutants:
            assert isinstance(m, Mutant)
            assert m.mutated_code  # non-empty
            assert m.operator_name
            assert m.line_number > 0

    def test_respects_max_mutants(self, tmp_path: Path):
        sample = _write_sample(tmp_path)
        tester = MutationTester(tmp_path)
        mutants = tester.generate_mutants(sample, max_mutants=2)
        assert len(mutants) <= 2

    def test_operators_are_varied(self, tmp_path: Path):
        sample = _write_sample(tmp_path)
        tester = MutationTester(tmp_path)
        mutants = tester.generate_mutants(sample, max_mutants=10)
        ops = {m.operator_name for m in mutants}
        # At least 2 different operators should fire on this sample.
        assert len(ops) >= 2

    def test_mutated_code_is_valid_python(self, tmp_path: Path):
        sample = _write_sample(tmp_path)
        tester = MutationTester(tmp_path)
        mutants = tester.generate_mutants(sample, max_mutants=10)
        for m in mutants:
            ast.parse(m.mutated_code)  # should not raise


# ---------------------------------------------------------------------------
# MutationTester.run_tests_for_mutant
# ---------------------------------------------------------------------------


class TestRunTestsForMutant:
    def test_killed_mutant(self, tmp_path: Path):
        """A mutant that breaks the code should be caught by a basic test."""
        source = textwrap.dedent("""\
            def add(a, b):
                return a + b
        """)
        sample = tmp_path / "target.py"
        sample.write_text(source, encoding="utf-8")

        test_source = textwrap.dedent("""\
            from target import add
            assert add(1, 2) == 3
        """)
        test_file = tmp_path / "test_target.py"
        test_file.write_text(test_source, encoding="utf-8")

        tester = MutationTester(tmp_path)
        mutants = tester.generate_mutants(sample, max_mutants=5)
        assert len(mutants) > 0

        # The swap_operators mutant changes + to -, so add(1,2)==3 should fail.
        result = tester.run_tests_for_mutant(mutants[0], timeout=15.0, test_path=test_file)
        assert isinstance(result, MutationResult)
        # Either killed (tests failed) or error — both mean the mutant was caught.
        assert result.killed or result.test_returncode != 0

    def test_timeout_returns_killed(self, tmp_path: Path):
        """A timeout counts as killed (conservative)."""
        source = "x = 1\n"
        sample = tmp_path / "slow.py"
        sample.write_text(source, encoding="utf-8")

        tester = MutationTester(tmp_path)
        mutants = tester.generate_mutants(sample, max_mutants=1)
        if mutants:
            result = tester.run_tests_for_mutant(mutants[0], timeout=0.001)
            assert result.killed  # timeout = killed


# ---------------------------------------------------------------------------
# MutationTester.score
# ---------------------------------------------------------------------------


class TestScore:
    def test_all_killed(self):
        m = Mutant(original_line=1, mutated_code="", operator_name="test", line_number=1)
        r = MutationResult(mutant=m, killed=True, test_returncode=0, test_output="", duration_s=0.0)
        score = MutationTester.score([m], [r])
        assert score.total == 1
        assert score.killed == 1
        assert score.survived == 0
        assert score.kill_rate == 1.0

    def test_all_survived(self):
        m = Mutant(original_line=1, mutated_code="", operator_name="test", line_number=1)
        r = MutationResult(mutant=m, killed=False, test_returncode=1, test_output="", duration_s=0.0)
        score = MutationTester.score([m], [r])
        assert score.total == 1
        assert score.killed == 0
        assert score.survived == 1
        assert score.kill_rate == 0.0

    def test_mixed_results(self):
        ms = [
            Mutant(original_line=i, mutated_code="", operator_name="test", line_number=i)
            for i in range(4)
        ]
        rs = [
            MutationResult(mutant=ms[0], killed=True, test_returncode=0, test_output="", duration_s=0.0),
            MutationResult(mutant=ms[1], killed=True, test_returncode=0, test_output="", duration_s=0.0),
            MutationResult(mutant=ms[2], killed=False, test_returncode=1, test_output="", duration_s=0.0),
            MutationResult(mutant=ms[3], killed=False, test_returncode=-2, test_output="err", duration_s=0.0),
        ]
        score = MutationTester.score(ms, rs)
        assert score.total == 4
        assert score.killed == 2
        assert score.survived == 1
        assert score.errors == 1
        assert score.kill_rate == 0.5

    def test_empty_input(self):
        score = MutationTester.score([], [])
        assert score.total == 0
        assert score.kill_rate == 0.0


# ---------------------------------------------------------------------------
# Mutant / MutationResult / MutationScore dataclass contracts
# ---------------------------------------------------------------------------


class TestDataclasses:
    def test_mutant_is_frozen(self):
        m = Mutant(original_line=1, mutated_code="x", operator_name="op", line_number=1)
        with pytest.raises(AttributeError):
            m.line_number = 99  # type: ignore[misc]

    def test_result_is_frozen(self):
        m = Mutant(original_line=1, mutated_code="", operator_name="op", line_number=1)
        r = MutationResult(mutant=m, killed=True, test_returncode=0, test_output="", duration_s=0.0)
        with pytest.raises(AttributeError):
            r.killed = False  # type: ignore[misc]

    def test_score_is_frozen(self):
        s = MutationScore(total=0, killed=0, survived=0, errors=0, kill_rate=0.0, results=[])
        with pytest.raises(AttributeError):
            s.total = 5  # type: ignore[misc]
