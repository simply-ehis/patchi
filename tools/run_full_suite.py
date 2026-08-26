"""Blocking full-suite runner (no shell quoting pitfalls). Prints summary."""
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

code = pytest.main(
    [
        str(ROOT / "tests"),
        "-q",
        "--tb=no",
        "-p",
        "no:cacheprovider",
        "--ignore=" + str(ROOT / "tests" / "benchmarks"),
        "-m",
        "not slow",
        "--timeout=300",
    ]
)
print(f"PYTEST_EXIT={code}")
sys.exit(code or 0)
