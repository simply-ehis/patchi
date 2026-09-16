"""CI gate: the committed security taxonomy equals a fresh regeneration.

The pytest twin of this check lives in ``tests/test_taxonomy_parity.py``;
this script runs the same byte-equality verdict as a plain CLI process so
CI (and anyone without pytest) can gate a PR with one command:

    python tools/gates/taxonomy_parity.py

Exit 0 when every committed YAML is byte-identical to a clean regeneration
into a temp dir; exit 1 with the exact offending file list otherwise.
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
GENERATOR = REPO_ROOT / "tools" / "taxonomy" / "generate_domains.py"
COMMITTED = [
    REPO_ROOT / "patchi" / "core" / "security" / "domains",
    REPO_ROOT / "patchi" / "core" / "security" / "fix-playbooks",
]


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="taxonomy-parity-") as tmp:
        out = Path(tmp)
        proc = subprocess.run(
            [sys.executable, str(GENERATOR), "--out", str(out)],
            capture_output=True,
            text=True,
            timeout=300,
        )
        if proc.returncode != 0:
            print(f"generator failed (rc={proc.returncode}):", file=sys.stderr)
            print(proc.stderr[-2000:], file=sys.stderr)
            return 1

        changed: list[str] = []
        for committed_dir in COMMITTED:
            fresh_dir = out / committed_dir.name
            # Package markers (``__init__.py``) ship alongside the generated
            # YAMLs but aren't generator output — they are not drift.
            committed_files = sorted(p.name for p in committed_dir.glob("*.*") if p.name != "__init__.py")
            fresh_files = sorted(p.name for p in fresh_dir.glob("*.*"))
            if committed_files != fresh_files:
                only_c = sorted(set(committed_files) - set(fresh_files))
                only_f = sorted(set(fresh_files) - set(committed_files))
                if only_c:
                    changed.append(f"{committed_dir.name}: committed-but-not-generated: {only_c[:5]}")
                if only_f:
                    changed.append(f"{committed_dir.name}: generated-but-not-committed: {only_f[:5]}")
                continue
            for name in committed_files:
                if (committed_dir / name).read_bytes() != (fresh_dir / name).read_bytes():
                    changed.append(f"{committed_dir.name}/{name}")

        if changed:
            print("TAXONOMY DRIFT — regenerate and commit:", file=sys.stderr)
            print("  python tools/taxonomy/generate_domains.py", file=sys.stderr)
            for entry in changed[:20]:
                print(f"  {entry}", file=sys.stderr)
            if len(changed) > 20:
                print(f"  … and {len(changed) - 20} more", file=sys.stderr)
            return 1

    print("taxonomy parity: committed YAMLs match a fresh regeneration")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
