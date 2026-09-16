"""Diagnose why SemgrepAgent returns no findings on the consensus fixture."""

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

import patchi.core.security.security_agents  # noqa: E402,F401
from patchi.core.agents.base import AgentGroup, AgentInput, list_agents  # noqa: E402

td = Path(tempfile.mkdtemp())
(td / "vuln.py").write_text(
    "import sqlite3\n"
    "conn = sqlite3.connect('x.db')\n"
    "cur = conn.cursor()\n"
    "cur.execute('SELECT * FROM u WHERE id=' + uid)\n",
    encoding="utf-8",
)

cls = {a.name: a for a in list_agents(AgentGroup.SECURITY)}.get("SemgrepAgent")
print("SemgrepAgent class:", cls)

agent = cls()
pack = agent._rules_pack(td)
print("rules pack:", pack, "exists:", pack.exists() if pack else None)

r = agent.run(AgentInput(root=td, scope=[], brain={}, config={}))
print("status:", r.status.value)
print("errors:", r.errors[:3])
print("findings:", len(r.findings), [(f.type, f.line) for f in r.findings][:6])
print("data:", dict(list(r.data.items())[:8]))

# Raw semgrep invocation for comparison
if pack and pack.exists():
    import subprocess

    proc = subprocess.run(
        ["semgrep", "--config", str(pack), "--json", "--quiet", str(td)],
        capture_output=True,
        text=True,
        timeout=120,
    )
    print("raw rc:", proc.returncode, "stdout head:", proc.stdout[:200])
