"""
Gradual Enforcement §10.2.2 — ratcheting baseline down week by week.

Stores baseline file count, fails if count exceeds target ratchet.
"""

from __future__ import annotations

import json
from pathlib import Path

_GATE_FILE = ".patchi/gradual_gate.json"

def ratchet_check(root: Path, current_count: int, weekly_reduction: int = 5) -> tuple[bool, str]:
    p=root/_GATE_FILE
    data=json.loads(p.read_text(encoding="utf-8")) if p.exists() else {"baseline": current_count, "target": current_count}
    target=data.get("target", current_count)
    # reduce target by weekly_reduction if week passed
    import time
    last=data.get("ts", time.time())
    if time.time()-last > 7*24*3600 and target>0:
        target=max(0, target-weekly_reduction)
        data["target"]=target
        data["ts"]=time.time()
        p.write_text(json.dumps(data, indent=2), encoding="utf-8")
    if current_count > target:
        return False, f"Ratchet fail: {current_count} > target {target} (baseline {data.get('baseline')}) — reduce {current_count-target} findings this week"
    return True, f"Ratchet pass: {current_count} <= target {target}"

def set_baseline(root: Path, count: int) -> None:
    p=root/_GATE_FILE
    p.parent.mkdir(parents=True, exist_ok=True)
    import time, json
    p.write_text(json.dumps({"baseline": count, "target": count, "ts": time.time()}, indent=2), encoding="utf-8")
