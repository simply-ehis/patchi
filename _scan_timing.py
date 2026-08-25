import time, tempfile
from pathlib import Path
from patchi.core.ai.tools import realize

d = Path(tempfile.mkdtemp())
(d / "app").mkdir()
(d / "app" / "config.py").write_text(
    'SECRET = "sk-live-abcdef1234567890abcdef1234567890"\ndef f(): return 1\n',
    encoding="utf-8",
)
realize.set_event_sink(lambda p: None)
t = time.time()
try:
    res = realize.scan_vulnerabilities(d, goal="find secrets")
    print("OK", round(time.time() - t, 1), "s",
          "findings=", res.get("total_findings"),
          "agents=", res.get("agents_executed"))
except Exception as e:
    print("ERR after", round(time.time() - t, 1), repr(e))
