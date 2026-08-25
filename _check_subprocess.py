import os, subprocess, sys
from pathlib import Path
sys.path.insert(0, r"C:\Users\ehis\source\repos\Patchi_COMPLETE")

d = Path(os.environ["TEMP"]) / "smart_demo2"
cmd = [sys.executable, "-m", "pytest", str(d), "-q", "--no-header", "-p", "no:cacheprovider"]
print("CMD", cmd)
p = subprocess.run(cmd, capture_output=True, text=True, cwd=r"C:\Users\ehis\source\repos\Patchi_COMPLETE", timeout=60)
print("RC", p.returncode)
print("OUT", repr(p.stdout))
print("ERR", repr(p.stderr))
