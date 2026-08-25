import os, sys
from pathlib import Path
sys.path.insert(0, r"C:\Users\ehis\source\repos\Patchi_COMPLETE")
from patchi.core.ai.tools import realize

d = Path(os.environ["TEMP"]) / "smart_demo2"
print("DIR EXISTS", d.exists())
print("FILES", os.listdir(d), os.listdir(d / "tests"))
res = realize.run_tests(d)
print("RES", res)
