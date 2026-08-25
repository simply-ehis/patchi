import os, sys, time
from pathlib import Path
sys.path.insert(0, r"C:\Users\ehis\source\repos\Patchi_COMPLETE")
import importlib.util
_HAS = importlib.util.find_spec("pytest_cov") is not None
print("HAS_PYTEST_COV", _HAS)
from patchi.core.ai.tools import realize
d = Path(os.environ["TEMP"]) / "smart_demo2"
t = time.time()
try:
    res = realize.run_tests(d)
    print("OK", round(time.time()-t,1), res)
except Exception as e:
    print("ERR", round(time.time()-t,1), repr(e))
