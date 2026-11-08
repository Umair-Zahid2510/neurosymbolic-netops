"""Root-level launcher. See neurosymbolic_netops/run_full_system.py."""
import runpy
import sys
from pathlib import Path

sub = Path(__file__).resolve().parent / "neurosymbolic_netops"
sys.path.insert(0, str(sub))
sys.argv[0] = str(sub / "run_full_system.py")
runpy.run_path(str(sub / "run_full_system.py"), run_name="__main__")
