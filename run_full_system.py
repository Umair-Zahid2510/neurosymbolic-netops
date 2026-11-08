"""Root-level launcher for the Neurosymbolic NetOps master benchmark suite."""

import sys
from pathlib import Path

# Add neurosymbolic_netops to path
sub_dir = Path(__file__).resolve().parent / "neurosymbolic_netops"
sys.path.insert(0, str(sub_dir))

from run_full_system import run_master_suite

if __name__ == "__main__":
    run_master_suite()
