"""Neurosymbolic NetOps - command-line entry point.

  python run_full_system.py demos [--reasoning rule_based|llm|offline] [--verifier local|batfish]
  python run_full_system.py benchmark [args passed to benchmark.run_benchmark]
  python run_full_system.py tests
  python run_full_system.py dashboard
"""
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DEMOS = ["demo1_bgp_single_fault", "demo2_multifault_self_correction", "demo3_failed_deployment_rollback"]


def main() -> int:
    cmd, rest = (sys.argv[1], sys.argv[2:]) if len(sys.argv) > 1 else ("demos", [])
    py = sys.executable
    if cmd == "demos":
        return max(subprocess.call([py, str(ROOT / "demos" / f"{d}.py"), *rest], cwd=ROOT) for d in DEMOS)
    if cmd == "benchmark":
        return subprocess.call([py, "-m", "benchmark.run_benchmark", *rest], cwd=ROOT)
    if cmd == "tests":
        return subprocess.call([py, "-m", "pytest", *rest], cwd=ROOT)
    if cmd == "dashboard":
        return subprocess.call([py, "-m", "streamlit", "run", str(ROOT / "dashboard" / "app.py")], cwd=ROOT)
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main())
