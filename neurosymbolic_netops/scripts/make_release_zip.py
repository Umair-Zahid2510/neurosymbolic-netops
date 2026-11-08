"""Build a shareable archive of the project WITHOUT secrets.

python scripts/make_release_zip.py [output.zip]

Excludes .env, runtime/ (LLM logs, cassettes, audit files), caches, virtualenvs and model pickles,
then scans every included file for API-key patterns and aborts if any is found. Share
.env.example, never .env.
"""

from __future__ import annotations

import re
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EXCLUDE_DIRS = {".git", "__pycache__", ".pytest_cache", ".venv", "venv", "runtime", ".claude"}
EXCLUDE_FILES = {".env"}
EXCLUDE_SUFFIX = {".pkl", ".pyc"}
SECRET = re.compile(r"(AIza[0-9A-Za-z_\-]{30,}|gsk_[0-9A-Za-z]{30,}|sk-[0-9A-Za-z_\-]{30,}|xai-[0-9A-Za-z]{30,})")


def files():
    for p in sorted(ROOT.rglob("*")):
        rel = p.relative_to(ROOT)
        if p.is_dir() or any(part in EXCLUDE_DIRS for part in rel.parts):
            continue
        if p.name in EXCLUDE_FILES or p.suffix in EXCLUDE_SUFFIX:
            continue
        yield p, rel


def main() -> int:
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT.parent / "neurosymbolic_netops_release.zip"
    leaks = []
    for p, rel in files():
        try:
            if SECRET.search(p.read_text(encoding="utf-8", errors="ignore")):
                leaks.append(str(rel))
        except OSError:
            pass
    if leaks:
        print("ABORTED: possible API keys found in:", *leaks, sep="\n  ")
        return 1
    n = 0
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        for p, rel in files():
            z.write(p, Path("neurosymbolic_netops") / rel)
            n += 1
    print(f"wrote {out} ({n} files; .env and runtime/ excluded; secret scan clean)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
