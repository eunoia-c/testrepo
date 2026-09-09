#!/usr/bin/env python3
"""Keep copilot-vapt/scripts in step with the js-recon skill.

The scripts are duplicated here so that downloading `copilot-vapt/` alone gives
a working package -- which matters when you can download from GitHub but not
clone. Duplication buys that convenience at the cost of drift: fix a regex in
one copy, forget the other, and the two halves of the project quietly disagree.

This guards against that. The skill at .claude/skills/js-recon/scripts is the
source of truth; this copies from it, or with --check reports differences and
exits non-zero so the smoke test catches them.

Usage:
    python sync_scripts.py            # copy skill -> copilot-vapt
    python sync_scripts.py --check    # report drift, exit 1 if any
"""

import argparse
import filecmp
import os
import shutil
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
SRC = os.path.join(REPO, ".claude", "skills", "js-recon", "scripts")
DST = os.path.join(HERE, "scripts")
SRC_FIX = os.path.join(REPO, ".claude", "skills", "js-recon", "tests", "fixtures")
DST_FIX = os.path.join(HERE, "tests", "fixtures")


def compare(src, dst, label):
    """Return (missing, differing, extra) filenames."""
    if not os.path.isdir(src):
        return None
    src_files = {f for f in os.listdir(src) if not f.startswith(".")}
    dst_files = set(os.listdir(dst)) if os.path.isdir(dst) else set()
    missing = sorted(src_files - dst_files)
    extra = sorted(dst_files - src_files)
    differing = sorted(
        f for f in (src_files & dst_files)
        if not filecmp.cmp(os.path.join(src, f), os.path.join(dst, f), shallow=False)
    )
    return missing, differing, extra


def sync(src, dst):
    os.makedirs(dst, exist_ok=True)
    for f in os.listdir(src):
        if f.startswith("."):
            continue
        shutil.copy2(os.path.join(src, f), os.path.join(dst, f))


def main():
    ap = argparse.ArgumentParser(description="Sync copilot-vapt/scripts with the js-recon skill.")
    ap.add_argument("--check", action="store_true",
                    help="Report drift without copying; exit 1 if the copies differ")
    args = ap.parse_args()

    if not os.path.isdir(SRC):
        print("Source not found: %s" % SRC, file=sys.stderr)
        print("This only runs inside a full checkout of the repository.", file=sys.stderr)
        return 2

    drift = False
    for src, dst, label in ((SRC, DST, "scripts"), (SRC_FIX, DST_FIX, "tests/fixtures")):
        result = compare(src, dst, label)
        if result is None:
            continue
        missing, differing, extra = result
        if missing or differing or extra:
            drift = True
            print("%s: out of sync" % label)
            for f in missing:
                print("  missing   %s" % f)
            for f in differing:
                print("  differs   %s" % f)
            for f in extra:
                print("  extra     %s  (not in the skill -- delete or move it there)" % f)
        else:
            print("%s: in sync (%d files)" % (label, len(os.listdir(dst))))

    if args.check:
        if drift:
            print("\nRun 'python sync_scripts.py' to update copilot-vapt from the skill.",
                  file=sys.stderr)
            return 1
        return 0

    if drift:
        sync(SRC, DST)
        if os.path.isdir(SRC_FIX):
            sync(SRC_FIX, DST_FIX)
        print("\nSynced.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
