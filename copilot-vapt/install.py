#!/usr/bin/env python3
"""Install the VAPT recon copilot into a VS Code workspace.

Cross-platform installer -- works on Windows, macOS and Linux. Python 3 is
already required by the analysis scripts themselves, so this adds no new
dependency, and unlike a PowerShell script it does not run into execution-policy
prompts.

It copies, it does not download. Two directories go into your workspace:

    .github/   Copilot instructions, chat mode and prompt files
    scripts/   the tested js-recon analysis scripts the prompts call

They have to travel together. With the prompts but no scripts, Copilot has
nothing to call and rewrites each analysis from scratch -- untested, different
every run, and it looks like it is working while it happens.

The scripts are copied from the js-recon skill rather than duplicated here, so
there is one source of truth and the two packages cannot drift apart.

Usage:
    python install.py <workspace-dir> [--force] [--verify]
"""

import argparse
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
SRC_GITHUB = os.path.join(HERE, ".github")


def _first_dir(*candidates):
    """Prefer the copy inside this folder so that downloading copilot-vapt on
    its own is enough; fall back to the skill in a full checkout."""
    for path in candidates:
        if os.path.isdir(path):
            return path
    return candidates[0]


SRC_SCRIPTS = _first_dir(
    os.path.join(HERE, "scripts"),
    os.path.join(REPO, ".claude", "skills", "js-recon", "scripts"),
)
SRC_FIXTURES = _first_dir(
    os.path.join(HERE, "tests", "fixtures"),
    os.path.join(REPO, ".claude", "skills", "js-recon", "tests", "fixtures"),
)


def fail(msg, *extra):
    print("Error: %s" % msg, file=sys.stderr)
    for line in extra:
        print("  %s" % line, file=sys.stderr)
    sys.exit(1)


def confirm(path, force):
    if not os.path.exists(path) or force:
        return
    try:
        reply = input("Overwrite existing %s? [y/N] " % path).strip().lower()
    except EOFError:
        reply = ""
    if not reply.startswith("y"):
        print("Aborted.")
        sys.exit(1)


def copy_tree(src, dst):
    os.makedirs(dst, exist_ok=True)
    for name in os.listdir(src):
        s, d = os.path.join(src, name), os.path.join(dst, name)
        if os.path.isdir(s):
            copy_tree(s, d)
        else:
            shutil.copy2(s, d)


def run(args, cwd=None):
    return subprocess.run([sys.executable] + args, cwd=cwd,
                          capture_output=True, text=True)


def verify(target):
    """Run the real pipeline over generated fixtures.

    The repository's smoke test is a bash script, which is no use on Windows --
    so this reimplements the essential checks in Python. It exercises the whole
    chain rather than merely importing the modules, because the failures that
    matter (a parser that silently returns nothing, a filter that lets
    placeholders through) all look fine to a syntax check.
    """
    scripts = os.path.join(target, "scripts")
    if not os.path.isdir(SRC_FIXTURES):
        print("  Fixtures not found; checking the scripts parse instead.")
        for fn in sorted(os.listdir(scripts)):
            if fn.endswith(".py"):
                r = run(["-c", "import ast,sys; ast.parse(open(sys.argv[1],encoding='utf-8').read())",
                         os.path.join(scripts, fn)])
                if r.returncode != 0:
                    print("  FAIL %s\n%s" % (fn, r.stderr.strip()))
                    return False
        print("  All scripts parse.")
        return True

    work = tempfile.mkdtemp(prefix="jsrecon-verify-")
    fix = os.path.join(work, "fixtures")
    try:
        os.makedirs(fix)
        for name in ("app.js", "page.html", "burp_export.xml"):
            shutil.copy2(os.path.join(SRC_FIXTURES, name), os.path.join(fix, name))
        gen = os.path.join(SRC_FIXTURES, "make_secrets_fixture.py")
        if os.path.exists(gen):
            run([gen, os.path.join(fix, "config.js")])

        checks, ok = [], True

        def check(label, condition, detail=""):
            nonlocal ok
            checks.append((label, condition, detail))
            if not condition:
                ok = False

        ep = os.path.join(work, "endpoints.json")
        r = run([os.path.join(scripts, "extract_endpoints.py"), fix, "--out", ep])
        check("extract_endpoints runs", r.returncode == 0, r.stderr.strip()[:200])

        import json
        if os.path.exists(ep):
            with open(ep, encoding="utf-8") as fh:
                d = json.load(fh)
            n = len(d.get("endpoints", []))
            check("endpoints recovered (%d)" % n, n >= 9)
            check("authorization verdicts assigned",
                  any(e["auth"]["verdict"] == "auth_at_callsite" for e in d["endpoints"]))

        bi = os.path.join(work, "burp_index.json")
        r = run([os.path.join(scripts, "parse_burp.py"), os.path.join(fix, "burp_export.xml"),
                 "--out-dir", os.path.join(work, "burp_js"), "--index", bi, "--all-responses"])
        check("parse_burp runs", r.returncode == 0, r.stderr.strip()[:200])
        check("burp response bodies decoded",
              os.path.isdir(os.path.join(work, "burp_js")) and
              len(os.listdir(os.path.join(work, "burp_js"))) >= 3)

        sec = os.path.join(work, "secrets.json")
        r = run([os.path.join(scripts, "find_secrets.py"), fix, "--out", sec, "--min-tier", "info"])
        check("find_secrets runs", r.returncode == 0, r.stderr.strip()[:200])
        if os.path.exists(sec):
            with open(sec, encoding="utf-8") as fh:
                d = json.load(fh)
            vals = [str(f.get("value")) for f in d.get("findings", [])]
            check("placeholders filtered out",
                  not any("YOUR_API_KEY" in v or "changeme" in v or "process.env" in v for v in vals))
            if os.path.exists(os.path.join(fix, "config.js")):
                check("provider credentials detected",
                      d.get("by_tier", {}).get("confirmed", 0) >= 4)

        dx = os.path.join(work, "domxss.json")
        r = run([os.path.join(scripts, "dom_xss_scan.py"), fix, "--out", dx])
        check("dom_xss_scan runs", r.returncode == 0, r.stderr.strip()[:200])

        rq = os.path.join(work, "reqs")
        r = run([os.path.join(scripts, "make_request.py"), ep, "--burp-index", bi,
                 "--match", "notifications", "--both", "--out-dir", rq])
        check("make_request runs", r.returncode == 0, r.stderr.strip()[:200])
        if os.path.isdir(rq):
            files = sorted(os.listdir(rq))
            check("authed + no-auth pair written", len(files) == 2)
            if files:
                with open(os.path.join(rq, files[0]), "rb") as fh:
                    raw = fh.read()
                check("CRLF line endings", b"\r\n" in raw)
                noauth = [f for f in files if "noauth" in f]
                if noauth:
                    with open(os.path.join(rq, noauth[0]), encoding="utf-8") as fh:
                        body = fh.read().lower()
                    check("credentials stripped in no-auth variant",
                          "\nauthorization:" not in body and "\ncookie:" not in body)

        rep = os.path.join(work, "report.md")
        r = run([os.path.join(scripts, "gen_report.py"), "--endpoints", ep, "--domxss", dx,
                 "--secrets", sec, "--out", rep, "--target", "verify"])
        check("gen_report runs", r.returncode == 0, r.stderr.strip()[:200])
        check("report written", os.path.exists(rep) and os.path.getsize(rep) > 500)

        for label, passed, detail in checks:
            print("  %s %s%s" % ("ok  " if passed else "FAIL", label,
                                 ("  -- " + detail) if (detail and not passed) else ""))
        return ok
    finally:
        shutil.rmtree(work, ignore_errors=True)


def main():
    ap = argparse.ArgumentParser(
        description="Install the VAPT recon copilot (.github + scripts) into a VS Code workspace.")
    ap.add_argument("workspace", help="Folder you open in VS Code")
    ap.add_argument("--force", action="store_true", help="Overwrite without asking")
    ap.add_argument("--verify", action="store_true", help="Run the pipeline over fixtures afterwards")
    args = ap.parse_args()

    if sys.version_info < (3, 6):
        fail("Python 3.6 or newer is required (found %d.%d)." % sys.version_info[:2])

    if not os.path.isdir(SRC_GITHUB):
        fail("Cannot find %s" % SRC_GITHUB, "Run this from a full checkout of the repository.")
    if not os.path.isdir(SRC_SCRIPTS):
        fail("Cannot find the analysis scripts at:", SRC_SCRIPTS,
             "Expected them in copilot-vapt/scripts/. If you downloaded only part",
             "of the folder, download it again including the scripts directory.")

    target = os.path.abspath(os.path.expanduser(args.workspace))
    if not os.path.isdir(target):
        fail("Workspace directory does not exist: %s" % target,
             "Create it first, or point at the folder you open in VS Code.")

    confirm(os.path.join(target, ".github"), args.force)
    confirm(os.path.join(target, "scripts"), args.force)

    copy_tree(SRC_GITHUB, os.path.join(target, ".github"))
    copy_tree(SRC_SCRIPTS, os.path.join(target, "scripts"))

    n_prompts = len(os.listdir(os.path.join(target, ".github", "prompts")))
    n_scripts = len([f for f in os.listdir(os.path.join(target, "scripts")) if f.endswith(".py")])
    print("Installed into %s" % target)
    print("  .github/copilot-instructions.md")
    print("  .github/chatmodes/     1 chat mode")
    print("  .github/instructions/  1 scoped instruction file")
    print("  .github/prompts/       %d slash commands" % n_prompts)
    print("  scripts/               %d analysis scripts" % n_scripts)
    print("     (from %s)" % os.path.relpath(SRC_SCRIPTS, os.path.dirname(REPO))
          if SRC_SCRIPTS.startswith(REPO) else "")

    if args.verify:
        print("\nVerifying the pipeline runs correctly...")
        if not verify(target):
            print("\nSome checks failed. The install is in place but the scripts are not",
                  "\nbehaving as expected -- report the failures above before relying on them.")
            return 1
        print("  All checks passed.")

    print("""
Next:
  1. Open this folder in VS Code:  %s
  2. Pick the "VAPT Recon" chat mode in Copilot Chat.
  3. Drop your Burp XML export and any saved bundles into the workspace.
  4. Run /js-endpoints -- it should call scripts/parse_burp.py rather than
     writing its own parser.

If Copilot writes its own analysis script instead of running one, it could not
see scripts/. Check that the folder open in VS Code is exactly the one above --
not a parent, and not a subfolder.""" % target)
    return 0


if __name__ == "__main__":
    sys.exit(main())
