#!/usr/bin/env python3
"""Turn an endpoint inventory into fuzzing wordlists.

Different jobs need different shapes, so the mode is explicit rather than
guessed: directory brute-forcing wants path prefixes, parameter mining wants
names, and endpoint replay wants full paths with a FUZZ marker where the
dynamic segments were.
"""

import argparse
import json
import re
import sys


def load(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def clean(p, placeholder):
    p = re.sub(r"^https?://[^/]+", "", p)
    if not p.startswith("/"):
        p = "/" + p
    p = p.split("#", 1)[0]
    p = re.sub(r"\{(?:param|id|guid|concat)\}", placeholder, p)
    return p


def main():
    ap = argparse.ArgumentParser(description="Generate wordlists from endpoints.json")
    ap.add_argument("endpoints", help="endpoints.json from extract_endpoints.py")
    ap.add_argument("--mode", default="paths",
                    choices=["paths", "dirs", "params", "files", "all"],
                    help="paths: full paths | dirs: unique path prefixes | "
                         "params: parameter names | files: last path segments | all: everything")
    ap.add_argument("--out", default=None, help="Write here instead of stdout")
    ap.add_argument("--placeholder", default="FUZZ",
                    help="Replaces {param}/{id}/{guid} segments (default FUZZ)")
    ap.add_argument("--leading-slash", dest="slash", action="store_true", default=False,
                    help="Keep the leading slash (ffuf usually wants it off)")
    ap.add_argument("--keep-query", action="store_true", help="Keep ?query strings")
    ap.add_argument("--verdict", action="append", default=None,
                    help="Only endpoints with this auth verdict (repeatable)")
    ap.add_argument("--method", action="append", default=None, help="Filter by HTTP method (repeatable)")
    args = ap.parse_args()

    data = load(args.endpoints)
    eps = data.get("endpoints", [])
    if args.verdict:
        want = {v.lower() for v in args.verdict}
        eps = [e for e in eps if e.get("auth", {}).get("verdict", "").lower() in want]
    if args.method:
        want = {m.upper() for m in args.method}
        eps = [e for e in eps if e.get("method", "").upper() in want]

    paths, dirs, params, files = set(), set(), set(), set()
    for e in eps:
        p = clean(e.get("normalized") or e.get("raw", ""), args.placeholder)
        if not args.keep_query:
            p = p.split("?", 1)[0]
        if p and p != "/":
            paths.add(p)
            segs = [s for s in p.split("?", 1)[0].split("/") if s]
            for i in range(1, len(segs)):
                dirs.add("/" + "/".join(segs[:i]))
            if segs:
                files.add(segs[-1])
        for name in e.get("params", []):
            if name != "concat" and re.match(r"^[\w.\-\[\]]+$", name):
                params.add(name)

    if args.mode == "paths":
        out = sorted(paths)
    elif args.mode == "dirs":
        out = sorted(dirs)
    elif args.mode == "params":
        out = sorted(params)
    elif args.mode == "files":
        out = sorted(f for f in files if f and args.placeholder not in f)
    else:
        out = sorted(paths | dirs)

    if args.mode in ("paths", "dirs", "files", "all") and not args.slash:
        out = [w[1:] if w.startswith("/") else w for w in out]
    out = [w for w in out if w]

    text = "\n".join(out) + ("\n" if out else "")
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text)
        print("Wrote %d entries to %s" % (len(out), args.out), file=sys.stderr)
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
