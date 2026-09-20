#!/usr/bin/env python3
"""Recover parameter names from client code, and flag the ones the UI never sends.

Endpoint discovery answers "what can I call". This answers "what can I send",
which is where mass assignment, hidden feature flags and forgotten debug
switches live. The interesting output is not the full list of parameters -- it
is the subset that exists in the code but never appears in captured traffic,
because those are the ones no amount of clicking through the application will
find for you.

Classification, when a Burp export is supplied:

  observed       the UI sends it; you already have it in Repeater
  hidden         present in the bundle, never sent -- the deliverable
  response_only  read off a response, never submitted (mass-assignment lead)
  commented      only ever appears inside a comment (often a removed parameter
                 the server still accepts)

Without a Burp index everything is reported as `code`, since nothing can be
called hidden until you know what normal traffic looks like.

Reads files on disk; never contacts a target.
"""

import argparse
import json
import os
import re
import sys
from datetime import datetime, timezone

# ---------------------------------------------------------------- patterns

SEARCH_PARAMS_RE = re.compile(
    r"(?:searchParams|params|qs|query)\s*\.\s*(?:set|append|get|has|delete)\s*\(\s*"
    r"(?P<q>['\"`])(?P<name>[\w.\[\]-]{1,60})(?P=q)", re.I)

FORMDATA_RE = re.compile(
    r"\.\s*append\s*\(\s*(?P<q>['\"`])(?P<name>[\w.\[\]-]{1,60})(?P=q)", re.I)

URLSEARCHPARAMS_CTOR_RE = re.compile(r"new\s+URLSearchParams\s*\(", re.I)

REQUEST_CALL_RE = re.compile(
    r"\b(?:fetch|axios(?:\s*\.\s*\w+)?|\$\s*\.\s*(?:ajax|get|post)|"
    r"http\s*\.\s*\w+|\.\s*send|JSON\s*\.\s*stringify)\s*\(", re.I)

OBJ_KEY_RE = re.compile(
    r"(?:(?P<q>['\"])(?P<qname>[\w.\[\]-]{1,60})(?P=q)|(?P<name>[A-Za-z_$][\w$]{0,59}))\s*:",
)

RESPONSE_VAR_RE = re.compile(
    r"\b(?:res|resp|response|data|result|results|json|payload|body|item|record|row|user|obj)\b"
    r"(?:\s*\.\s*(?:data|body|json|result|payload))?\s*\.\s*(?P<name>[A-Za-z_$][\w$]{1,59})",
    re.I)

COMMENT_PARAM_RE = re.compile(
    r"(?P<name>[A-Za-z_][\w.-]{1,59})\s*(?:=|:)(?=\s*['\"]?[\w.-]{0,40})")

LINE_COMMENT_RE = re.compile(r"//[^\n]*")
BLOCK_COMMENT_RE = re.compile(r"/\*[\s\S]*?\*/")

# Names that are JavaScript, not parameters. Without this the output is mostly
# language noise and nobody reads past the first screen.
NOISE = {
    "then", "catch", "finally", "map", "filter", "reduce", "forEach", "length",
    "push", "pop", "shift", "slice", "splice", "concat", "join", "split",
    "indexOf", "includes", "charAt", "substring", "substr", "replace", "trim",
    "toString", "valueOf", "hasOwnProperty", "constructor", "prototype",
    "call", "apply", "bind", "default", "value", "type", "name", "key",
    "props", "state", "children", "className", "style", "target", "currentTarget",
    "preventDefault", "stopPropagation", "addEventListener", "removeEventListener",
    "querySelector", "querySelectorAll", "getElementById", "createElement",
    "appendChild", "innerHTML", "textContent", "classList", "dataset",
    "parentNode", "nextSibling", "firstChild", "log", "warn", "error", "info",
    "debug_", "keys", "values", "entries", "assign", "freeze", "stringify",
    "parse", "resolve", "reject", "all", "race", "status", "statusText",
    "headers", "ok", "url", "method", "mode", "cache", "redirect", "referrer",
    "integrity", "signal", "credentials", "body", "json", "text", "blob",
    "arrayBuffer", "formData", "clone", "exec", "test", "source", "flags",
    "global", "lastIndex", "now", "floor", "ceil", "round", "random", "max",
    "min", "abs", "pow", "sqrt", "toFixed", "padStart", "padEnd", "repeat",
    "startsWith", "endsWith", "toLowerCase", "toUpperCase", "localeCompare",
    "sort", "reverse", "find", "findIndex", "some", "every", "flat", "flatMap",
    "prop", "attr", "css", "html", "on", "off", "one", "trigger", "ready",
    "done", "fail", "always", "success", "complete", "beforeSend", "dataType",
    "contentType", "async", "timeout", "xhr", "processData", "cors",
}

MIN_LEN = 2
MAX_LEN = 60


def balanced_span(text: str, open_paren: int, max_len: int = 2000) -> tuple[int, int]:
    depth, quote, i = 0, None, open_paren
    n = min(len(text), open_paren + max_len)
    while i < n:
        c = text[i]
        if quote:
            if c == "\\":
                i += 2
                continue
            if c == quote:
                quote = None
        elif c in "'\"`":
            quote = c
        elif c in "({[":
            depth += 1
        elif c in ")}]":
            depth -= 1
            if depth == 0:
                return open_paren + 1, i
        i += 1
    return open_paren + 1, n


def header_object_spans(seg: str) -> list[tuple[int, int]]:
    """Spans of `headers: { ... }` blocks, whose keys are headers not parameters."""
    spans = []
    for hm in re.finditer(r"\bheaders\s*:\s*\{", seg, re.I):
        brace = seg.find("{", hm.end() - 1)
        if brace == -1:
            continue
        a, b = balanced_span(seg, brace)
        spans.append((brace, b + 1))
    return spans


def strip_comments(text: str) -> tuple[str, str]:
    """(code_without_comments, comments_only) -- both same length as input is not
    required here, only that the two views are separable."""
    comments = []

    def grab(m):
        comments.append(m.group(0))
        return " " * len(m.group(0))

    no_block = BLOCK_COMMENT_RE.sub(grab, text)
    no_line = LINE_COMMENT_RE.sub(grab, no_block)
    return no_line, "\n".join(comments)


def line_starts(text: str) -> list[int]:
    out = [0]
    for i, ch in enumerate(text):
        if ch == "\n":
            out.append(i + 1)
    return out


def line_of(starts: list[int], idx: int) -> int:
    lo, hi = 0, len(starts) - 1
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if starts[mid] <= idx:
            lo = mid
        else:
            hi = mid - 1
    return lo + 1


def plausible(name: str) -> bool:
    if not name or name in NOISE:
        return False
    if not (MIN_LEN <= len(name) <= MAX_LEN):
        return False
    if name.isdigit():
        return False
    if not re.match(r"^[A-Za-z_$][\w$.\[\]-]*$", name):
        return False
    # Minified single/double-letter identifiers are not parameter names.
    if len(name) <= 2 and name.islower():
        return False
    return True


class Collector:
    def __init__(self):
        self.params: dict[str, dict] = {}

    def add(self, name: str, kind: str, path: str, line: int, snippet: str) -> None:
        if not plausible(name):
            return
        rec = self.params.setdefault(name, {
            "name": name, "kinds": set(), "occurrences": [], "files": set()})
        rec["kinds"].add(kind)
        rec["files"].add(path)
        if len(rec["occurrences"]) < 8:
            rec["occurrences"].append({
                "file": path, "line": line, "kind": kind,
                "code": re.sub(r"\s+", " ", snippet).strip()[:160]})


def scan_file(path: str, root: str, col: Collector) -> None:
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError:
        return
    rel = os.path.relpath(path, root) if root else path
    code, comments = strip_comments(text)
    starts = line_starts(text)

    def ctx(idx: int) -> str:
        a = code.rfind("\n", 0, idx) + 1
        b = code.find("\n", idx)
        return code[a: b if b != -1 else len(code)]

    # 1. URLSearchParams / query-string helpers
    for m in SEARCH_PARAMS_RE.finditer(code):
        col.add(m.group("name"), "query-api", rel, line_of(starts, m.start()), ctx(m.start()))

    # 2. FormData.append and friends
    for m in FORMDATA_RE.finditer(code):
        col.add(m.group("name"), "formdata", rel, line_of(starts, m.start()), ctx(m.start()))

    # 3. Literal query strings inside URLs
    for m in re.finditer(r"['\"`](?P<url>[^'\"`\s]*\?[^'\"`\s]{1,400})['\"`]", code):
        qs = m.group("url").split("?", 1)[1]
        for pair in re.split(r"[&;]", qs):
            key = pair.split("=", 1)[0].strip()
            key = re.sub(r"^\{+|\}+$", "", key)
            col.add(key, "query-string", rel, line_of(starts, m.start()), m.group(0)[:160])

    # 4. Object-literal keys inside request calls -- body and params payloads
    for m in REQUEST_CALL_RE.finditer(code):
        open_idx = code.find("(", m.end() - 1)
        if open_idx == -1:
            continue
        a, b = balanced_span(code, open_idx)
        seg = code[a:b]
        header_spans = header_object_spans(seg)
        for om in OBJ_KEY_RE.finditer(seg):
            name = om.group("qname") or om.group("name")
            # Skip fetch's own option keys; they are transport, not parameters.
            if name in {"method", "headers", "body", "credentials", "mode", "cache",
                        "redirect", "signal", "params", "data", "url", "timeout"}:
                continue
            # ...and skip anything inside a headers:{} block for the same reason.
            if any(x <= om.start() < y for x, y in header_spans):
                continue
            col.add(name, "request-payload", rel, line_of(starts, a + om.start()),
                    seg[max(0, om.start() - 40): om.start() + 60])

    # 5. Fields read off a response but never submitted -- mass-assignment leads
    for m in RESPONSE_VAR_RE.finditer(code):
        col.add(m.group("name"), "response-field", rel,
                line_of(starts, m.start()), ctx(m.start()))

    # 6. Parameters that survive only in comments. A removed parameter is often
    #    still accepted by the server, which is exactly what makes it worth
    #    trying and exactly why it is invisible to traffic capture.
    for cm in COMMENT_PARAM_RE.finditer(comments):
        col.add(cm.group("name"), "commented", rel, 0, cm.group(0)[:120])


def collect_observed(burp_index: str | None) -> set[str]:
    """Parameter names that appear in captured traffic."""
    if not burp_index or not os.path.exists(burp_index):
        return set()
    with open(burp_index, encoding="utf-8") as fh:
        data = json.load(fh)
    seen: set[str] = set()
    for req in data.get("requests", []):
        url = req.get("url") or ""
        if "?" in url:
            for pair in re.split(r"[&;]", url.split("?", 1)[1]):
                k = pair.split("=", 1)[0].strip()
                if k:
                    seen.add(k)
        body = req.get("request_body") or ""
        if not body:
            continue
        stripped = body.strip()
        if stripped.startswith(("{", "[")):
            try:
                def walk(o):
                    if isinstance(o, dict):
                        for k, v in o.items():
                            seen.add(str(k))
                            walk(v)
                    elif isinstance(o, list):
                        for v in o:
                            walk(v)
                walk(json.loads(stripped))
                continue
            except ValueError:
                pass
        for pair in re.split(r"[&;]", body):
            k = pair.split("=", 1)[0].strip()
            if k and len(k) < 60 and re.match(r"^[\w.\[\]-]+$", k):
                seen.add(k)
    return seen


def classify(rec: dict, observed: set[str], have_traffic: bool) -> str:
    if not have_traffic:
        return "code"
    if rec["name"] in observed:
        return "observed"
    kinds = rec["kinds"]
    if kinds == {"commented"}:
        return "commented"
    if kinds == {"response-field"}:
        return "response_only"
    return "hidden"


def collect(paths, exts):
    files = []
    for p in paths:
        if os.path.isfile(p):
            files.append(p)
        else:
            for dirpath, dirnames, filenames in os.walk(p):
                dirnames[:] = sorted(d for d in dirnames
                                     if d not in (".git", "node_modules", "__pycache__"))
                for fn in sorted(filenames):
                    if os.path.splitext(fn)[1].lower() in exts:
                        files.append(os.path.join(dirpath, fn))
    return sorted(files)


def main():
    ap = argparse.ArgumentParser(
        description="Recover parameter names from client code and flag those the UI never sends.")
    ap.add_argument("paths", nargs="+")
    ap.add_argument("--burp-index", default=None,
                    help="burp_index.json -- without it nothing can be called hidden")
    ap.add_argument("--out", default="hidden_params.json")
    ap.add_argument("--wordlist", default=None,
                    help="Also write a plain name-per-line wordlist here")
    ap.add_argument("--root", default=None)
    ap.add_argument("--only", action="append", default=None,
                    choices=["hidden", "observed", "response_only", "commented", "code"],
                    help="Restrict output to these classes (repeatable)")
    args = ap.parse_args()

    exts = {".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".axd", ".html", ".htm",
            ".aspx", ".vue", ".json", ".map"}
    root = args.root or (args.paths[0] if os.path.isdir(args.paths[0])
                         else os.path.dirname(args.paths[0]) or ".")
    files = collect(args.paths, exts)
    if not files:
        print("No matching files found.", file=sys.stderr)
        return 1

    col = Collector()
    for f in files:
        scan_file(f, root, col)

    observed = collect_observed(args.burp_index)
    have_traffic = bool(observed)

    records = []
    for name in sorted(col.params):
        rec = col.params[name]
        cls = classify(rec, observed, have_traffic)
        records.append({
            "name": name,
            "classification": cls,
            "kinds": sorted(rec["kinds"]),
            "file_count": len(rec["files"]),
            "occurrences": rec["occurrences"],
        })

    if args.only:
        records = [r for r in records if r["classification"] in set(args.only)]

    order = {"hidden": 0, "response_only": 1, "commented": 2, "code": 3, "observed": 4}
    records.sort(key=lambda r: (order.get(r["classification"], 9), r["name"]))

    counts: dict[str, int] = {}
    for r in records:
        counts[r["classification"]] = counts.get(r["classification"], 0) + 1

    out = {
        "generated": datetime.now(timezone.utc).isoformat(),
        "root": os.path.abspath(root),
        "files_scanned": len(files),
        "traffic_available": have_traffic,
        "observed_parameter_count": len(observed),
        "by_classification": counts,
        "parameters": records,
    }
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=2)

    if args.wordlist:
        names = [r["name"] for r in records]
        with open(args.wordlist, "w", encoding="utf-8") as fh:
            fh.write("\n".join(names) + ("\n" if names else ""))

    print("Scanned %d file(s) -> %d distinct parameter name(s)" % (len(files), len(records)))
    for cls in ("hidden", "response_only", "commented", "code", "observed"):
        if counts.get(cls):
            print("  %-14s %d" % (cls, counts[cls]))
    if not have_traffic:
        print("\nNo Burp index supplied, so nothing is classified as hidden -- a name is")
        print("only interesting once you know the UI never sends it. Re-run with")
        print("--burp-index burp_index.json.")
    else:
        hidden = [r["name"] for r in records if r["classification"] == "hidden"]
        if hidden:
            print("\nNever seen in traffic: %s" % ", ".join(hidden[:25]))
            if len(hidden) > 25:
                print("... and %d more" % (len(hidden) - 25))
    print("\nWrote %s" % args.out)
    if args.wordlist:
        print("Wrote %s" % args.wordlist)
    return 0


if __name__ == "__main__":
    sys.exit(main())
