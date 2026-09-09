#!/usr/bin/env python3
"""Find DOM XSS candidates: attacker-controllable sources reaching HTML/JS sinks.

This is a triage aid, not a decision procedure. Regex cannot do real taint
analysis across function boundaries, so the output is ranked by how much
evidence was actually observed:

  high   - a source appears inside the sink's own argument
  medium - a variable assigned from a source is used in the sink
  low    - a sink with no visible source (still worth a look; the data may
           arrive from a caller, a framework binding, or server-rendered state)

Confidence is deliberately capped: every hit needs manual confirmation in a
browser before it goes in a report.
"""

import argparse
import json
import os
import re
import sys
from datetime import datetime, timezone

SOURCES = [
    ("location.hash",       re.compile(r"\blocation\s*\.\s*hash\b")),
    ("location.search",     re.compile(r"\blocation\s*\.\s*search\b")),
    ("location.href",       re.compile(r"\b(?:window\s*\.\s*)?location\s*(?:\.\s*href)?\b(?!\s*=)")),
    ("location.pathname",   re.compile(r"\blocation\s*\.\s*pathname\b")),
    ("document.URL",        re.compile(r"\bdocument\s*\.\s*(?:URL|documentURI|baseURI)\b")),
    ("document.referrer",   re.compile(r"\bdocument\s*\.\s*referrer\b")),
    ("window.name",         re.compile(r"\bwindow\s*\.\s*name\b")),
    ("document.cookie",     re.compile(r"\bdocument\s*\.\s*cookie\b")),
    ("postMessage.data",    re.compile(r"\b(?:event|e|msg|ev)\s*\.\s*data\b")),
    ("URLSearchParams",     re.compile(r"\bURLSearchParams\s*\(|\.\s*searchParams\b")),
    ("storage.getItem",     re.compile(r"\b(?:localStorage|sessionStorage)\s*\.\s*getItem\s*\(")),
    ("history.state",       re.compile(r"\bhistory\s*\.\s*state\b")),
    ("hashchange",          re.compile(r"['\"]hashchange['\"]")),
]

# (name, pattern, category, severity_hint)
SINKS = [
    ("innerHTML",              re.compile(r"\.\s*innerHTML\s*(?:\+?=|\bset\b)"), "html", "high"),
    ("outerHTML",              re.compile(r"\.\s*outerHTML\s*\+?="), "html", "high"),
    ("insertAdjacentHTML",     re.compile(r"\.\s*insertAdjacentHTML\s*\("), "html", "high"),
    ("document.write",         re.compile(r"\bdocument\s*\.\s*write(?:ln)?\s*\("), "html", "high"),
    ("eval",                   re.compile(r"(?<![.\w])eval\s*\("), "exec", "high"),
    ("Function-ctor",          re.compile(r"\bnew\s+Function\s*\(|(?<![.\w])Function\s*\(\s*['\"]"), "exec", "high"),
    ("setTimeout-string",      re.compile(r"\bset(?:Timeout|Interval)\s*\(\s*['\"]|\bset(?:Timeout|Interval)\s*\(\s*[A-Za-z_$][\w$]*\s*\+"), "exec", "high"),
    ("jquery-html",            re.compile(r"\.\s*html\s*\("), "html", "high"),
    ("jquery-append",          re.compile(r"\.\s*(?:append|prepend|before|after|replaceWith|wrap|wrapAll)\s*\("), "html", "medium"),
    ("jquery-selector",        re.compile(r"\$\s*\(\s*[A-Za-z_$][\w$.]*\s*\)"), "html", "medium"),
    ("jquery-globalEval",      re.compile(r"\$\s*\.\s*globalEval\s*\("), "exec", "high"),
    ("dangerouslySetInnerHTML", re.compile(r"dangerouslySetInnerHTML"), "html", "high"),
    ("v-html",                 re.compile(r"v-html\s*="), "html", "high"),
    ("angular-trustAsHtml",    re.compile(r"\btrustAsHtml\s*\(|\bbypassSecurityTrust(?:Html|Script|Url|ResourceUrl)\s*\("), "html", "high"),
    ("createContextualFragment", re.compile(r"createContextualFragment\s*\("), "html", "high"),
    ("DOMParser",              re.compile(r"\bDOMParser\s*\(\s*\)[\s\S]{0,80}?parseFromString\s*\("), "html", "medium"),
    ("srcdoc",                 re.compile(r"\.\s*srcdoc\s*=|srcdoc\s*="), "html", "high"),
    ("script.src",             re.compile(r"\.\s*src\s*=\s*(?![\"'](?:https?:)?/[^\"']*[\"']\s*;)"), "resource", "medium"),
    ("location-assign",        re.compile(r"\blocation\s*(?:\.\s*(?:href|assign|replace))?\s*=\s*(?![\"'])|location\s*\.\s*(?:assign|replace)\s*\("), "navigation", "medium"),
    ("window.open",            re.compile(r"\bwindow\s*\.\s*open\s*\("), "navigation", "low"),
    ("setAttribute-danger",    re.compile(r"\.\s*setAttribute\s*\(\s*['\"](?:src|href|onerror|onload|formaction|data|action)['\"]", re.I), "resource", "medium"),
    ("importScripts",          re.compile(r"\bimportScripts\s*\("), "exec", "high"),
]

SANITIZERS = re.compile(
    r"\bDOMPurify\s*\.\s*sanitize\b|\bsanitize(?:Html|HTML)?\s*\(|\bescapeHtml\b|\bencodeURIComponent\s*\(|"
    r"\btextContent\s*=|\binnerText\s*=|\bhtmlspecialchars\b|\bxss\s*\(|\bDOMPurify\b",
    re.I,
)

ASSIGN_FROM_SOURCE = re.compile(
    r"(?:var|let|const)\s+(?P<var>[A-Za-z_$][\w$]*)\s*=\s*(?P<rhs>[^;\n]{0,200})"
)


def build_line_starts(text):
    starts = [0]
    for i, ch in enumerate(text):
        if ch == "\n":
            starts.append(i + 1)
    return starts


def line_of(idx, line_starts):
    lo, hi = 0, len(line_starts) - 1
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if line_starts[mid] <= idx:
            lo = mid
        else:
            hi = mid - 1
    return lo + 1


def sink_arg_span(text, start, max_len=400):
    """The sink's own expression: its argument list, or the RHS of an assignment."""
    open_idx = text.find("(", start)
    eq_idx = text.find("=", start)
    if open_idx != -1 and (eq_idx == -1 or open_idx < eq_idx):
        depth, i, n, quote = 0, open_idx, min(len(text), open_idx + max_len), None
        while i < n:
            ch = text[i]
            if quote:
                if ch == "\\":
                    i += 2
                    continue
                if ch == quote:
                    quote = None
            elif ch in "'\"`":
                quote = ch
            elif ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0:
                    return text[open_idx: i + 1]
            i += 1
        return text[open_idx: n]
    if eq_idx != -1:
        end = text.find(";", eq_idx)
        nl = text.find("\n", eq_idx)
        cands = [c for c in (end, nl) if c != -1]
        stop = min(cands) if cands else min(len(text), eq_idx + max_len)
        return text[eq_idx: stop]
    return text[start: start + 120]


def tainted_vars(text):
    """Variables assigned directly from a source. One hop only -- enough to
    catch the common `var h = location.hash; el.innerHTML = h;` shape without
    pretending to be a real taint engine."""
    out = {}
    for m in ASSIGN_FROM_SOURCE.finditer(text):
        rhs = m.group("rhs")
        for sname, spat in SOURCES:
            if spat.search(rhs):
                out.setdefault(m.group("var"), set()).add(sname)
                break
    return out


def scan_file(path, root):
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError:
        return []
    rel = os.path.relpath(path, root) if root else path
    line_starts = build_line_starts(text)
    tainted = tainted_vars(text)
    file_sources = sorted({n for n, p in SOURCES if p.search(text)})
    findings = []

    for sink_name, pat, category, sev in SINKS:
        for m in pat.finditer(text):
            arg = sink_arg_span(text, m.start())
            direct = sorted({n for n, p in SOURCES if p.search(arg)})
            via = {}
            for var, srcs in tainted.items():
                if re.search(r"(?<![\w$.])%s(?![\w$])" % re.escape(var), arg):
                    via[var] = sorted(srcs)
            sanitized = bool(SANITIZERS.search(arg))

            if direct:
                confidence = "high"
            elif via:
                confidence = "medium"
            else:
                confidence = "low"
            if sanitized and confidence != "low":
                confidence = "needs-review-sanitizer-present"

            findings.append({
                "file": rel,
                "line": line_of(m.start(), line_starts),
                "sink": sink_name,
                "category": category,
                "severity_hint": sev,
                "confidence": confidence,
                "direct_sources": direct,
                "tainted_vars": via,
                "sanitizer_nearby": sanitized,
                "sources_present_in_file": file_sources,
                "snippet": text[max(0, m.start() - 40): m.start() + 180].replace("\n", " ").strip(),
            })
    return findings


def collect(paths, exts):
    files = []
    for p in paths:
        if os.path.isfile(p):
            files.append(p)
        else:
            for dirpath, dirnames, filenames in os.walk(p):
                dirnames[:] = [d for d in dirnames if d not in (".git", "node_modules", "__pycache__")]
                for fn in filenames:
                    if os.path.splitext(fn)[1].lower() in exts:
                        files.append(os.path.join(dirpath, fn))
    return sorted(files)


def main():
    ap = argparse.ArgumentParser(description="DOM XSS source/sink triage for JS, .axd and HTML.")
    ap.add_argument("paths", nargs="+")
    ap.add_argument("--out", default="domxss.json")
    ap.add_argument("--root", default=None)
    ap.add_argument("--min-confidence", default="low",
                    choices=["low", "medium", "high"],
                    help="Drop findings below this confidence")
    args = ap.parse_args()

    exts = {".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".axd", ".html", ".htm", ".aspx", ".vue"}
    root = args.root or (args.paths[0] if os.path.isdir(args.paths[0]) else os.path.dirname(args.paths[0]) or ".")
    files = collect(args.paths, exts)
    if not files:
        print("No matching files found.", file=sys.stderr)
        return 1

    findings = []
    for f in files:
        findings.extend(scan_file(f, root))

    order = {"high": 3, "medium": 2, "needs-review-sanitizer-present": 2, "low": 1}
    floor = {"low": 1, "medium": 2, "high": 3}[args.min_confidence]
    findings = [f for f in findings if order.get(f["confidence"], 1) >= floor]
    findings.sort(key=lambda f: (-order.get(f["confidence"], 1),
                                 {"high": 0, "medium": 1, "low": 2}.get(f["severity_hint"], 3),
                                 f["file"], f["line"]))

    counts = {}
    for f in findings:
        counts[f["confidence"]] = counts.get(f["confidence"], 0) + 1

    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump({
            "generated": datetime.now(timezone.utc).isoformat(),
            "root": os.path.abspath(root),
            "files_scanned": len(files),
            "finding_count": len(findings),
            "by_confidence": counts,
            "findings": findings,
        }, fh, indent=2)

    print("Scanned %d files -> %d DOM XSS candidates" % (len(files), len(findings)))
    for k in ("high", "medium", "needs-review-sanitizer-present", "low"):
        if counts.get(k):
            print("  %-34s %d" % (k, counts[k]))
    print("Wrote %s" % args.out)
    if counts.get("high"):
        print("\nStart with the high-confidence hits: a source inside the sink's own argument.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
