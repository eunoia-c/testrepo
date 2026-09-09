#!/usr/bin/env python3
"""Extract HTTP endpoints from JavaScript, .axd, and HTML files.

Static analysis only: this reads files off disk and never contacts a target.

Output is a JSON inventory of endpoints, each annotated with where it came
from and what authorization evidence (if any) sits at the call site. The
auth verdict is deliberately conservative -- static analysis cannot see
server-side enforcement, so "no_auth_indicator" means "worth testing",
never "confirmed unauthenticated".
"""

import argparse
import json
import os
import re
import sys
from datetime import datetime, timezone

# ---------------------------------------------------------------- constants

DEFAULT_EXTS = {".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".axd", ".html", ".htm", ".aspx", ".json", ".map"}

# Strings that look like a path or URL worth recording.
PATH_HINT = re.compile(
    r"""(?:^|/)(?:api|rest|service|services|svc|graphql|gateway|v\d+)(?:/|$)"""
    r"""|\.(?:aspx|asmx|ashx|axd|svc|json|php|do|jsp|action|cgi)\b""",
    re.I,
)

STRING_LIT = re.compile(
    r"""(?P<q>['"`])(?P<val>(?:\\.|(?!(?P=q))[^\\])*)(?P=q)""",
    re.S,
)

# Call-site signatures -> a label. Order matters: more specific first.
CALL_SIGS = [
    ("fetch",              re.compile(r"\bfetch\s*\(")),
    ("xhr-open",           re.compile(r"\.open\s*\(\s*['\"](?P<m>GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)['\"]", re.I)),
    ("axios-method",       re.compile(r"\baxios\s*\.\s*(?P<m>get|post|put|patch|delete|head|options|request)\s*\(", re.I)),
    ("axios-call",         re.compile(r"\baxios\s*\(")),
    ("jquery-ajax",        re.compile(r"\$(?:\.\w+)?\s*\.\s*ajax\s*\(")),
    ("jquery-shorthand",   re.compile(r"\$\s*\.\s*(?P<m>get|post|getJSON|getScript|load)\s*\(")),
    ("angular-http",       re.compile(r"\bhttp\s*\.\s*(?P<m>get|post|put|patch|delete|head|options|request)\s*(?:<[^>]*>)?\s*\(", re.I)),
    ("wcf-proxy",          re.compile(r"WebServiceProxy\s*\.\s*invoke\s*\(")),
    ("pagemethods",        re.compile(r"\bPageMethods\s*\.\s*(?P<m>\w+)\s*\(")),
    ("dopostback",         re.compile(r"\b__doPostBack\s*\(")),
    ("navigator-beacon",   re.compile(r"navigator\s*\.\s*sendBeacon\s*\(")),
    ("websocket",          re.compile(r"new\s+WebSocket\s*\(")),
    ("eventsource",        re.compile(r"new\s+EventSource\s*\(")),
]

METHOD_IN_OPTS = re.compile(r"""["']?(?:method|type)["']?\s*:\s*['"](?P<m>GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)['"]""", re.I)

# Authorization evidence at a call site.
AUTH_HEADER_PAT = re.compile(
    r"""["']?(?P<h>Authorization|X-API-Key|X-Api-Key|apikey|api_key|X-Auth-Token|X-Access-Token|"""
    r"""X-CSRF-Token|X-XSRF-TOKEN|RequestVerificationToken|X-Requested-With|Cookie)["']?\s*:""",
    re.I,
)
BEARER_PAT = re.compile(r"""['"]\s*Bearer\s|Bearer\s+\$\{|['"]Basic\s""", re.I)
CREDENTIALS_PAT = re.compile(r"""["']?(?:credentials|withCredentials)["']?\s*:\s*(?P<v>true|false|['"](?:include|same-origin|omit)['"])""", re.I)

# Bundle-wide auth mechanisms: if present, endpoints may inherit auth
# even when the call site itself shows nothing.
GLOBAL_AUTH_SIGS = [
    ("axios-interceptor",  re.compile(r"axios\s*\.\s*interceptors\s*\.\s*request\s*\.\s*use")),
    ("axios-defaults",     re.compile(r"axios\s*\.\s*defaults\s*\.\s*headers")),
    ("jquery-ajaxsetup",   re.compile(r"\$\s*\.\s*ajaxSetup\s*\(")),
    ("jquery-beforesend",  re.compile(r"\bbeforeSend\s*:")),
    ("fetch-wrapper",      re.compile(r"(?:const|let|var|function)\s+\w*(?:apiClient|httpClient|authFetch|apiFetch|request)\w*\s*[=(]", re.I)),
    ("angular-interceptor", re.compile(r"HTTP_INTERCEPTORS|implements\s+HttpInterceptor")),
    ("msal-adal",          re.compile(r"\b(?:Msal|AuthenticationContext|acquireTokenSilent|adalFetch)\b")),
    ("token-storage",      re.compile(r"(?:localStorage|sessionStorage)\s*\.\s*(?:getItem|setItem)\s*\(\s*['\"][^'\"]*(?:token|jwt|auth)[^'\"]*['\"]", re.I)),
]

# ASP.NET specific extraction.
ASMX_INVOKE = re.compile(
    r"WebServiceProxy\s*\.\s*invoke\s*\(\s*(?P<q1>['\"])(?P<path>[^'\"]+)(?P=q1)\s*,\s*(?P<q2>['\"])(?P<op>[^'\"]*)(?P=q2)",
)
DOPOSTBACK = re.compile(r"__doPostBack\s*\(\s*['\"](?P<target>[^'\"]*)['\"]")
AXD_RES = re.compile(r"(?P<path>(?:/[\w.\-]+)*/(?:ScriptResource|WebResource)\.axd)\?(?P<qs>[^\"'\s<>]+)", re.I)

NOISE_VALUES = re.compile(
    r"^(?:https?://)?(?:www\.)?(?:w3\.org|schemas\.|json-schema|github\.com|npmjs|unpkg|jsdelivr|cdnjs|googleapis|gstatic|mozilla\.org|ecma-international)",
    re.I,
)


def line_of(text, idx, line_starts):
    lo, hi = 0, len(line_starts) - 1
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if line_starts[mid] <= idx:
            lo = mid
        else:
            hi = mid - 1
    return lo + 1


def build_line_starts(text):
    starts = [0]
    for i, ch in enumerate(text):
        if ch == "\n":
            starts.append(i + 1)
    return starts


def normalize(raw):
    """Collapse template params and obvious IDs so endpoints group sensibly."""
    n = re.sub(r"\$\{[^}]*\}", "{param}", raw)
    n = re.sub(r"['\"]\s*\+\s*[\w.$\[\]()]+\s*\+\s*['\"]", "{param}", n)
    n = re.sub(r"['\"]\s*\+\s*[\w.$\[\]()]+", "{param}", n)
    n = re.sub(r"\{\{[^}]*\}\}", "{param}", n)
    n = re.sub(r"/:\w+", "/{param}", n)
    n = re.sub(r"/\d{2,}(?=/|$)", "/{id}", n)
    n = re.sub(
        r"/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(?=/|$)",
        "/{guid}",
        n,
        flags=re.I,
    )
    return n


def extract_params(raw):
    out = []
    out += re.findall(r"\$\{\s*([\w.$]+)\s*\}", raw)
    out += re.findall(r"/:(\w+)", raw)
    q = raw.split("?", 1)
    if len(q) == 2:
        for pair in re.split(r"[&;]", q[1]):
            k = pair.split("=", 1)[0].strip()
            if k and re.match(r"^[\w.\-\[\]]+$", k):
                out.append(k)
    seen, uniq = set(), []
    for p in out:
        if p not in seen:
            seen.add(p)
            uniq.append(p)
    return uniq


def looks_like_endpoint(val):
    if not val or len(val) > 400:
        return False
    if NOISE_VALUES.search(val):
        return False
    if val.startswith(("data:", "blob:", "javascript:", "mailto:", "tel:")):
        return False
    if re.match(r"^https?://", val):
        return True
    if val.startswith("//") and "/" in val[2:]:
        return True
    if val.startswith("/") and len(val) > 1 and not val.startswith("//"):
        # Reject CSS/regex-ish noise.
        if re.match(r"^/[\w.\-/{}$:%@~+]*(?:\?[^\s]*)?$", val):
            return True
    if PATH_HINT.search(val) and "/" in val:
        return True
    return False


def call_span(text, start, max_len=1200):
    """Return the source span of the call whose signature begins at `start`.

    Fixed-size windows are the obvious approach and they are wrong: an options
    object 300 chars later belongs to the *next* call, and attributing its
    credentials/method to this one produces confident nonsense. Walking the
    balanced parentheses (while skipping string bodies) keeps each call's
    evidence to itself."""
    open_idx = text.find("(", start)
    if open_idx == -1:
        return text[start: start + 200]
    depth, i, n = 0, open_idx, min(len(text), open_idx + max_len)
    quote = None
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
                return text[start: i + 1]
        i += 1
    return text[start: n]


def auth_evidence(ctx):
    headers = sorted({m.group("h") for m in AUTH_HEADER_PAT.finditer(ctx)})
    bearer = bool(BEARER_PAT.search(ctx))
    cm = CREDENTIALS_PAT.search(ctx)
    creds = cm.group("v").strip("'\"") if cm else None
    return headers, bearer, creds


def verdict_for(headers, bearer, creds, has_global):
    """Conservative classification. Static analysis proves nothing about
    server-side enforcement -- this only ranks what deserves manual testing."""
    strong = [h for h in headers if h.lower() in
              ("authorization", "x-api-key", "apikey", "api_key", "x-auth-token", "x-access-token")]
    csrf = [h for h in headers if "csrf" in h.lower() or "xsrf" in h.lower() or "verificationtoken" in h.lower()]
    if strong or bearer:
        return "auth_at_callsite"
    if creds in ("include", "same-origin", "true"):
        return "cookie_auth_likely"
    if creds == "omit" or creds == "false":
        return "explicit_no_credentials"
    if csrf:
        return "csrf_only"
    if has_global:
        return "no_callsite_auth_global_present"
    return "no_auth_indicator"


def scan_file(path, root):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError as exc:
        return [], [], {"file": path, "error": str(exc)}

    rel = os.path.relpath(path, root) if root else path
    line_starts = build_line_starts(text)
    endpoints, globals_found = [], []

    for kind, pat in GLOBAL_AUTH_SIGS:
        for m in pat.finditer(text):
            globals_found.append({
                "file": rel,
                "line": line_of(text, m.start(), line_starts),
                "kind": kind,
                "snippet": text[m.start(): m.start() + 120].replace("\n", " ").strip(),
            })
            break  # one hit per kind per file is enough signal

    has_global = bool(globals_found)

    # Pass 1: call sites. These carry method + auth context, so they are the
    # highest-confidence records.
    call_hits = []
    for kind, pat in CALL_SIGS:
        for m in pat.finditer(text):
            call_hits.append((m.start(), kind, m))

    claimed = set()
    for start, kind, m in sorted(call_hits):
        ctx = call_span(text, start)
        method = None
        if m.groupdict().get("m") and kind != "pagemethods":
            method = m.group("m").upper()
        if not method:
            mm = METHOD_IN_OPTS.search(ctx)
            if mm:
                method = mm.group("m").upper()
        if kind in ("jquery-shorthand",) and method in ("GETJSON", "GETSCRIPT", "LOAD"):
            method = "GET"

        headers, bearer, creds = auth_evidence(ctx)

        # The URL is the first endpoint-shaped literal inside this call's own
        # span. Searching beyond the span is how you end up attributing a
        # WebSocket URL to a PageMethods call.
        target, target_end = None, None
        for sm in STRING_LIT.finditer(ctx):
            val = sm.group("val")
            if looks_like_endpoint(val):
                target, target_end = val, start + sm.end()
                break
        if target is None:
            continue

        # `'/api/users/' + id` -- the literal ends mid-path, so record the
        # concatenated tail as a parameter rather than losing it.
        if target_end is not None and re.match(r"\s*\+", text[target_end: target_end + 8]) \
                and (target.endswith("/") or target.endswith("=") or target.endswith("&")):
            target = target + "${concat}"

        claimed.add(target)
        endpoints.append({
            "raw": target,
            "normalized": normalize(target),
            "method": method or ("POST" if kind in ("pagemethods", "dopostback", "wcf-proxy") else "GET"),
            "method_confidence": "explicit" if method else "inferred",
            "call_kind": kind,
            "file": rel,
            "line": line_of(text, start, line_starts),
            "snippet": text[start: start + 160].replace("\n", " ").strip(),
            "params": extract_params(target),
            "auth": {
                "headers": headers,
                "bearer_literal": bearer,
                "credentials": creds,
                "verdict": verdict_for(headers, bearer, creds, has_global),
            },
        })

    # Pass 2: ASP.NET service proxies.
    for m in ASMX_INVOKE.finditer(text):
        raw = m.group("path")
        op = m.group("op")
        full = raw if not op else raw.rstrip("/") + "/" + op
        claimed.add(raw)
        endpoints.append({
            "raw": full,
            "normalized": normalize(full),
            "method": "POST",
            "method_confidence": "inferred",
            "call_kind": "wcf-proxy",
            "file": rel,
            "line": line_of(text, m.start(), line_starts),
            "snippet": text[m.start(): m.start() + 160].replace("\n", " ").strip(),
            "params": [],
            "auth": {"headers": [], "bearer_literal": False, "credentials": None,
                     "verdict": verdict_for([], False, None, has_global)},
        })

    # Pass 3: bare string literals that look like endpoints but had no call site.
    for sm in STRING_LIT.finditer(text):
        val = sm.group("val")
        if val in claimed or not looks_like_endpoint(val):
            continue
        ctx = text[sm.start(): sm.start() + 200]
        headers, bearer, creds = auth_evidence(ctx)
        endpoints.append({
            "raw": val,
            "normalized": normalize(val),
            "method": "GET",
            "method_confidence": "unknown",
            "call_kind": "string-literal",
            "file": rel,
            "line": line_of(text, sm.start(), line_starts),
            "snippet": text[max(0, sm.start() - 60): sm.start() + 100].replace("\n", " ").strip(),
            "params": extract_params(val),
            "auth": {"headers": headers, "bearer_literal": bearer, "credentials": creds,
                     "verdict": "unknown_no_callsite"},
        })

    # WebForms postback targets: not endpoints themselves (they POST to the
    # containing page) but they name server-side controls worth exercising.
    postbacks = []
    for m in DOPOSTBACK.finditer(text):
        postbacks.append({
            "file": rel,
            "line": line_of(text, m.start(), line_starts),
            "kind": "__doPostBack",
            "target": m.group("target"),
        })
    for m in re.finditer(r"\bPageMethods\s*\.\s*(\w+)\s*\(", text):
        postbacks.append({
            "file": rel,
            "line": line_of(text, m.start(), line_starts),
            "kind": "PageMethods",
            "target": m.group(1),
        })

    # Pass 4: .axd references (ASP.NET resource handlers embedded in markup).
    axd = []
    for m in AXD_RES.finditer(text):
        axd.append({
            "file": rel,
            "line": line_of(text, m.start(), line_starts),
            "path": m.group("path"),
            "query": m.group("qs")[:300],
        })

    return endpoints, globals_found, {"file": rel, "axd_refs": axd, "postbacks": postbacks}


def absorb_fragments(endpoints):
    """Drop bare string literals that are really truncated call-site URLs.

    `'/api/users/' + id` yields both a literal `/api/users/` and a call-site
    `/api/users/{param}`. Reporting both inflates the inventory and wastes
    triage time. The tell is the trailing `/`, `=`, `?` or `&`: a complete path
    rarely ends that way, so only those are treated as fragments. `/api/cases`
    alongside `/api/cases/{param}` is two genuine endpoints and both survive."""
    keep, absorbed = [], []
    longer = [e for e in endpoints if e["call_kind"] != "string-literal"]
    for e in endpoints:
        n = e["normalized"]
        is_fragment = e["call_kind"] == "string-literal" and n.rstrip().endswith(("/", "=", "?", "&"))
        parent = None
        if is_fragment:
            for o in longer:
                if o is not e and o["normalized"].startswith(n) and len(o["normalized"]) > len(n):
                    parent = o
                    break
        # A WCF/ASMX service path is also a prefix of its own operations; the
        # operation-level entries are the actionable ones.
        if parent is None and e["call_kind"] == "wcf-proxy":
            for o in longer:
                if o is not e and o["call_kind"] == "wcf-proxy" and \
                        o["normalized"].startswith(n + "/"):
                    parent = o
                    break
        if parent is not None:
            absorbed.append({"fragment": n, "absorbed_into": parent["normalized"]})
        else:
            keep.append(e)
    return keep, absorbed


def dedupe(endpoints):
    """Group by (normalized, method) but keep every source location -- knowing
    an endpoint appears in five bundles is useful, five near-identical rows are not."""
    grouped = {}
    for e in endpoints:
        key = (e["normalized"], e["method"])
        if key not in grouped:
            e = dict(e)
            e["occurrences"] = [{"file": e.pop("file"), "line": e.pop("line"), "snippet": e.pop("snippet")}]
            grouped[key] = e
        else:
            g = grouped[key]
            g["occurrences"].append({"file": e["file"], "line": e["line"], "snippet": e["snippet"]})
            # Prefer the most informative record.
            rank = {"explicit": 3, "inferred": 2, "unknown": 1}
            if rank.get(e["method_confidence"], 0) > rank.get(g["method_confidence"], 0):
                g["method_confidence"] = e["method_confidence"]
            if e["call_kind"] != "string-literal" and g["call_kind"] == "string-literal":
                g["call_kind"] = e["call_kind"]
            if e["auth"]["verdict"] not in ("unknown_no_callsite",) and \
               g["auth"]["verdict"] == "unknown_no_callsite":
                g["auth"] = e["auth"]
            for p in e["params"]:
                if p not in g["params"]:
                    g["params"].append(p)
    out = list(grouped.values())
    for i, e in enumerate(sorted(out, key=lambda x: (x["normalized"], x["method"])), 1):
        e["id"] = "e%03d" % i
    return sorted(out, key=lambda x: x["id"])


def collect_files(paths, exts):
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
    ap = argparse.ArgumentParser(description="Extract endpoints from JS/.axd/HTML for VAPT triage.")
    ap.add_argument("paths", nargs="+", help="Files or directories to scan")
    ap.add_argument("--out", default="endpoints.json")
    ap.add_argument("--root", default=None, help="Base dir for relative paths in output")
    ap.add_argument("--ext", action="append", default=None, help="Extra extension to include (repeatable)")
    ap.add_argument("--include-noise", action="store_true",
                    help="Keep string-literal-only hits (default keeps them; use --calls-only to drop)")
    ap.add_argument("--calls-only", action="store_true", help="Only report endpoints found at a call site")
    args = ap.parse_args()

    exts = set(DEFAULT_EXTS)
    for e in (args.ext or []):
        exts.add(e if e.startswith(".") else "." + e)

    root = args.root or (args.paths[0] if os.path.isdir(args.paths[0]) else os.path.dirname(args.paths[0]) or ".")
    files = collect_files(args.paths, exts)
    if not files:
        print("No matching files found.", file=sys.stderr)
        return 1

    all_eps, all_globals, all_axd, all_pb, errors = [], [], [], [], []
    for f in files:
        eps, globs, meta = scan_file(f, root)
        if meta.get("error"):
            errors.append(meta)
            continue
        all_eps.extend(eps)
        all_globals.extend(globs)
        all_axd.extend(meta.get("axd_refs", []))
        all_pb.extend(meta.get("postbacks", []))

    if args.calls_only:
        all_eps = [e for e in all_eps if e["call_kind"] != "string-literal"]

    endpoints, absorbed = absorb_fragments(dedupe(all_eps))
    for i, e in enumerate(endpoints, 1):
        e["id"] = "e%03d" % i

    result = {
        "generated": datetime.now(timezone.utc).isoformat(),
        "root": os.path.abspath(root),
        "files_scanned": len(files),
        "endpoint_count": len(endpoints),
        "global_auth_mechanisms": all_globals,
        "axd_references": all_axd,
        "postback_targets": all_pb,
        "endpoints": endpoints,
        "absorbed_fragments": absorbed,
        "errors": errors,
    }

    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2)

    by_verdict = {}
    for e in endpoints:
        by_verdict[e["auth"]["verdict"]] = by_verdict.get(e["auth"]["verdict"], 0) + 1
    print("Scanned %d files -> %d unique endpoints" % (len(files), len(endpoints)))
    for k in sorted(by_verdict, key=lambda x: -by_verdict[x]):
        print("  %-38s %d" % (k, by_verdict[k]))
    if all_globals:
        kinds = sorted({g["kind"] for g in all_globals})
        print("Bundle-wide auth mechanisms: %s" % ", ".join(kinds))
    if all_axd:
        print(".axd references: %d" % len(all_axd))
    if all_pb:
        print("WebForms postback targets: %d" % len(all_pb))
    print("Wrote %s" % args.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
