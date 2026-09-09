#!/usr/bin/env python3
"""Merge the analysis artifacts into one Markdown findings report.

The report is written for someone who has to act on it: candidates are ranked
by how much testing effort they justify, and every claim carries a file:line so
it can be checked. Static analysis cannot observe server-side enforcement, so
the language throughout is "candidate" and "worth testing" -- never "vulnerable".
Overstating a static finding is how a report loses credibility on page one.
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone

# Verdicts ranked by how much attention they deserve during manual testing.
VERDICT_PRIORITY = {
    "explicit_no_credentials": (1, "Call site explicitly disables credentials"),
    "no_auth_indicator": (2, "No authorization evidence anywhere near the call"),
    "unknown_no_callsite": (3, "Path found as a bare string; no call site to judge"),
    "csrf_only": (4, "CSRF token present but no authentication header"),
    "no_callsite_auth_global_present": (5, "Call site is bare, but the bundle installs auth globally"),
    "cookie_auth_likely": (6, "Sends cookies; likely session-authenticated"),
    "auth_at_callsite": (7, "Authorization header set at the call site"),
}


def load(path, required=False):
    if not path or not os.path.exists(path):
        if required:
            print("Missing required input: %s" % path, file=sys.stderr)
            sys.exit(1)
        return None
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def esc(s):
    return str(s).replace("|", "\\|").replace("\n", " ").strip()


def burp_lookup(burp):
    """method+path -> observation, so static candidates can be corroborated
    against traffic that was actually captured."""
    if not burp:
        return {}
    out = {}
    for o in burp.get("observed_endpoints", []):
        out[(o["method"].upper(), o["path"].split("?", 1)[0].rstrip("/"))] = o
    return out


def main():
    ap = argparse.ArgumentParser(description="Generate a Markdown VAPT report from analysis artifacts.")
    ap.add_argument("--endpoints", required=True)
    ap.add_argument("--domxss", default=None)
    ap.add_argument("--burp-index", default=None)
    ap.add_argument("--out", default="js-recon-report.md")
    ap.add_argument("--target", default="the application under test",
                    help="Target name/scope as it should read in the report")
    ap.add_argument("--max-endpoints", type=int, default=0,
                    help="Truncate the full inventory table (0 = no limit)")
    args = ap.parse_args()

    inv = load(args.endpoints, required=True)
    dom = load(args.domxss)
    burp = load(args.burp_index)
    obs = burp_lookup(burp)

    eps = inv.get("endpoints", [])
    globals_ = inv.get("global_auth_mechanisms", [])
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    def prio(e):
        return VERDICT_PRIORITY.get(e.get("auth", {}).get("verdict", ""), (9, ""))[0]

    candidates = sorted([e for e in eps if prio(e) <= 4], key=lambda e: (prio(e), e["normalized"]))

    L = []
    L.append("# JavaScript static analysis — endpoint and client-side review")
    L.append("")
    L.append("**Target:** %s  " % args.target)
    L.append("**Generated:** %s  " % now)
    L.append("**Method:** Static analysis of client-side JavaScript, `.axd` resources and markup. "
             "No requests were issued to the target as part of this analysis.")
    L.append("")

    L.append("## Summary")
    L.append("")
    L.append("| Metric | Count |")
    L.append("| --- | --- |")
    L.append("| Files analysed | %d |" % inv.get("files_scanned", 0))
    L.append("| Unique endpoints recovered | %d |" % len(eps))
    L.append("| Endpoints flagged for authorization testing | %d |" % len(candidates))
    if dom:
        bc = dom.get("by_confidence", {})
        L.append("| DOM XSS candidates (high / medium / low) | %d / %d / %d |" % (
            bc.get("high", 0),
            bc.get("medium", 0) + bc.get("needs-review-sanitizer-present", 0),
            bc.get("low", 0)))
    if burp:
        L.append("| Requests observed in Burp export | %d |" % burp.get("item_count", 0))
    L.append("| `.axd` resource references | %d |" % len(inv.get("axd_references", [])))
    L.append("| WebForms postback / PageMethods targets | %d |" % len(inv.get("postback_targets", [])))
    L.append("")

    L.append("### How to read this report")
    L.append("")
    L.append("Static analysis shows what the *client* does, which is evidence about the "
             "attack surface and no evidence at all about server-side enforcement. An endpoint "
             "listed below as an authorization candidate may well be properly protected — the "
             "point is that nothing in the client proves it is, so it earns a manual test. "
             "Nothing here should be reported as a vulnerability until it has been confirmed "
             "against the running application.")
    L.append("")

    # --- Authorization candidates ---------------------------------------
    L.append("## 1. Endpoints to test for missing authorization")
    L.append("")
    if not candidates:
        L.append("_No endpoints were flagged. Every recovered call site showed authorization "
                 "evidence or inherited a bundle-wide mechanism._")
    else:
        L.append("Ranked by how little authorization evidence the client shows. "
                 "The **Observed** column reflects the Burp export where one was supplied: "
                 "`no-auth` means a captured request to this path carried neither an "
                 "authorization header nor a cookie, which is considerably stronger evidence "
                 "than the static signal alone.")
        L.append("")
        L.append("| ID | Method | Path | Why flagged | Observed | Source |")
        L.append("| --- | --- | --- | --- | --- | --- |")
        for e in candidates:
            v = e.get("auth", {}).get("verdict", "")
            why = VERDICT_PRIORITY.get(v, (9, v))[1]
            key = (e["method"].upper(), e["normalized"].split("?", 1)[0].rstrip("/"))
            o = obs.get(key)
            if o is None:
                seen = "—"
            elif o["ever_without_auth"] and not o["ever_with_auth"]:
                seen = "**no-auth**"
            elif o["ever_without_auth"]:
                seen = "mixed"
            else:
                seen = "authed"
            occ = e.get("occurrences", [{}])[0]
            src = "`%s:%s`" % (occ.get("file", "?"), occ.get("line", "?"))
            L.append("| %s | %s | `%s` | %s | %s | %s |" % (
                e["id"], e["method"], esc(e["normalized"]), esc(why), seen, src))
        L.append("")
        L.append("**Suggested test.** For each row, issue the request twice — once with the "
                 "session's credentials and once with every credential removed — and compare "
                 "status, body length and content. A response that is materially identical "
                 "without credentials is a broken access control finding. "
                 "`make_request.py --both` emits both variants ready for Repeater.")
        L.append("")

    if globals_:
        kinds = sorted({g["kind"] for g in globals_})
        L.append("### Bundle-wide authorization mechanisms")
        L.append("")
        L.append("These were found in the client code, which is why many call sites carry no "
                 "visible credential of their own — the token is attached centrally:")
        L.append("")
        for k in kinds:
            ex = next(g for g in globals_ if g["kind"] == k)
            L.append("- **%s** — `%s:%s`" % (k, ex["file"], ex["line"]))
        L.append("")
        if any(g["kind"] == "token-storage" for g in globals_):
            L.append("> A bearer token held in `localStorage`/`sessionStorage` is readable by "
                     "any script executing in the origin. Combined with any XSS in this "
                     "application, that turns into full session theft — worth stating "
                     "explicitly if a cross-site scripting issue is also confirmed.")
            L.append("")

    # --- DOM XSS ---------------------------------------------------------
    L.append("## 2. DOM-based XSS candidates")
    L.append("")
    if not dom or not dom.get("findings"):
        L.append("_No sink/source pairs were identified._")
    else:
        L.append("Confidence reflects observed evidence, not exploitability: **high** means a "
                 "source appears inside the sink's own argument, **medium** that a variable "
                 "assigned from a source reaches it. Each still needs confirmation in a browser "
                 "— a sink can be unreachable, the value can be validated server-side, or a "
                 "framework may escape it downstream.")
        L.append("")
        L.append("| Confidence | Sink | Source | Location |")
        L.append("| --- | --- | --- | --- |")
        for f in dom["findings"]:
            if f["confidence"] == "low":
                continue
            srcs = ", ".join(f["direct_sources"]) or ", ".join(
                "%s (via `%s`)" % (", ".join(v), k) for k, v in f["tainted_vars"].items()) or "—"
            L.append("| %s | `%s` | %s | `%s:%s` |" % (
                f["confidence"], f["sink"], esc(srcs), f["file"], f["line"]))
        low = [f for f in dom["findings"] if f["confidence"] == "low"]
        L.append("")
        if low:
            L.append("%d additional sink(s) were found with no visible source in scope. They are "
                     "in `%s` under `confidence: low` — worth a pass if the high and medium rows "
                     "do not pan out, since data can reach a sink from a caller or a "
                     "server-rendered value." % (len(low), os.path.basename(args.domxss or "domxss.json")))
            L.append("")

    # --- Platform surface ------------------------------------------------
    axd = inv.get("axd_references", [])
    pbs = inv.get("postback_targets", [])
    if axd or pbs:
        L.append("## 3. ASP.NET-specific surface")
        L.append("")
        if axd:
            L.append("### Resource handlers (`.axd`)")
            L.append("")
            L.append("`ScriptResource.axd` and `WebResource.axd` serve assembly-embedded "
                     "resources, keyed by an encrypted `d` parameter. They are worth attention "
                     "because they expose framework internals and, on unpatched versions, have a "
                     "history of padding-oracle and resource-disclosure issues. Confirm the "
                     "framework version before drawing conclusions.")
            L.append("")
            L.append("| Handler | Referenced from |")
            L.append("| --- | --- |")
            for a in axd[:25]:
                L.append("| `%s` | `%s:%s` |" % (a["path"], a["file"], a["line"]))
            L.append("")
        if pbs:
            L.append("### Postback and PageMethods targets")
            L.append("")
            L.append("These do not have URLs of their own — they POST to the hosting page — but "
                     "each names a server-side handler reachable by forging the postback. Check "
                     "whether the server authorizes the *action* or merely renders the control "
                     "conditionally.")
            L.append("")
            L.append("| Kind | Target | Source |")
            L.append("| --- | --- | --- |")
            for p in pbs[:25]:
                L.append("| %s | `%s` | `%s:%s` |" % (p.get("kind", "?"), esc(p["target"]),
                                                      p["file"], p["line"]))
            L.append("")

    # --- Full inventory --------------------------------------------------
    L.append("## 4. Full endpoint inventory")
    L.append("")
    shown = eps[:args.max_endpoints] if args.max_endpoints else eps
    L.append("| ID | Method | Path | Params | Auth signal | Discovered via |")
    L.append("| --- | --- | --- | --- | --- | --- |")
    for e in shown:
        params = ", ".join(p for p in e.get("params", []) if p != "concat") or "—"
        L.append("| %s | %s | `%s` | %s | %s | %s |" % (
            e["id"], e["method"], esc(e["normalized"]), esc(params),
            e.get("auth", {}).get("verdict", ""), e.get("call_kind", "")))
    if args.max_endpoints and len(eps) > args.max_endpoints:
        L.append("")
        L.append("_%d further endpoints omitted; see `%s`._" % (
            len(eps) - args.max_endpoints, os.path.basename(args.endpoints)))
    L.append("")

    # --- Limitations -----------------------------------------------------
    L.append("## 5. Method and limitations")
    L.append("")
    L.append("Endpoints were recovered by parsing client-side JavaScript, `.axd` payloads and "
             "markup for request call sites (`fetch`, `XMLHttpRequest`, jQuery AJAX, axios, "
             "Angular `HttpClient`, ASP.NET service proxies) and for endpoint-shaped string "
             "literals. Authorization signals come from headers and credential options visible "
             "at each call site, plus any bundle-wide mechanism such as an interceptor.")
    L.append("")
    L.append("Known limitations, stated so the results are not over-read:")
    L.append("")
    L.append("- **Server-side enforcement is invisible here.** Every authorization row is a "
             "hypothesis to test, not a finding.")
    L.append("- **Runtime-constructed URLs are missed.** Paths assembled from variables, "
             "configuration objects or server-injected values will not appear.")
    L.append("- **Minified and bundled code loses names**, which weakens the variable-level "
             "taint reasoning behind medium-confidence DOM XSS rows.")
    L.append("- **Dead code counts.** A bundle often ships endpoints the deployed application "
             "no longer exposes, and unreachable sinks.")
    L.append("- Coverage is bounded by the files supplied. Bundles behind authentication, "
             "lazy-loaded chunks and per-role bundles must be captured separately — a "
             "low-privilege account's bundle is the useful one for authorization testing, "
             "since anything it names that the UI never shows is a candidate.")
    L.append("")

    with open(args.out, "w", encoding="utf-8") as fh:
        fh.write("\n".join(L) + "\n")

    print("Wrote %s" % args.out)
    print("  %d endpoints, %d flagged for authorization testing" % (len(eps), len(candidates)))
    if dom:
        print("  %d DOM XSS candidates" % dom.get("finding_count", 0))
    return 0


if __name__ == "__main__":
    sys.exit(main())
