#!/usr/bin/env python3
"""Deep-dive a single JavaScript file and report what it is and what matters.

The rest of this toolkit answers "what is the whole attack surface". This
answers a different question: "here is one file -- what can you tell me about
it". So the output is a briefing meant to be read, not JSON meant to be joined,
and it leads with what the file *is* before listing what was found in it.

Two things this adds over running the other scripts separately:

  Fingerprinting -- bundler, framework, and third-party library versions. On a
  single vendor bundle that is often the finding, because an outdated library
  with published advisories is concrete in a way that "this path had no
  Authorization header" is not.

  Cross-cutting observations -- a bearer token in localStorage is unremarkable,
  and an innerHTML sink is unremarkable, but both in one file is a session-theft
  chain. Those joins are the point of looking at a file as a whole.

Reads a file on disk; never contacts a target.
"""

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))

# ---------------------------------------------------------------- fingerprints

BUNDLERS = [
    ("webpack",       re.compile(r"__webpack_require__|webpackJsonp|webpackChunk")),
    ("rollup",        re.compile(r"\bROLLUP_ASSET_URL|rollup:")),
    ("parcel",        re.compile(r"\bparcelRequire\b")),
    ("browserify",    re.compile(r"\brequire=function\s*\(\s*[a-z],\s*[a-z],\s*[a-z]\s*\)")),
    ("vite",          re.compile(r"__vite__|/@vite/client")),
    ("systemjs",      re.compile(r"\bSystem\.register\s*\(")),
    ("requirejs/amd", re.compile(r"\bdefine\.amd\b")),
    ("esbuild",       re.compile(r"__toCommonJS|__esbuild")),
]

FRAMEWORKS = [
    ("React",     re.compile(r"__REACT_DEVTOOLS_GLOBAL_HOOK__|react-dom|createElementWithValidation|\breactRootContainer\b")),
    ("Angular",   re.compile(r"@angular/core|ng\.probe|ɵɵdefineComponent|platformBrowserDynamic")),
    ("AngularJS", re.compile(r"angular\.module\s*\(|ng-app|\$scope\b|angular\.version")),
    ("Vue",       re.compile(r"__VUE_DEVTOOLS_GLOBAL_HOOK__|Vue\.config|createElementVNode")),
    ("jQuery",    re.compile(r"jQuery\.fn\.jquery|\$\.fn\.jquery")),
    ("Ext JS",    re.compile(r"\bExt\.define\s*\(|Ext\.onReady")),
    ("Dojo",      re.compile(r"\bdojo\.require\b|dojoConfig")),
    ("Backbone",  re.compile(r"Backbone\.(?:Model|View|Router)\.extend")),
    ("Knockout",  re.compile(r"\bko\.observable\b|knockout")),
    ("Pega UI",   re.compile(r"\bpega\b.{0,40}\b(?:pzHarnessID|pyActivity|pzInsKey)|PRServlet", re.I)),
    ("ASP.NET AJAX", re.compile(r"Sys\.Application|Sys\.WebForms|Sys\.Net\.WebServiceProxy")),
]

# Version extraction. Banner comments are the most reliable source in bundled
# vendor code; the rest are library-specific assignments.
VERSION_PATTERNS = [
    ("banner",  re.compile(r"/\*!?\s*(?P<name>[A-Za-z][\w.\-]{1,30}(?:\.js)?)\s+v?(?P<ver>\d+\.\d+(?:\.\d+)?)")),
    ("jquery",  re.compile(r"(?:jQuery\.fn\.jquery|\$\.fn\.jquery)\s*=\s*[\"'](?P<ver>\d+\.\d+(?:\.\d+)?)")),
    ("jquery2", re.compile(r"\bjquery[\"']?\s*[:=]\s*[\"'](?P<ver>\d+\.\d+\.\d+)")),
    ("angularjs", re.compile(r"full\s*:\s*[\"'](?P<ver>\d+\.\d+\.\d+)[\"']\s*,\s*major")),
    ("lodash",  re.compile(r"lodash[@/\-\s]+v?(?P<ver>\d+\.\d+\.\d+)")),
    ("moment",  re.compile(r"(?:hooks|moment)\.version\s*=\s*[\"'](?P<ver>\d+\.\d+\.\d+)")),
    ("bootstrap", re.compile(r"bootstrap[@/\-\s]+v?(?P<ver>\d+\.\d+\.\d+)", re.I)),
    ("pkg",     re.compile(r"[\"'](?P<name>[a-z][\w.\-]{2,30})@(?P<ver>\d+\.\d+\.\d+)[\"']")),
]

# Libraries with well-known advisories below a given version. Deliberately
# short: a wrong or stale entry here costs more credibility than a missing one,
# so it only carries issues that are widely documented and easy to verify.
KNOWN_ADVISORIES = [
    ("jquery",    (3, 5, 0),  "XSS via htmlPrefilter (CVE-2020-11022 / CVE-2020-11023)"),
    ("jquery",    (3, 0, 0),  "multiple XSS and prototype issues in 1.x/2.x"),
    ("lodash",    (4, 17, 21), "prototype pollution; command injection in _.template (CVE-2021-23337)"),
    ("moment",    (2, 29, 4), "path traversal in locale loading (CVE-2022-24785) and ReDoS"),
    ("bootstrap", (3, 4, 1),  "XSS in tooltip/popover data-template (3.x line)"),
    ("bootstrap", (4, 3, 1),  "XSS in tooltip/popover data-template (4.x line)"),
    ("handlebars", (4, 7, 7), "prototype pollution leading to RCE in some configurations"),
    ("angular",   (1, 8, 3),  "AngularJS 1.x is end-of-life; template injection and known bypasses"),
]

NOISE_NAMES = {"the", "this", "license", "copyright", "version", "js", "min", "eslint", "prettier"}


def parse_version(v):
    parts = [int(x) for x in re.findall(r"\d+", v)[:3]]
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts)


def fingerprint(text):
    bundlers = [n for n, p in BUNDLERS if p.search(text)]
    frameworks = [n for n, p in FRAMEWORKS if p.search(text)]

    versions = {}
    for kind, pat in VERSION_PATTERNS:
        for m in pat.finditer(text):
            gd = m.groupdict()
            name = (gd.get("name") or kind).lower().replace(".js", "")
            name = re.sub(r"^(?:jquery\d?|angularjs)$", lambda mm: mm.group(0).rstrip("2"), name)
            if name in NOISE_NAMES or len(name) < 3:
                continue
            ver = gd.get("ver")
            if not ver:
                continue
            versions.setdefault(name, set()).add(ver)

    advisories = []
    for name, vers in versions.items():
        for v in vers:
            for lib, ceiling, note in KNOWN_ADVISORIES:
                if name.startswith(lib) and parse_version(v) < ceiling:
                    advisories.append((name, v, "%d.%d.%d" % ceiling, note))
    return bundlers, frameworks, versions, advisories


def characterise(path, text):
    size = len(text.encode("utf-8", "replace"))
    lines = text.count("\n") + 1
    longest = max((len(l) for l in text.split("\n")), default=0)
    minified = longest > 500 and (size / max(lines, 1)) > 200
    return {
        "bytes": size,
        "lines": lines,
        "longest_line": longest,
        "minified": minified,
        "has_source_map": bool(re.search(r"//[#@]\s*sourceMappingURL", text)),
    }


def run_json(script, args):
    """Run a sibling script that writes JSON, and return the parsed result."""
    fd, out = tempfile.mkstemp(suffix=".json")
    os.close(fd)
    try:
        r = subprocess.run([sys.executable, os.path.join(HERE, script)] + args + ["--out", out],
                           capture_output=True, text=True)
        if r.returncode != 0 or not os.path.exists(out):
            return None, (r.stderr or "").strip()
        with open(out, encoding="utf-8") as fh:
            return json.load(fh), None
    finally:
        if os.path.exists(out):
            os.unlink(out)


def human_bytes(n):
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return "%.0f %s" % (n, unit) if unit != "B" else "%d B" % n
        n /= 1024.0


def observations(meta, fp, eps, secrets, dom):
    """Joins across the individual results. These are the reason to look at a
    file as a whole rather than at four separate reports."""
    out = []
    bundlers, frameworks, versions, advisories = fp

    token_storage = any(g["kind"] == "token-storage"
                        for g in (eps or {}).get("global_auth_mechanisms", []))
    html_sinks = [f for f in (dom or {}).get("findings", [])
                  if f["category"] in ("html", "exec") and f["confidence"] != "low"]
    if token_storage and html_sinks:
        out.append(
            "A bearer token is read from web storage AND there %s %d script/HTML "
            "sink%s with a reachable source in this file. Script executing in this "
            "origin can read that token, so an XSS here is session theft rather "
            "than a defacement -- state the two together in the report."
            % ("is" if len(html_sinks) == 1 else "are", len(html_sinks),
               "" if len(html_sinks) == 1 else "s"))

    admin = [e for e in (eps or {}).get("endpoints", [])
             if re.search(r"/(?:admin|internal|manage|backoffice|sys)(?:/|$)", e["normalized"], re.I)]
    if admin:
        out.append(
            "%d administrative endpoint%s appear%s in this bundle (%s). If this file "
            "is served to non-administrative users, each is an authorization test "
            "with the privilege boundary already identified."
            % (len(admin), "" if len(admin) == 1 else "s", "s" if len(admin) == 1 else "",
               ", ".join(e["normalized"] for e in admin[:3])))

    versions_seen = {int(v) for e in (eps or {}).get("endpoints", [])
                     for v in re.findall(r"/v(\d+)(?=/|$)", e["normalized"])}
    if len(versions_seen) > 1:
        out.append(
            "Endpoints span API versions %s. Older versions usually stay routed after "
            "the client moves on and keep the authorization model they shipped with -- "
            "compare the same operation across versions."
            % ", ".join("v%d" % v for v in sorted(versions_seen)))

    if meta["has_source_map"]:
        out.append(
            "A source map is referenced. If the .map is actually served, it "
            "reconstructs the original source with comments and real names -- fetch "
            "it and re-run this analysis over the result before doing anything else.")

    if advisories:
        out.append(
            "%d third-party librar%s below a version with published advisories. These "
            "are concrete, checkable findings; confirm the version is really the one "
            "loaded at runtime before reporting."
            % (len(advisories), "y is" if len(advisories) == 1 else "ies are"))

    confirmed = [f for f in (secrets or {}).get("findings", []) if f["tier"] == "confirmed"]
    if confirmed:
        out.append(
            "%d credential%s in provider-specific format. Establish whether each is "
            "live before reporting -- and if one is, tell the client immediately "
            "rather than at delivery." % (len(confirmed), "" if len(confirmed) == 1 else "s"))

    no_auth = [e for e in (eps or {}).get("endpoints", [])
               if e["auth"]["verdict"] in ("explicit_no_credentials", "no_auth_indicator")]
    if no_auth and not (eps or {}).get("global_auth_mechanisms"):
        out.append(
            "No bundle-wide auth mechanism was found, and %d endpoint%s show no "
            "credential at the call site. Either authentication is by cookie alone, "
            "or these are genuinely unauthenticated -- worth settling early since it "
            "changes how you read every other endpoint here."
            % (len(no_auth), "" if len(no_auth) == 1 else "s"))

    return out


def main():
    ap = argparse.ArgumentParser(
        description="Deep-dive one JavaScript file: what it is, and what matters in it.")
    ap.add_argument("path", help="The .js / .axd / .html file to analyse")
    ap.add_argument("--json", dest="as_json", action="store_true", help="Emit JSON instead of a briefing")
    ap.add_argument("--out", default=None, help="Write the briefing (or JSON) to this file")
    args = ap.parse_args()

    if not os.path.isfile(args.path):
        print("Not a file: %s" % args.path, file=sys.stderr)
        return 1

    with open(args.path, encoding="utf-8", errors="replace") as fh:
        text = fh.read()

    meta = characterise(args.path, text)
    fp = fingerprint(text)
    bundlers, frameworks, versions, advisories = fp

    eps, e_err = run_json("extract_endpoints.py", [args.path])
    secrets, s_err = run_json("find_secrets.py", [args.path, "--min-tier", "info"])
    dom, d_err = run_json("dom_xss_scan.py", [args.path])

    if args.as_json:
        payload = {
            "file": os.path.abspath(args.path),
            "characteristics": meta,
            "bundlers": bundlers, "frameworks": frameworks,
            "library_versions": {k: sorted(v) for k, v in versions.items()},
            "advisories": [{"library": a, "version": b, "fixed_in": c, "issue": d}
                           for a, b, c, d in advisories],
            "endpoints": (eps or {}).get("endpoints", []),
            "global_auth_mechanisms": (eps or {}).get("global_auth_mechanisms", []),
            "secrets": (secrets or {}).get("findings", []),
            "dom_xss": (dom or {}).get("findings", []),
            "observations": observations(meta, fp, eps, secrets, dom),
        }
        text_out = json.dumps(payload, indent=2)
    else:
        L = []
        name = os.path.basename(args.path)
        L.append("=" * 74)
        L.append("  %s" % name)
        L.append("  %s · %s · %s line%s" % (
            human_bytes(meta["bytes"]),
            "minified" if meta["minified"] else "readable",
            "{:,}".format(meta["lines"]), "" if meta["lines"] == 1 else "s"))
        L.append("=" * 74)

        L.append("")
        L.append("WHAT THIS FILE IS")
        bits = []
        if bundlers:
            bits.append("%s bundle" % "/".join(bundlers))
        if frameworks:
            bits.append("uses " + ", ".join(frameworks))
        L.append("  %s" % ("; ".join(bits) if bits else
                           "No bundler or framework fingerprint -- likely hand-written page script."))
        if (eps or {}).get("global_auth_mechanisms"):
            kinds = sorted({g["kind"] for g in eps["global_auth_mechanisms"]})
            L.append("  Auth wiring: %s" % ", ".join(kinds))
        if meta["has_source_map"]:
            L.append("  References a source map.")

        if versions:
            L.append("")
            L.append("LIBRARY VERSIONS")
            flagged = {a[0] for a in advisories}
            for lib in sorted(versions):
                mark = " !" if lib in flagged else "  "
                L.append("  %s %-22s %s" % (mark, lib, ", ".join(sorted(versions[lib]))))
            if advisories:
                L.append("")
                for lib, ver, fixed, note in advisories:
                    L.append("  ! %s %s — advisories below %s: %s" % (lib, ver, fixed, note))
                L.append("    Confirm the version actually loaded at runtime before reporting;")
                L.append("    bundles frequently ship a version string that a shim then replaces.")

        endpoints = (eps or {}).get("endpoints", [])
        L.append("")
        L.append("ENDPOINTS (%d)" % len(endpoints))
        if not endpoints:
            L.append("  None recovered." + (" [%s]" % e_err if e_err else ""))
        else:
            for e in endpoints[:30]:
                L.append("  %-7s %-46s %s" % (e["method"], e["normalized"][:46],
                                              e["auth"]["verdict"]))
            if len(endpoints) > 30:
                L.append("  ... %d more" % (len(endpoints) - 30))

        sfind = (secrets or {}).get("findings", [])
        real = [f for f in sfind if f["tier"] in ("confirmed", "probable")]
        info = [f for f in sfind if f["tier"] == "info"]
        L.append("")
        L.append("SECRETS AND DISCLOSURES (%d credential-shaped, %d informational)"
                 % (len(real), len(info)))
        for f in real[:15]:
            L.append("  %-10s %-26s %s  (line %s)" % (f["tier"], f["kind"][:26],
                                                      str(f["value"])[:34], f["line"]))
        for f in info[:10]:
            extra = ""
            if f.get("jwt", {}).get("notes"):
                extra = " — " + "; ".join(f["jwt"]["notes"][:2])
            L.append("  info       %-26s %s%s" % (f["kind"][:26], str(f["value"])[:34], extra))
        if not sfind:
            L.append("  None found." + (" [%s]" % s_err if s_err else ""))

        dfind = [f for f in (dom or {}).get("findings", []) if f["confidence"] != "low"]
        L.append("")
        L.append("DOM XSS CANDIDATES (%d above low confidence)" % len(dfind))
        for f in dfind[:15]:
            src = ", ".join(f["direct_sources"]) or ", ".join(f["tainted_vars"]) or "—"
            L.append("  %-9s %-24s %-30s line %s" % (f["confidence"][:9], f["sink"][:24],
                                                     src[:30], f["line"]))
        if not dfind:
            L.append("  None above low confidence." + (" [%s]" % d_err if d_err else ""))

        obs = observations(meta, fp, eps, secrets, dom)
        if obs:
            L.append("")
            L.append("WHAT STANDS OUT")
            for o in obs:
                wrapped, line = [], "  - "
                for word in o.split():
                    if len(line) + len(word) + 1 > 74:
                        wrapped.append(line)
                        line = "    " + word
                    else:
                        line += ("" if line.endswith(("- ", "    ")) else " ") + word
                wrapped.append(line)
                L.extend(wrapped)

        L.append("")
        L.append("-" * 74)
        L.append("Static analysis: evidence about attack surface, not about server-side")
        L.append("enforcement. Everything above is a candidate to confirm against the")
        L.append("running application.")
        if meta["minified"]:
            L.append("This file is minified, so identifier names are lost -- variable-level")
            L.append("reasoning is weaker here than the confidence labels suggest.")
        text_out = "\n".join(L)

    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text_out + "\n")
        print("Wrote %s" % args.out)
    else:
        print(text_out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
