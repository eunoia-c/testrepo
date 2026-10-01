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

# ---------------------------------------------------- feature flags and config
#
# A regex inventory of endpoints answers "what can I call". It does not answer
# "what is switched off in this build" -- and a flag defaulting to false is a
# feature whose UI is hidden while its server-side endpoints are frequently
# already live and unprotected. Flipping the flag in the browser is a one-line
# change; the endpoints behind it are the actual finding.

FLAG_PROVIDERS = [
    ("LaunchDarkly", re.compile(r"launchdarkly|LDClient|ldclient", re.I)),
    ("Split.io", re.compile(r"splitio|SplitFactory|getTreatment\s*\(", re.I)),
    ("Optimizely", re.compile(r"optimizely", re.I)),
    ("Unleash", re.compile(r"unleash", re.I)),
    ("GrowthBook", re.compile(r"growthbook", re.I)),
    ("Flagsmith", re.compile(r"flagsmith", re.I)),
    ("ConfigCat", re.compile(r"configcat", re.I)),
    ("Statsig", re.compile(r"statsig", re.I)),
    ("PostHog flags", re.compile(r"isFeatureEnabled\s*\(|posthog", re.I)),
]

# `!0` and `!1` are what minifiers emit for true and false, so a bundle's flags
# are invisible without them.
FLAG_ASSIGN_RE = re.compile(
    r"""["']?(?P<name>
          (?:enable|disable|allow|show|hide|use|is|has|can|should)[A-Z][\w$]{2,40}
        | [A-Z][A-Z0-9]{2,}(?:_[A-Z0-9]+){1,6}
        | [\w$]*(?:[Ff]lag|[Tt]oggle|[Ff]eature|[Ee]xperiment|[Bb]eta|[Rr]ollout)[\w$]*
        )["']?\s*[:=]\s*(?P<value>true|false|!0|!1)(?![\w$])""",
    re.X)

CONFIG_BLOB_RE = re.compile(
    r"(?:window|globalThis|self)\s*\.\s*(?P<name>__[A-Z_]+__|[A-Z][A-Z0-9_]{2,40}|"
    r"(?:app|site|env|runtime|client)Config)\s*=\s*\{", re.I)

FLAG_NAME_NOISE = {"true", "false", "isarray", "isnan", "isinteger", "isfinite",
                   "isprototypeof", "hasownproperty", "useState", "useEffect",
                   "useMemo", "useRef", "useCallback", "isview", "isbuffer"}


def normalise_bool(raw: str) -> bool:
    return raw in ("true", "!0")


def feature_flags(text):
    """(providers, flags) where flags is [(name, default_bool, line_hint)]."""
    providers = [name for name, pat in FLAG_PROVIDERS if pat.search(text)]
    flags: dict[str, bool] = {}
    for m in FLAG_ASSIGN_RE.finditer(text):
        name = m.group("name")
        if name.lower() in FLAG_NAME_NOISE or len(name) < 4:
            continue
        # First definition wins; a later override is usually test setup.
        flags.setdefault(name, normalise_bool(m.group("value")))
    configs = sorted({m.group("name") for m in CONFIG_BLOB_RE.finditer(text)})
    return providers, flags, configs


# ------------------------------------------------------------- key scope
#
# Detecting a key is half the job. What it grants decides whether it is a
# finding at all: a Stripe publishable key is *designed* to sit in client code,
# while a secret key beside it is an incident. Scope is the part a format match
# cannot tell you, so it is stated per provider rather than assumed.

KEY_SCOPE = {
    "aws-access-key-id": (
        "critical",
        "Long-lived IAM credentials. Permissions come entirely from the attached "
        "policy, so confirm with sts:GetCallerIdentity and check what it actually "
        "reaches rather than assuming either way."),
    "google-api-key": (
        "depends",
        "Scope is set by the key's API and HTTP-referrer restrictions in GCP, not by "
        "the key string. An unrestricted key means billable abuse and sometimes data "
        "access; a referrer-locked Maps key in client code is by design and is not a "
        "finding. Check the restrictions before reporting."),
    "google-oauth-client-id": (
        "low",
        "A public client identifier, intended to be visible. Interesting only for "
        "the redirect-URI configuration it points at."),
    "github-token": (
        "depends",
        "A fine-grained token may be read-only on one repository; a classic token "
        "with `repo` scope grants write to every repository the user can reach. The "
        "scope is not visible in the token string -- check /user and the "
        "X-OAuth-Scopes response header."),
    "github-fine-grained-pat": (
        "depends",
        "Scoped per repository and per permission at creation. Enumerate before "
        "assuming reach."),
    "gitlab-token": ("depends", "Scope is set at creation and not visible in the token."),
    "slack-token": (
        "high",
        "xoxb is a bot token, xoxp a user token carrying that user's access. Either "
        "reads channel history where the workspace permits it; auth.test identifies "
        "which."),
    "slack-webhook": (
        "medium",
        "Post-only into one channel. Not a read primitive -- useful for spoofing "
        "internal messages, not for extraction."),
    "stripe-secret-key": (
        "critical",
        "A secret server key must never reach client code. Note the contrast: a pk_ "
        "publishable key in the same bundle is by design and is not a finding."),
    "stripe-test-key": (
        "medium",
        "Test-mode key: no live money or customer data. Report as hygiene, and check "
        "whether the live equivalent is built the same way."),
    "twilio-api-key": ("high", "Can send messages and read logs that may contain OTPs."),
    "twilio-account-sid": (
        "low", "An account identifier, not a credential. Only useful paired with a token."),
    "sendgrid-key": ("high", "Send-as-the-domain, and often read access to suppression data."),
    "openai-key": ("high", "Billable, and usable against any model the account can reach."),
    "anthropic-key": ("high", "Billable, and usable against any model the account can reach."),
    "mapbox-secret-token": (
        "high", "An sk. token is a secret token, unlike the pk. form that belongs in clients."),
    "private-key-block": (
        "critical",
        "A private key delivered to clients is compromised by definition, whatever "
        "it signs."),
    "azure-storage-key": ("critical", "Full control of the storage account."),
    "basic-auth-in-url": ("critical", "Credentials in a URL, also logged by every proxy in the path."),
    "db-connection-string": ("critical", "Direct database credentials."),
    "dotnet-connection-string": ("critical", "Direct database credentials."),
    "firebase-cloud-messaging": ("high", "Can push notifications to every app install."),
    "jwt": (
        "depends",
        "The value is in the claims, not the token: subject, roles or scopes "
        "asserted, and whether it has expired. Decode before judging."),
}

# Formats that belong in client code by design. They are still listed -- a
# Google key with no referrer restriction is a real finding -- but they are kept
# out of the credential tally, because "8 credentials found" where six are
# publishable keys is the kind of number that gets a whole report dismissed.
EXPECTED_PUBLIC = re.compile(
    r"^(?:pk_(?:live|test)_|AIzaSy|G-[A-Z0-9]{8,}|UA-\d+-\d+|phc_)")


def by_design_public(finding):
    return bool(EXPECTED_PUBLIC.match(str(finding.get("value") or "")))


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


def _wrap(text, width):
    out, line = [], ""
    for word in text.split():
        if len(line) + len(word) + 1 > width:
            out.append(line)
            line = word
        else:
            line = (line + " " + word).strip()
    if line:
        out.append(line)
    return out


def human_bytes(n):
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return "%.0f %s" % (n, unit) if unit != "B" else "%d B" % n
        n /= 1024.0


def flag_gated_endpoints(flags, eps):
    """Endpoints whose path echoes a flag that is off in this build.

    This is the join worth making. A flag defaulting to false hides a feature in
    the UI; it says nothing about whether the server-side route behind it is
    deployed or protected. Where the names line up, the endpoint is reachable
    now and the flag is only hiding the button."""
    off = [n for n, v in (flags or {}).items() if not v]
    if not off:
        return []
    pairs = []
    for name in off:
        # Split camelCase and SNAKE_CASE into words long enough to be meaningful.
        words = [w.lower() for w in re.findall(r"[A-Z]+(?![a-z])|[A-Z][a-z]+|[a-z]+|[0-9]+", name)
                 if len(w) >= 4 and w.lower() not in
                 ("enable", "disable", "allow", "show", "hide", "flag", "feature",
                  "toggle", "rollout", "beta", "should")]
        if not words:
            continue
        for e in (eps or {}).get("endpoints", []):
            path = e["normalized"].lower()
            if any(w in path for w in words):
                pairs.append((name, e["method"], e["normalized"],
                              e.get("auth", {}).get("verdict", "")))
                break
    return pairs


def observations(meta, fp, eps, secrets, dom, flags=None):
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

    gated = flag_gated_endpoints(flags, eps)
    if gated:
        lines = ", ".join("%s -> %s %s" % (n, m, p) for n, m, p, _v in gated[:3])
        unauth = [g for g in gated if g[3] in ("no_auth_indicator", "explicit_no_credentials")]
        note = (" %d of them show no authorization evidence, so the route is reachable "
                "now and the flag is only hiding the button." % len(unauth)) if unauth else ""
        out.append(
            "%d endpoint%s match a feature flag that is OFF in this build (%s).%s Flipping "
            "a client-side flag is a one-line change in the browser; whether the "
            "server-side route is deployed and protected is a separate question, and "
            "this is where to ask it."
            % (len(gated), "" if len(gated) == 1 else "s", lines, note))

    if advisories:
        out.append(
            "%d third-party librar%s below a version with published advisories. These "
            "are concrete, checkable findings; confirm the version is really the one "
            "loaded at runtime before reporting."
            % (len(advisories), "y is" if len(advisories) == 1 else "ies are"))

    confirmed = [f for f in (secrets or {}).get("findings", [])
                 if f["tier"] == "confirmed" and not by_design_public(f)]
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
    providers, flags, configs = feature_flags(text)

    eps, e_err = run_json("extract_endpoints.py", [args.path])
    secrets, s_err = run_json("find_secrets.py", [args.path, "--min-tier", "info"])
    dom, d_err = run_json("dom_xss_scan.py", [args.path])

    if args.as_json:
        payload = {
            "file": os.path.abspath(args.path),
            "characteristics": meta,
            "bundlers": bundlers, "frameworks": frameworks,
            "library_versions": {k: sorted(v) for k, v in versions.items()},
            "feature_flags": {"providers": providers,
                              "flags": [{"name": n, "default": v} for n, v in sorted(flags.items())],
                              "config_objects": configs},
            "advisories": [{"library": a, "version": b, "fixed_in": c, "issue": d}
                           for a, b, c, d in advisories],
            "endpoints": (eps or {}).get("endpoints", []),
            "global_auth_mechanisms": (eps or {}).get("global_auth_mechanisms", []),
            "secrets": [dict(f, by_design_public=by_design_public(f))
                        for f in (secrets or {}).get("findings", [])],
            "dom_xss": (dom or {}).get("findings", []),
            "observations": observations(meta, fp, eps, secrets, dom, flags),
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

        if providers or flags or configs:
            off = sorted(n for n, v in flags.items() if not v)
            on = sorted(n for n, v in flags.items() if v)
            L.append("")
            L.append("FEATURE FLAGS AND CLIENT CONFIG")
            if providers:
                L.append("  provider: %s" % ", ".join(providers))
            if configs:
                L.append("  config object(s): %s" % ", ".join(configs))
            if off:
                L.append("  off in this build (%d) — the interesting half:" % len(off))
                for name in off[:20]:
                    L.append("    - %s" % name)
                if len(off) > 20:
                    L.append("    ... %d more" % (len(off) - 20))
            if on:
                L.append("  on (%d): %s%s" % (
                    len(on), ", ".join(on[:12]), " ..." if len(on) > 12 else ""))

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
        real = [f for f in sfind
                if f["tier"] in ("confirmed", "probable") and not by_design_public(f)]
        public = [f for f in sfind
                  if f["tier"] in ("confirmed", "probable") and by_design_public(f)]
        info = [f for f in sfind if f["tier"] == "info"]
        L.append("")
        L.append("SECRETS AND DISCLOSURES (%d credential-shaped, %d informational)"
                 % (len(real), len(info)))
        for f in real[:15]:
            L.append("  %-10s %-26s %s  (line %s)" % (f["tier"], f["kind"][:26],
                                                      str(f["value"])[:34], f["line"]))
            scope = KEY_SCOPE.get(f.get("format") or f["kind"])
            if scope:
                for i, chunk in enumerate(_wrap(scope[1], 68)):
                    prefix = "             scope [%s]: " % scope[0] if i == 0 else "               "
                    L.append(prefix + chunk)
        for f in info[:10]:
            extra = ""
            if f.get("jwt", {}).get("notes"):
                extra = " — " + "; ".join(f["jwt"]["notes"][:2])
            L.append("  info       %-26s %s%s" % (f["kind"][:26], str(f["value"])[:34], extra))
            scope = KEY_SCOPE.get(f.get("format") or f["kind"])
            if scope:
                for i, chunk in enumerate(_wrap(scope[1], 68)):
                    prefix = "             scope [%s]: " % scope[0] if i == 0 else "               "
                    L.append(prefix + chunk)
        for f in public[:10]:
            L.append("  public     %-26s %s  (line %s)" % (f["kind"][:26],
                                                           str(f["value"])[:34], f["line"]))
            scope = KEY_SCOPE.get(f.get("format") or f["kind"])
            if scope:
                for i, chunk in enumerate(_wrap(scope[1], 68)):
                    prefix = "             scope [%s]: " % scope[0] if i == 0 else "               "
                    L.append(prefix + chunk)
        if public:
            L.append("  The `public` rows are formats that belong in client code; they are")
            L.append("  listed for completeness and excluded from the count above. Each is")
            L.append("  only a finding if its restrictions are missing -- check, do not assume.")
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

        obs = observations(meta, fp, eps, secrets, dom, flags)
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
