#!/usr/bin/env python3
"""Rank endpoints and parameters by testing value, and suggest concrete tests.

An endpoint inventory tells you what exists. This tells you where to start.
Parameter names are the strongest cheap signal available: a parameter called
`redirect_url` is an SSRF and open-redirect test whatever the endpoint does,
and one called `isAdmin` reaching the client at all is worth a look. Path
segments and HTTP methods add endpoint-level signal on top.

Everything here is a hypothesis generator. The suggestions say what to try and
why the name warrants trying it -- they are not claims that anything is
vulnerable, and a name is only ever circumstantial evidence about behaviour.
"""

import argparse
import json
import os
import re
import sys
from datetime import datetime, timezone

# (class, name-pattern, weight, attack, why, how)
PARAM_CLASSES = [
    ("object-reference", r"^(?:.*_)?(?:id|uid|guid|uuid|pk|key|ref|no|num|number)$|"
                         r"(?:user|account|acct|customer|client|member|case|order|invoice|doc|document|"
                         r"file|record|item|entity|profile|ticket|claim|policy|txn|transaction)[_\-]?id$|"
                         r"^(?:userid|accountid|caseid|orderid|docid|fileid)$", 5,
     "IDOR / broken object-level authorization",
     "Direct object references are the most common access-control failure in "
     "business applications, and the identifier is right there in the request.",
     "Capture a working request with your own object, then substitute an "
     "identifier belonging to another account. Sequential IDs enumerate; GUIDs "
     "usually need one leaked from elsewhere. Repeat for every HTTP method the "
     "endpoint accepts -- read is often protected where delete is not."),

    ("ssrf", r"^(?:url|uri|link|src|source|dest|destination|target|endpoint|host|hostname|domain|"
             r"site|server|addr|address|proxy|fetch|feed|callback|webhook|remote|upstream|"
             r"image[_\-]?url|img[_\-]?url|file[_\-]?url|doc[_\-]?url|next|continue|return|"
             r"return[_\-]?url|redirect|redirect[_\-]?uri|redirect[_\-]?url|goto|forward|"
             r"out|to|u|r|link[_\-]?url)$", 5,
     "SSRF and open redirect",
     "A parameter the server dereferences turns the application into a request "
     "proxy; one the browser follows turns it into a phishing redirector.",
     "For SSRF: point it at a listener you control and watch for a callback, "
     "then at cloud metadata (169.254.169.254) and internal ranges. Try scheme "
     "changes (file://, gopher://, dict://) and parser tricks "
     "(http://target@evil, http://evil#target, double URL-encoding). "
     "For open redirect: supply an external origin and see whether the 302 "
     "follows it; test protocol-relative //evil.com and javascript: too."),

    ("path-traversal", r"^(?:file|filename|filepath|path|dir|directory|folder|doc|document|"
                       r"template|tpl|page|view|include|load|read|download|attachment|"
                       r"resource|asset|report|export|name|f|p)$", 5,
     "Path traversal / local file read",
     "Parameters naming a file or template are resolved against the filesystem "
     "somewhere, and normalisation bugs there are common.",
     "Try ../ sequences at varying depth, encoded (%2e%2e%2f), double-encoded, "
     "and with a null byte where the stack is old. On Windows targets use both "
     "separators and try UNC paths. Absolute paths sometimes work where "
     "traversal is filtered. Look for a difference in error text between "
     "'not found' and 'access denied' -- that is an oracle."),

    ("sql-injection", r"^(?:q|query|search|s|filter|where|clause|sort|order|order[_\-]?by|orderby|"
                      r"group[_\-]?by|sortby|column|col|field|table|select|limit|offset|"
                      r"criteria|expression|expr|sql)$", 4,
     "SQL / NoSQL injection",
     "Names drawn from query construction usually reach a query builder, and "
     "sort/column parameters in particular are often concatenated because they "
     "cannot be parameterised.",
     "Sort and column parameters are the highest-yield: they land in ORDER BY "
     "or a projection where placeholders do not work. Test with a syntactically "
     "valid alternative first to confirm it reaches the query, then error-based "
     "and time-based payloads. For NoSQL, try operator injection "
     "({\"$ne\":null}, {\"$gt\":\"\"}) as both JSON and bracketed query syntax."),

    ("command-injection", r"^(?:cmd|command|exec|execute|run|ping|host|shell|script|"
                          r"process|task|job|action|op|operation|util|tool)$", 4,
     "OS command injection",
     "These names show up where user input reaches a shell or a process launcher.",
     "Chain with shell metacharacters (; | & $() ``), then confirm blind cases "
     "with a timing payload or an out-of-band DNS callback. Argument injection "
     "is the subtler variant -- a leading dash can change a tool's behaviour "
     "without any metacharacter surviving the filter."),

    ("template-injection", r"^(?:template|tpl|view|render|layout|theme|format|pattern|"
                           r"message|msg|body|content|text|html|description|comment|"
                           r"title|subject|label|note)$", 3,
     "SSTI and stored XSS",
     "Content parameters get rendered somewhere; if that render path is a "
     "template engine rather than an escaper, the input becomes code.",
     "Send an arithmetic probe for the engine family ({{7*7}}, ${7*7}, "
     "<%=7*7%>, #{7*7}) and look for 49 in the output. For XSS, plant a unique "
     "marker first and find every view that renders it -- including admin and "
     "log views, which frequently use different escaping than the page you "
     "submitted from."),

    ("privilege-flag", r"^(?:role|roles|is[_\-]?admin|isadmin|admin|superuser|su|priv|privilege|"
                       r"permission|permissions|perm|level|access|access[_\-]?level|scope|scopes|"
                       r"group|groups|tier|plan|type|usertype|user[_\-]?type|status|state|"
                       r"approved|verified|confirmed|enabled|active|is[_\-]?staff|owner)$", 5,
     "Mass assignment / privilege escalation",
     "A privilege-bearing field visible on the client is a field the server may "
     "bind from the request body without re-checking who is allowed to set it.",
     "Add the field to a request that legitimately updates your own object, "
     "even where the UI never sends it, and check whether it persists. Compare "
     "a response for a privileged account to find field names the client "
     "receives but never submits -- those are the candidates. Nested objects "
     "and JSON-vs-form encodings sometimes bypass a binder allowlist."),

    ("business-value", r"^(?:amount|amt|price|cost|total|subtotal|qty|quantity|count|"
                       r"discount|balance|credit|points|rate|fee|tax|currency|"
                       r"value|sum|max|min)$", 4,
     "Business logic / value tampering",
     "Money and quantity fields decided client-side are a classic and they are "
     "rarely covered by generic scanners.",
     "Try negative values, zero, extreme magnitudes, high-precision decimals, "
     "and a different currency code. Check whether the server recomputes the "
     "total or trusts the submitted one, and whether a race between two "
     "concurrent submissions double-applies a credit."),

    ("auth-material", r"^(?:token|access[_\-]?token|refresh[_\-]?token|auth|authorization|"
                      r"jwt|bearer|session|sess|sid|otp|code|pin|hash|sig|signature|"
                      r"nonce|state|csrf|xsrf|key|secret|password|passwd|pwd|api[_\-]?key)$", 5,
     "Authentication bypass / token handling",
     "Credential material in a URL or body is both an exposure (logs, referrers, "
     "history) and a place where validation is often incomplete.",
     "Remove it and see whether the request still works. Replay another "
     "session's value. Truncate or bit-flip a signature to learn whether it is "
     "verified or merely present. For OTP and reset codes, test rate limiting "
     "and whether the code is bound to the account it was issued for."),

    ("user-identity", r"^(?:email|e[_\-]?mail|username|user|login|phone|mobile|msisdn|"
                      r"ssn|nid|national[_\-]?id|dob|birthdate)$", 3,
     "User enumeration / account takeover",
     "Identity parameters drive lookup flows, and those flows leak whether an "
     "account exists far more often than they should.",
     "Compare responses for a known-good and a known-bad identity: status, body "
     "length, and timing. Then check whether the identifier can be changed to "
     "another user's on flows that should be bound to the session -- password "
     "reset, profile update, MFA enrolment."),

    ("pagination", r"^(?:limit|size|per[_\-]?page|page[_\-]?size|count|top|take|"
                   r"offset|skip|start|page|from|cursor|rows|max[_\-]?results)$", 3,
     "Mass data extraction / resource exhaustion",
     "Pagination bounds enforced only by the UI let one request return the "
     "entire table.",
     "Raise the limit far beyond what the interface offers (10000, 999999) and "
     "see whether the server caps it. A negative or zero value sometimes "
     "disables the bound entirely. Watch response time -- an uncapped limit is "
     "also a cheap denial-of-service, so confirm scope before pushing volume."),

    ("xxe", r"^(?:xml|soap|data|payload|feed|rss|xsl|xslt|doc|request|body)$", 3,
     "XXE and deserialization",
     "Structured-document parameters imply a parser, and parser defaults are "
     "unsafe more often than not.",
     "Test whether the endpoint accepts XML at all -- switching Content-Type "
     "from JSON to XML sometimes reaches a second, less-hardened parser. Then "
     "try an external entity against a listener you control, and parameter "
     "entities for the blind case. For serialized objects, identify the format "
     "from magic bytes (rO0AB for Java, base64 gASV for pickle) before going "
     "further."),

    ("jsonp-xssi", r"^(?:callback|cb|jsonp|json[_\-]?callback|wrap|prefix|"
                   r"function|fn|method[_\-]?name)$", 4,
     "JSONP / cross-site script inclusion",
     "A callback parameter reflected into a script response lets any origin "
     "read the data by including it as a script.",
     "Confirm the response is served as JavaScript and that the callback name "
     "is reflected. If the endpoint returns per-user data and relies on cookie "
     "authentication, any site can read it -- that is the finding. Also test "
     "whether the callback name is escaped, since it may be an XSS in its own "
     "right."),

    ("debug-mode", r"^(?:debug|verbose|trace|test|dev|mock|stub|sandbox|preview|draft|"
                   r"internal|admin[_\-]?mode|maintenance|bypass|skip|force|override|"
                   r"nocache|no[_\-]?auth|disable)$", 5,
     "Debug / safety-check bypass",
     "A flag whose whole purpose is to turn off a behaviour is worth trying "
     "against the behaviours you want turned off.",
     "Set it true/1/yes on requests that currently fail or that hide detail. "
     "Debug flags commonly expand error output into stack traces, disable rate "
     "limits, or skip a validation step. If the parameter name appears in the "
     "bundle but the server ignores it, note it and move on -- but check first."),

    ("content-type", r"^(?:format|output|type|ext|extension|content[_\-]?type|accept|"
                     r"mime|response[_\-]?type|alt)$", 2,
     "Response-format confusion",
     "Format switches can reach alternative serializers with different escaping "
     "and different authorization wrappers.",
     "Enumerate the accepted values (json, xml, csv, html, yaml). An XML "
     "response path may be XXE-capable; an HTML one may skip the escaping the "
     "JSON path applies; a CSV one may allow formula injection."),

    ("file-upload", r"^(?:file|upload|attachment|image|img|photo|avatar|document|"
                    r"content[_\-]?disposition|filename)$", 4,
     "Unrestricted file upload",
     "Upload handlers combine content validation, storage naming and retrieval "
     "serving -- three places to get it wrong.",
     "Test extension and content-type validation independently; they are often "
     "checked separately and inconsistently. Then check how the file is served "
     "back: an HTML or SVG file returned inline and same-origin is stored XSS "
     "regardless of what the upload filter allowed."),
]

# (signal, path-pattern, weight, note)
PATH_SIGNALS = [
    ("admin-surface",   r"/(?:admin|administrator|manage|management|console|backoffice|internal|"
                        r"staff|operator|supervisor|root|sys|system)(?:/|$)", 5,
     "An administrative path reachable from a non-administrative bundle is an "
     "authorization test with a privilege boundary already built in."),
    ("debug-surface",   r"/(?:debug|trace|test|dev|staging|mock|sandbox|_dev|__debug|"
                        r"actuator|metrics|health|status|env|info|dump|phpinfo)(?:/|$)", 5,
     "Diagnostic endpoints leak configuration, environment and sometimes "
     "credentials, and are frequently exempt from the app's auth filter."),
    ("api-docs",        r"/(?:swagger|openapi|api-docs|apidocs|graphiql|playground|"
                        r"redoc|explorer|wsdl|\$metadata)(?:/|$|\?)", 5,
     "Machine-readable API descriptions enumerate every operation, including "
     "those the client never calls. Highest-value single request in recon."),
    ("graphql",         r"/(?:graphql|gql|graph)(?:/|$)", 5,
     "Test introspection first; if it is disabled, field suggestions in error "
     "messages often rebuild the schema. Then check per-field authorization "
     "and query depth/complexity limits."),
    ("auth-flow",       r"/(?:login|signin|logout|register|signup|auth|oauth|sso|saml|oidc|"
                        r"token|refresh|password|reset|forgot|verify|mfa|otp|2fa)(?:/|$)", 4,
     "Authentication flows carry the highest-impact logic bugs: reset-token "
     "binding, state parameter handling, MFA step skipping."),
    ("data-export",     r"/(?:export|download|report|backup|dump|extract|bulk|batch|csv|"
                        r"excel|pdf|print|archive)(?:/|$)", 4,
     "Export endpoints return more data than the UI shows and often accept a "
     "wider filter than the screen offers."),
    ("file-handling",   r"/(?:upload|file|files|attachment|attachments|media|image|images|"
                        r"document|documents|blob|storage|static|content)(?:/|$)", 3,
     "File paths combine traversal, IDOR on stored objects, and content-type "
     "handling on retrieval."),
    ("user-management", r"/(?:user|users|account|accounts|profile|member|members|employee|"
                        r"customer|customers|person|people|identity)(?:/|$)", 3,
     "User collections are where IDOR and mass assignment usually land."),
    ("config-surface",  r"/(?:config|configuration|settings|setup|install|options|"
                        r"preferences|properties|env)(?:/|$)", 4,
     "Configuration endpoints disclose deployment detail and sometimes accept "
     "writes that change application behaviour."),
    # legacy-version is applied contextually in main(): flagging every /v1/ path
    # is noise when v1 is the only version. It earns its place only when the
    # inventory shows a newer version alongside it.
    ("dotnet-service",  r"\.(?:asmx|svc|ashx|axd)(?:/|$|\?)", 3,
     "ASP.NET service handlers: check per-operation authorization and whether "
     "an alternative protocol binding (SOAP, GET) skips filters."),
]

DESTRUCTIVE = {"DELETE", "PUT", "PATCH"}


def score_param(name):
    hits = []
    n = name.strip().lower()
    for cls, pat, weight, attack, why, how in PARAM_CLASSES:
        if re.search(pat, n, re.I):
            hits.append({"class": cls, "weight": weight, "attack": attack, "why": why, "how": how})
    return hits


def main():
    ap = argparse.ArgumentParser(
        description="Rank endpoints/parameters by testing value and suggest concrete tests.")
    ap.add_argument("endpoints", help="endpoints.json from extract_endpoints.py")
    ap.add_argument("--secrets", default=None, help="secrets.json from find_secrets.py")
    ap.add_argument("--out", default="attacks.json")
    ap.add_argument("--top", type=int, default=20, help="How many endpoints to print")
    args = ap.parse_args()

    if not os.path.exists(args.endpoints):
        print("Cannot read %s" % args.endpoints, file=sys.stderr)
        return 1
    with open(args.endpoints, encoding="utf-8") as fh:
        inv = json.load(fh)
    secrets = None
    if args.secrets and os.path.exists(args.secrets):
        with open(args.secrets, encoding="utf-8") as fh:
            secrets = json.load(fh)

    eps = inv.get("endpoints", [])

    # ---- parameter view -------------------------------------------------
    param_index = {}
    for e in eps:
        for p in e.get("params", []):
            if p == "concat":
                continue
            rec = param_index.setdefault(p, {"name": p, "classes": [], "endpoints": []})
            rec["endpoints"].append(e["id"])
            if not rec["classes"]:
                rec["classes"] = score_param(p)
    interesting = [r for r in param_index.values() if r["classes"]]
    for r in interesting:
        r["score"] = sum(c["weight"] for c in r["classes"])
    interesting.sort(key=lambda r: (-r["score"], r["name"]))
    other_params = sorted(r["name"] for r in param_index.values() if not r["classes"])

    # ---- endpoint view --------------------------------------------------
    # Which API versions does this application expose? An older version is only
    # interesting when a newer one exists -- that is what makes it *legacy*,
    # and legacy routes keep the authorization model they shipped with.
    versions = set()
    for e in eps:
        for v in re.findall(r"/v([0-9]+)(?=/|$)", e["normalized"]):
            versions.add(int(v))
    newest = max(versions) if versions else None
    multi_version = len(versions) > 1

    ranked = []
    for e in eps:
        signals, tests, score = [], [], 0
        path = e["normalized"]

        for sig, pat, weight, note in PATH_SIGNALS:
            if re.search(pat, path, re.I):
                signals.append({"signal": sig, "weight": weight, "note": note})
                score += weight

        if multi_version:
            mine = [int(v) for v in re.findall(r"/v([0-9]+)(?=/|$)", path)]
            if mine and max(mine) < newest:
                signals.append({"signal": "legacy-version", "weight": 3,
                                "note": "This application also exposes v%d. Older versions stay "
                                        "routed after the client moves on and retain the "
                                        "authorization model they shipped with -- compare the "
                                        "same operation across versions." % newest})
                score += 3

        verdict = e.get("auth", {}).get("verdict", "")
        if verdict in ("explicit_no_credentials", "no_auth_indicator"):
            score += 4
            tests.append({
                "attack": "Unauthenticated access",
                "why": "The client attaches no credential here (%s)." % verdict,
                "how": "Send the request with every credential removed and compare status, "
                       "body length and content against the authenticated response. "
                       "make_request.py --both emits the pair.",
            })
        elif verdict == "unknown_no_callsite":
            score += 1

        if e.get("method", "").upper() in DESTRUCTIVE:
            score += 3
            tests.append({
                "attack": "Method-level authorization",
                "why": "%s is state-changing; read access is often protected where "
                       "write and delete are not." % e["method"],
                "how": "Confirm the endpoint enforces authorization on this verb "
                       "specifically, then try verb tampering: override with "
                       "X-HTTP-Method-Override, or send the same action as POST if "
                       "the framework accepts it.",
            })

        if e.get("call_kind") == "websocket":
            score += 3
            tests.append({
                "attack": "WebSocket origin and authorization",
                "why": "WebSocket handshakes are not covered by CORS, so origin checking "
                       "is the server's job and is frequently skipped.",
                "how": "Replay the handshake from an unrelated Origin. If it upgrades, "
                       "cross-site WebSocket hijacking reads the victim's stream. Then "
                       "check whether per-message authorization exists or only the "
                       "handshake is authenticated.",
            })

        if e.get("call_kind") == "wcf-proxy":
            score += 2
            tests.append({
                "attack": "Service metadata and protocol switching",
                "why": "ASMX/WCF services publish their contract and accept several bindings.",
                "how": "Request the service root and ?WSDL for the full operation list, then "
                       "call an operation the client never uses. Try SOAP and GET bindings "
                       "against an operation that is filtered over JSON POST.",
            })

        # A path segment the client filled from a variable is an object
        # reference even though it has no parameter name. Path-based IDOR is
        # the most common shape of the bug, so it must not depend on the
        # identifier happening to appear as a named query parameter.
        if re.search(r"\{(?:param|id|guid|concat)\}", path):
            score += 5
            tests.append({
                "attack": "IDOR / broken object-level authorization",
                "parameter": "path segment",
                "why": "The client substitutes a value into the path, so the request "
                       "carries a direct object reference.",
                "how": "Request an object belonging to your own account to establish a "
                       "working baseline, then substitute an identifier owned by another "
                       "account. Sequential values enumerate directly; GUIDs usually need "
                       "one leaked from a listing endpoint. Test every method the endpoint "
                       "accepts -- read is often authorized where write and delete are not.",
            })

        for p in e.get("params", []):
            for c in score_param(p):
                score += c["weight"]
                tests.append({
                    "attack": c["attack"],
                    "parameter": p,
                    "why": c["why"],
                    "how": c["how"],
                })

        for s in signals:
            tests.append({"attack": s["signal"], "why": s["note"],
                          "how": "Request it directly, authenticated and not, and compare."})

        # De-duplicate by (attack, parameter) while preserving order.
        seen, uniq = set(), []
        for t in tests:
            k = (t["attack"], t.get("parameter"))
            if k not in seen:
                seen.add(k)
                uniq.append(t)

        ranked.append({
            "id": e["id"], "method": e["method"], "path": path,
            "auth_verdict": verdict, "score": score,
            "signals": [s["signal"] for s in signals],
            "suggested_tests": uniq,
            "repeater": "make_request.py endpoints.json --id %s --both" % e["id"],
        })

    ranked.sort(key=lambda r: (-r["score"], r["path"]))

    secret_notes = []
    if secrets:
        tiers = secrets.get("by_tier", {})
        if tiers.get("confirmed") or tiers.get("probable"):
            secret_notes.append(
                "Credentials were recovered from the client bundle. Test each against the "
                "service it belongs to to establish whether it is live and what it grants "
                "-- an unused key is a low finding, a working one is not.")
        for f in secrets.get("findings", []):
            if f.get("kind") == "jwt" and f.get("jwt"):
                for n in f["jwt"].get("notes", []):
                    if "alg=none" in n or "HMAC" in n:
                        secret_notes.append("JWT in %s:%s -- %s" % (f["file"], f["line"], n))
            if f.get("kind") == "source-map-ref":
                secret_notes.append(
                    "Source map referenced at %s:%s. If it is served, it reconstructs original "
                    "sources including comments and unminified names -- re-run the extractor "
                    "over the recovered sources." % (f["file"], f["line"]))

    out = {
        "generated": datetime.now(timezone.utc).isoformat(),
        "endpoint_count": len(eps),
        "interesting_parameters": interesting,
        "uncategorised_parameters": other_params,
        "endpoints": ranked,
        "secret_notes": sorted(set(secret_notes)),
    }
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=2)

    print("Ranked %d endpoints; %d parameters matched an attack class" % (len(ranked), len(interesting)))
    print()
    print("Top parameters:")
    for r in interesting[:12]:
        print("  %-22s %-3d %s" % (r["name"][:22], r["score"],
                                   ", ".join(c["class"] for c in r["classes"])))
    print()
    print("Top endpoints:")
    for r in ranked[:args.top]:
        if r["score"] <= 0:
            continue
        print("  %-5s %-3d %-7s %-44s %s" % (r["id"], r["score"], r["method"],
                                             r["path"][:44], ",".join(r["signals"]) or "-"))
    for n in out["secret_notes"]:
        print("\n  ! %s" % n)
    print("\nWrote %s" % args.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
