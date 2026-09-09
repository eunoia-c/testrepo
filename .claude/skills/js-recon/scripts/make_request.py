#!/usr/bin/env python3
"""Emit raw HTTP requests ready to paste into Burp Repeater.

Raw HTTP, not curl: Repeater takes a pasted request verbatim, so the output has
to be a well-formed message with correct CRLF line endings and a Content-Length
that matches the body. Getting either wrong wastes time at exactly the moment
you are trying to test something.

Where a Burp export is available, headers are lifted from a real observed
request to that path. Synthesised headers are a fallback -- real ones keep the
request indistinguishable from application traffic, which matters when a WAF or
a server-side framework check is in play.

The --no-auth variant is the point of the exercise for authorization testing:
same request, credentials removed, so any difference in response is attributable
to the missing credential rather than to a request the server never liked.
"""

import argparse
import json
import os
import re
import sys

CRLF = "\r\n"

DEFAULT_HEADERS = [
    ("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                   "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"),
    ("Accept", "application/json, text/javascript, */*; q=0.01"),
    ("Accept-Language", "en-US,en;q=0.9"),
    ("X-Requested-With", "XMLHttpRequest"),
    ("Connection", "close"),
]

AUTH_HEADER_NAMES = {
    "authorization", "cookie", "x-api-key", "x-auth-token", "x-access-token",
    "apikey", "api-key", "x-csrf-token", "x-xsrf-token", "requestverificationtoken",
}

DROP_HEADERS = {"content-length", "host", "connection", "accept-encoding",
                "if-none-match", "if-modified-since", "sec-fetch-dest",
                "sec-fetch-mode", "sec-fetch-site", "sec-ch-ua",
                "sec-ch-ua-mobile", "sec-ch-ua-platform"}


def load(path):
    if not path or not os.path.exists(path):
        return None
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def pick_endpoints(inv, args):
    eps = inv.get("endpoints", [])
    if args.id:
        want = {i.lower() for i in args.id}
        eps = [e for e in eps if e["id"].lower() in want]
    if args.path:
        eps = [e for e in eps if e["normalized"] == args.path or e["raw"] == args.path]
    if args.match:
        rx = re.compile(args.match, re.I)
        eps = [e for e in eps if rx.search(e["normalized"])]
    if args.verdict:
        want = {v.lower() for v in args.verdict}
        eps = [e for e in eps if e.get("auth", {}).get("verdict", "").lower() in want]
    return eps


def observed_for(burp, path, method):
    """Best real request for this path: exact method+path, then any method."""
    if not burp:
        return None
    reqs = burp.get("requests", [])
    norm = re.sub(r"\{[^}]*\}", "", path).rstrip("/")
    best = None
    for r in reqs:
        rp = (r.get("path") or "").split("?", 1)[0].rstrip("/")
        if not rp:
            continue
        if rp == path.split("?", 1)[0].rstrip("/") or (norm and rp.startswith(norm)):
            if r.get("method", "").upper() == method.upper():
                return r
            best = best or r
    return best


def fill_params(path, value):
    return re.sub(r"\{(?:param|id|guid|concat)\}", value, path)


def build_body(ep, content_type, marker):
    params = [p for p in ep.get("params", []) if p != "concat"]
    q = ep["normalized"].split("?", 1)
    query_params = []
    if len(q) == 2:
        for pair in re.split(r"[&;]", q[1]):
            k = pair.split("=", 1)[0].strip()
            if k:
                query_params.append(k)
    body_params = [p for p in params if p not in query_params] or params

    if ep.get("call_kind") == "wcf-proxy" or ep["normalized"].split("?")[0].endswith(
            tuple("/" + s for s in ("",))) and ".asmx/" in ep["normalized"]:
        content_type = content_type or "application/json; charset=utf-8"
    if not content_type:
        content_type = "application/json"

    if "json" in content_type:
        if not body_params:
            return "{}", content_type
        return json.dumps({p: marker for p in body_params}, indent=2), content_type
    if "x-www-form-urlencoded" in content_type:
        return "&".join("%s=%s" % (p, marker) for p in body_params) or "", content_type
    if "xml" in content_type or "soap" in content_type:
        inner = "".join("<%s>%s</%s>" % (p, marker, p) for p in body_params)
        return ('<?xml version="1.0" encoding="utf-8"?>'
                '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">'
                "<soap:Body>%s</soap:Body></soap:Envelope>" % inner), content_type
    return "", content_type


def render(ep, args, burp, strip_auth):
    method = (args.method or ep.get("method") or "GET").upper()
    path = fill_params(ep["normalized"], args.param_value)
    if not path.startswith("/"):
        path = "/" + re.sub(r"^https?://[^/]+", "", path)

    obs = observed_for(burp, path, method) if burp else None

    host = args.host
    if not host and obs:
        h, port = obs.get("host"), str(obs.get("port") or "")
        proto = obs.get("protocol", "https")
        host = h if (not port or (proto == "https" and port == "443") or
                     (proto == "http" and port == "80")) else "%s:%s" % (h, port)
    if not host and burp:
        for r in burp.get("requests", []):
            if r.get("host"):
                host = r["host"]
                break
    if not host:
        host = "TARGET-HOST"

    headers = []
    seen = set()
    if obs and not args.synthetic_headers:
        for k, v in (obs.get("request_headers") or {}).items():
            if k.lower() in DROP_HEADERS:
                continue
            if strip_auth and k.lower() in AUTH_HEADER_NAMES:
                continue
            headers.append((k, v))
            seen.add(k.lower())
    for k, v in DEFAULT_HEADERS:
        if k.lower() not in seen:
            headers.append((k, v))
            seen.add(k.lower())
    if not strip_auth and "authorization" not in seen and not obs:
        headers.append(("Authorization", "Bearer REPLACE_WITH_TOKEN"))
    if args.header:
        for h in args.header:
            if ":" in h:
                k, v = h.split(":", 1)
                headers = [(hk, hv) for hk, hv in headers if hk.lower() != k.strip().lower()]
                headers.append((k.strip(), v.strip()))

    body = ""
    ctype = None
    if method in ("POST", "PUT", "PATCH", "DELETE"):
        existing_ct = next((v for k, v in headers if k.lower() == "content-type"), None)
        if obs and obs.get("request_body") and not args.regenerate_body:
            body = obs["request_body"]
            ctype = existing_ct or "application/json"
        else:
            body, ctype = build_body(ep, args.content_type or existing_ct, args.param_value)
        headers = [(k, v) for k, v in headers if k.lower() != "content-type"]
        if ctype:
            headers.append(("Content-Type", ctype))

    lines = ["%s %s HTTP/1.1" % (method, path), "Host: %s" % host]
    lines += ["%s: %s" % (k, v) for k, v in headers]
    if method in ("POST", "PUT", "PATCH", "DELETE"):
        lines.append("Content-Length: %d" % len(body.encode("utf-8")))
    return CRLF.join(lines) + CRLF + CRLF + body


def main():
    ap = argparse.ArgumentParser(
        description="Build Burp Repeater-ready raw HTTP requests from an endpoint inventory.")
    ap.add_argument("endpoints", help="endpoints.json from extract_endpoints.py")
    ap.add_argument("--burp-index", default=None, help="burp_index.json for real headers/host")
    ap.add_argument("--id", action="append", help="Endpoint id, e.g. e005 (repeatable)")
    ap.add_argument("--path", help="Exact normalized or raw path")
    ap.add_argument("--match", help="Regex against the normalized path")
    ap.add_argument("--verdict", action="append", help="Filter by auth verdict (repeatable)")
    ap.add_argument("--list", action="store_true", help="List endpoints and exit")
    ap.add_argument("--host", help="Override Host header")
    ap.add_argument("--method", help="Override HTTP method")
    ap.add_argument("--header", action="append", help="Add/replace a header, 'Name: value' (repeatable)")
    ap.add_argument("--content-type", default=None)
    ap.add_argument("--param-value", default="FUZZ", help="Value substituted for {param} and body fields")
    ap.add_argument("--no-auth", action="store_true", help="Emit only the credential-stripped variant")
    ap.add_argument("--both", action="store_true",
                    help="Emit authenticated and credential-stripped variants for comparison")
    ap.add_argument("--synthetic-headers", action="store_true",
                    help="Ignore Burp-observed headers and synthesise a clean set")
    ap.add_argument("--regenerate-body", action="store_true",
                    help="Build a body from params instead of reusing the observed one")
    ap.add_argument("--out-dir", default=None, help="Write one .txt per request instead of stdout")
    args = ap.parse_args()

    inv = load(args.endpoints)
    if inv is None:
        print("Cannot read %s" % args.endpoints, file=sys.stderr)
        return 1
    burp = load(args.burp_index)

    if args.list:
        for e in inv.get("endpoints", []):
            print("%-6s %-7s %-52s %s" % (e["id"], e["method"], e["normalized"][:52],
                                          e.get("auth", {}).get("verdict", "")))
        return 0

    eps = pick_endpoints(inv, args)
    if not eps:
        print("No endpoints matched. Use --list to see what is available.", file=sys.stderr)
        return 1

    if args.out_dir:
        os.makedirs(args.out_dir, exist_ok=True)

    written = 0
    for e in eps:
        variants = []
        if args.both:
            variants = [("authed", False), ("noauth", True)]
        elif args.no_auth:
            variants = [("noauth", True)]
        else:
            variants = [("authed", False)]

        for label, strip in variants:
            req = render(e, args, burp, strip)
            if args.out_dir:
                fn = os.path.join(args.out_dir, "%s_%s.txt" % (e["id"], label))
                with open(fn, "w", encoding="utf-8", newline="") as fh:
                    fh.write(req)
                written += 1
            else:
                header = "# %s  %s  [%s]  %s" % (
                    e["id"], e["normalized"], label, e.get("auth", {}).get("verdict", ""))
                print(header)
                print("# " + "-" * (len(header) - 2))
                print(req.replace(CRLF, "\n"))
                print()

    if args.out_dir:
        print("Wrote %d request file(s) to %s/" % (written, args.out_dir), file=sys.stderr)
        print("Paste a file's contents into Burp Repeater (Ctrl+R from Proxy, then replace).",
              file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
