#!/usr/bin/env python3
"""Ingest a Burp Suite sitemap/proxy XML export.

Two jobs, both feeding the rest of the workflow:

1. Write every JavaScript-ish response body to disk so extract_endpoints.py
   can analyse the code the target actually served -- including bundles behind
   authentication that you cannot fetch anonymously.
2. Build an index of observed requests. Real captured headers are far better
   evidence than anything static analysis can infer: an endpoint Burp saw
   answered *without* an Authorization header is a concrete auth-gap candidate,
   and the captured headers make generated Repeater requests realistic.

Reads a file you exported yourself; never contacts the target.
"""

import argparse
import base64
import json
import os
import re
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

JS_MIME = re.compile(r"script|javascript|json", re.I)
JS_EXT = re.compile(r"\.(?:js|mjs|axd|json|map)(?:$|\?)", re.I)

AUTH_HEADERS = ("authorization", "x-api-key", "x-auth-token", "x-access-token",
                "apikey", "api-key", "x-csrf-token", "x-xsrf-token",
                "requestverificationtoken")


def text_of(el, default=""):
    return el.text if el is not None and el.text is not None else default


def decode(el):
    if el is None:
        return ""
    raw = el.text or ""
    if el.get("base64") == "true":
        try:
            return base64.b64decode(raw).decode("utf-8", errors="replace")
        except Exception:
            return ""
    return raw


def parse_http_message(msg):
    """Split a raw HTTP message into start line, headers dict, and body."""
    if not msg:
        return "", {}, ""
    parts = re.split(r"\r?\n\r?\n", msg, maxsplit=1)
    head = parts[0]
    body = parts[1] if len(parts) > 1 else ""
    lines = re.split(r"\r?\n", head)
    start = lines[0] if lines else ""
    headers = {}
    for ln in lines[1:]:
        if ":" in ln:
            k, v = ln.split(":", 1)
            headers[k.strip()] = v.strip()
    return start, headers, body


def safe_name(url, idx):
    base = re.sub(r"^https?://", "", url)
    base = re.sub(r"[?#].*$", "", base)
    base = re.sub(r"[^A-Za-z0-9._/-]", "_", base).strip("/")
    base = base.replace("/", "__")
    if not base:
        base = "resource"
    if not re.search(r"\.(js|json|axd|map|mjs)$", base, re.I):
        base += ".js"
    return "%04d__%s" % (idx, base[-160:])


def main():
    ap = argparse.ArgumentParser(description="Parse a Burp XML export into JS files + a request index.")
    ap.add_argument("xml", help="Burp sitemap or proxy history XML export")
    ap.add_argument("--out-dir", default="burp_js", help="Where to write JS/JSON response bodies")
    ap.add_argument("--index", default="burp_index.json")
    ap.add_argument("--all-responses", action="store_true",
                    help="Save every response body, not just script/JSON ones")
    args = ap.parse_args()

    try:
        tree = ET.parse(args.xml)
    except ET.ParseError as exc:
        print("Could not parse %s: %s" % (args.xml, exc), file=sys.stderr)
        return 1
    root = tree.getroot()

    os.makedirs(args.out_dir, exist_ok=True)
    requests, saved = [], 0

    for idx, item in enumerate(root.findall("item"), 1):
        url = text_of(item.find("url"))
        path = text_of(item.find("path"))
        mime = text_of(item.find("mimetype"))
        status = text_of(item.find("status"))
        method = text_of(item.find("method")) or "GET"
        host = text_of(item.find("host"))
        port = text_of(item.find("port"))
        proto = text_of(item.find("protocol")) or "https"

        req_raw = decode(item.find("request"))
        resp_raw = decode(item.find("response"))
        start, req_headers, req_body = parse_http_message(req_raw)
        _, resp_headers, resp_body = parse_http_message(resp_raw)

        lower = {k.lower(): v for k, v in req_headers.items()}
        present_auth = [h for h in AUTH_HEADERS if h in lower]
        has_cookie = "cookie" in lower

        requests.append({
            "index": idx,
            "url": url,
            "host": host,
            "port": port,
            "protocol": proto,
            "method": method.upper(),
            "path": path,
            "status": status,
            "mimetype": mime,
            "request_headers": req_headers,
            "request_body": req_body[:8000],
            "auth_headers_present": present_auth,
            "cookie_present": has_cookie,
            "response_content_type": resp_headers.get("Content-Type", ""),
            "response_bytes": len(resp_body),
        })

        wants = args.all_responses or JS_MIME.search(mime or "") or JS_EXT.search(url or "")
        if wants and resp_body:
            fn = os.path.join(args.out_dir, safe_name(url, idx))
            with open(fn, "w", encoding="utf-8", errors="replace") as fh:
                fh.write(resp_body)
            saved += 1

    # Roll requests up per (method, path) so the index answers "was this
    # endpoint ever observed without auth?" directly.
    observed = {}
    for r in requests:
        key = "%s %s" % (r["method"], r["path"])
        o = observed.setdefault(key, {
            "method": r["method"], "path": r["path"], "host": r["host"],
            "port": r["port"], "protocol": r["protocol"],
            "times_seen": 0, "statuses": [], "ever_without_auth": False,
            "ever_with_auth": False, "sample_index": r["index"],
        })
        o["times_seen"] += 1
        if r["status"] and r["status"] not in o["statuses"]:
            o["statuses"].append(r["status"])
        if r["auth_headers_present"] or r["cookie_present"]:
            o["ever_with_auth"] = True
        else:
            o["ever_without_auth"] = True

    out = {
        "generated": datetime.now(timezone.utc).isoformat(),
        "source": os.path.abspath(args.xml),
        "item_count": len(requests),
        "js_files_written": saved,
        "js_dir": os.path.abspath(args.out_dir),
        "observed_endpoints": sorted(observed.values(), key=lambda x: (x["path"], x["method"])),
        "requests": requests,
    }
    with open(args.index, "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=2)

    no_auth = [o for o in observed.values() if o["ever_without_auth"] and not o["ever_with_auth"]]
    print("Parsed %d items from %s" % (len(requests), args.xml))
    print("Wrote %d script/JSON bodies to %s/" % (saved, args.out_dir))
    print("Distinct method+path observed: %d" % len(observed))
    print("Observed *only* without auth headers/cookie: %d" % len(no_auth))
    print("Wrote %s" % args.index)
    print("\nNext: run extract_endpoints.py on %s/ to mine the saved bundles." % args.out_dir)
    return 0


if __name__ == "__main__":
    sys.exit(main())
