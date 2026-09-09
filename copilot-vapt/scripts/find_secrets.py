#!/usr/bin/env python3
"""Find credentials, API keys and sensitive disclosures in client-side code.

Secret scanners live or die on false positives: a report with 300 hits, 295 of
them placeholders and minified variable names, gets skimmed and discarded. So
findings here are tiered by how much the pattern itself proves:

  confirmed  - a provider-specific format that essentially cannot be anything
               else (AKIA..., ghp_..., sk_live_..., a PEM private key)
  probable   - a credential-shaped assignment whose value passes an entropy
               check and is not a placeholder
  possible   - keyword match with weak value evidence; skim these
  info       - not a credential but useful disclosure (source maps, internal
               hosts, JWTs, cloud storage URLs)

JWTs get decoded (header and payload only, no signature verification) because
their claims -- algorithm, expiry, issuer, roles -- are usually more useful
than the token string itself.

Reads files on disk; never contacts a target.
"""

import argparse
import base64
import json
import math
import os
import re
import sys
from datetime import datetime, timezone

# ---- provider-specific patterns: format alone is near-conclusive -----------
CONFIRMED = [
    ("aws-access-key-id",      re.compile(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA|APKA)[0-9A-Z]{16}\b")),
    ("github-token",           re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b")),
    ("github-fine-grained-pat", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{60,}\b")),
    ("gitlab-token",           re.compile(r"\bglpat-[A-Za-z0-9\-_]{20,}\b")),
    ("slack-token",            re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b")),
    ("slack-webhook",          re.compile(r"https://hooks\.slack\.com/services/T[A-Za-z0-9_]+/B[A-Za-z0-9_]+/[A-Za-z0-9_]+")),
    ("google-api-key",         re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("google-oauth-client-id", re.compile(r"\b[0-9]+-[0-9a-z_]{32}\.apps\.googleusercontent\.com\b")),
    ("stripe-secret-key",      re.compile(r"\b(?:sk|rk)_live_[0-9a-zA-Z]{24,}\b")),
    ("stripe-test-key",        re.compile(r"\b(?:sk|rk)_test_[0-9a-zA-Z]{24,}\b")),
    ("twilio-api-key",         re.compile(r"\bSK[0-9a-fA-F]{32}\b")),
    ("twilio-account-sid",     re.compile(r"\bAC[0-9a-fA-F]{32}\b")),
    ("sendgrid-key",           re.compile(r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b")),
    ("mailgun-key",            re.compile(r"\bkey-[0-9a-f]{32}\b")),
    ("mailchimp-key",          re.compile(r"\b[0-9a-f]{32}-us[0-9]{1,2}\b")),
    ("npm-token",              re.compile(r"\bnpm_[A-Za-z0-9]{36}\b")),
    ("square-token",           re.compile(r"\bsq0(?:atp|csp)-[0-9A-Za-z\-_]{22,}\b")),
    ("shopify-token",          re.compile(r"\bshp(?:at|ss|pa|ca)_[0-9a-fA-F]{32}\b")),
    ("openai-key",             re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{20,}\b")),
    ("anthropic-key",          re.compile(r"\bsk-ant-(?:api|admin)[0-9]{2}-[A-Za-z0-9_\-]{80,}\b")),
    ("mapbox-secret-token",    re.compile(r"\bsk\.eyJ[A-Za-z0-9_\-]{50,}\b")),
    ("private-key-block",      re.compile(r"-----BEGIN\s+(?:RSA|EC|DSA|OPENSSH|PGP|ENCRYPTED)?\s*PRIVATE KEY(?:\s+BLOCK)?-----")),
    ("firebase-cloud-messaging", re.compile(r"\bAAAA[A-Za-z0-9_\-]{7}:APA91b[A-Za-z0-9_\-]{100,}\b")),
    ("azure-storage-key",      re.compile(r"DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{60,}")),
    ("basic-auth-in-url",      re.compile(r"\b[a-z][a-z0-9+.\-]*://[^/\s:@]+:[^/\s:@]+@[^\s/'\"]+", re.I)),
    ("db-connection-string",   re.compile(r"\b(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis|amqp|mssql)://[^\s'\"<>]{8,}", re.I)),
    ("dotnet-connection-string", re.compile(r"(?:Data Source|Server)\s*=[^;'\"]{2,60};[^'\"]{0,200}?(?:Password|Pwd)\s*=\s*[^;'\"\s]{3,}", re.I)),
]

# ---- credential-shaped assignments: need value evidence -------------------
SECRET_KEYWORD = (
    r"(?:api[_\-]?key|apikey|secret[_\-]?key|client[_\-]?secret|app[_\-]?secret|"
    r"access[_\-]?token|refresh[_\-]?token|auth[_\-]?token|bearer[_\-]?token|"
    r"private[_\-]?key|encryption[_\-]?key|signing[_\-]?key|master[_\-]?key|"
    r"password|passwd|pwd|passphrase|credential|secret|token|api[_\-]?secret|"
    r"consumer[_\-]?secret|session[_\-]?key|machine[_\-]?key|validation[_\-]?key|decryption[_\-]?key)"
)
ASSIGNMENT = re.compile(
    r"""["']?(?P<key>[\w.\-]*""" + SECRET_KEYWORD + r"""[\w.\-]*)["']?\s*[:=]\s*"""
    r"""(?P<q>['"`])(?P<val>[^'"`\n]{6,200})(?P=q)""",
    re.I,
)

# ---- informational disclosures -------------------------------------------
INFO = [
    ("jwt",                    re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]*")),
    ("source-map-ref",         re.compile(r"//[#@]\s*sourceMappingURL\s*=\s*(?P<v>[^\s*]+)")),
    ("s3-bucket-url",          re.compile(r"\b[a-z0-9.\-]{3,63}\.s3(?:[.\-][a-z0-9\-]+)?\.amazonaws\.com\b", re.I)),
    ("azure-blob-url",         re.compile(r"\b[a-z0-9]{3,24}\.blob\.core\.windows\.net\b", re.I)),
    ("gcs-bucket-url",         re.compile(r"\bstorage\.googleapis\.com/[A-Za-z0-9._\-]+")),
    ("internal-hostname",      re.compile(r"\bhttps?://(?:[a-z0-9\-]+\.)*(?:internal|intranet|corp|local|lan|test|dev|staging|uat|qa|preprod)\b[^\s'\"<>]*", re.I)),
    ("private-ip-url",         re.compile(r"\bhttps?://(?:10\.\d{1,3}|192\.168|172\.(?:1[6-9]|2\d|3[01])|127\.0\.0\.1|localhost)[^\s'\"<>]*", re.I)),
    # Anchored so the password half of `scheme://user:pass@host` is not
    # re-reported as an email address.
    ("email-address",          re.compile(r"(?<![:/%\w.\-])[A-Za-z0-9._+\-]+@(?!example\.|test\.|sentry\.|schema\.)[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")),
    ("aspnet-machine-key",     re.compile(r"<machineKey[^>]*(?:validationKey|decryptionKey)\s*=", re.I)),
]

# Values that look like secrets but are not.
PLACEHOLDER = re.compile(
    r"^(?:x{3,}|y{3,}|\.{3,}|-+|_+|0+|1+|"
    r".*(?:your[_\-]?|my[_\-]?|the[_\-]?)?(?:api[_\-]?key|secret|token|password|value|here|goes)[_\-]?(?:here|goes)?$|"
    r".*(?:example|sample|dummy|placeholder|changeme|change[_\-]me|replace|insert|todo|tbd|fixme|"
    r"redacted|removed|hidden|masked|none|null|undefined|empty|test123|foobar|lorem)\b.*|"
    r"\$\{.*\}|<[^>]*>|\{\{.*\}\}|%[A-Z_]+%|process\.env\..*|import\.meta\.env\..*|"
    r"\[.*\]|@@.*@@)$",
    re.I,
)
# Minified identifiers and common non-secret values.
LOW_VALUE = re.compile(r"^(?:[a-z]{1,4}|\d{1,6}|true|false|on|off|yes|no|utf-?8|application/[\w.+-]+|"
                       r"[\w.-]+\.(?:js|css|png|jpg|svg|json|html)|#[0-9a-f]{3,8})$", re.I)


def entropy(s):
    if not s:
        return 0.0
    counts = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


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


def redact(value, keep=4):
    if len(value) <= keep * 2:
        return value[:2] + "*" * max(0, len(value) - 2)
    return "%s%s%s" % (value[:keep], "*" * min(12, len(value) - keep * 2), value[-keep:])


def b64pad(s):
    return s + "=" * (-len(s) % 4)


def decode_jwt(tok):
    """Header and payload only. The signature is not verified -- the point is
    to read the claims, and `alg: none` or an expired token is itself a finding."""
    parts = tok.split(".")
    if len(parts) < 2:
        return None
    out = {}
    for name, part in (("header", parts[0]), ("payload", parts[1])):
        try:
            out[name] = json.loads(base64.urlsafe_b64decode(b64pad(part)).decode("utf-8", "replace"))
        except Exception:
            return None
    notes = []
    hdr, pl = out.get("header") or {}, out.get("payload") or {}
    alg = str(hdr.get("alg", "")).lower()
    if alg in ("none", ""):
        notes.append("alg=none -- signature not required; test whether the server accepts it")
    if alg.startswith("hs"):
        notes.append("HMAC algorithm -- test key confusion (RS->HS) and weak-secret cracking")
    exp = pl.get("exp")
    if isinstance(exp, (int, float)):
        now = datetime.now(timezone.utc).timestamp()
        notes.append("expired" if exp < now else "still valid until %s UTC"
                     % datetime.fromtimestamp(exp, timezone.utc).strftime("%Y-%m-%d %H:%M"))
    for claim in ("iss", "aud", "sub", "role", "roles", "scope", "scp", "groups", "admin", "email", "upn"):
        if claim in pl:
            notes.append("claim %s=%r" % (claim, pl[claim]))
    return {"header": hdr, "payload": pl, "notes": notes}


def classify_assignment(key, val):
    if PLACEHOLDER.match(val.strip()) or LOW_VALUE.match(val.strip()):
        return None, None
    v = val.strip()
    if len(v) < 8:
        return None, None
    if re.match(r"^[\w.\-/]+\.(?:js|json|css|html|png|svg)$", v, re.I):
        return None, None
    ent = entropy(v)
    # Long, high-entropy values that are not words: strong evidence.
    if len(v) >= 20 and ent >= 3.8:
        return "probable", ent
    if len(v) >= 12 and ent >= 3.2 and re.search(r"\d", v) and re.search(r"[A-Za-z]", v):
        return "probable", ent
    if "password" in key.lower() or "secret" in key.lower():
        # A short low-entropy password is still a hardcoded password.
        return "possible", ent
    if ent >= 3.0:
        return "possible", ent
    return None, None


def scan_file(path, root, args):
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError:
        return []
    rel = os.path.relpath(path, root) if root else path
    ls = build_line_starts(text)
    found = []
    seen = set()

    def add(tier, kind, value, idx, extra=None):
        key = (kind, value, rel)
        if key in seen:
            return
        seen.add(key)
        rec = {
            "tier": tier,
            "kind": kind,
            "file": rel,
            "line": line_of(idx, ls),
            "value": redact(value) if args.redact else value,
            "value_length": len(value),
            "snippet": text[max(0, idx - 50): idx + 130].replace("\n", " ").strip(),
        }
        if args.redact:
            rec["snippet"] = rec["snippet"].replace(value, redact(value))
        if extra:
            rec.update(extra)
        found.append(rec)

    for kind, pat in CONFIRMED:
        for m in pat.finditer(text):
            add("confirmed", kind, m.group(0), m.start())

    for m in ASSIGNMENT.finditer(text):
        tier, ent = classify_assignment(m.group("key"), m.group("val"))
        if tier:
            add(tier, "hardcoded-%s" % re.sub(r"[^a-z]+", "-", m.group("key").lower()).strip("-"),
                m.group("val"), m.start(), {"assigned_to": m.group("key"), "entropy": round(ent, 2)})

    for kind, pat in INFO:
        for m in pat.finditer(text):
            val = m.groupdict().get("v") or m.group(0)
            extra = None
            if kind == "jwt":
                dec = decode_jwt(m.group(0))
                if dec:
                    extra = {"jwt": dec}
            add("info", kind, val, m.start(), extra)

    return found


def collect(paths, exts):
    files = []
    for p in paths:
        if os.path.isfile(p):
            files.append(p)
        else:
            for dirpath, dirnames, filenames in os.walk(p):
                dirnames[:] = [d for d in dirnames if d not in (".git", "node_modules", "__pycache__")]
                for fn in filenames:
                    if not exts or os.path.splitext(fn)[1].lower() in exts:
                        files.append(os.path.join(dirpath, fn))
    return sorted(files)


def main():
    ap = argparse.ArgumentParser(description="Find secrets, API keys and sensitive disclosures in client-side files.")
    ap.add_argument("paths", nargs="+")
    ap.add_argument("--out", default="secrets.json")
    ap.add_argument("--root", default=None)
    ap.add_argument("--redact", action="store_true",
                    help="Mask values in output -- use when the results go into a shared report")
    ap.add_argument("--min-tier", default="possible",
                    choices=["info", "possible", "probable", "confirmed"])
    ap.add_argument("--all-files", action="store_true", help="Scan every file, not just web assets")
    args = ap.parse_args()

    exts = None if args.all_files else {
        ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".axd", ".html", ".htm",
        ".aspx", ".json", ".map", ".vue", ".config", ".xml", ".env", ".txt"}
    root = args.root or (args.paths[0] if os.path.isdir(args.paths[0]) else os.path.dirname(args.paths[0]) or ".")
    files = collect(args.paths, exts)
    if not files:
        print("No matching files found.", file=sys.stderr)
        return 1

    findings = []
    for f in files:
        findings.extend(scan_file(f, root, args))

    rank = {"confirmed": 4, "probable": 3, "possible": 2, "info": 1}

    # The same value often matches several patterns -- a connection string is
    # also a basic-auth URL, and a provider token also trips the generic
    # assignment rule. Report each value once at its strongest tier, listing
    # the other patterns it matched, so the count reflects distinct secrets.
    merged = {}
    for f in findings:
        key = (f["file"], f["value"])
        cur = merged.get(key)
        if cur is None:
            f["also_matched"] = []
            merged[key] = f
        elif rank[f["tier"]] > rank[cur["tier"]]:
            f["also_matched"] = sorted(set(cur["also_matched"] + [cur["kind"]]))
            merged[key] = f
        elif f["kind"] != cur["kind"]:
            cur["also_matched"] = sorted(set(cur["also_matched"] + [f["kind"]]))
    findings = list(merged.values())

    floor = rank[args.min_tier]
    findings = [f for f in findings if rank[f["tier"]] >= floor]
    findings.sort(key=lambda f: (-rank[f["tier"]], f["kind"], f["file"], f["line"]))

    counts = {}
    for f in findings:
        counts[f["tier"]] = counts.get(f["tier"], 0) + 1

    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump({
            "generated": datetime.now(timezone.utc).isoformat(),
            "root": os.path.abspath(root),
            "files_scanned": len(files),
            "redacted": args.redact,
            "finding_count": len(findings),
            "by_tier": counts,
            "findings": findings,
        }, fh, indent=2)

    print("Scanned %d files -> %d findings" % (len(files), len(findings)))
    for t in ("confirmed", "probable", "possible", "info"):
        if counts.get(t):
            print("  %-10s %d" % (t, counts[t]))
    print("Wrote %s" % args.out)
    if counts.get("confirmed"):
        print("\nConfirmed provider credentials found. Verify each is live before reporting,")
        print("and tell the client immediately if it is -- a live key is not a routine finding.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
