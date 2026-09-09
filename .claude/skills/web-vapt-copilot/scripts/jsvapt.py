#!/usr/bin/env python3
"""
jsvapt.py - Offline static analysis of JavaScript / ASP.NET .axd bundles for web VAPT.

Strictly local: reads files from disk, never performs network I/O. The analyst is
responsible for capturing the JS/.axd bodies (via Burp "Save item", browser
DevTools, or wget) and for running any request this tool prints.

Subcommands:
  scan       Parse JS/.axd/.map/.html files -> results.json
  endpoints  List / filter discovered endpoints
  wordlist   Emit a wordlist (paths, segments, params, files) for ffuf/Intruder
  request    Emit a Burp Repeater-ready raw HTTP/1.1 request
  authgaps   Show endpoints with no observed Authorization material
  domxss     Show DOM XSS source/sink findings
  secrets    Show hardcoded credential-shaped strings
  report     Emit a Markdown assessment report
"""
from __future__ import annotations

import argparse
import bisect
import json
import os
import re
import sys
from datetime import datetime, timezone
from urllib.parse import urlsplit, parse_qsl

TOOL = "jsvapt"
VERSION = "1.0.0"

DEFAULT_EXTS = {".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".axd", ".map",
                ".html", ".htm", ".aspx", ".json", ".txt"}

# Hosts that are almost always third-party noise, not in-scope attack surface.
THIRD_PARTY = (
    "google-analytics.com", "googletagmanager.com", "doubleclick.net", "gstatic.com",
    "fonts.googleapis.com", "fonts.gstatic.com", "facebook.net", "facebook.com",
    "cdn.jsdelivr.net", "cdnjs.cloudflare.com", "unpkg.com", "jquery.com",
    "w3.org", "schema.org", "xmlns.com", "purl.org", "sentry.io", "ingest.sentry.io",
    "newrelic.com", "nr-data.net", "hotjar.com", "segment.io", "segment.com",
    "mixpanel.com", "bugsnag.com", "cloudflareinsights.com", "clarity.ms",
    "bing.com", "adobedtm.com", "demdex.net", "omtrdc.net", "youtube.com",
    "vimeo.com", "twitter.com", "licdn.com", "recaptcha.net", "polyfill.io",
)

MIME_PREFIX = ("application", "text", "image", "audio", "video", "multipart",
               "font", "model", "message", "chemical", "x-shader")

INTERESTING_EXT = (".json", ".php", ".aspx", ".ashx", ".asmx", ".axd", ".svc",
                   ".jsp", ".jspx", ".do", ".action", ".cgi", ".pl", ".py",
                   ".xml", ".config", ".bak", ".zip", ".sql", ".log")

# Path fragments that raise the value of an unauthenticated endpoint.
SENSITIVE_HINTS = (
    "admin", "manage", "internal", "private", "config", "setting", "debug",
    "trace", "console", "actuator", "swagger", "openapi", "graphql", "export",
    "download", "upload", "backup", "delete", "remove", "drop", "impersonat",
    "user", "account", "profile", "customer", "employee", "payment", "invoice",
    "order", "token", "password", "credential", "secret", "key", "session",
    "auth", "login", "register", "reset", "otp", "mfa", "2fa", "role",
    "permission", "privilege", "report", "audit", "log", "health", "metrics",
    "env", "info", "version", "status", "test", "dev", "staging", "beta",
)


# --------------------------------------------------------------------------
# Source helpers
# --------------------------------------------------------------------------
class Source:
    """A single analysed source unit (a file, or one embedded .map source)."""

    def __init__(self, name: str, text: str, origin: str = ""):
        self.name = name
        self.text = text
        self.origin = origin or name
        self._nl = [m.start() for m in re.finditer(r"\n", text)]

    def line_of(self, offset: int) -> int:
        return bisect.bisect_right(self._nl, offset) + 1

    def line_text(self, offset: int) -> str:
        start = self.text.rfind("\n", 0, offset) + 1
        end = self.text.find("\n", offset)
        if end == -1:
            end = len(self.text)
        return self.text[start:end]

    def window(self, offset: int, before: int = 400, after: int = 400) -> str:
        return self.text[max(0, offset - before): offset + after]


def snippet(text: str, limit: int = 200) -> str:
    s = " ".join(text.split())
    return s if len(s) <= limit else s[: limit - 3] + "..."


# --------------------------------------------------------------------------
# String literal extraction
# --------------------------------------------------------------------------
RE_SQ = re.compile(r"'((?:\\.|[^'\\\n])*)'")
RE_DQ = re.compile(r'"((?:\\.|[^"\\\n])*)"')
RE_BT = re.compile(r"`((?:\\.|[^`\\])*)`", re.S)
RE_TEMPLATE_EXPR = re.compile(r"\$\{([^{}]*)\}")


def iter_literals(src: Source):
    """Yield (offset, raw_value, quote_kind) for every JS string literal."""
    for rx, kind in ((RE_SQ, "'"), (RE_DQ, '"'), (RE_BT, "`")):
        for m in rx.finditer(src.text):
            yield m.start(), m.group(1), kind


def normalise_template(value: str) -> str:
    """`/api/users/${id}/roles` -> /api/users/{id}/roles"""

    def repl(m):
        expr = m.group(1).strip()
        name = re.sub(r"[^A-Za-z0-9_]", "", expr.split(".")[-1].split("(")[0]) or "param"
        return "{" + name + "}"

    return RE_TEMPLATE_EXPR.sub(repl, value)


# --------------------------------------------------------------------------
# Endpoint recognition
# --------------------------------------------------------------------------
RE_ABS = re.compile(r"^https?://", re.I)
RE_PROTO_REL = re.compile(r"^//[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
RE_DATE = re.compile(r"^\d{1,4}/\d{1,2}(/\d{1,4})?$")
RE_VERSION_PATH = re.compile(r"^/(?:api|rest|svc|service|graphql|v\d|_next|_api|ajax|json|rpc)\b", re.I)
RE_CSS_SEL = re.compile(r"[#.\[\]>+~*:]{1}[A-Za-z\-_]")


def looks_like_endpoint(value: str) -> bool:
    v = value.strip()
    if not v or len(v) > 400:
        return False
    if " " in v or "\t" in v or "\n" in v:
        return False
    if RE_ABS.match(v):
        return True
    if RE_PROTO_REL.match(v):
        return True
    if RE_DATE.match(v):
        return False
    low = v.lower()
    # MIME types / charsets
    head = low.split("/", 1)[0]
    if head in MIME_PREFIX and "." not in head:
        return False
    if v.startswith("/"):
        if len(v) < 2:
            return False
        if v.startswith("//"):
            return False
        # Regex-ish leftovers such as /^\d+$/ or CSS-in-JS
        if v[1] in "^*?+|\\":
            return False
        if v.endswith((".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".woff",
                       ".woff2", ".ttf", ".eot", ".ico", ".webp", ".mp4")):
            return False
        return True
    if "/" in v and (low.endswith(INTERESTING_EXT) or RE_VERSION_PATH.match("/" + v)):
        if RE_CSS_SEL.search(v.split("/")[0]):
            return False
        return True
    if low.endswith((".asmx", ".ashx", ".axd", ".svc", ".aspx")) and "/" not in v:
        return True
    return False


def is_third_party(url: str) -> bool:
    if not RE_ABS.match(url) and not url.startswith("//"):
        return False
    host = urlsplit(url if RE_ABS.match(url) else "https:" + url).netloc.lower()
    host = host.split("@")[-1].split(":")[0]
    return any(host == d or host.endswith("." + d) for d in THIRD_PARTY)


# --------------------------------------------------------------------------
# HTTP method inference
# --------------------------------------------------------------------------
RE_XHR_OPEN = re.compile(r"\.open\s*\(\s*['\"]([A-Za-z]+)['\"]\s*,\s*$")
RE_LIB_VERB = re.compile(
    r"(?:axios|http|https|client|api|request|rest|\$http|this\.http|superagent|got|ky)"
    r"\s*\.\s*(get|post|put|patch|delete|del|head|options)\s*(?:<[^<>()]*>)?\s*\($",
    re.I)
RE_JQ_VERB = re.compile(r"\$\s*\.\s*(get|post|getJSON|getScript|load)\s*\($", re.I)
RE_FETCH = re.compile(r"(?:^|[^\w$.])fetch\s*\($|new\s+Request\s*\($")
RE_METHOD_PROP = re.compile(r"\b(?:method|type)\s*:\s*['\"]([A-Za-z]+)['\"]", re.I)
RE_URL_PROP = re.compile(r"\b(?:url|uri|endpoint|path|action|src)\s*:\s*$", re.I)

VERB_MAP = {"del": "DELETE", "getjson": "GET", "getscript": "GET", "load": "GET"}


def forward_stmt(src: Source, offset: int, limit: int = 500) -> str:
    """Text from `offset` to the end of the current statement.

    Without this bound, `fetch("/a");` would inherit the `method: "POST"` of the
    next call in the file.
    """
    end = min(len(src.text), offset + limit)
    term = src.text.find(";", offset + 1, end)
    return src.text[offset: term if term != -1 else end]


def infer_method(src: Source, offset: int) -> tuple[str, str]:
    """Return (METHOD, evidence) for a literal starting at `offset`."""
    back = src.text[max(0, offset - 220): offset]
    back_tight = back.rstrip()
    m = RE_XHR_OPEN.search(back_tight)
    if m:
        return m.group(1).upper(), "XMLHttpRequest.open"
    m = RE_LIB_VERB.search(back_tight)
    if m:
        v = m.group(1).lower()
        return VERB_MAP.get(v, v.upper()), "http client verb"
    m = RE_JQ_VERB.search(back_tight)
    if m:
        v = m.group(1).lower()
        if v == "post":
            return "POST", "jQuery.post"
        return VERB_MAP.get(v, "GET"), "jQuery." + m.group(1)
    if RE_FETCH.search(back_tight):
        mm = RE_METHOD_PROP.search(forward_stmt(src, offset))
        return (mm.group(1).upper() if mm else "GET"), "fetch()"
    if RE_URL_PROP.search(back_tight):
        # url: '...' inside an options object - look both ways for method/type
        both = src.text[max(0, offset - 300): offset] + forward_stmt(src, offset)
        mm = RE_METHOD_PROP.search(both)
        return (mm.group(1).upper() if mm else "GET"), "options object"
    if re.search(r"\.(?:ajax|request|send|call|invoke|fetchJson|apiCall)\s*\($", back_tight):
        mm = RE_METHOD_PROP.search(forward_stmt(src, offset))
        return (mm.group(1).upper() if mm else "GET"), "ajax wrapper"
    if re.search(r"\b(?:action|formAction|href)\s*=\s*$", back_tight):
        return "GET", "markup attribute"
    return "GET", "string literal"


# --------------------------------------------------------------------------
# Authorization signal detection
# --------------------------------------------------------------------------
AUTH_SIGNALS = [
    ("bearer-header", re.compile(r"['\"]?Authorization['\"]?\s*[:=,]\s*['\"`]?\s*(?:Bearer|Basic|Token|JWT)", re.I)),
    ("authorization-header", re.compile(r"['\"]Authorization['\"]", re.I)),
    ("set-request-header-auth", re.compile(r"setRequestHeader\s*\(\s*['\"](?:Authorization|X-Auth[\w-]*|X-Api-Key|X-Access-Token)['\"]", re.I)),
    ("api-key-header", re.compile(r"['\"](?:x-api-key|api[-_]?key|apikey|x-access-token|x-auth-token|x-token)['\"]\s*[:=]", re.I)),
    ("bearer-template", re.compile(r"`\s*Bearer\s+\$\{", re.I)),
    ("token-var", re.compile(r"\b(?:accessToken|access_token|idToken|id_token|authToken|auth_token|bearerToken|jwt|sessionToken)\b")),
    ("csrf-header", re.compile(r"['\"](?:X-CSRF-Token|X-XSRF-TOKEN|RequestVerificationToken|__RequestVerificationToken|X-CSRFToken)['\"]", re.I)),
    ("cookie-credentials", re.compile(r"\bwithCredentials\s*[:=]\s*(?:true|!0)|credentials\s*:\s*['\"](?:include|same-origin)['\"]", re.I)),
    ("auth-helper-call", re.compile(r"\b(?:getToken|getAccessToken|getAuthHeader|authHeader|withAuth|requireAuth|getIdToken|acquireTokenSilent)\s*\(")),
]

FILE_AUTH_SIGNALS = [
    ("axios-request-interceptor", re.compile(r"interceptors\s*\.\s*request\s*\.\s*use", re.I)),
    ("angular-http-interceptor", re.compile(r"HTTP_INTERCEPTORS|implements\s+HttpInterceptor|\$httpProvider\.interceptors", re.I)),
    ("fetch-wrapper", re.compile(r"(?:window\.)?fetch\s*=\s*(?:function|\()|const\s+originalFetch")),
    ("jquery-ajax-setup", re.compile(r"\$\.ajaxSetup\s*\(|ajaxPrefilter\s*\(", re.I)),
    ("msal-auth0-oidc", re.compile(r"\b(?:msal|Auth0Client|UserManager|oidc-client|keycloak)\b", re.I)),
]


def detect_file_auth(src: Source) -> list[str]:
    return [name for name, rx in FILE_AUTH_SIGNALS if rx.search(src.text)]


def statement_span(src: Source, offset: int, back: int = 300, fwd: int = 350,
                   fwd_terminators: int = 2) -> str:
    """Text of the statement containing `offset`.

    Backwards: stop at the nearest `;` or `}` so a neighbouring function's headers
    do not leak in. Forwards: run to the Nth `;` so patterns split across statements
    (xhr.open(...); xhr.setRequestHeader(...)) are still seen.
    """
    lo = max(0, offset - back)
    prefix = src.text[lo:offset]
    cut = max(prefix.rfind(";"), prefix.rfind("}"))
    start = lo + cut + 1 if cut != -1 else lo

    end = offset
    limit = min(len(src.text), offset + fwd)
    for _ in range(fwd_terminators):
        nxt = src.text.find(";", end + 1, limit)
        if nxt == -1:
            end = limit
            break
        end = nxt + 1
    return src.text[start:max(end, offset)]


def detect_local_auth(src: Source, offset: int) -> list[str]:
    # XHR splits url and headers across statements (open(); setRequestHeader();),
    # so that shape alone gets a second statement of reach.
    back = src.text[max(0, offset - 220): offset].rstrip()
    terms = 2 if RE_XHR_OPEN.search(back) else 1
    win = statement_span(src, offset, fwd_terminators=terms)
    return [name for name, rx in AUTH_SIGNALS if rx.search(win)]


# Which call shapes a given global mechanism is actually able to instrument.
# An axios interceptor does nothing for a raw fetch() or a jQuery call.
INTERCEPTOR_COVERS = {
    "axios-request-interceptor": {"http client verb"},
    "angular-http-interceptor": {"http client verb"},
    "fetch-wrapper": {"fetch()"},
    "jquery-ajax-setup": {"jQuery.get", "jQuery.post", "jQuery.getJSON",
                          "jQuery.getScript", "jQuery.load", "ajax wrapper"},
    "msal-auth0-oidc": None,  # token library, could be wired to anything
}


def applicable_interceptors(file_level: list[str], evidence: str) -> list[str]:
    out = []
    for name in file_level:
        covers = INTERCEPTOR_COVERS.get(name, None)
        if covers is None or evidence in covers:
            out.append(name)
    return out


def classify_auth(local: list[str], file_level: list[str],
                  evidence: str = "") -> tuple[str, str]:
    """Return (status, rationale)."""
    strong = {"bearer-header", "authorization-header", "set-request-header-auth",
              "api-key-header", "bearer-template", "auth-helper-call"}
    if strong.intersection(local):
        return "explicit", "auth material attached at the call site"
    if "cookie-credentials" in local:
        return "cookie", "relies on cookies (withCredentials / credentials:include)"
    if "csrf-header" in local:
        return "cookie", "CSRF token present, implies cookie-based session"
    if "token-var" in local:
        return "probable", "a token variable is referenced nearby"
    covering = applicable_interceptors(file_level, evidence) if evidence else file_level
    if covering:
        return "interceptor", ("no auth at the call site; file installs "
                               + ", ".join(covering))
    return "none-observed", "no authorization material observed for this call site"


# --------------------------------------------------------------------------
# Parameter extraction
# --------------------------------------------------------------------------
RE_BODY_OBJ = re.compile(r"\b(?:body|data|params|payload)\s*:\s*(?:JSON\.stringify\s*\(\s*)?\{([^{}]{0,400})\}")
RE_KEY = re.compile(r"([A-Za-z_$][\w$\-]*)\s*:")


def extract_params(raw: str, src: Source, offset: int) -> list[dict]:
    params: list[dict] = []
    seen = set()
    q = raw.split("?", 1)[1] if "?" in raw else ""
    if q:
        for k, v in parse_qsl(q, keep_blank_values=True):
            if k not in seen:
                seen.add(k)
                params.append({"name": k, "loc": "query", "example": v})
    for ph in re.findall(r"\{([A-Za-z_][\w]*)\}", raw):
        if ph not in seen:
            seen.add(ph)
            params.append({"name": ph, "loc": "path", "example": ""})
    # Stop at the first statement terminator so the next call's options object
    # does not donate its keys to this endpoint.
    fwd = src.text[offset: offset + 400]
    term = fwd.find(";")
    if term != -1:
        fwd = fwd[:term]
    m = RE_BODY_OBJ.search(fwd)
    if m:
        for k in RE_KEY.findall(m.group(1)):
            if k not in seen and k.lower() not in ("method", "headers", "url"):
                seen.add(k)
                params.append({"name": k, "loc": "body", "example": ""})
    return params


# --------------------------------------------------------------------------
# DOM XSS
# --------------------------------------------------------------------------
DOM_SOURCES = [
    ("location.search", re.compile(r"location\s*\.\s*search")),
    ("location.hash", re.compile(r"location\s*\.\s*hash")),
    ("location.href", re.compile(r"location\s*\.\s*href")),
    ("location.pathname", re.compile(r"location\s*\.\s*pathname")),
    ("document.URL", re.compile(r"document\s*\.\s*(?:URL|documentURI|baseURI)")),
    ("document.referrer", re.compile(r"document\s*\.\s*referrer")),
    ("window.name", re.compile(r"\bwindow\s*\.\s*name\b")),
    ("document.cookie", re.compile(r"document\s*\.\s*cookie")),
    ("postMessage.data", re.compile(r"\b(?:event|e|msg|ev)\s*\.\s*data\b|addEventListener\s*\(\s*['\"]message['\"]")),
    ("URLSearchParams", re.compile(r"new\s+URLSearchParams\s*\(")),
    ("history.state", re.compile(r"history\s*\.\s*state")),
    ("webStorage", re.compile(r"(?:local|session)Storage\s*(?:\.\s*getItem\s*\(|\[)")),
    ("hashchange", re.compile(r"['\"]hashchange['\"]")),
    ("bare-location", re.compile(r"(?<![\w.])location(?![\w.])")),
]

DOM_SINKS = [
    ("innerHTML", re.compile(r"\.\s*innerHTML\s*(?:\+?=)"), "high"),
    ("outerHTML", re.compile(r"\.\s*outerHTML\s*(?:\+?=)"), "high"),
    ("insertAdjacentHTML", re.compile(r"\.\s*insertAdjacentHTML\s*\("), "high"),
    ("document.write", re.compile(r"document\s*\.\s*write(?:ln)?\s*\("), "high"),
    ("eval", re.compile(r"(?<![\w.])eval\s*\("), "critical"),
    ("Function-ctor", re.compile(r"new\s+Function\s*\(|(?<![\w.])Function\s*\(\s*['\"]"), "critical"),
    ("setTimeout-string", re.compile(r"set(?:Timeout|Interval)\s*\(\s*['\"`]"), "high"),
    ("setTimeout-var", re.compile(r"set(?:Timeout|Interval)\s*\(\s*[A-Za-z_$][\w$.]*\s*,"), "low"),
    ("jQuery.html", re.compile(r"\.\s*(?:html|append|prepend|after|before|replaceWith|wrap)\s*\("), "high"),
    ("jQuery-selector-sink", re.compile(r"\$\s*\(\s*(?!['\"`])[A-Za-z_$][\w$.]*\s*\)"), "medium"),
    ("srcdoc", re.compile(r"\.\s*srcdoc\s*="), "high"),
    ("script.src", re.compile(r"\.\s*src\s*=\s*[A-Za-z_$][\w$.]*"), "medium"),
    ("location-assign", re.compile(r"(?:location\s*(?:\.\s*(?:href|assign|replace))?\s*=|location\s*\.\s*(?:assign|replace)\s*\()"), "medium"),
    ("setAttribute-danger", re.compile(r"setAttribute\s*\(\s*['\"](?:href|src|srcdoc|action|formaction|data|onclick|on\w+)['\"]", re.I), "high"),
    ("createContextualFragment", re.compile(r"createContextualFragment\s*\("), "high"),
    ("dangerouslySetInnerHTML", re.compile(r"dangerouslySetInnerHTML"), "high"),
    ("v-html", re.compile(r"v-html\s*="), "high"),
    ("angular-trustAsHtml", re.compile(r"trustAsHtml\s*\(|bypassSecurityTrust(?:Html|Script|Url|ResourceUrl)\s*\("), "high"),
    ("angular-sce-disabled", re.compile(r"\$sceProvider\s*\.\s*enabled\s*\(\s*false"), "high"),
    ("document.domain", re.compile(r"document\s*\.\s*domain\s*="), "low"),
    ("jQuery.globalEval", re.compile(r"globalEval\s*\(|\$\.\s*parseHTML\s*\("), "high"),
]
RE_TAINT_ASSIGN = re.compile(
    r"(?:var|let|const)?\s*([A-Za-z_$][\w$]*)\s*=\s*([^;\n]{0,200})")


RESERVED = {"function", "return", "if", "for", "while", "new", "var", "let",
            "const", "typeof", "else", "case", "do", "in", "of"}


def find_tainted_vars(src: Source, passes: int = 3) -> dict[str, str]:
    """Variables carrying attacker-controllable data, propagated a few hops.

    Pass 1 seeds from a direct source expression; later passes carry taint through
    `var b = a.trim()` style reassignment so multi-step flows are not missed.
    """
    assigns = []
    for m in RE_TAINT_ASSIGN.finditer(src.text):
        name, rhs = m.group(1), m.group(2)
        if name in RESERVED:
            continue
        assigns.append((name, rhs))

    tainted: dict[str, str] = {}
    for name, rhs in assigns:
        for sname, srx in DOM_SOURCES:
            if sname == "bare-location":
                continue
            if srx.search(rhs):
                tainted.setdefault(name, sname)
                break

    for _ in range(passes - 1):
        grew = False
        for name, rhs in assigns:
            if name in tainted or len(name) < 2:
                continue  # single-letter names propagate too loosely
            for tv, origin in list(tainted.items()):
                if re.search(r"(?<![\w$.])" + re.escape(tv) + r"(?![\w$])", rhs):
                    tainted[name] = origin
                    grew = True
                    break
        if not grew:
            break
    return tainted


def scan_dom_xss(src: Source) -> list[dict]:
    findings = []
    tainted = find_tainted_vars(src)
    for sink_name, rx, base_sev in DOM_SINKS:
        for m in rx.finditer(src.text):
            off = m.start()
            line = src.line_text(off)
            stmt = statement_span(src, off, back=250, fwd=250, fwd_terminators=1)
            hit_sources = [n for n, srx in DOM_SOURCES
                           if n != "bare-location" and srx.search(stmt)]
            hit_taint = [f"{v} <- {s}" for v, s in tainted.items()
                         if re.search(r"(?<![\w$.])" + re.escape(v) + r"(?![\w$])", line)]
            if hit_sources:
                sev, conf = base_sev, "high"
            elif hit_taint:
                sev, conf = base_sev, "medium"
            else:
                sev, conf = "info", "low"
            findings.append({
                "file": src.name,
                "line": src.line_of(off),
                "sink": sink_name,
                "severity": sev,
                "confidence": conf,
                "sources": hit_sources,
                "tainted_vars": hit_taint[:4],
                "snippet": snippet(line, 220),
            })
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    conf_order = {"high": 0, "medium": 1, "low": 2}
    findings.sort(key=lambda f: (conf_order[f["confidence"]], order[f["severity"]]))
    return findings


# --------------------------------------------------------------------------
# Secrets / hardcoded material
# --------------------------------------------------------------------------
SECRET_PATTERNS = [
    ("aws-access-key-id", re.compile(r"\b(?:AKIA|ASIA|AIDA|AROA)[0-9A-Z]{16}\b")),
    ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("slack-token", re.compile(r"\bxox[baprs]-[0-9A-Za-z\-]{10,}\b")),
    ("github-token", re.compile(r"\bgh[pousr]_[0-9A-Za-z]{36,}\b")),
    ("stripe-key", re.compile(r"\b[sr]k_(?:live|test)_[0-9A-Za-z]{16,}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{4,}")),
    ("private-key-block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----")),
    ("basic-auth-url", re.compile(r"https?://[A-Za-z0-9._%\-]+:[^@\s/'\"]{3,}@[A-Za-z0-9.\-]+")),
    ("firebase-config", re.compile(r"\bfirebase(?:io|app)\.com|databaseURL\s*:")),
    ("assigned-secret", re.compile(
        r"\b(?:api[_-]?key|apikey|secret|client[_-]?secret|password|passwd|pwd|token|auth[_-]?key|access[_-]?key|private[_-]?key)"
        r"\s*[:=]\s*['\"]([^'\"\s]{8,120})['\"]", re.I)),
    ("connection-string", re.compile(r"\b(?:Data Source|Server|Initial Catalog|User ID|mongodb(?:\+srv)?://|postgres(?:ql)?://|mysql://)", re.I)),
]

PLACEHOLDER = re.compile(
    r"^(?:x{3,}|\*{3,}|\.{3,}|<[^>]+>|\{\{?[^}]*\}?\}|%[A-Z_]+%|\$\{[^}]*\}|"
    r"your[_-]?\w*|change[_-]?me|placeholder|example|dummy|sample|test|todo|none|null|undefined|"
    r"\[[^\]]*\])$", re.I)


def scan_secrets(src: Source) -> list[dict]:
    out = []
    seen = set()
    for name, rx in SECRET_PATTERNS:
        for m in rx.finditer(src.text):
            val = m.group(1) if m.groups() else m.group(0)
            if PLACEHOLDER.match(val.strip()):
                continue
            if name == "assigned-secret" and (len(set(val)) < 4 or val.lower() in ("password", "changeit")):
                continue
            key = (name, val[:60])
            if key in seen:
                continue
            seen.add(key)
            out.append({
                "file": src.name,
                "line": src.line_of(m.start()),
                "type": name,
                "value": val[:24] + ("..." if len(val) > 24 else ""),
                "snippet": snippet(src.line_text(m.start()), 160),
            })
    return out


# --------------------------------------------------------------------------
# ASP.NET / .axd specific observations
# --------------------------------------------------------------------------
ASPNET_NOTES = [
    ("ScriptResource.axd", re.compile(r"ScriptResource\.axd", re.I),
     "ASP.NET script resource handler. The d= parameter is an encrypted resource "
     "reference; legacy builds are affected by the padding-oracle issue (CVE-2010-3332). "
     "Confirm the patch level rather than assuming."),
    ("WebResource.axd", re.compile(r"WebResource\.axd", re.I),
     "ASP.NET web resource handler. Same padding-oracle family as ScriptResource.axd; "
     "also commonly used to enumerate embedded assembly resources."),
    ("Telerik.Web.UI.WebResource.axd", re.compile(r"Telerik\.Web\.UI\.WebResource\.axd", re.I),
     "Telerik UI handler. Historically affected by CVE-2017-9248 (dialog parameters "
     "encryption weakness) and CVE-2019-18935 (insecure deserialisation -> RCE). "
     "Version-check before testing."),
    ("Telerik.Web.UI.DialogHandler", re.compile(r"Telerik\.Web\.UI\.DialogHandler|Telerik\.Web\.UI\.SpellCheckHandler", re.I),
     "Telerik dialog/spellcheck handler - classic file-upload and deserialisation surface."),
    ("__doPostBack", re.compile(r"__doPostBack\s*\(", re.I),
     "WebForms postback. Every control that calls it is a server-side entry point; "
     "__EVENTTARGET / __EVENTARGUMENT are attacker-controlled."),
    ("__VIEWSTATE", re.compile(r"__VIEWSTATE|__VIEWSTATEGENERATOR|__EVENTVALIDATION", re.I),
     "ViewState present. Check for MAC-disabled ViewState and known machineKey leakage "
     "before considering deserialisation paths."),
    ("PageMethods", re.compile(r"\bPageMethods\s*\.", re.I),
     "ASP.NET AJAX page methods - each is a callable [WebMethod] on the hosting .aspx."),
    ("WebServiceProxy", re.compile(r"Sys\.Net\.WebServiceProxy|_invoke\s*\(", re.I),
     "ASP.NET AJAX service proxy; the generated JS enumerates the .asmx/.svc operations."),
    ("SignalR", re.compile(r"signalr|/signalr/hubs|HubConnection", re.I),
     "SignalR hub surface. /signalr/hubs exposes the generated hub proxy listing all "
     "server methods and their arity."),
    ("Elmah", re.compile(r"elmah\.axd", re.I),
     "ELMAH error log handler - frequently left world-readable and leaks stack traces, "
     "cookies and session identifiers."),
    ("Trace.axd", re.compile(r"trace\.axd", re.I),
     "ASP.NET trace handler - leaks per-request headers, cookies and server variables."),
    ("Reserved.ReportViewer", re.compile(r"Reserved\.ReportViewerWebControl\.axd", re.I),
     "SSRS ReportViewer handler; historically a source of information disclosure."),
    ("sourceMappingURL", re.compile(r"sourceMappingURL\s*=\s*(\S+)", re.I),
     "Source map reference. Fetching the .map recovers original sources (including "
     "comments and dead code paths) - analyse those too."),
    ("webpack-bundle", re.compile(r"webpackJsonp|__webpack_require__|webpackChunk"),
     "Webpack bundle. Chunk names and the module map often reveal lazily-loaded routes "
     "and admin-only code paths not reachable from the visible UI."),
    ("graphql", re.compile(r"graphql|__schema|gql`", re.I),
     "GraphQL usage detected. Check introspection, and note that a single /graphql "
     "endpoint hides many operations - enumerate them from the bundle."),
    ("feature-flags", re.compile(r"\b(?:isAdmin|hasRole|canEdit|featureFlag|permissions?\s*\.\s*includes)\b"),
     "Client-side authorisation logic. Anything gated only here is a server-side "
     "authorisation test case."),
]


def scan_notes(src: Source) -> list[dict]:
    out = []
    for name, rx, text in ASPNET_NOTES:
        m = rx.search(src.text)
        if m:
            out.append({
                "file": src.name,
                "line": src.line_of(m.start()),
                "topic": name,
                "note": text,
                "occurrences": len(rx.findall(src.text)),
            })
    return out

# --------------------------------------------------------------------------
# File loading
# --------------------------------------------------------------------------
RE_OWN_OUTPUT = re.compile(r'"tool"\s*:\s*"' + TOOL + '"')


def load_sources(paths: list[str], exts: set[str], max_mb: float,
                 skip: set[str] | None = None) -> list[Source]:
    files: list[str] = []
    for p in paths:
        if os.path.isdir(p):
            for root, dirs, names in os.walk(p):
                dirs[:] = [d for d in dirs if d not in (".git", "node_modules", ".svn")]
                for n in sorted(names):
                    if os.path.splitext(n)[1].lower() in exts:
                        files.append(os.path.join(root, n))
        elif os.path.isfile(p):
            files.append(p)
        else:
            print(f"[!] not found: {p}", file=sys.stderr)

    skip = {os.path.realpath(x) for x in (skip or set())}
    sources: list[Source] = []
    for f in files:
        if os.path.realpath(f) in skip:
            continue
        try:
            if os.path.getsize(f) > max_mb * 1024 * 1024:
                print(f"[!] skipping {f} (> {max_mb} MB, raise with --max-mb)", file=sys.stderr)
                continue
            text = open(f, "r", encoding="utf-8", errors="replace").read()
        except OSError as e:
            print(f"[!] cannot read {f}: {e}", file=sys.stderr)
            continue
        if RE_OWN_OUTPUT.search(text[:400]):
            print(f"[i] skipping {f} (a {TOOL} results file)", file=sys.stderr)
            continue
        # Source maps: analyse the embedded original sources too.
        if f.lower().endswith(".map"):
            try:
                data = json.loads(text)
                names = data.get("sources") or []
                contents = data.get("sourcesContent") or []
                for i, c in enumerate(contents):
                    if c:
                        nm = names[i] if i < len(names) else f"source{i}"
                        sources.append(Source(f"{f}!{nm}", c, origin=f))
                if contents:
                    continue
            except (ValueError, TypeError):
                pass
        sources.append(Source(f, text))
    return sources


# --------------------------------------------------------------------------
# scan
# --------------------------------------------------------------------------
def resolve_url(raw: str, base: str) -> tuple[str, str]:
    """Return (absolute_or_raw_url, path_only)."""
    if RE_ABS.match(raw):
        parts = urlsplit(raw)
        return raw, parts.path or "/"
    if raw.startswith("//"):
        return "https:" + raw, urlsplit("https:" + raw).path or "/"
    path = raw if raw.startswith("/") else "/" + raw
    path_only = path.split("?", 1)[0].split("#", 1)[0]
    if base:
        return base.rstrip("/") + path, path_only
    return path, path_only


def score_endpoint(path: str, auth_status: str, method: str) -> int:
    score = 0
    low = path.lower()
    hits = sum(1 for h in SENSITIVE_HINTS if h in low)
    score += min(hits, 3) * 10
    if auth_status == "none-observed":
        score += 30
    elif auth_status == "interceptor":
        score += 15
    elif auth_status == "probable":
        score += 5
    if method in ("POST", "PUT", "PATCH", "DELETE"):
        score += 15
    if RE_VERSION_PATH.match(path):
        score += 10
    if "{" in path:
        score += 10  # object-identifier in the path -> IDOR candidate
    return score


def cmd_scan(args) -> int:
    exts = set(DEFAULT_EXTS)
    for e in args.ext or []:
        exts.add(e if e.startswith(".") else "." + e)
    out = args.out or "results.json"
    sources = load_sources(args.paths, exts, args.max_mb, skip={out})
    if not sources:
        print("[!] no analysable files found", file=sys.stderr)
        return 1

    endpoints: dict[tuple, dict] = {}
    dom_xss: list[dict] = []
    secrets: list[dict] = []
    notes: list[dict] = []

    for src in sources:
        file_auth = detect_file_auth(src)
        for off, raw, kind in iter_literals(src):
            value = normalise_template(raw) if kind == "`" else raw
            value = value.replace("\\/", "/").strip()
            if not looks_like_endpoint(value):
                continue
            if not args.include_thirdparty and is_third_party(value):
                continue
            method, evidence = infer_method(src, off)
            url, path = resolve_url(value, args.base or "")
            local_auth = detect_local_auth(src, off)
            status, rationale = classify_auth(local_auth, file_auth, evidence)
            key = (method, url)
            if key in endpoints:
                rec = endpoints[key]
                rec["occurrences"] += 1
                if src.name not in rec["seen_in"]:
                    rec["seen_in"].append(src.name)
                # Keep the strongest auth evidence seen for this endpoint.
                rank = {"explicit": 0, "cookie": 1, "probable": 2, "interceptor": 3, "none-observed": 4}
                if rank[status] < rank[rec["auth"]["status"]]:
                    rec["auth"] = {"status": status, "rationale": rationale, "signals": local_auth}
                continue
            rec = {
                "url": url,
                "path": path,
                "raw": value,
                "method": method,
                "evidence": evidence,
                "file": src.name,
                "line": src.line_of(off),
                "occurrences": 1,
                "seen_in": [src.name],
                "params": extract_params(value, src, off),
                "auth": {"status": status, "rationale": rationale, "signals": local_auth},
                "file_auth": file_auth,
                "snippet": snippet(src.line_text(off), 200),
                "third_party": is_third_party(value),
            }
            rec["score"] = score_endpoint(path, status, method)
            endpoints[key] = rec

        dom_xss.extend(scan_dom_xss(src))
        secrets.extend(scan_secrets(src))
        notes.extend(scan_notes(src))

    eps = sorted(endpoints.values(), key=lambda r: (-r["score"], r["path"], r["method"]))
    results = {
        "meta": {
            "tool": TOOL,
            "version": VERSION,
            "generated": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "base": args.base or "",
            "target": args.target or "",
            "inputs": args.paths,
            "sources_analysed": len(sources),
            "source_names": [s.name for s in sources][:500],
        },
        "endpoints": eps,
        "dom_xss": dom_xss,
        "secrets": secrets,
        "notes": notes,
    }
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(results, fh, indent=2)

    ngaps = sum(1 for e in eps if e["auth"]["status"] == "none-observed")
    nxss = sum(1 for f in dom_xss if f["confidence"] in ("high", "medium"))
    print(f"[+] sources analysed : {len(sources)}")
    print(f"[+] endpoints        : {len(eps)}")
    print(f"[+] no auth observed : {ngaps}")
    print(f"[+] dom xss (h/m)    : {nxss}  (total sink hits: {len(dom_xss)})")
    print(f"[+] secrets          : {len(secrets)}")
    print(f"[+] platform notes   : {len(notes)}")
    print(f"[+] written          : {out}")
    return 0


# --------------------------------------------------------------------------
# shared loading / filtering
# --------------------------------------------------------------------------
def load_results(path: str) -> dict:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except OSError as e:
        sys.exit(f"[!] cannot read {path}: {e} (run `{TOOL} scan` first)")
    except ValueError as e:
        sys.exit(f"[!] {path} is not valid JSON: {e}")


def filter_endpoints(eps: list[dict], args) -> list[dict]:
    out = eps
    if not getattr(args, "include_thirdparty", False):
        out = [e for e in out if not e.get("third_party")]
    if getattr(args, "method", None):
        wanted = {m.strip().upper() for m in args.method.split(",")}
        out = [e for e in out if e["method"] in wanted]
    if getattr(args, "grep", None):
        rx = re.compile(args.grep, re.I)
        out = [e for e in out if rx.search(e["url"]) or rx.search(e["path"])]
    if getattr(args, "exclude", None):
        rx = re.compile(args.exclude, re.I)
        out = [e for e in out if not (rx.search(e["url"]) or rx.search(e["path"]))]
    if getattr(args, "no_auth_only", False):
        out = [e for e in out if e["auth"]["status"] == "none-observed"]
    if getattr(args, "auth", None):
        wanted = {a.strip() for a in args.auth.split(",")}
        out = [e for e in out if e["auth"]["status"] in wanted]
    if getattr(args, "min_score", None):
        out = [e for e in out if e["score"] >= args.min_score]
    return out


def print_table(rows: list[list[str]], headers: list[str]) -> None:
    widths = [len(h) for h in headers]
    for r in rows:
        for i, c in enumerate(r):
            widths[i] = max(widths[i], len(c))
    line = "  ".join(h.ljust(widths[i]) for i, h in enumerate(headers))
    print(line)
    print("  ".join("-" * widths[i] for i in range(len(headers))))
    for r in rows:
        print("  ".join(c.ljust(widths[i]) for i, c in enumerate(r)))


AUTH_LABEL = {
    "none-observed": "NONE",
    "interceptor": "intercept",
    "probable": "probable",
    "cookie": "cookie",
    "explicit": "explicit",
}


def cmd_endpoints(args) -> int:
    res = load_results(args.results)
    eps = filter_endpoints(res["endpoints"], args)
    if args.limit:
        eps = eps[: args.limit]
    if args.format == "json":
        print(json.dumps(eps, indent=2))
        return 0
    if args.format == "csv":
        print("score,method,path,auth,params,file,line")
        for e in eps:
            names = "|".join(p["name"] for p in e["params"])
            print(f'{e["score"]},{e["method"]},"{e["path"]}",{e["auth"]["status"]},'
                  f'"{names}","{e["file"]}",{e["line"]}')
        return 0
    if args.format == "plain":
        for e in eps:
            print(f'{e["method"]} {e["url"]}')
        return 0
    rows = [[str(e["score"]), e["method"], e["path"][:80],
             AUTH_LABEL.get(e["auth"]["status"], e["auth"]["status"]),
             ",".join(p["name"] for p in e["params"])[:36] or "-",
             f'{os.path.basename(e["file"])}:{e["line"]}']
            for e in eps]
    if not rows:
        print("(no endpoints matched)")
        return 0
    print_table(rows, ["SCORE", "METHOD", "PATH", "AUTH", "PARAMS", "SOURCE"])
    print(f"\n{len(rows)} endpoint(s). SCORE ranks manual-testing priority, not severity.")
    return 0


def cmd_authgaps(args) -> int:
    res = load_results(args.results)
    args.no_auth_only = False
    eps = filter_endpoints(res["endpoints"], args)
    buckets: dict[str, list[dict]] = {}
    for e in eps:
        buckets.setdefault(e["auth"]["status"], []).append(e)
    order = ["none-observed", "interceptor", "probable", "cookie", "explicit"]
    heading = {
        "none-observed": "NO AUTHORIZATION MATERIAL OBSERVED - highest priority for "
                         "unauthenticated-access testing",
        "interceptor": "AUTH ADDED GLOBALLY (interceptor/wrapper) - the call site itself "
                       "carries nothing; confirm the interceptor really covers this path",
        "probable": "A TOKEN VARIABLE IS NEARBY - inconclusive, verify in Burp",
        "cookie": "COOKIE / SESSION BASED - test for CSRF and for cross-account access",
        "explicit": "EXPLICIT AUTH AT THE CALL SITE - still test for broken object-level "
                    "and function-level authorization",
    }
    for status in order:
        group = buckets.get(status, [])
        if not group or (args.only and status != "none-observed"):
            continue
        print(f"\n=== {heading[status]} ({len(group)}) ===")
        rows = [[str(e["score"]), e["method"], e["path"][:76],
                 ",".join(e["auth"]["signals"])[:30] or "-",
                 f'{os.path.basename(e["file"])}:{e["line"]}'] for e in group[: args.limit or None]]
        print_table(rows, ["SCORE", "METHOD", "PATH", "SIGNALS", "SOURCE"])
    print("\nStatic inference only: a missing client-side header does not prove the server "
          "allows anonymous access. Confirm each one in Repeater with credentials removed.")
    return 0


def cmd_domxss(args) -> int:
    res = load_results(args.results)
    findings = res["dom_xss"]
    if args.min_confidence:
        rank = {"high": 0, "medium": 1, "low": 2}
        findings = [f for f in findings if rank[f["confidence"]] <= rank[args.min_confidence]]
    if args.sink:
        findings = [f for f in findings if args.sink.lower() in f["sink"].lower()]
    if args.limit:
        findings = findings[: args.limit]
    if args.format == "json":
        print(json.dumps(findings, indent=2))
        return 0
    if not findings:
        print("(no findings at this confidence level)")
        return 0
    for f in findings:
        print(f'[{f["severity"].upper()}/{f["confidence"]}] {f["sink"]}  '
              f'{f["file"]}:{f["line"]}')
        if f["sources"]:
            print(f'    sources : {", ".join(f["sources"])}')
        if f["tainted_vars"]:
            print(f'    tainted : {", ".join(f["tainted_vars"])}')
        print(f'    code    : {f["snippet"]}')
        print()
    print(f"{len(findings)} finding(s). Confidence high = a source and a sink share a "
          "statement window; medium = a variable assigned from a source reaches the sink; "
          "low = sink with no visible source. Confirm every one by driving the sink in a browser.")
    return 0


def cmd_secrets(args) -> int:
    res = load_results(args.results)
    items = res["secrets"]
    if args.format == "json":
        print(json.dumps(items, indent=2))
        return 0
    if not items:
        print("(no hardcoded credential-shaped strings found)")
        return 0
    rows = [[i["type"], i["value"], f'{os.path.basename(i["file"])}:{i["line"]}'] for i in items]
    print_table(rows, ["TYPE", "VALUE", "SOURCE"])
    print("\nVerify each before reporting: many are public identifiers (Firebase web "
          "config, publishable Stripe keys) and are not findings on their own.")
    return 0


# --------------------------------------------------------------------------
# wordlist
# --------------------------------------------------------------------------
STOP_SEGMENTS = {"", ".", "..", "api", "http:", "https:"}


def cmd_wordlist(args) -> int:
    res = load_results(args.results)
    eps = filter_endpoints(res["endpoints"], args)
    words: list[str] = []
    modes = {m.strip() for m in args.mode.split(",")}
    if "all" in modes:
        modes = {"paths", "segments", "params", "files", "dirs"}

    for e in eps:
        path = e["path"]
        if "paths" in modes:
            words.append(path)
        segs = [s for s in path.split("/") if s]
        if "segments" in modes:
            for s in segs:
                if s.lower() not in STOP_SEGMENTS and not s.startswith("{"):
                    words.append(s)
        if "files" in modes and segs and "." in segs[-1]:
            words.append(segs[-1])
        if "dirs" in modes:
            acc = ""
            for s in segs[:-1] if ("." in segs[-1] if segs else False) else segs:
                if s.startswith("{"):
                    break
                acc += "/" + s
                words.append(acc)
        if "params" in modes:
            words.extend(p["name"] for p in e["params"])

    if "params" in modes:
        # Parameter names also hide in the raw query strings of absolute URLs.
        for e in eps:
            if "?" in e["raw"]:
                words.extend(k for k, _ in parse_qsl(e["raw"].split("?", 1)[1], keep_blank_values=True))

    clean: list[str] = []
    seen = set()
    for w in words:
        w = w.strip()
        if args.strip_leading_slash:
            w = w.lstrip("/")
        if args.strip_ext:
            w = re.sub(r"\.[A-Za-z0-9]{1,6}$", "", w)
        if args.lower:
            w = w.lower()
        if not w or len(w) < args.min_len or len(w) > args.max_len:
            continue
        if "{" in w or "$" in w or "*" in w:
            continue
        if args.alnum_only and not re.fullmatch(r"[A-Za-z0-9_\-./]+", w):
            continue
        if w in seen:
            continue
        seen.add(w)
        clean.append(w)

    clean.sort(key=lambda s: (s.count("/"), s.lower()) if args.sort else (0, 0))
    if not clean:
        print(f"[!] no words produced. Check --mode ({args.mode}) against what the scan "
              f"found, and loosen any --grep/--min-score filters.", file=sys.stderr)
        return 1
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write("\n".join(clean) + "\n")
        print(f"[+] {len(clean)} word(s) -> {args.out}")
        print(f"    ffuf -w {args.out} -u {res['meta'].get('base') or 'https://TARGET'}/FUZZ -mc all -fc 404")
    else:
        print("\n".join(clean))
    return 0


# --------------------------------------------------------------------------
# Burp-ready raw request
# --------------------------------------------------------------------------
UA_CHROME = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
             "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")

PLACEHOLDER_VALUE = {
    "id": "1", "userid": "1", "user_id": "1", "uid": "1", "accountid": "1",
    "page": "1", "limit": "10", "offset": "0", "size": "10", "count": "10",
    "q": "test", "query": "test", "search": "test", "term": "test",
    "email": "test@example.com", "username": "test", "name": "test",
    "password": "Passw0rd!", "token": "REPLACE_ME", "lang": "en", "locale": "en-US",
    "format": "json", "type": "1", "status": "1", "date": "2026-01-01",
    "file": "test.txt", "filename": "test.txt", "path": "test", "url": "https://example.com",
}


def guess_value(name: str) -> str:
    return PLACEHOLDER_VALUE.get(name.lower(), "FUZZ")


def find_endpoint(res: dict, needle: str, method: str | None) -> dict | None:
    eps = res["endpoints"]
    cands = [e for e in eps if e["path"] == needle or e["url"] == needle]
    if not cands:
        cands = [e for e in eps if needle.lower() in e["url"].lower()]
    if method:
        m = method.upper()
        exact = [e for e in cands if e["method"] == m]
        if exact:
            return exact[0]
    return cands[0] if cands else None


def build_request(method: str, url: str, *, host: str = "", params: list[dict] | None = None,
                  body: str | None = None, content_type: str | None = None,
                  headers: list[str] | None = None, cookie: str = "",
                  auth: str = "", strip_auth: bool = False, http2_style: bool = False,
                  referer: str = "", accept: str = "") -> str:
    params = params or []
    parts = urlsplit(url) if RE_ABS.match(url) else urlsplit("https://" + host.strip("/") + url
                                                             if host else url)
    hostname = parts.netloc or host
    if not hostname:
        hostname = "TARGET-HOST"
    scheme = parts.scheme or "https"
    path = parts.path or "/"
    query = parts.query
    had_query = bool(query)

    # Fill unresolved path placeholders such as /api/users/{id}
    def fill(m):
        return guess_value(m.group(1))
    path = re.sub(r"\{([A-Za-z_][\w]*)\}", fill, path)

    query_params = [p for p in params if p["loc"] == "query"]
    body_params = [p for p in params if p["loc"] == "body"]

    if not query and query_params and method in ("GET", "HEAD", "DELETE", "OPTIONS"):
        query = "&".join(f'{p["name"]}={p["example"] or guess_value(p["name"])}'
                         for p in query_params)
    target = path + ("?" + query if query else "")

    # Body
    if body is None and method in ("POST", "PUT", "PATCH"):
        if body_params:
            body = json.dumps({p["name"]: guess_value(p["name"]) for p in body_params})
            content_type = content_type or "application/json"
        elif query_params and not had_query:
            # Only move params into the body if they are not already in the URL.
            body = "&".join(f'{p["name"]}={p["example"] or guess_value(p["name"])}'
                            for p in query_params)
            content_type = content_type or "application/x-www-form-urlencoded"
        else:
            body = "{}"
            content_type = content_type or "application/json"
    if body is not None and content_type is None:
        content_type = "application/json" if body.lstrip().startswith(("{", "[")) \
            else "application/x-www-form-urlencoded"

    origin = f"{scheme}://{hostname}"
    lines = [f"{method} {target} HTTP/1.1", f"Host: {hostname}"]
    lines.append(f"User-Agent: {UA_CHROME}")
    lines.append("Accept: " + (accept or ("application/json, text/plain, */*"
                                          if (content_type or "").startswith("application/json")
                                          else "*/*")))
    lines.append("Accept-Language: en-US,en;q=0.9")
    lines.append("Accept-Encoding: gzip, deflate")
    if content_type and body is not None:
        lines.append(f"Content-Type: {content_type}")
    lines.append(f"Origin: {origin}")
    lines.append(f"Referer: {referer or origin + '/'}")
    lines.append("X-Requested-With: XMLHttpRequest")
    if auth and not strip_auth:
        lines.append(f"Authorization: {auth}")
    if cookie and not strip_auth:
        lines.append(f"Cookie: {cookie}")
    for h in headers or []:
        if strip_auth and re.match(r"\s*(authorization|cookie|x-api-key|x-auth[\w-]*|x-csrf[\w-]*)\s*:", h, re.I):
            continue
        lines.append(h.strip())
    if body is not None:
        lines.append(f"Content-Length: {len(body.encode('utf-8'))}")
    lines.append("Connection: close" if http2_style else "Connection: keep-alive")

    raw = "\r\n".join(lines) + "\r\n\r\n"
    if body is not None:
        raw += body
    return raw


def cmd_request(args) -> int:
    params: list[dict] = []
    ep = None
    if args.results and os.path.exists(args.results) and not args.url:
        res = load_results(args.results)
        ep = find_endpoint(res, args.endpoint, args.method)
        if not ep:
            sys.exit(f"[!] no endpoint matching {args.endpoint!r} in {args.results}. "
                     f"Try `{TOOL} endpoints {args.results} --grep <substring>`.")
        url = ep["url"]
        method = (args.method or ep["method"]).upper()
        params = ep["params"]
        host = args.host or urlsplit(url).netloc or urlsplit(res["meta"].get("base", "")).netloc
    else:
        url = args.url or args.endpoint
        if not url:
            sys.exit("[!] give --url, or an endpoint plus a results.json")
        method = (args.method or "GET").upper()
        host = args.host or urlsplit(url).netloc

    body = None
    if args.body_file:
        body = open(args.body_file, "r", encoding="utf-8").read()
    elif args.body is not None:
        body = args.body

    common = dict(host=host, params=params, body=body, content_type=args.content_type,
                  headers=args.header, cookie=args.cookie or "", auth=args.auth or "",
                  referer=args.referer or "", accept=args.accept or "")

    authed = build_request(method, url, strip_auth=False, **common)
    if args.pair or args.no_auth:
        stripped = build_request(method, url, strip_auth=True, **common)

    def emit(text: str, suffix: str, label: str):
        if args.out:
            root, ext = os.path.splitext(args.out)
            name = args.out if not args.pair else f"{root}{suffix}{ext or '.txt'}"
            with open(name, "w", encoding="utf-8", newline="") as fh:
                fh.write(text)
            print(f"[+] {label} -> {name}")
        else:
            if args.pair:
                print(f"===== {label} =====")
            print(text)
            if args.pair:
                print()

    if args.pair:
        emit(authed, "_authed", "baseline (credentials present)")
        emit(stripped, "_unauth", "auth-stripped twin")
        if not args.out:
            print("Send both from Repeater and diff the responses. Identical 200s mean the "
                  "server never enforced the credential.")
    elif args.no_auth:
        emit(stripped, "", "auth-stripped request")
    else:
        emit(authed, "", "request")

    if ep and not args.out:
        print(f"# source: {ep['file']}:{ep['line']}  auth-status: {ep['auth']['status']}",
              file=sys.stderr)
    return 0


# --------------------------------------------------------------------------
# report
# --------------------------------------------------------------------------
def cmd_report(args) -> int:
    res = load_results(args.results)
    meta = res["meta"]
    eps = [e for e in res["endpoints"] if not e.get("third_party")]
    third = [e for e in res["endpoints"] if e.get("third_party")]
    gaps = [e for e in eps if e["auth"]["status"] == "none-observed"]
    intercept = [e for e in eps if e["auth"]["status"] == "interceptor"]
    xss = res["dom_xss"]
    xss_hi = [f for f in xss if f["confidence"] == "high"]
    xss_md = [f for f in xss if f["confidence"] == "medium"]
    secrets = res["secrets"]
    notes = res["notes"]
    target = args.target or meta.get("target") or meta.get("base") or "the in-scope application"

    methods: dict[str, int] = {}
    for e in eps:
        methods[e["method"]] = methods.get(e["method"], 0) + 1
    method_line = ", ".join(f"{k} {v}" for k, v in sorted(methods.items(), key=lambda x: -x[1]))

    L: list[str] = []
    a = L.append
    a(f"# Client-Side Static Analysis - {target}")
    a("")
    a(f"**Generated:** {meta['generated']}  ")
    a(f"**Tool:** {meta['tool']} {meta.get('version', '')} (offline static analysis)  ")
    a(f"**Inputs:** {', '.join(meta['inputs'])} - {meta['sources_analysed']} source unit(s)")
    a("")
    a("## 1. Scope and method")
    a("")
    a("This report covers **static analysis of client-side JavaScript and ASP.NET `.axd` "
      "resources only**. Nothing here was validated against a live host by the tooling; "
      "every item below is a lead that the tester confirms manually in an intercepting "
      "proxy. No requests were issued during analysis.")
    a("")
    a("Method: string-literal and call-site extraction to recover the endpoint surface, "
      "call-site inspection for authorization material, source-to-sink matching for DOM "
      "XSS, and pattern matching for hardcoded credentials and platform fingerprints. "
      "Mapped to OWASP WSTG (INFO-02 fingerprinting, CONF-04 client-side surface, ATHZ "
      "authorization, CLNT-01 DOM XSS) and OWASP API Top 10 (API1 BOLA, API5 BFLA).")
    a("")
    a("## 2. Summary of what was recovered")
    a("")
    a("| Item | Count |")
    a("|---|---|")
    a(f"| Distinct first-party endpoints | {len(eps)} |")
    a(f"| Third-party / CDN references (excluded) | {len(third)} |")
    a(f"| Endpoints with **no** authorization material at the call site | {len(gaps)} |")
    a(f"| Endpoints relying on a global interceptor | {len(intercept)} |")
    a(f"| DOM XSS leads - high confidence | {len(xss_hi)} |")
    a(f"| DOM XSS leads - medium confidence | {len(xss_md)} |")
    a(f"| Dangerous-sink hits in total | {len(xss)} |")
    a(f"| Hardcoded credential-shaped strings | {len(secrets)} |")
    a(f"| Platform / framework observations | {len(notes)} |")
    a("")
    a(f"Methods observed: {method_line or 'n/a'}.")
    a("")

    a("## 3. Endpoint inventory")
    a("")
    a("Ranked by testing priority (sensitive path keywords, state-changing method, "
      "missing client-side auth, identifiers in the path). Priority is **not** severity.")
    a("")
    a("| # | Pri | Method | Path | Auth signal | Params | Source |")
    a("|---:|---:|---|---|---|---|---|")
    top = eps[: args.max_endpoints]
    for i, e in enumerate(top, 1):
        p = ", ".join(x["name"] for x in e["params"])[:48] or "-"
        a(f'| {i} | {e["score"]} | {e["method"]} | `{e["path"][:90]}` | '
          f'{AUTH_LABEL.get(e["auth"]["status"], e["auth"]["status"])} | {p} | '
          f'`{os.path.basename(e["file"])}:{e["line"]}` |')
    if len(eps) > len(top):
        a("")
        a(f"_{len(eps) - len(top)} further endpoints omitted - full set in `{args.results}`._")
    a("")

    a("## 4. Endpoints with no observed authorization (possible unauthenticated access)")
    a("")
    if not gaps:
        a("Every recovered endpoint carried authorization material at or near its call site, "
          "or sat behind a global interceptor. No candidates from static analysis alone.")
    else:
        a("These call sites attach no `Authorization` header, API key, CSRF token or "
          "`withCredentials` flag. **This is a lead, not a finding** - the server may still "
          "enforce a session cookie sent automatically by the browser. Confirm each by "
          "replaying the request in Repeater with all credential material removed.")
        a("")
        a("| Pri | Method | Path | Source |")
        a("|---:|---|---|---|")
        for e in gaps[: args.max_endpoints]:
            a(f'| {e["score"]} | {e["method"]} | `{e["path"][:90]}` | '
              f'`{os.path.basename(e["file"])}:{e["line"]}` |')
        a("")
        a("**Test procedure per endpoint**")
        a("")
        a("1. Capture the endpoint working as an authenticated user.")
        a("2. Remove `Authorization`, `Cookie` and any custom auth headers; resend. "
          "A 200 with real data is a broken function-level authorization finding (API5 / WSTG-ATHZ-01).")
        a("3. Resend as a *different, lower-privileged* user. Same data returned means BOLA (API1).")
        a("4. Where the path carries an identifier, iterate it across objects you do not own.")
        a("5. Retry the same path with an alternate verb (`GET`->`POST`/`PUT`/`DELETE`) and with "
          "`X-HTTP-Method-Override`, in case only one verb is protected.")
        a("")
        a(f"Generate the paired requests with: "
          f"`jsvapt.py request {args.results} --endpoint <path> --pair --host <host>`")
    a("")

    a("## 5. DOM-based XSS leads")
    a("")
    if not (xss_hi or xss_md):
        a("No dangerous sink was found in a statement that also references a controllable "
          "source. Low-confidence sink hits, if any, are listed in the JSON output.")
    else:
        a("A finding requires an attacker-controllable **source** reaching a dangerous "
          "**sink** without adequate encoding. The pairs below share a statement window; "
          "each still needs to be driven in a browser to confirm execution.")
        a("")
        a("| Severity | Conf | Sink | Source(s) | Location |")
        a("|---|---|---|---|---|")
        for f in (xss_hi + xss_md)[: args.max_findings]:
            srcs = ", ".join(f["sources"]) or ", ".join(f["tainted_vars"]) or "-"
            a(f'| {f["severity"]} | {f["confidence"]} | `{f["sink"]}` | {srcs[:60]} | '
              f'`{os.path.basename(f["file"])}:{f["line"]}` |')
        a("")
        a("**Confirmation workflow**")
        a("")
        a("1. Set a DevTools breakpoint on the sink and drive the source (URL fragment, "
          "query string, `postMessage`, storage value).")
        a("2. Prove reflection first with a benign marker, then escalate to execution.")
        a("3. For fragment-based sinks remember the fragment never reaches the server - "
          "WAF and server-side filters are not in the path.")
        a("4. Record the exact minimal URL or message payload for the write-up.")
        a("")
        for f in (xss_hi + xss_md)[: args.max_findings]:
            a(f'- `{f["file"]}:{f["line"]}` - `{f["sink"]}`  ')
            a(f'  ```js')
            a(f'  {f["snippet"]}')
            a(f'  ```')
    a("")

    a("## 6. Hardcoded material in client-side code")
    a("")
    if not secrets:
        a("No credential-shaped strings identified.")
    else:
        a("Client-side code is public. Anything below is disclosed to every visitor; triage "
          "each for whether it is a genuine secret or a public identifier.")
        a("")
        a("| Type | Value (truncated) | Location |")
        a("|---|---|---|")
        for s in secrets[: args.max_findings]:
            a(f'| {s["type"]} | `{s["value"]}` | `{os.path.basename(s["file"])}:{s["line"]}` |')
        a("")
        a("Publishable Stripe keys, Firebase web config and Google Maps browser keys are "
          "public by design - report them only where the key lacks referrer/scope "
          "restrictions or grants server-side capability.")
    a("")

    a("## 7. Platform and framework observations")
    a("")
    if not notes:
        a("No framework-specific markers identified.")
    else:
        for n in notes:
            a(f'- **{n["topic"]}** (`{os.path.basename(n["file"])}:{n["line"]}`, '
              f'{n["occurrences"]}x) - {n["note"]}')
    a("")

    a("## 8. Recommended next actions")
    a("")
    a("1. Build a wordlist from this surface and fuzz for siblings the bundle does not "
      f"reference: `jsvapt.py wordlist {args.results} --mode all --out wl.txt`.")
    a("2. Work the no-auth candidates in section 4 through the authenticated / "
      "unauthenticated / cross-user matrix.")
    a("3. Confirm the DOM XSS leads in section 5 in a browser.")
    a("4. Pull any source maps and re-run the scan over the recovered original sources - "
      "they usually expose more routes than the minified bundle.")
    a("5. Re-run this scan after authenticating: logged-in users are often served "
      "additional bundles containing admin-only routes.")
    a("")
    a("## 9. Limitations")
    a("")
    a("- Static analysis only; no request was sent and no finding here is confirmed.")
    a("- Endpoints assembled at runtime from variables, or fetched from a config API, "
      "are not recoverable by literal extraction.")
    a("- Authorization status is inferred from the *client*; server-side enforcement can "
      "differ in either direction.")
    a("- Sink hits without a matched source are not evidence of a vulnerability.")
    a("- Minified or obfuscated code lowers recall across every check.")

    text = "\n".join(L) + "\n"
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text)
        print(f"[+] report -> {args.out}")
    else:
        print(text)
    return 0


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------
def add_filters(p):
    p.add_argument("--method", help="comma-separated methods to keep, e.g. POST,PUT")
    p.add_argument("--grep", help="regex the URL or path must match")
    p.add_argument("--exclude", help="regex the URL or path must NOT match")
    p.add_argument("--auth", dest="auth", help="keep only these auth statuses "
                   "(none-observed,interceptor,probable,cookie,explicit)")
    p.add_argument("--no-auth-only", action="store_true",
                   help="only endpoints with no observed authorization")
    p.add_argument("--min-score", type=int, help="minimum priority score")
    p.add_argument("--include-thirdparty", action="store_true",
                   help="keep CDN/analytics hosts")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog=TOOL, description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--version", action="version", version=f"{TOOL} {VERSION}")
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="parse JS/.axd files into results.json")
    s.add_argument("paths", nargs="+", help="files or directories")
    s.add_argument("--out", "-o", default="results.json")
    s.add_argument("--base", help="base URL to prefix relative paths, e.g. https://app.tgt")
    s.add_argument("--target", help="target name for the report header")
    s.add_argument("--ext", action="append", help="extra file extension to include")
    s.add_argument("--max-mb", type=float, default=25.0)
    s.add_argument("--include-thirdparty", action="store_true")
    s.set_defaults(func=cmd_scan)

    e = sub.add_parser("endpoints", help="list discovered endpoints")
    e.add_argument("results", nargs="?", default="results.json")
    e.add_argument("--format", choices=["table", "json", "csv", "plain"], default="table")
    e.add_argument("--limit", type=int)
    add_filters(e)
    e.set_defaults(func=cmd_endpoints)

    g = sub.add_parser("authgaps", help="endpoints lacking observed authorization")
    g.add_argument("results", nargs="?", default="results.json")
    g.add_argument("--only", action="store_true", help="show only the none-observed bucket")
    g.add_argument("--limit", type=int)
    add_filters(g)
    g.set_defaults(func=cmd_authgaps)

    w = sub.add_parser("wordlist", help="emit a wordlist for ffuf / Burp Intruder")
    w.add_argument("results", nargs="?", default="results.json")
    w.add_argument("--mode", default="segments",
                   help="paths,segments,dirs,files,params or all (comma-separated)")
    w.add_argument("--out", "-o")
    w.add_argument("--min-len", type=int, default=2)
    w.add_argument("--max-len", type=int, default=80)
    w.add_argument("--lower", action="store_true")
    w.add_argument("--sort", action="store_true", default=True)
    w.add_argument("--strip-ext", action="store_true")
    w.add_argument("--strip-leading-slash", action="store_true")
    w.add_argument("--alnum-only", action="store_true")
    add_filters(w)
    w.set_defaults(func=cmd_wordlist)

    r = sub.add_parser("request", help="emit a Burp Repeater-ready raw HTTP request")
    r.add_argument("results", nargs="?", default="results.json")
    r.add_argument("--endpoint", "-e", help="path or URL substring to look up")
    r.add_argument("--url", help="build from a literal URL instead of results.json")
    r.add_argument("--method", "-X")
    r.add_argument("--host", help="override the Host header")
    r.add_argument("--body", help="raw request body")
    r.add_argument("--body-file", help="read the body from a file")
    r.add_argument("--content-type")
    r.add_argument("--header", "-H", action="append", help="extra header, repeatable")
    r.add_argument("--cookie")
    r.add_argument("--auth", help="Authorization header value, e.g. 'Bearer eyJ...'")
    r.add_argument("--referer")
    r.add_argument("--accept")
    r.add_argument("--no-auth", action="store_true", help="emit the auth-stripped variant")
    r.add_argument("--pair", action="store_true",
                   help="emit both the baseline and the auth-stripped twin")
    r.add_argument("--http2-style", action="store_true", help="use Connection: close")
    r.add_argument("--out", "-o")
    r.set_defaults(func=cmd_request)

    d = sub.add_parser("domxss", help="DOM XSS source/sink findings")
    d.add_argument("results", nargs="?", default="results.json")
    d.add_argument("--min-confidence", choices=["high", "medium", "low"], default="medium")
    d.add_argument("--sink", help="filter by sink name substring")
    d.add_argument("--format", choices=["text", "json"], default="text")
    d.add_argument("--limit", type=int)
    d.set_defaults(func=cmd_domxss)

    x = sub.add_parser("secrets", help="hardcoded credential-shaped strings")
    x.add_argument("results", nargs="?", default="results.json")
    x.add_argument("--format", choices=["text", "json"], default="text")
    x.set_defaults(func=cmd_secrets)

    p = sub.add_parser("report", help="emit a Markdown assessment report")
    p.add_argument("results", nargs="?", default="results.json")
    p.add_argument("--out", "-o")
    p.add_argument("--target", help="target name for the header")
    p.add_argument("--max-endpoints", type=int, default=60)
    p.add_argument("--max-findings", type=int, default=25)
    p.set_defaults(func=cmd_report)

    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except BrokenPipeError:
        os._exit(0)
    except KeyboardInterrupt:
        sys.exit(130)
