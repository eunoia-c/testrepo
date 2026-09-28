#!/usr/bin/env python3
"""snowpick.py — ServiceNow exposure scanner (Python port).

A faithful Python 3 port of Bishop Fox's snowpick (https://github.com/BishopFox/snowpick),
written because environments that block the Go module proxy cannot build the
original. Original tool © Bishop Fox, MIT licensed; this port keeps that licence
and preserves the JSON schema, exit codes and request formats so output from
either implementation is interchangeable.

What it does: identifies misconfigured access controls on ServiceNow instances by
obtaining an unauthenticated session token from /login.do and probing two
surfaces — Service Portal widgets (/api/now/sp/widget/) and the Table REST API
(/api/now/table/). It reports exposed records, "count oracles" (a record count
returned with no rows, which still confirms data exists and is queryable), and a
curl command to reproduce each finding.

Depends only on `requests` (plus PySocks if you use a SOCKS proxy), so it
installs in one command and needs no Go toolchain or module proxy.

Authorised testing only. This sends requests to the hosts you name.

Usage:
    python3 snowpick.py --target acme.service-now.com
    python3 snowpick.py --targets hosts.txt --proxy socks5://127.0.0.1:1080 --insecure
    python3 snowpick.py --target acme.service-now.com --fingerprint --table-api
    python3 snowpick.py --target acme.service-now.com --output results.json --quiet
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import re
import sys
import threading
import time
import urllib.parse
from dataclasses import dataclass, field, asdict
from typing import Any, Iterable, Sequence

try:
    import requests
except ImportError:  # pragma: no cover - environment problem, not a code path
    sys.stderr.write(
        "snowpick: the requests library is required.\n"
        "  pip install requests            # or, for SOCKS proxy support:\n"
        "  pip install 'requests[socks]'\n")
    raise SystemExit(1)

VERSION = "0.2.0-py"

# Byte caps mirroring the Go implementation's io.LimitReader calls.
MAX_BODY = 4 * 1024 * 1024
MAX_STATS_BODY = 256 * 1024

USER_AGENT = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/96.0.4664.93 Safari/537.36")

SIMPLE_LIST_WIDGET_ID = "widget-simple-list"

# Set from --vendor, sent as X-Vendor on every request for engagement tracking.
VENDOR_HEADER = ""


# --------------------------------------------------------------------------
# Colour
# --------------------------------------------------------------------------

class C:
    """ANSI codes, enabled only when stderr is a terminal."""
    reset = bold = red = green = yellow = cyan = dim = ""

    @classmethod
    def init(cls) -> None:
        if sys.stderr.isatty():
            cls.reset = "\033[0m"
            cls.bold = "\033[1m"
            cls.red = "\033[1;31m"
            cls.green = "\033[1;32m"
            cls.yellow = "\033[1;33m"
            cls.cyan = "\033[1;36m"
            cls.dim = "\033[2m"


def red(s: str) -> str:
    return C.red + s + C.reset


def green(s: str) -> str:
    return C.green + s + C.reset


def yellow(s: str) -> str:
    return C.yellow + s + C.reset


def cyan(s: str) -> str:
    return C.cyan + s + C.reset


def bold(s: str) -> str:
    return C.bold + s + C.reset


def dim(s: str) -> str:
    return C.dim + s + C.reset


_quiet = False


def logf(msg: str) -> None:
    if not _quiet:
        sys.stderr.write(msg)
        sys.stderr.flush()


# --------------------------------------------------------------------------
# HTTP transport
# --------------------------------------------------------------------------

class HttpError(Exception):
    pass


class WidgetNotFound(Exception):
    """A 404 from the widget endpoint: the widget is not installed."""


@dataclass
class Response:
    status: int
    headers: dict[str, str]
    body: bytes
    set_cookies: list[tuple[str, str]]

    def header(self, name: str) -> str:
        return self.headers.get(name.lower(), "")


class Client:
    """HTTPS client over requests, with rate limiting and no redirect following.

    Redirects are deliberately not followed, matching the Go client's
    ErrUseLastResponse: a 302 to a login page is a meaningful result here, and
    chasing it would turn a clear "not exposed" into a confusing 200.

    Cookies are handled explicitly rather than through a cookie jar, because the
    original captures the /login.do cookies once and replays them on every
    request -- and the reproduction curl commands need that exact Cookie header
    string. A jar would also make concurrent probes share mutable state.
    """

    def __init__(self, proxy: str = "", timeout: float = 15.0, insecure: bool = False,
                 rate: float = 0.0):
        self.timeout = timeout
        self.rate = rate
        self.verify = not insecure
        self._lock = threading.Lock()
        self._last_request = 0.0
        # requests.Session is not documented as thread-safe, and this scanner
        # probes tables concurrently. One session per thread keeps connection
        # pooling without sharing mutable state.
        self._local = threading.local()

        self.proxies: dict[str, str] = {}
        if proxy:
            parsed = urllib.parse.urlparse(proxy)
            if parsed.scheme not in ("http", "https", "socks5", "socks5h"):
                raise HttpError("unsupported proxy scheme %r "
                                "(use http, https, socks5 or socks5h)" % parsed.scheme)
            if not parsed.hostname:
                raise HttpError("proxy URL has no host")
            if parsed.scheme.startswith("socks"):
                try:
                    import socks  # noqa: F401  (PySocks, pulled in by requests[socks])
                except ImportError:
                    raise HttpError(
                        "SOCKS proxy support needs PySocks: pip install 'requests[socks]'")
            self.proxies = {"http": proxy, "https": proxy}

        if insecure:
            try:
                import urllib3
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            except Exception:
                pass

    @property
    def _session(self):
        session = getattr(self._local, "session", None)
        if session is None:
            session = requests.Session()
            # Ignore ambient HTTP_PROXY/REQUESTS_CA_BUNDLE and friends: on a
            # corporate laptop those are usually set, and silently routing an
            # engagement's traffic through an unexpected proxy is worse than
            # failing to connect.
            session.trust_env = False
            self._local.session = session
        return session

    def _throttle(self) -> None:
        if self.rate <= 0:
            return
        with self._lock:
            wait = self.rate - (time.monotonic() - self._last_request)
            if wait > 0:
                time.sleep(wait)
            self._last_request = time.monotonic()

    def request(self, method: str, url: str, headers: dict[str, str] | None = None,
                body: str = "", max_body: int = MAX_BODY) -> Response:
        self._throttle()
        session = self._session
        try:
            resp = session.request(
                method, url,
                headers=headers or {},
                data=body.encode("utf-8") if body else None,
                timeout=self.timeout,
                allow_redirects=False,
                proxies=self.proxies or None,
                verify=self.verify,
                stream=True,
            )
        except requests.RequestException as exc:
            raise HttpError(_terse(exc)) from exc

        try:
            # Cap the read the way the Go implementation's io.LimitReader does,
            # so a hostile or broken endpoint cannot exhaust memory.
            raw = resp.raw.read(max_body, decode_content=True) or b""
            set_cookies = [(c.name, c.value or "") for c in resp.cookies]
            hmap = {k.lower(): v for k, v in resp.headers.items()}
            return Response(status=resp.status_code, headers=hmap, body=raw,
                            set_cookies=set_cookies)
        except requests.RequestException as exc:
            raise HttpError(_terse(exc)) from exc
        finally:
            resp.close()
            # Keep the per-thread jar empty: cookies travel in an explicit
            # header, and a populated jar would send them twice.
            session.cookies.clear()


def _terse(exc: Exception) -> str:
    """requests wraps urllib3 which wraps the OS error, producing three nested
    layers of text per failure. Scan output lists one line per unreachable
    target, so the innermost cause is what belongs there."""
    text = str(exc)
    for marker in ("Caused by ", "NewConnectionError('", "error: "):
        idx = text.rfind(marker)
        if idx != -1:
            text = text[idx + len(marker):]
    return text.strip().rstrip("')\"").strip() or exc.__class__.__name__


# --------------------------------------------------------------------------
# Session
# --------------------------------------------------------------------------

GCK_PATTERN = re.compile(rb"g_ck\s*=\s*'([a-f0-9]+)'")


@dataclass
class Session:
    target: str
    token: str
    cookies: list[tuple[str, str]]

    def cookie_header(self) -> str:
        return "; ".join("%s=%s" % (n, v) for n, v in self.cookies)


def base_headers() -> dict[str, str]:
    hdrs = {"User-Agent": USER_AGENT}
    if VENDOR_HEADER:
        hdrs["X-Vendor"] = VENDOR_HEADER
    return hdrs


def session_headers(session: Session, extra: dict[str, str] | None = None) -> dict[str, str]:
    hdrs = base_headers()
    hdrs["Accept"] = "application/json"
    hdrs["X-UserToken"] = session.token
    if extra:
        hdrs.update(extra)
    cookie = session.cookie_header()
    if cookie:
        hdrs["Cookie"] = cookie
    return hdrs


def bootstrap(target: str, client: Client) -> Session:
    """Create an unauthenticated session by reading the g_ck CSRF token out of
    /login.do. No credentials are involved: ServiceNow issues a usable token to
    anonymous visitors, which is what makes the rest of this possible."""
    url = "https://%s/login.do" % target
    resp = client.request("GET", url, base_headers())
    if resp.status != 200:
        raise HttpError("/login.do returned %d" % resp.status)
    match = GCK_PATTERN.search(resp.body)
    if match is None:
        raise HttpError("g_ck token not found in /login.do response (%d bytes)" % len(resp.body))
    return Session(target=target, token=match.group(1).decode("ascii"),
                   cookies=resp.set_cookies)


# --------------------------------------------------------------------------
# Reproduction material
# --------------------------------------------------------------------------

def shell_quote(s: str) -> str:
    return "'" + s.replace("'", "'\\''") + "'"


def curl_command(method: str, url: str, headers: dict[str, str], body: str = "") -> str:
    parts = ["curl", "-i", "-sS", "-X", shell_quote(method), shell_quote(url)]
    for key in sorted(headers):
        parts += ["-H", shell_quote("%s: %s" % (key, headers[key]))]
    if body:
        parts += ["--data", shell_quote(body)]
    return " ".join(parts)


def reproduction_headers(session: Session, content_type: bool = True) -> dict[str, str]:
    hdrs = {"User-Agent": USER_AGENT, "Accept": "application/json",
            "X-UserToken": session.token}
    if content_type:
        hdrs["Content-Type"] = "application/json"
    cookie = session.cookie_header()
    if cookie:
        hdrs["Cookie"] = cookie
    return {k: v for k, v in hdrs.items() if v.strip()}


def build_oracle_hint(session: Session, widget_id: str) -> str:
    """Two curl commands whose differing record counts demonstrate the oracle.

    The count responds to filterText (CVE-2025-3648), so a common prefix returns
    a non-zero count and an unlikely string returns zero. The delta proves the
    data is queryable even though no row is ever returned; extending the matching
    prefix one character at a time infers field values."""
    url = "https://%s/api/now/sp/widget/%s" % (session.target, widget_id)
    headers = reproduction_headers(session)
    match = curl_command("POST", url, headers,
                         '{"filterText":"a","payload":{"start":0,"end":1}}')
    no_match = curl_command("POST", url, headers,
                            '{"filterText":"zqxj9","payload":{"start":0,"end":1}}')
    return ("# common prefix -> result.data.count > 0:\n" + match +
            "\n# unlikely string -> result.data.count == 0 (the delta confirms the oracle):\n" +
            no_match)


# --------------------------------------------------------------------------
# Classification
# --------------------------------------------------------------------------

IMPACT_PII = "pii"
IMPACT_CREDENTIALS = "credentials"
IMPACT_INFRASTRUCTURE = "infrastructure"
IMPACT_OPERATIONS = "internal_operations"
IMPACT_REVIEW = "review_required"

CATEGORY_ORDER = [IMPACT_PII, IMPACT_CREDENTIALS, IMPACT_INFRASTRUCTURE, IMPACT_OPERATIONS]

REASON_TABLE_PII = "table name associated with PII"
REASON_TABLE_CREDENTIALS = "table name associated with credentials"
REASON_TABLE_INFRASTRUCTURE = "table name associated with infrastructure"
REASON_TABLE_OPERATIONS = "table name associated with internal operations"
REASON_FIELD_PII = "field name associated with PII"
REASON_FIELD_CREDENTIALS = "field name associated with credentials"
REASON_WIDGET_OPERATIONS = "widget name associated with internal operations"
REASON_WIDGET_PII = "widget name associated with PII"
REASON_CONTENT_EMAIL = "email pattern in sample content"
REASON_CONTENT_CREDENTIAL = "credential keyword in sample content"
REASON_CONTENT_INFRA = "infrastructure pattern in sample content"
REASON_REVIEW_REQUIRED = "records returned, no hint rules matched"

TABLE_REASONS = {
    IMPACT_PII: REASON_TABLE_PII,
    IMPACT_CREDENTIALS: REASON_TABLE_CREDENTIALS,
    IMPACT_INFRASTRUCTURE: REASON_TABLE_INFRASTRUCTURE,
    IMPACT_OPERATIONS: REASON_TABLE_OPERATIONS,
}
FIELD_REASONS = {IMPACT_PII: REASON_FIELD_PII, IMPACT_CREDENTIALS: REASON_FIELD_CREDENTIALS}

TABLE_HINTS = {
    "sys_user": IMPACT_PII, "customer_contact": IMPACT_PII,
    "cmn_notif_device": IMPACT_PII, "sys_email_attachment": IMPACT_PII,
    "oauth_entity": IMPACT_CREDENTIALS, "sys_properties": IMPACT_CREDENTIALS,
    "cmdb_model": IMPACT_INFRASTRUCTURE, "cmdb_ci": IMPACT_INFRASTRUCTURE,
    "cmn_company": IMPACT_INFRASTRUCTURE, "cmn_cost_center": IMPACT_INFRASTRUCTURE,
    "cmn_department": IMPACT_INFRASTRUCTURE, "alm_asset": IMPACT_INFRASTRUCTURE,
    "sys_portal_page": IMPACT_INFRASTRUCTURE,
    "incident": IMPACT_OPERATIONS, "work_order": IMPACT_OPERATIONS,
    "task": IMPACT_OPERATIONS, "sn_customerservice_case": IMPACT_OPERATIONS,
    "customer_project": IMPACT_OPERATIONS, "customer_project_task": IMPACT_OPERATIONS,
    "customer_account": IMPACT_OPERATIONS,
}

FIELD_HINTS = {
    "email": IMPACT_PII, "email_address": IMPACT_PII, "phone": IMPACT_PII,
    "mobile_phone": IMPACT_PII, "home_phone": IMPACT_PII,
    "password": IMPACT_CREDENTIALS, "api_key": IMPACT_CREDENTIALS,
    "token": IMPACT_CREDENTIALS, "secret": IMPACT_CREDENTIALS,
}

# Phone numbers are intentionally absent: bare digit sequences produce false
# positives at a rate that costs more than the finding is worth.
CONTENT_PATTERNS = {
    IMPACT_PII: (re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", re.I),
                 REASON_CONTENT_EMAIL),
    IMPACT_CREDENTIALS: (re.compile(
        r"(\b(api[_-]?key|token|secret|password|private[_-]?key)\b\s*[:=]\s*\S"
        r"|\bbearer\s+[a-zA-Z0-9._-]{8,}"
        r"|-----begin[a-z ]*private key-----)", re.I), REASON_CONTENT_CREDENTIAL),
    IMPACT_INFRASTRUCTURE: (re.compile(r"\.(internal|corp|local)([:/\s\"']|$)", re.I),
                            REASON_CONTENT_INFRA),
}


@dataclass
class Hint:
    category: str
    basis: str            # "observed", "inferred", "none"
    reason: str
    signals: list[str] = field(default_factory=list)


class HintAccumulator:
    """Collects signals per category. An observed signal (found in returned data)
    outranks an inferred one (guessed from a name), and says so in `basis` --
    the distinction is what keeps a name-based guess from reading like evidence."""

    def __init__(self) -> None:
        self.signals: dict[str, list[str]] = {}
        self.observed: dict[str, bool] = {}
        self.reasons: dict[str, str] = {}

    def add_inferred(self, cat: str, signal: str, reason: str) -> None:
        self.signals.setdefault(cat, []).append(signal)
        if not self.reasons.get(cat):
            self.reasons[cat] = reason

    def add_observed(self, cat: str, signal: str, reason: str) -> None:
        self.signals.setdefault(cat, []).append(signal)
        self.observed[cat] = True
        self.reasons[cat] = reason

    def build(self) -> list[Hint]:
        out = []
        for cat in CATEGORY_ORDER:
            sigs = self.signals.get(cat)
            if not sigs:
                continue
            out.append(Hint(category=cat,
                            basis="observed" if self.observed.get(cat) else "inferred",
                            reason=self.reasons.get(cat, ""),
                            signals=sorted(sigs)))
        return out


def classify_content(acc: HintAccumulator, text: str) -> None:
    if not text:
        return
    for cat, (pattern, reason) in CONTENT_PATTERNS.items():
        m = pattern.search(text)
        if m:
            acc.add_observed(cat, "content:" + m.group(0), reason)


def classify_widget(widget_name: str, samples: Sequence["RecordSample"]) -> list[Hint]:
    acc = HintAccumulator()
    lower = widget_name.lower()
    if "kb" in lower or "knowledge" in lower:
        acc.add_inferred(IMPACT_OPERATIONS, "widget:" + widget_name, REASON_WIDGET_OPERATIONS)
    if "attachment" in lower:
        acc.add_inferred(IMPACT_OPERATIONS, "widget:" + widget_name, REASON_WIDGET_OPERATIONS)
    if "user" in lower:
        acc.add_inferred(IMPACT_PII, "widget:" + widget_name, REASON_WIDGET_PII)
    for s in samples:
        classify_content(acc, s.title)
        classify_content(acc, s.snippet)
        classify_content(acc, s.id)
    return acc.build()


def classify_table(table: str, fieldname: str, samples: Sequence["TableSample"]) -> list[Hint]:
    acc = HintAccumulator()
    cat = TABLE_HINTS.get(table)
    if cat:
        acc.add_inferred(cat, "table:" + table, TABLE_REASONS.get(cat, ""))
    cat = FIELD_HINTS.get(fieldname)
    if cat:
        reason = FIELD_REASONS.get(cat) or TABLE_REASONS.get(cat, "")
        acc.add_inferred(cat, "field:" + fieldname, reason)
    for s in samples:
        classify_content(acc, s.display_value)
    return acc.build()


def review_required_hint(record_count: int) -> list[Hint]:
    return [Hint(category=IMPACT_REVIEW, basis="none", reason=REASON_REVIEW_REQUIRED,
                 signals=["records_returned:%d" % record_count])]


# --------------------------------------------------------------------------
# Shared result shapes
# --------------------------------------------------------------------------

STATUS_EXPOSED = "exposed"
STATUS_NOT_EXPOSED = "not_exposed"
STATUS_COUNT_ORACLE = "count_oracle"
STATUS_WIDGET_MISSING = "widget_not_found"
STATUS_TOKEN_ERROR = "token_error"
STATUS_ERROR = "error"


@dataclass
class Reproduction:
    method: str
    url: str
    headers: dict[str, str]
    body: str
    status_code: int
    curl: str
    oracle_hint: str = ""


@dataclass
class RecordSample:
    title: str = ""
    id: str = ""
    link: str = ""
    snippet: str = ""


@dataclass
class TableSample:
    sys_id: str = ""
    display_value: str = ""


@dataclass
class Widget:
    id: str
    name: str


@dataclass
class TableCandidate:
    table: str
    field: str


@dataclass
class WidgetResult:
    id: str
    name: str
    status: str = STATUS_NOT_EXPOSED
    record_count: int = 0
    sample_count: int = 0
    evidence_fields: list[str] = field(default_factory=list)
    samples: list[RecordSample] = field(default_factory=list)
    hints: list[Hint] = field(default_factory=list)
    reproduction: Reproduction | None = None
    error: str = ""


@dataclass
class TableResult:
    table: str
    field_name: str
    status: str = STATUS_NOT_EXPOSED
    count: int = 0
    sample_count: int = 0
    evidence_fields: list[str] = field(default_factory=list)
    samples: list[TableSample] = field(default_factory=list)
    hints: list[Hint] = field(default_factory=list)
    reproduction: Reproduction | None = None
    error: str = ""


@dataclass
class TableAPIResult:
    table: str
    status: str = STATUS_NOT_EXPOSED
    record_count: int = 0
    sample_count: int = 0
    fields: list[str] = field(default_factory=list)
    samples: list[TableSample] = field(default_factory=list)
    hints: list[Hint] = field(default_factory=list)
    reproduction: Reproduction | None = None
    error: str = ""


# --------------------------------------------------------------------------
# Evidence extraction
# --------------------------------------------------------------------------

EVIDENCE_FIELD_NAMES = {
    "title", "id", "sys_id", "number", "link", "url", "snippet", "text",
    "short_description", "description",
}


def is_evidence_field(name: str) -> bool:
    if not name:
        return False
    if name.endswith("display_value"):
        return True
    return name in EVIDENCE_FIELD_NAMES


def collect_evidence_fields(prefix: str, value: Any, fields: set[str]) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            name = key if not prefix else prefix + "." + key
            collect_evidence_fields(name, child, fields)
    elif isinstance(value, list):
        for child in value:
            collect_evidence_fields(prefix, child, fields)
    elif isinstance(value, str):
        if value.strip() and is_evidence_field(prefix):
            fields.add(prefix)
    elif isinstance(value, bool) or isinstance(value, (int, float)):
        if is_evidence_field(prefix):
            fields.add(prefix)


def evidence_fields(results: Iterable[dict]) -> list[str]:
    """Field names carrying actual values.

    This is what separates "exposed" from a count oracle: a record count alone
    proves data exists, but only a populated field proves it can be read."""
    fields: set[str] = set()
    for result in results or []:
        collect_evidence_fields("", result, fields)
    return sorted(fields)


def string_field(record: dict, key: str) -> str:
    v = record.get(key)
    return v if isinstance(v, str) else ""


def first_string_field(record: dict, *keys: str) -> str:
    for key in keys:
        v = string_field(record, key)
        if v:
            return v
    return ""


def value_string(v: Any) -> str:
    if isinstance(v, str):
        return v
    if isinstance(v, dict):
        for key in ("value", "display_value"):
            if isinstance(v.get(key), str):
                return v[key]
    return ""


def nested_display_value(v: Any) -> str:
    if isinstance(v, dict) and isinstance(v.get("display_value"), str):
        return v["display_value"]
    return ""


def collect_display_values(value: Any, out: list[str]) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if key == "display_value":
                if isinstance(child, str) and child.strip():
                    out.append(child)
                continue
            collect_display_values(child, out)
    elif isinstance(value, list):
        for child in value:
            collect_display_values(child, out)


def first_display_value(record: dict) -> str:
    values: list[str] = []
    collect_display_values(record, values)
    values.sort()
    return values[0] if values else ""


def resolve_link(target: str, link: str) -> str:
    link = (link or "").strip()
    if not link:
        return ""
    parsed = urllib.parse.urlsplit(link)
    if parsed.scheme:
        if parsed.scheme in ("http", "https"):
            return urllib.parse.urlunsplit(parsed)
        return link
    if parsed.netloc:
        return urllib.parse.urlunsplit(("https",) + tuple(parsed)[1:])
    path = parsed.path
    if link.startswith("?"):
        path = "/sp"
    elif path and not path.startswith("/"):
        path = "/" + path
    return urllib.parse.urlunsplit(("https", target, path, parsed.query, parsed.fragment))


def truncate(s: str, n: int) -> str:
    return s if len(s) <= n else s[:n] + "..."


def abbreviate(s: str, n: int) -> str:
    return s if len(s) <= n else s[:n]


def encode_query(params: dict[str, str]) -> str:
    """Sorted, matching Go's url.Values.Encode() so generated URLs -- and the
    curl commands in the report -- are identical between implementations."""
    return "&".join("%s=%s" % (urllib.parse.quote_plus(k), urllib.parse.quote_plus(params[k]))
                    for k in sorted(params))


# --------------------------------------------------------------------------
# Widgets
# --------------------------------------------------------------------------

# The curated list from the original. The first entry is known to be
# misconfigured on certain ServiceNow instances.
DEFAULT_WIDGETS = [
    Widget("ff26f2b1db12220099f93691f0b8f5ce", "ticket-attachments"),
    Widget("c6545050ff223100ba13ffffffffffe8", "kb-article-page"),
    Widget("2c429b55cb22020000f8d856634c9cf4", "kb-search"),
    Widget("2f6d5e20cb12020000f8d856634c9c2d", "kb-category-list"),
    Widget("2c16b5c5cb32020000f8d856634c9c48", "sc-category"),
    Widget("1a5af858cb12020000f8d856634c9c30", "simple-list"),
]

DEFAULT_TABLE_CANDIDATES = [
    TableCandidate("cmdb_model", "name"),
    TableCandidate("cmn_department", "app_name"),
    TableCandidate("kb_knowledge", "text"),
    TableCandidate("licensable_app", "app_name"),
    TableCandidate("alm_asset", "display_name"),
    TableCandidate("sys_attachment", "file_name"),
    TableCandidate("sys_attachment_doc", "data"),
    TableCandidate("oauth_entity", "name"),
    TableCandidate("cmn_cost_center", "name"),
    TableCandidate("sc_cat_item", "name"),
    TableCandidate("sn_admin_center_application", "name"),
    TableCandidate("cmn_company", "name"),
    TableCandidate("customer_account", "name"),
    TableCandidate("sys_email_attachment", "email"),
    TableCandidate("sys_email_attachment", "attachment"),
    TableCandidate("cmn_notif_device", "email_address"),
    TableCandidate("sys_portal_page", "display_name"),
    TableCandidate("incident", "short_description"),
    TableCandidate("work_order", "number"),
    TableCandidate("incident", "number"),
    TableCandidate("sn_customerservice_case", "number"),
    TableCandidate("task", "number"),
    TableCandidate("customer_project", "number"),
    TableCandidate("customer_project_task", "number"),
    TableCandidate("sys_user", "name"),
    TableCandidate("customer_contact", "name"),
]

DEFAULT_TABLE_API_TABLES = [
    "sys_user", "incident", "kb_knowledge", "sys_attachment", "oauth_entity",
    "sc_cat_item", "cmdb_ci", "alm_asset", "task", "customer_contact",
    "cmn_department", "sys_properties",
]


def load_widgets_file(path: str) -> list[Widget]:
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, list):
        raise ValueError("widgets file must contain a JSON array")
    widgets = []
    for i, entry in enumerate(data):
        if not isinstance(entry, dict) or not str(entry.get("id", "")).strip():
            raise ValueError("widgets file entry %d missing id" % i)
        wid = str(entry["id"]).strip()
        name = str(entry.get("name", "")).strip() or abbreviate(wid, 8)
        widgets.append(Widget(wid, name))
    return widgets


def load_tables_file(path: str) -> list[TableCandidate]:
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, list):
        raise ValueError("tables file must contain a JSON array")
    out = []
    for i, entry in enumerate(data):
        if not isinstance(entry, dict) or not str(entry.get("table", "")).strip():
            raise ValueError("tables file entry %d missing table" % i)
        if not str(entry.get("field", "")).strip():
            raise ValueError("tables file entry %d missing field" % i)
        out.append(TableCandidate(str(entry["table"]).strip(), str(entry["field"]).strip()))
    return out


def merge_widgets(base: Sequence[Widget], extra: Sequence[Widget] | None) -> list[Widget]:
    by_id: dict[str, Widget] = {}
    for w in list(base) + list(extra or []):
        if w.id:
            by_id[w.id] = w
    return sorted(by_id.values(), key=lambda w: w.id)


def merge_table_candidates(base: Sequence[TableCandidate],
                           extra: Sequence[TableCandidate] | None) -> list[TableCandidate]:
    by_pair: dict[tuple[str, str], TableCandidate] = {}
    for c in list(base) + list(extra or []):
        if c.table and c.field:
            by_pair[(c.table, c.field)] = c
    return [by_pair[k] for k in sorted(by_pair)]


# --------------------------------------------------------------------------
# Widget probing
# --------------------------------------------------------------------------

def build_widget_url(session: Session, widget_id: str) -> str:
    return "https://%s/api/now/sp/widget/%s" % (session.target, widget_id)


def query_widget(session: Session, widget_id: str, end: int,
                 client: Client) -> tuple[dict, int]:
    url = build_widget_url(session, widget_id)
    payload = '{"payload":{"start":0,"end":%d}}' % end
    headers = session_headers(session, {"Content-Type": "application/json"})
    resp = client.request("POST", url, headers, payload)
    if resp.status == 404:
        raise WidgetNotFound()
    if resp.status not in (200, 201):
        raise HttpError("HTTP %d" % resp.status)
    try:
        return json.loads(resp.body.decode("utf-8", "replace")), resp.status
    except ValueError as exc:
        raise HttpError("parsing JSON: %s (first 200 bytes: %s)"
                        % (exc, truncate(resp.body.decode("utf-8", "replace"), 200)))


def widget_meta(doc: dict) -> tuple[bool, int, list[dict]]:
    result = doc.get("result") or {}
    invalid = bool(result.get("invalid_token"))
    data = (result.get("data") or {}).get("results") or {}
    meta = data.get("meta") or {}
    count = meta.get("count") or 0
    if not isinstance(count, int):
        try:
            count = int(count)
        except (TypeError, ValueError):
            count = 0
    rows = data.get("results") or []
    rows = [r for r in rows if isinstance(r, dict)]
    return invalid, count, rows


def build_widget_reproduction(session: Session, widget_id: str, end: int,
                              status_code: int) -> Reproduction:
    url = build_widget_url(session, widget_id)
    payload = '{"payload":{"start":0,"end":%d}}' % end
    headers = reproduction_headers(session)
    return Reproduction(method="POST", url=url, headers=headers, body=payload,
                        status_code=status_code,
                        curl=curl_command("POST", url, headers, payload))


def probe_widget(session: Session, widget: Widget, client: Client) -> WidgetResult:
    result = WidgetResult(id=widget.id, name=widget.name)
    try:
        doc, status_code = query_widget(session, widget.id, 1, client)
    except WidgetNotFound:
        result.status = STATUS_WIDGET_MISSING
        return result
    except Exception as exc:
        result.status = STATUS_ERROR
        result.error = str(exc)
        return result

    invalid, count, rows = widget_meta(doc)
    if invalid:
        result.status = STATUS_TOKEN_ERROR
        result.error = "invalid_token response"
        return result

    fields = evidence_fields(rows)
    if count > 0 and fields:
        result.status = STATUS_EXPOSED
        result.record_count = count
        result.evidence_fields = fields
        result.reproduction = build_widget_reproduction(session, widget.id, 1, status_code)
    elif count > 0:
        result.status = STATUS_COUNT_ORACLE
        result.record_count = count
        result.error = "count without evidence — blind extraction may be possible"
        repro = build_widget_reproduction(session, widget.id, 1, status_code)
        repro.oracle_hint = build_oracle_hint(session, widget.id)
        result.reproduction = repro
    else:
        result.status = STATUS_NOT_EXPOSED
    return result


def collect_samples(session: Session, widget_id: str, count: int,
                    client: Client) -> list[RecordSample]:
    doc, _ = query_widget(session, widget_id, count, client)
    invalid, _, rows = widget_meta(doc)
    if invalid:
        raise HttpError("invalid_token on sample collection")
    out = []
    for r in rows:
        out.append(RecordSample(
            title=string_field(r, "title"),
            id=first_string_field(r, "id", "sys_id", "number"),
            link=resolve_link(session.target, first_string_field(r, "link", "url")),
            snippet=first_string_field(r, "snippet", "text", "short_description", "description"),
        ))
    return out


# --------------------------------------------------------------------------
# Table probing via widget-simple-list
# --------------------------------------------------------------------------

def build_table_url(session: Session, candidate: TableCandidate) -> str:
    query = encode_query({"t": candidate.table, "f": candidate.field})
    return "https://%s/api/now/sp/widget/%s?%s" % (
        session.target, SIMPLE_LIST_WIDGET_ID, query)


def query_simple_list(session: Session, candidate: TableCandidate,
                      client: Client) -> tuple[dict, int]:
    url = build_table_url(session, candidate)
    headers = session_headers(session, {"Content-Type": "application/json"})
    resp = client.request("POST", url, headers, "{}")
    if resp.status == 404:
        raise WidgetNotFound()
    if resp.status not in (200, 201):
        raise HttpError("HTTP %d" % resp.status)
    try:
        return json.loads(resp.body.decode("utf-8", "replace")), resp.status
    except ValueError as exc:
        raise HttpError("parsing JSON: %s (first 200 bytes: %s)"
                        % (exc, truncate(resp.body.decode("utf-8", "replace"), 200)))


def simple_list_meta(doc: dict) -> tuple[bool, int, list[dict]]:
    result = doc.get("result") or {}
    invalid = bool(result.get("invalid_token"))
    data = result.get("data") or {}
    count = data.get("count") or 0
    if not isinstance(count, int):
        try:
            count = int(count)
        except (TypeError, ValueError):
            count = 0
    rows = [r for r in (data.get("list") or []) if isinstance(r, dict)]
    return invalid, count, rows


def build_table_reproduction(session: Session, candidate: TableCandidate,
                             status_code: int) -> Reproduction:
    url = build_table_url(session, candidate)
    headers = reproduction_headers(session)
    return Reproduction(method="POST", url=url, headers=headers, body="{}",
                        status_code=status_code,
                        curl=curl_command("POST", url, headers, "{}"))


def table_samples(records: Sequence[dict], limit: int) -> list[TableSample]:
    if limit > len(records) or limit < 1:
        limit = len(records)
    out = []
    for record in records[:limit]:
        sample = TableSample(sys_id=value_string(record.get("sys_id")),
                             display_value=nested_display_value(record.get("display_field")))
        if not sample.display_value:
            sample.display_value = first_display_value(record)
        out.append(sample)
    return out


def probe_table(session: Session, candidate: TableCandidate, sample_count: int,
                client: Client) -> TableResult:
    result = TableResult(table=candidate.table, field_name=candidate.field)
    try:
        doc, status_code = query_simple_list(session, candidate, client)
    except WidgetNotFound:
        result.status = STATUS_WIDGET_MISSING
        return result
    except Exception as exc:
        result.status = STATUS_ERROR
        result.error = str(exc)
        return result

    invalid, count, rows = simple_list_meta(doc)
    if invalid:
        result.status = STATUS_TOKEN_ERROR
        result.error = "invalid_token response"
        return result

    fields = evidence_fields(rows)
    if count > 0 and rows and fields:
        result.status = STATUS_EXPOSED
        result.count = count
        result.samples = table_samples(rows, sample_count)
        result.sample_count = len(result.samples)
        result.evidence_fields = fields
        result.reproduction = build_table_reproduction(session, candidate, status_code)
        return result

    if count > 0:
        result.status = STATUS_COUNT_ORACLE
        result.count = count
        result.error = "count without evidence — blind extraction may be possible"
        repro = build_table_reproduction(session, candidate, status_code)
        repro.oracle_hint = build_oracle_hint(
            session, "%s?t=%s&f=%s" % (SIMPLE_LIST_WIDGET_ID, candidate.table, candidate.field))
        result.reproduction = repro
        return result

    result.status = STATUS_NOT_EXPOSED
    return result


def enumerate_tables(session: Session, candidates: Sequence[TableCandidate],
                     sample_count: int, concurrency: int,
                     client: Client) -> list[TableResult]:
    concurrency = max(1, concurrency)
    results: list[TableResult | None] = [None] * len(candidates)

    def work(idx: int) -> None:
        results[idx] = probe_table(session, candidates[idx], sample_count, client)

    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as pool:
        list(pool.map(work, range(len(candidates))))

    return [r for r in results
            if r is not None and r.status in (STATUS_EXPOSED, STATUS_COUNT_ORACLE)]


def discover_widgets(session: Session, limit: int, client: Client) -> list[Widget]:
    """Enumerate installed widgets via sp_widget. Returns [] on any failure --
    sp_widget being inaccessible is the normal case, not an error worth surfacing."""
    try:
        doc, _ = query_simple_list(session, TableCandidate("sp_widget", "id"), client)
    except Exception:
        return []
    invalid, count, rows = simple_list_meta(doc)
    if invalid or count == 0 or not rows:
        return []
    out = []
    for item in rows:
        wid = nested_display_value(item.get("display_field")) or value_string(item.get("sys_id"))
        if not wid:
            continue
        out.append(Widget(wid, abbreviate(wid, 12)))
        if 0 < limit <= len(out):
            break
    return out


def discover_tables(session: Session, limit: int, client: Client) -> list[TableCandidate]:
    """Enumerate table names via sys_db_object, pairing each with `name` as the
    most common display field. Returns [] on failure, same rationale as above."""
    try:
        doc, _ = query_simple_list(session, TableCandidate("sys_db_object", "name"), client)
    except Exception:
        return []
    invalid, count, rows = simple_list_meta(doc)
    if invalid or count == 0 or not rows:
        return []
    out = []
    for item in rows:
        name = nested_display_value(item.get("display_field")) or value_string(item.get("sys_id"))
        if not name:
            continue
        out.append(TableCandidate(name, "name"))
        if 0 < limit <= len(out):
            break
    return out


# --------------------------------------------------------------------------
# Table REST API
# --------------------------------------------------------------------------

def table_api_field_string(record: dict, key: str) -> str:
    v = record.get(key)
    return v if isinstance(v, str) else ""


def table_api_first_field(record: dict, *keys: str) -> str:
    for key in keys:
        v = table_api_field_string(record, key)
        if v:
            return v
    for v in record.values():
        if isinstance(v, str) and v.strip() and len(v) < 100:
            return v
    return ""


def parse_x_total_count(header: str, fallback: int) -> int:
    if not header:
        return fallback
    try:
        n = int(header.strip())
    except ValueError:
        return fallback
    return n if n >= 1 else fallback


def build_table_api_url(session: Session, table: str, limit: int) -> str:
    return "https://%s/api/now/table/%s?%s" % (
        session.target, table, encode_query({"sysparm_limit": str(limit)}))


def build_table_api_reproduction(session: Session, table: str, limit: int,
                                 status_code: int) -> Reproduction:
    url = build_table_api_url(session, table, limit)
    headers = reproduction_headers(session, content_type=False)
    return Reproduction(method="GET", url=url, headers=headers, body="",
                        status_code=status_code,
                        curl=curl_command("GET", url, headers, ""))


def probe_table_api(session: Session, table: str, limit: int,
                    client: Client) -> TableAPIResult:
    result = TableAPIResult(table=table)
    url = build_table_api_url(session, table, limit)
    headers = session_headers(session)
    try:
        resp = client.request("GET", url, headers)
    except Exception as exc:
        result.status = STATUS_ERROR
        result.error = str(exc)
        return result

    if resp.status in (401, 403):
        result.status = STATUS_NOT_EXPOSED
        return result
    if resp.status == 404:
        result.status = STATUS_NOT_EXPOSED
        result.error = "table not found"
        return result
    if resp.status != 200:
        result.status = STATUS_ERROR
        result.error = "HTTP %d" % resp.status
        return result

    try:
        doc = json.loads(resp.body.decode("utf-8", "replace"))
    except ValueError as exc:
        result.status = STATUS_ERROR
        result.error = "parsing JSON: %s" % exc
        return result

    rows = doc.get("result") if isinstance(doc, dict) else None
    rows = [r for r in (rows or []) if isinstance(r, dict)]
    if not rows:
        result.status = STATUS_NOT_EXPOSED
        return result

    samples = [TableSample(
        sys_id=table_api_field_string(r, "sys_id"),
        display_value=table_api_first_field(r, "name", "number", "short_description",
                                            "title", "display_name"),
    ) for r in rows]

    result.status = STATUS_EXPOSED
    result.record_count = parse_x_total_count(resp.header("X-Total-Count"), len(rows))
    result.sample_count = len(samples)
    result.fields = sorted(rows[0].keys())
    result.samples = samples
    result.hints = classify_table(table, "", samples) or review_required_hint(result.record_count)
    result.reproduction = build_table_api_reproduction(session, table, limit, resp.status)
    return result


def enumerate_table_api(session: Session, tables: Sequence[str], limit: int,
                        concurrency: int, client: Client) -> list[TableAPIResult]:
    concurrency = max(1, concurrency)
    results: list[TableAPIResult | None] = [None] * len(tables)

    def work(idx: int) -> None:
        results[idx] = probe_table_api(session, tables[idx], limit, client)

    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as pool:
        list(pool.map(work, range(len(tables))))

    return [r for r in results if r is not None and r.status == STATUS_EXPOSED]


# --------------------------------------------------------------------------
# Fingerprinting
# --------------------------------------------------------------------------

BUILD_TAG_PATTERN = re.compile(r'build[_ ]?tag[>:\s"=]+([a-zA-Z0-9._-]+)', re.I)
VERSION_PATTERN = re.compile(r'(?:glide|version)[>:\s"=]+([a-zA-Z0-9._-]+)', re.I)

RELEASE_NAMES = {
    "tokyo": "Tokyo", "utah": "Utah", "vancouver": "Vancouver",
    "washington": "Washington DC", "xanadu": "Xanadu",
    "yokohama": "Yokohama", "zurich": "Zurich",
}


@dataclass
class InstanceFingerprint:
    version: str = ""
    release: str = ""
    build_tag: str = ""
    signals: list[str] = field(default_factory=list)


def infer_release(tag: str) -> str:
    lower = tag.lower()
    for prefix, release in RELEASE_NAMES.items():
        if prefix in lower:
            return release
    return ""


def fingerprint_from_stats_do(target: str, client: Client) -> tuple[str, str]:
    try:
        resp = client.request("GET", "https://%s/stats.do" % target, base_headers(),
                              max_body=MAX_STATS_BODY)
    except Exception:
        return "", ""
    if resp.status != 200:
        return "", ""
    text = resp.body.decode("utf-8", "replace")
    m = BUILD_TAG_PATTERN.search(text)
    if m:
        tag = m.group(1)
        return tag, infer_release(tag)
    m = VERSION_PATTERN.search(text)
    if m:
        tag = m.group(1)
        return tag, infer_release(tag)
    return "", ""


def fingerprint_from_headers(target: str, client: Client) -> list[str]:
    try:
        resp = client.request("HEAD", "https://%s/login.do" % target, base_headers())
    except Exception:
        return []
    signals = []
    if resp.header("Server"):
        signals.append("header:server=" + resp.header("Server"))
    if resp.header("X-Is-Logged-In"):
        signals.append("header:x-is-logged-in=" + resp.header("X-Is-Logged-In"))
    if resp.header("Strict-Transport-Security"):
        signals.append("header:hsts=present")
    for name, _value in resp.set_cookies:
        lower = name.lower()
        if lower.startswith("glide_") or lower == "bn":
            signals.append("cookie:" + name)
    return signals


def fingerprint_instance(session: Session, client: Client,
                         stats_do: bool) -> InstanceFingerprint:
    fp = InstanceFingerprint()
    if stats_do:
        tag, release = fingerprint_from_stats_do(session.target, client)
        if tag:
            fp.build_tag = tag
            fp.signals.append("stats.do:build_tag=" + tag)
            if release:
                fp.release = release
    fp.signals.extend(fingerprint_from_headers(session.target, client))
    if not fp.release and fp.build_tag:
        fp.release = infer_release(fp.build_tag)
    if fp.release:
        fp.version = fp.release
        if fp.build_tag:
            fp.version = "%s (%s)" % (fp.release, fp.build_tag)
    return fp


# --------------------------------------------------------------------------
# Serialisation
# --------------------------------------------------------------------------
#
# Written out by hand rather than via asdict() so the JSON matches the Go
# implementation field for field, including its `omitempty` behaviour. Output
# from either tool can then be diffed or fed to the same downstream parser --
# which is the point of a port, as opposed to a rewrite.

def _prune(d: dict, omit: Sequence[str]) -> dict:
    for key in omit:
        value = d.get(key)
        if value in (None, "", 0, [], {}):
            d.pop(key, None)
    return d


def hint_json(h: Hint) -> dict:
    return {"category": h.category, "basis": h.basis, "reason": h.reason,
            "signals": h.signals or None}


def reproduction_json(r: Reproduction | None) -> dict | None:
    if r is None:
        return None
    out = {"method": r.method, "url": r.url, "headers": r.headers, "body": r.body,
           "status_code": r.status_code, "curl": r.curl, "oracle_hint": r.oracle_hint}
    return _prune(out, ["oracle_hint"])


def record_sample_json(s: RecordSample) -> dict:
    return {"title": s.title, "id": s.id, "link": s.link, "snippet": s.snippet}


def table_sample_json(s: TableSample) -> dict:
    return _prune({"sys_id": s.sys_id, "display_value": s.display_value},
                  ["sys_id", "display_value"])


def widget_result_json(w: WidgetResult) -> dict:
    out = {
        "id": w.id, "name": w.name, "status": w.status, "record_count": w.record_count,
        "sample_count": w.sample_count, "evidence_fields": w.evidence_fields,
        "samples": [record_sample_json(s) for s in w.samples],
        "hints": [hint_json(h) for h in w.hints],
        "reproduction": reproduction_json(w.reproduction), "error": w.error,
    }
    return _prune(out, ["sample_count", "evidence_fields", "samples", "hints",
                        "reproduction", "error"])


def table_result_json(t: TableResult) -> dict:
    out = {
        "table": t.table, "field": t.field_name, "status": t.status, "count": t.count,
        "sample_count": t.sample_count, "evidence_fields": t.evidence_fields,
        "samples": [table_sample_json(s) for s in t.samples],
        "hints": [hint_json(h) for h in t.hints],
        "reproduction": reproduction_json(t.reproduction), "error": t.error,
    }
    return _prune(out, ["sample_count", "evidence_fields", "samples", "hints",
                        "reproduction", "error"])


def table_api_result_json(a: TableAPIResult) -> dict:
    out = {
        "table": a.table, "status": a.status, "record_count": a.record_count,
        "sample_count": a.sample_count, "fields": a.fields,
        "samples": [table_sample_json(s) for s in a.samples],
        "hints": [hint_json(h) for h in a.hints],
        "reproduction": reproduction_json(a.reproduction), "error": a.error,
    }
    return _prune(out, ["sample_count", "fields", "samples", "hints",
                        "reproduction", "error"])


def fingerprint_json(fp: InstanceFingerprint | None) -> dict | None:
    if fp is None:
        return None
    out = {"version": fp.version, "release": fp.release, "build_tag": fp.build_tag,
           "signals": fp.signals or None}
    return _prune(out, ["version", "release", "build_tag"])


# --------------------------------------------------------------------------
# Report
# --------------------------------------------------------------------------

@dataclass
class TargetResult:
    target: str
    reachable: bool = False
    token_obtained: bool = False
    stats_do: bool = False
    fingerprint: InstanceFingerprint | None = None
    error: str = ""
    widgets: list[WidgetResult] = field(default_factory=list)
    table_findings: list[TableResult] = field(default_factory=list)
    table_api_findings: list[TableAPIResult] = field(default_factory=list)

    def to_json(self) -> dict:
        out = {
            "target": self.target, "reachable": self.reachable,
            "token_obtained": self.token_obtained, "stats_do": self.stats_do,
            "fingerprint": fingerprint_json(self.fingerprint), "error": self.error,
            "widgets": [widget_result_json(w) for w in self.widgets],
            "table_findings": [table_result_json(t) for t in self.table_findings],
            "table_api_findings": [table_api_result_json(a) for a in self.table_api_findings],
        }
        return _prune(out, ["fingerprint", "error", "widgets", "table_findings",
                            "table_api_findings"])


@dataclass
class ScanReport:
    scan_time: str
    proxy: str
    targets_scanned: int
    targets_reachable: int
    widgets_probed: int
    findings: list[TargetResult]
    elapsed_ms: int = 0

    def to_json(self) -> dict:
        out = {
            "scan_time": self.scan_time, "proxy": self.proxy,
            "targets_scanned": self.targets_scanned,
            "targets_reachable": self.targets_reachable,
            "widgets_probed": self.widgets_probed, "elapsed_ms": self.elapsed_ms,
            "findings": [t.to_json() for t in self.findings],
        }
        return _prune(out, ["elapsed_ms"])

    def has_findings(self) -> bool:
        return any(target_has_findings(t) for t in self.findings)

    def has_scan_errors(self) -> bool:
        return any((not t.reachable) or t.error for t in self.findings)


def target_has_findings(r: TargetResult) -> bool:
    if r.table_findings or r.table_api_findings:
        return True
    return any(w.status in (STATUS_EXPOSED, STATUS_COUNT_ORACLE) for w in r.widgets)


def build_report(results: Sequence[TargetResult], proxy: str, widget_count: int) -> ScanReport:
    return ScanReport(
        scan_time=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        proxy=proxy,
        targets_scanned=len(results),
        targets_reachable=sum(1 for r in results if r.reachable),
        widgets_probed=widget_count,
        findings=list(results),
    )


def write_json(report: ScanReport, path: str) -> None:
    data = json.dumps(report.to_json(), indent=2) + "\n"
    if not path:
        # A terminal gets the summary only; the JSON would scroll it away.
        if sys.stdout.isatty():
            return
        sys.stdout.write(data)
        return
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(data)


# --------------------------------------------------------------------------
# Severity scoring and summary
# --------------------------------------------------------------------------

HINT_WEIGHTS = {IMPACT_PII: 10, IMPACT_CREDENTIALS: 20,
                IMPACT_INFRASTRUCTURE: 2, IMPACT_OPERATIONS: 1}


def hint_weight(hints: Sequence[Hint]) -> int:
    return sum(HINT_WEIGHTS.get(h.category, 0) for h in hints)


def finding_score(status: str, count: int, hints: Sequence[Hint]) -> int:
    if status == STATUS_EXPOSED:
        return count + hint_weight(hints) * count
    if status == STATUS_COUNT_ORACLE:
        return count // 2
    return 0


def target_score(t: TargetResult) -> int:
    score = sum(finding_score(w.status, w.record_count, w.hints) for w in t.widgets)
    score += sum(finding_score(x.status, x.count, x.hints) for x in t.table_findings)
    score += sum(finding_score(a.status, a.record_count, a.hints) for a in t.table_api_findings)
    return score


def severity_color(count: int, hints: Sequence[Hint]) -> str:
    if any(h.category in (IMPACT_PII, IMPACT_CREDENTIALS) for h in hints):
        return C.red
    if count >= 1000:
        return C.red
    if count >= 100:
        return C.yellow
    return C.cyan


def fmt_count(count: int, hints: Sequence[Hint] | None = None) -> str:
    return "%s%d%s" % (severity_color(count, hints or []), count, C.reset)


def fmt_count_sampled(total: int, sampled: int, hints: Sequence[Hint] | None) -> str:
    color = severity_color(total, hints or [])
    if sampled > 0 and total > sampled:
        return "%s%d%s records, %d sampled" % (color, total, C.reset, sampled)
    return "%s%d%s records" % (color, total, C.reset)


def hint_tag(h: Hint) -> str:
    if h.category == IMPACT_REVIEW:
        return yellow("[review_required]")
    label = "%s:%s" % (h.category, h.basis)
    if h.category in (IMPACT_PII, IMPACT_CREDENTIALS):
        return red("[" + label + "]")
    if h.category == IMPACT_INFRASTRUCTURE:
        return yellow("[" + label + "]")
    if h.category == IMPACT_OPERATIONS:
        return dim("[" + label + "]")
    return "[" + label + "]"


def hint_tags(hints: Sequence[Hint]) -> str:
    if not hints:
        return ""
    return " " + " ".join(hint_tag(h) for h in hints)


def finding_count_summary(status: str, total: int, sampled: int,
                          hints: Sequence[Hint]) -> str:
    if status == STATUS_COUNT_ORACLE:
        return "%s records %s%s" % (fmt_count(total, hints), yellow("[blind oracle]"),
                                    hint_tags(hints))
    return fmt_count_sampled(total, sampled, hints) + hint_tags(hints)


def category_label(cat: str) -> str:
    if cat == IMPACT_PII:
        return red("%-18s" % "PII")
    if cat == IMPACT_CREDENTIALS:
        return red("%-18s" % "CREDENTIALS")
    if cat == IMPACT_INFRASTRUCTURE:
        return yellow("%-18s" % "INFRASTRUCTURE")
    if cat == IMPACT_OPERATIONS:
        return "%-18s" % "OPERATIONS"
    return "%-18s" % cat


def target_records(t: TargetResult) -> tuple[int, int]:
    exposed = count_only = 0
    for w in t.widgets:
        if w.status == STATUS_EXPOSED:
            exposed += w.record_count
        elif w.status == STATUS_COUNT_ORACLE:
            count_only += w.record_count
    for x in t.table_findings:
        if x.status == STATUS_EXPOSED:
            exposed += x.count
        elif x.status == STATUS_COUNT_ORACLE:
            count_only += x.count
    for a in t.table_api_findings:
        if a.status == STATUS_EXPOSED:
            exposed += a.record_count
        elif a.status == STATUS_COUNT_ORACLE:
            count_only += a.record_count
    return exposed, count_only


def target_exposure_summary(t: TargetResult) -> str:
    exposed, count_only = target_records(t)
    if exposed > 0 and count_only > 0:
        return "%s records, %s count-only" % (fmt_count(exposed), fmt_count(count_only))
    if exposed > 0:
        return "%s records" % fmt_count(exposed)
    if count_only > 0:
        return "%s count-only records" % fmt_count(count_only)
    return "0 records"


def target_top_categories(t: TargetResult) -> str:
    best: dict[str, str] = {}

    def add(status: str, hints: Sequence[Hint]) -> None:
        if status != STATUS_EXPOSED:
            return
        for h in hints:
            if h.category == IMPACT_REVIEW:
                continue
            if not best.get(h.category) or h.basis == "observed":
                best[h.category] = h.basis

    for w in t.widgets:
        add(w.status, w.hints)
    for x in t.table_findings:
        add(x.status, x.hints)
    for a in t.table_api_findings:
        add(a.status, a.hints)
    if not best:
        return ""
    tags = [hint_tag(Hint(cat, best[cat], "")) for cat in CATEGORY_ORDER if cat in best]
    return " " + " ".join(tags)


def plural(n: int) -> str:
    return "" if n == 1 else "s"


def bar_len(value: int, maximum: int, width: int) -> int:
    if maximum == 0:
        return 0
    n = (value * width) // maximum
    return 1 if n < 1 and value > 0 else n


def build_vector_stats(targets: Sequence[TargetResult]) -> list[tuple[str, int, int]]:
    stats: dict[str, list[int]] = {}   # name -> [target_count, total_records]

    def bump(name: str, records: int, seen: set[str]) -> None:
        entry = stats.setdefault(name, [0, 0])
        entry[1] += records
        if name not in seen:
            entry[0] += 1
            seen.add(name)

    for t in targets:
        seen: set[str] = set()
        for w in t.widgets:
            if w.status not in (STATUS_EXPOSED, STATUS_COUNT_ORACLE):
                continue
            name = w.name + (" [blind oracle]" if w.status == STATUS_COUNT_ORACLE else "")
            bump(name, w.record_count, seen)
        for x in t.table_findings:
            name = "table:%s.%s" % (x.table, x.field_name)
            if x.status == STATUS_COUNT_ORACLE:
                name += " [blind oracle]"
            bump(name, x.count, seen)
        for a in t.table_api_findings:
            name = "api:" + a.table
            if a.status == STATUS_COUNT_ORACLE:
                name += " [blind oracle]"
            bump(name, a.record_count, seen)

    out = [(name, v[0], v[1]) for name, v in stats.items()]
    out.sort(key=lambda row: -row[2])
    return out[:10]


def build_category_stats(targets: Sequence[TargetResult]) -> list[tuple[str, int, int]]:
    counters: dict[str, tuple[set[str], list[int]]] = {}

    def add(target: str, status: str, hints: Sequence[Hint]) -> None:
        if status != STATUS_EXPOSED:
            return
        for h in hints:
            entry = counters.setdefault(h.category, (set(), [0]))
            entry[0].add(target)
            entry[1][0] += 1

    for t in targets:
        for w in t.widgets:
            add(t.target, w.status, w.hints)
        for x in t.table_findings:
            add(t.target, x.status, x.hints)
        for a in t.table_api_findings:
            add(t.target, a.status, a.hints)

    return [(cat, len(counters[cat][0]), counters[cat][1][0])
            for cat in CATEGORY_ORDER if cat in counters]


def print_summary(report: ScanReport, elapsed: float) -> None:
    err = sys.stderr
    err.write("\n")

    exposed, clean, unreachable, no_token = [], [], [], []
    for t in report.findings:
        if not t.reachable:
            unreachable.append(t)
        elif not t.token_obtained:
            no_token.append(t)
        elif target_has_findings(t):
            exposed.append(t)
        else:
            clean.append(t)

    exposed.sort(key=target_score, reverse=True)

    err.write("%s\n" % bold("RESULTS"))
    err.write("%s targets scanned in %.3fs | %s reachable | %s with findings\n" % (
        bold(str(report.targets_scanned)), elapsed,
        bold(str(report.targets_reachable)), red(str(len(exposed)))))
    err.write("\n")

    for t in exposed:
        version_tag = ""
        if t.fingerprint and t.fingerprint.version:
            version_tag = " " + dim("[" + t.fingerprint.version + "]")
        stats_tag = " " + yellow("[stats.do]") if t.stats_do else ""
        err.write("  %s %s  %s%s%s%s\n" % (
            red("EXPOSED"), bold(t.target), target_exposure_summary(t),
            target_top_categories(t), version_tag, stats_tag))

        for w in t.widgets:
            if w.status == STATUS_EXPOSED:
                err.write("    %s %-24s %s\n" % (
                    cyan("|"), w.name,
                    finding_count_summary(w.status, w.record_count, w.sample_count, w.hints)))
                for sample in w.samples[:3]:
                    title = sample.title or sample.snippet
                    if len(title) > 60:
                        title = title[:57] + "..."
                    if title:
                        err.write("    %s   %s\n" % (dim("|"), dim(title)))
            elif w.status == STATUS_COUNT_ORACLE:
                err.write("    %s %-24s %s\n" % (
                    cyan("|"), w.name,
                    finding_count_summary(w.status, w.record_count, w.sample_count, w.hints)))

        for x in t.table_findings:
            if x.status not in (STATUS_EXPOSED, STATUS_COUNT_ORACLE):
                continue
            err.write("    %s %-24s %s\n" % (
                cyan("|"), "%s.%s" % (x.table, x.field_name),
                finding_count_summary(x.status, x.count, x.sample_count, x.hints)))

        for a in t.table_api_findings:
            if a.status not in (STATUS_EXPOSED, STATUS_COUNT_ORACLE):
                continue
            err.write("    %s %s %-19s %s\n" % (
                cyan("|"), yellow("[API]"), a.table,
                finding_count_summary(a.status, a.record_count, a.sample_count, a.hints)))
        err.write("\n")

    if clean:
        err.write("  %s %d targets clean: %s\n" % (
            green("CLEAN"), len(clean), dim(", ".join(t.target for t in clean))))
    if no_token:
        err.write("  %s %d targets (bootstrap failed): %s\n" % (
            dim("SKIP"), len(no_token), dim(", ".join(t.target for t in no_token))))
    if unreachable:
        err.write("  %s %d targets unreachable: %s\n" % (
            dim("DOWN"), len(unreachable), dim(", ".join(t.target for t in unreachable))))
    err.write("\n")

    if exposed:
        vectors = build_vector_stats(exposed)
        if vectors:
            err.write("%s\n" % bold("ATTACK SURFACE"))
            top = vectors[0][2]
            for name, target_count, total in vectors:
                bar = "#" * bar_len(total, top, 20)
                err.write("  %-28s %s %s across %d target%s\n" % (
                    name, red(bar), fmt_count(total), target_count, plural(target_count)))
            err.write("\n")

        cats = build_category_stats(exposed)
        if cats:
            err.write("%s\n" % bold("DATA CLASSIFICATION"))
            for cat, target_count, finding_count in cats:
                err.write("  %s  %d finding%s across %d target%s\n" % (
                    category_label(cat), finding_count, plural(finding_count),
                    target_count, plural(target_count)))
            err.write("\n")
    err.flush()


# --------------------------------------------------------------------------
# Scan orchestration
# --------------------------------------------------------------------------

CANCELLED = threading.Event()
_flush_lock = threading.Lock()


def flush_lines(lines: Sequence[str]) -> None:
    """Write a target's output as one block.

    Targets are scanned concurrently, so per-line writes interleave into
    unreadable soup. Buffering per target and flushing under a lock keeps each
    target's findings together."""
    if not lines:
        return
    block = "\n".join(lines) + "\n"
    with _flush_lock:
        logf(block)


class Progress:
    def __init__(self, total: int):
        self.total = total
        self._lock = threading.Lock()
        self.completed = 0
        self.findings = 0

    def done(self, had_findings: bool) -> None:
        with self._lock:
            self.completed += 1
            if had_findings:
                self.findings += 1

    def line(self) -> str:
        with self._lock:
            completed, findings = self.completed, self.findings
        if findings > 0:
            return "[%s] %d/%d targets complete, %s with findings" % (
                dim("*"), completed, self.total, red(str(findings)))
        return "[%s] %d/%d targets complete" % (dim("*"), completed, self.total)


@dataclass
class ScanConfig:
    client: Client
    widgets: list[Widget]
    table_candidates: list[TableCandidate]
    sample_count: int = 10
    concurrency: int = 3
    table_concurrency: int = 5
    enumerate_tables: bool = True
    discover_widgets_limit: int = 50
    fingerprint: bool = False
    discover: bool = False
    discover_limit: int = 100
    table_api: bool = False


def check_endpoint(target: str, path: str, client: Client) -> int:
    resp = client.request("GET", "https://%s%s" % (target, path), base_headers())
    return resp.status


def scan_target(target: str, cfg: ScanConfig, prog: Progress) -> TargetResult:
    result = TargetResult(target=target)
    client = cfg.client
    lines: list[str] = []

    if CANCELLED.is_set():
        result.error = "cancelled"
        prog.done(False)
        return result

    # Liveness is an HTTP GET through the proxy rather than a raw TCP dial, so a
    # proxy that cannot reach the target is reported as unreachable here instead
    # of failing confusingly later.
    try:
        check_endpoint(target, "/", client)
    except Exception as exc:
        result.error = "unreachable: %s" % exc
        lines.append("[%s] %s %s" % (red("-"), bold(target), dim(result.error)))
        prog.done(False)
        flush_lines(lines)
        return result
    result.reachable = True

    try:
        if check_endpoint(target, "/stats.do", client) == 200:
            result.stats_do = True
    except Exception:
        pass

    try:
        session = bootstrap(target, client)
    except Exception as exc:
        result.error = "bootstrap failed: %s" % exc
        lines.append("[%s] %s %s" % (red("-"), bold(target), dim(result.error)))
        prog.done(False)
        flush_lines(lines)
        return result
    result.token_obtained = True

    if cfg.fingerprint:
        result.fingerprint = fingerprint_instance(session, client, result.stats_do)

    widgets = cfg.widgets
    if cfg.discover_widgets_limit > 0:
        discovered = discover_widgets(session, cfg.discover_widgets_limit, client)
        if discovered:
            widgets = merge_widgets(widgets, discovered)

    for w in widgets:
        if CANCELLED.is_set():
            break
        wr = probe_widget(session, w, client)
        if wr.status == STATUS_EXPOSED:
            try:
                samples = collect_samples(session, w.id, cfg.sample_count, client)
            except Exception:
                samples = None
            if samples is not None:
                wr.samples = samples
                wr.sample_count = len(samples)
                wr.hints = classify_widget(w.name, samples) or review_required_hint(wr.record_count)
        if wr.status == STATUS_COUNT_ORACLE and not wr.hints:
            wr.hints = review_required_hint(wr.record_count)
        result.widgets.append(wr)

    table_candidates = cfg.table_candidates
    if cfg.discover and cfg.enumerate_tables and not CANCELLED.is_set():
        discovered_tables = discover_tables(session, cfg.discover_limit, client)
        if discovered_tables:
            table_candidates = merge_table_candidates(table_candidates, discovered_tables)

    if cfg.enumerate_tables and not CANCELLED.is_set():
        result.table_findings = enumerate_tables(
            session, table_candidates, cfg.sample_count, cfg.table_concurrency, client)
        for t in result.table_findings:
            t.hints = classify_table(t.table, t.field_name, t.samples)
            if not t.hints and t.status in (STATUS_EXPOSED, STATUS_COUNT_ORACLE):
                t.hints = review_required_hint(t.count)

    if cfg.table_api and not CANCELLED.is_set():
        result.table_api_findings = enumerate_table_api(
            session, DEFAULT_TABLE_API_TABLES, cfg.sample_count,
            cfg.table_concurrency, client)

    has_findings = target_has_findings(result)
    prog.done(has_findings)

    if has_findings:
        version_tag = ""
        if cfg.fingerprint and result.fingerprint and result.fingerprint.version:
            version_tag = " " + dim("[" + result.fingerprint.version + "]")
        stats_tag = " " + yellow("[stats.do]") if result.stats_do else ""
        lines.append("[%s] %s%s%s" % (red("!"), bold(target), version_tag, stats_tag))
        for w in result.widgets:
            if w.status in (STATUS_EXPOSED, STATUS_COUNT_ORACLE):
                lines.append("  %s %s %s" % (
                    cyan("|"), w.name,
                    finding_count_summary(w.status, w.record_count, w.sample_count, w.hints)))
        for t in result.table_findings:
            if t.status in (STATUS_EXPOSED, STATUS_COUNT_ORACLE):
                lines.append("  %s %s.%s %s" % (
                    cyan("|"), t.table, t.field_name,
                    finding_count_summary(t.status, t.count, t.sample_count, t.hints)))
        for a in result.table_api_findings:
            if a.status in (STATUS_EXPOSED, STATUS_COUNT_ORACLE):
                lines.append("  %s %s %s %s" % (
                    cyan("|"), yellow("[API]"), a.table,
                    finding_count_summary(a.status, a.record_count, a.sample_count, a.hints)))
    else:
        reason = dim(result.error) if result.error else green("clean")
        lines.append("[%s] %s %s" % (dim("+"), target, reason))

    lines.append(prog.line())
    flush_lines(lines)
    return result


def scan_targets(targets: Sequence[str], cfg: ScanConfig,
                 out: list[TargetResult | None]) -> None:
    prog = Progress(len(targets))

    def work(idx: int) -> None:
        out[idx] = scan_target(targets[idx], cfg, prog)

    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, cfg.concurrency)) as pool:
        list(pool.map(work, range(len(targets))))


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

DURATION_RE = re.compile(r"^\s*(\d+(?:\.\d+)?)\s*(ns|us|µs|ms|s|m|h)?\s*$", re.I)
DURATION_UNITS = {"ns": 1e-9, "us": 1e-6, "µs": 1e-6, "ms": 1e-3,
                  "s": 1.0, "m": 60.0, "h": 3600.0}


def parse_duration(text: str) -> float:
    """Accept Go duration strings (15s, 200ms, 1m) as well as bare seconds, so
    runbooks written against the original tool work unchanged."""
    if not text:
        return 0.0
    m = DURATION_RE.match(text)
    if not m:
        raise argparse.ArgumentTypeError(
            "invalid duration %r (try 15s, 200ms, 1m or a plain number of seconds)" % text)
    return float(m.group(1)) * DURATION_UNITS.get((m.group(2) or "s").lower(), 1.0)


def normalize_target(t: str) -> str:
    t = t.strip()
    for prefix in ("https://", "http://"):
        if t.startswith(prefix):
            t = t[len(prefix):]
    return t.rstrip("/")


def resolve_targets(single: str, path: str) -> list[str]:
    targets = []
    if single:
        targets.append(normalize_target(single))
    if path:
        try:
            with open(path, encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        targets.append(normalize_target(line))
        except OSError as exc:
            sys.stderr.write("error: opening targets file: %s\n" % exc)
            raise SystemExit(1)
    return targets


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="snowpick.py",
        description="ServiceNow exposure scanner (Python port of BishopFox/snowpick).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples:
  python3 snowpick.py --target acme.service-now.com
  python3 snowpick.py --targets hosts.txt --proxy socks5://127.0.0.1:1080 --insecure
  python3 snowpick.py --target acme.service-now.com --fingerprint --table-api
  python3 snowpick.py --target acme.service-now.com --output results.json --quiet

exit codes:
  0  no findings
  1  scan errors (a target was unreachable or bootstrap failed)
  2  findings present

Single-dash forms (-target, -proxy, ...) are accepted as well, so scripts
written for the Go tool work unchanged.
""")
    # Both spellings of every flag: the Go original uses -flag, and muscle
    # memory plus existing runbooks are worth more than argparse purity.
    p.add_argument("--target", "-target", default="", help="single ServiceNow hostname")
    p.add_argument("--targets", "-targets", default="",
                   help="file with one hostname per line ('#' comments allowed)")
    p.add_argument("--proxy", "-proxy", default="",
                   help="proxy URL (http://, https://, socks5://, socks5h://)")
    p.add_argument("--widgets", "-widgets", default="",
                   help="comma-separated widget IDs (overrides defaults)")
    p.add_argument("--widgets-file", "-widgets-file", default="",
                   help="JSON file with widget candidates")
    p.add_argument("--tables-file", "-tables-file", default="",
                   help="JSON file with table/field candidates")
    p.add_argument("--output", "-output", "-o", default="",
                   help="JSON output file (default: stdout when piped)")
    p.add_argument("--samples", "-samples", type=int, default=10,
                   help="sample records per exposed finding (default 10)")
    p.add_argument("--timeout", "-timeout", type=parse_duration, default=15.0,
                   help="HTTP timeout per request (default 15s)")
    p.add_argument("--concurrency", "-concurrency", type=int, default=3,
                   help="max parallel targets (default 3)")
    p.add_argument("--table-concurrency", "-table-concurrency", type=int, default=5,
                   help="max parallel table probes per target (default 5)")
    p.add_argument("--insecure", "-insecure", action="store_true",
                   help="skip TLS certificate verification")
    p.add_argument("--tables", "-tables", action=argparse.BooleanOptionalAction, default=True,
                   help="enumerate table/field exposure via widget-simple-list (default on)")
    p.add_argument("--rate", "-rate", type=parse_duration, default=0.0,
                   help="minimum interval between HTTP requests (e.g. 200ms)")
    p.add_argument("--discover-widgets-limit", "-discover-widgets-limit", type=int, default=50,
                   help="max widgets to probe from dynamic discovery (default 50)")
    p.add_argument("--fingerprint", "-fingerprint", action="store_true",
                   help="detect ServiceNow version and release from response signals")
    p.add_argument("--discover", "-discover", action="store_true",
                   help="discover tables via sys_db_object and enumerate dynamically")
    p.add_argument("--discover-limit", "-discover-limit", type=int, default=100,
                   help="max tables to probe from dynamic discovery (default 100)")
    p.add_argument("--table-api", "-table-api", action="store_true",
                   help="probe /api/now/table/{table} REST API for data exposure")
    p.add_argument("--vendor", "-vendor", default="",
                   help="X-Vendor header value for engagement tracking")
    p.add_argument("--quiet", "-quiet", "-q", action="store_true",
                   help="suppress informational output (errors still print)")
    p.add_argument("--version", "-version", action="store_true",
                   help="print version and exit")
    return p


def main(argv: Sequence[str] | None = None) -> int:
    global _quiet, VENDOR_HEADER
    args = build_parser().parse_args(argv)

    if args.version:
        print("snowpick.py %s (port of BishopFox/snowpick)" % VERSION)
        return 0

    _quiet = args.quiet
    C.init()

    if args.vendor:
        VENDOR_HEADER = args.vendor
    if args.concurrency < 1:
        sys.stderr.write("error: --concurrency must be at least 1\n")
        return 1
    if args.table_concurrency < 1:
        sys.stderr.write("error: --table-concurrency must be at least 1\n")
        return 1

    targets = resolve_targets(args.target, args.targets)
    if not targets:
        sys.stderr.write("snowpick - ServiceNow exposure scanner\n\n"
                         "error: no targets specified\n\n"
                         "Run snowpick.py -h for usage.\n")
        return 1

    widgets = list(DEFAULT_WIDGETS)
    if args.widgets:
        widgets = [Widget(wid, abbreviate(wid, 8))
                   for wid in (x.strip() for x in args.widgets.split(",")) if wid]
    if args.widgets_file:
        try:
            widgets = merge_widgets(widgets, load_widgets_file(args.widgets_file))
        except (OSError, ValueError) as exc:
            sys.stderr.write("error: loading widgets file: %s\n" % exc)
            return 1
    else:
        widgets = merge_widgets(widgets, None)

    table_candidates = merge_table_candidates(DEFAULT_TABLE_CANDIDATES, None)
    if args.tables_file:
        try:
            table_candidates = merge_table_candidates(
                table_candidates, load_tables_file(args.tables_file))
        except (OSError, ValueError) as exc:
            sys.stderr.write("error: loading tables file: %s\n" % exc)
            return 1

    try:
        client = Client(proxy=args.proxy, timeout=args.timeout,
                        insecure=args.insecure, rate=args.rate)
    except HttpError as exc:
        sys.stderr.write("error: building HTTP client: %s\n" % exc)
        return 1

    proxy_label = args.proxy or "direct"
    cfg = ScanConfig(
        client=client, widgets=widgets, table_candidates=table_candidates,
        sample_count=args.samples, concurrency=args.concurrency,
        table_concurrency=args.table_concurrency, enumerate_tables=args.tables,
        discover_widgets_limit=args.discover_widgets_limit,
        fingerprint=args.fingerprint, discover=args.discover,
        discover_limit=args.discover_limit, table_api=args.table_api,
    )

    logf("%s %s%s | %d targets | %d widgets | proxy %s\n" % (
        bold("snowpick.py"), dim(VERSION), C.reset, len(targets), len(widgets), proxy_label))

    slots: list[TargetResult | None] = [None] * len(targets)
    started = time.monotonic()
    try:
        scan_targets(targets, cfg, slots)
    except KeyboardInterrupt:
        CANCELLED.set()
        sys.stderr.write("\ninterrupted — reporting the targets that finished\n")
    elapsed = time.monotonic() - started

    results = [r for r in slots if r is not None]
    report = build_report(results, proxy_label, len(widgets))
    report.elapsed_ms = int(elapsed * 1000)
    print_summary(report, elapsed)

    try:
        write_json(report, args.output)
    except OSError as exc:
        sys.stderr.write("error: writing output: %s\n" % exc)
        return 1

    if report.has_findings():
        return 2
    if report.has_scan_errors():
        return 1
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
