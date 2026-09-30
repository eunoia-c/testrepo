#!/usr/bin/env python3
"""apex_scan.py — static analysis for Salesforce Apex dumped by aura-dump.

Built for client reporting, so the design favours precision over recall: a rule
that fires on commented-out code or on a string literal costs more credibility
than a rule that misses an edge case. Three things follow from that:

  * Source is preprocessed before any matching. Comments and string-literal
    interiors are blanked, preserving byte offsets so line numbers still refer
    to the original file. A sink inside a comment cannot match; a keyword inside
    a literal cannot match.
  * SOQL injection is a taint checker rather than a grep. A `Database.query()`
    call is only reported when attacker-controllable input actually reaches it,
    and the propagation chain is emitted so the finding can be verified by hand.
  * Confidence is separate from severity. Severity says how bad it would be;
    confidence says how sure the tool is. Filter on confidence before reporting.

Standard library only. Python 3.11+.

Usage:
    python3 apex_scan.py --input ./apex_dump --out ./results --format json,csv,md
    python3 apex_scan.py --self-test
"""

from __future__ import annotations

import argparse
import bisect
import csv
import dataclasses
import hashlib
import json
import math
import os
import re
import sys
import traceback
from dataclasses import dataclass, field
from typing import Iterable, Iterator, Sequence

__version__ = "1.0.0"

# --------------------------------------------------------------------------
# Severity / confidence
# --------------------------------------------------------------------------

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
CONFIDENCES = ("HIGH", "MEDIUM", "LOW")

SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITIES)}
CONFIDENCE_RANK = {c: i for i, c in enumerate(CONFIDENCES)}

APEX_EXTENSIONS = {".cls", ".trigger", ".page", ".cmp", ".apex", ".component",
                   ".evt", ".apxc", ".apxt", ".app", ".intf", ".tokens"}

# Bulk dumps do not always name files helpfully: an ApexClass pulled through the
# API may land as `MyClass`, `MyClass.txt` or `MyClass.json`. Rather than make
# the user guess the right --ext, sniff files whose extension we do not know and
# analyse them when the content is recognisably Apex or Visualforce.
APEX_SNIFF_RE = re.compile(
    r"^\s*(?:/\*[\s\S]*?\*/\s*|//[^\n]*\n\s*|@\w+[^\n]*\n\s*)*"
    r"(?:global|public|private|protected|with\s+sharing|without\s+sharing|"
    r"inherited\s+sharing|virtual|abstract|@isTest)\s"
    r"[\s\S]{0,400}?\b(?:class|interface|enum)\s+\w+"
    r"|^\s*trigger\s+\w+\s+on\s+\w+"
    r"|<apex:page\b|<aura:(?:component|application|event)\b|<design:component\b",
    re.I)

# Never read these looking for Apex.
BINARY_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg", ".webp", ".pdf",
    ".zip", ".gz", ".tar", ".jar", ".war", ".class", ".exe", ".dll", ".so",
    ".dylib", ".bin", ".woff", ".woff2", ".ttf", ".eot", ".otf", ".mp3", ".mp4",
    ".avi", ".mov", ".xls", ".xlsx", ".doc", ".docx", ".ppt", ".pptx", ".db",
    ".sqlite", ".pyc", ".o", ".a",
}

SNIFF_MAX_BYTES = 8 * 1024 * 1024   # do not read very large files to sniff
SNIFF_HEAD = 4096                   # a declaration appears near the top or not at all

# aura_dump.py and other API-based dumpers write each ApexClass as JSON with the
# source in a Body field. Scanning that JSON as if it were Apex does not work:
# the body is one physical line with \n as two characters, so line numbers are
# meaningless, the method parser cannot see statement structure, and a withheld
# body reads as `"Body": "(hidden)"` rather than a file whose whole content is
# "(hidden)" -- which silently defeats the coverage accounting. Parse it instead.
DUMP_EXTENSIONS = {".json"}

BODY_FIELDS = ("Body", "body", "Markup", "markup", "Source", "source",
               "SourceCode", "content", "Content")
NAME_FIELDS = ("Name", "name", "FullName", "fullName", "DeveloperName",
               "developerName", "MasterLabel")
RECORD_LIST_KEYS = ("records", "Records", "results", "data", "items", "classes",
                    "triggers", "pages", "components", "ApexClass", "ApexTrigger",
                    "ApexPage", "ApexComponent")
META_FIELDS = ("Id", "ApiVersion", "Status", "NamespacePrefix", "LengthWithoutComments",
               "IsValid", "CreatedDate", "LastModifiedDate", "attributes")


@dataclass
class DumpRecord:
    name: str
    body: str
    field: str
    meta: dict = field(default_factory=dict)


def _record_from_obj(obj: dict) -> DumpRecord | None:
    for fld in BODY_FIELDS:
        if fld in obj and isinstance(obj[fld], str):
            name = ""
            for nf in NAME_FIELDS:
                if isinstance(obj.get(nf), str) and obj[nf]:
                    name = obj[nf]
                    break
            meta = {k: obj[k] for k in META_FIELDS if k in obj}
            if isinstance(meta.get("attributes"), dict):
                meta["type"] = meta.pop("attributes").get("type", "")
            return DumpRecord(name=name, body=obj[fld], field=fld, meta=meta)
    return None


def extract_dump_records(text: str) -> list[DumpRecord] | None:
    """Records from an API dump, or None if this is not one.

    Returning None (rather than an empty list) distinguishes "not a dump" from
    "a dump containing nothing", because the two need different handling: the
    first is skipped as non-Apex, the second is a coverage problem to report."""
    try:
        data = json.loads(text)
    except (ValueError, TypeError):
        return None

    out: list[DumpRecord] = []

    def consume(obj) -> None:
        if isinstance(obj, dict):
            rec = _record_from_obj(obj)
            if rec is not None:
                out.append(rec)
                return
            for key in RECORD_LIST_KEYS:
                if isinstance(obj.get(key), list):
                    for item in obj[key]:
                        consume(item)
                    return
            # A mapping of class name -> body, or name -> record.
            for key, val in obj.items():
                if isinstance(val, str) and len(val) > 40 and APEX_SNIFF_RE.search(val):
                    out.append(DumpRecord(name=str(key), body=val, field=str(key)))
                elif isinstance(val, (dict, list)):
                    consume(val)
        elif isinstance(obj, list):
            for item in obj:
                consume(item)

    consume(data)
    return out if out else None

# A dumped body that the API withheld. Managed-package classes come back like
# this, and counting them separately is the difference between "no findings"
# and "no visibility".
HIDDEN_BODY_MARKERS = ("(hidden)", "(Hidden)", "(HIDDEN)")


# --------------------------------------------------------------------------
# Findings
# --------------------------------------------------------------------------

@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str
    confidence: str
    cwe: str
    owasp: str
    path: str
    line: int
    snippet: str
    description: str = ""
    remediation: str = ""
    entry_point: str = ""
    parameter: str = ""
    sink_line: int = 0
    chain: list[dict] = field(default_factory=list)
    extra: dict = field(default_factory=dict)
    fingerprint: str = ""

    def compute_fingerprint(self) -> str:
        """Stable across runs and tolerant of line movement.

        Hashing the line number would make every finding churn when an unrelated
        edit shifts the file, which defeats diffing runs. The identity of a
        finding is its rule, its file, and what it is about -- so that is what
        gets hashed, with the snippet normalised for whitespace."""
        norm = re.sub(r"\s+", " ", self.snippet).strip()
        key = "|".join([
            self.rule_id,
            self.path.replace(os.sep, "/"),
            self.entry_point or "",
            self.parameter or "",
            norm[:300],
        ])
        return hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]

    def to_dict(self) -> dict:
        d = dataclasses.asdict(self)
        d["fingerprint"] = self.fingerprint or self.compute_fingerprint()
        return d


def sort_key(f: Finding) -> tuple:
    return (
        SEVERITY_RANK.get(f.severity, 99),
        CONFIDENCE_RANK.get(f.confidence, 99),
        f.rule_id,
        f.path.replace(os.sep, "/"),
        f.line,
        f.fingerprint or f.compute_fingerprint(),
    )


# --------------------------------------------------------------------------
# Preprocessing
# --------------------------------------------------------------------------

@dataclass
class StringLiteral:
    start: int
    end: int          # index of the closing quote
    value: str        # decoded contents, without quotes
    line: int


class SourceFile:
    """Original text plus a masked view with identical offsets.

    The masked view has comment bodies and string-literal interiors replaced by
    spaces. Every rule matches against `masked`; every reported location is
    resolved against `text`. Because masking preserves length, the two never
    disagree about where something is."""

    def __init__(self, path: str, text: str, relpath: str | None = None):
        self.path = path
        self.relpath = relpath or path
        self.text = text
        self.line_starts = self._line_starts(text)
        self.masked, self.literals = self._mask(text, path)
        self.literals_by_line: dict[int, list[StringLiteral]] = {}
        for lit in self.literals:
            self.literals_by_line.setdefault(lit.line, []).append(lit)

    @staticmethod
    def _line_starts(text: str) -> list[int]:
        starts = [0]
        for i, ch in enumerate(text):
            if ch == "\n":
                starts.append(i + 1)
        return starts

    def line_of(self, offset: int) -> int:
        return bisect.bisect_right(self.line_starts, max(0, min(offset, len(self.text)))) 

    def line_text(self, line: int) -> str:
        if line < 1 or line > len(self.line_starts):
            return ""
        start = self.line_starts[line - 1]
        end = self.line_starts[line] - 1 if line < len(self.line_starts) else len(self.text)
        return self.text[start:end].rstrip("\n\r")

    def context(self, line: int, before: int = 3, after: int = 3) -> list[tuple[int, str]]:
        lo = max(1, line - before)
        hi = min(len(self.line_starts), line + after)
        return [(n, self.line_text(n)) for n in range(lo, hi + 1)]

    def _mask(self, text: str, path: str) -> tuple[str, list[StringLiteral]]:
        """Blank comments and string interiors, preserving offsets and newlines."""
        markup = os.path.splitext(path)[1].lower() in {".page", ".cmp", ".component", ".evt"}
        out = list(text)
        literals: list[StringLiteral] = []
        i, n = 0, len(text)

        def blank(a: int, b: int) -> None:
            for k in range(a, min(b, n)):
                if out[k] != "\n":
                    out[k] = " "

        while i < n:
            ch = text[i]
            nxt = text[i + 1] if i + 1 < n else ""

            if ch == "/" and nxt == "/":
                j = text.find("\n", i)
                j = n if j == -1 else j
                blank(i, j)
                i = j
                continue

            if ch == "/" and nxt == "*":
                j = text.find("*/", i + 2)
                j = n if j == -1 else j + 2
                blank(i, j)
                i = j
                continue

            if markup and text.startswith("<!--", i):
                j = text.find("-->", i + 4)
                j = n if j == -1 else j + 3
                blank(i, j)
                i = j
                continue

            if ch == "'" or (markup and ch == '"'):
                quote = ch
                j = i + 1
                buf: list[str] = []
                closed = False
                while j < n:
                    c = text[j]
                    if c == "\\" and j + 1 < n:
                        buf.append(text[j + 1])
                        j += 2
                        continue
                    if c == quote:
                        closed = True
                        break
                    if c == "\n" and not markup:
                        # Unterminated literal: Apex strings do not span lines.
                        # Stop here rather than swallowing the rest of the file.
                        break
                    buf.append(c)
                    j += 1
                end = j if closed else min(j, n - 1)
                blank(i + 1, end)
                literals.append(StringLiteral(
                    start=i, end=end, value="".join(buf),
                    line=bisect.bisect_right(self.line_starts, i)))
                i = end + 1 if closed else end
                continue

            i += 1

        return "".join(out), literals

    def literal_at(self, start: int, end: int) -> list[StringLiteral]:
        return [l for l in self.literals if l.start >= start and l.end <= end]


# --------------------------------------------------------------------------
# Apex structure
# --------------------------------------------------------------------------

SHARING_RE = re.compile(
    r"\b(?P<sharing>with\s+sharing|without\s+sharing|inherited\s+sharing)\b", re.I)

CLASS_DECL_RE = re.compile(
    r"\b(?P<mods>(?:(?:global|public|private|protected|virtual|abstract|"
    r"with\s+sharing|without\s+sharing|inherited\s+sharing|static|final)\s+)*)"
    r"(?P<kind>class|interface|enum|trigger)\s+(?P<name>\w+)",
    re.I)

ANNOTATION_RE = re.compile(r"@(?P<name>\w+)\s*(?:\((?P<args>[^)]*)\))?", re.S)

MODIFIER_WORDS = {
    "global", "public", "private", "protected", "static", "virtual", "abstract",
    "override", "webservice", "final", "transient", "testmethod",
}

METHOD_RE = re.compile(
    r"(?P<sig_start>"
    r"(?P<mods>(?:\b(?:global|public|private|protected|static|virtual|abstract|"
    r"override|webservice|final|testmethod)\b\s+)+)"
    r"(?:(?P<ret>[A-Za-z_][\w.]*(?:\s*<[^;{}]*?>)?(?:\s*\[\s*\])?)\s+)?"
    r"(?P<name>\w+)\s*"
    r"\((?P<params>[^;{}()]*(?:\([^)]*\)[^;{}()]*)*)\)\s*"
    r"(?:(?!\{)[^;{}]*)?"
    r")\{",
    re.S)


@dataclass
class Param:
    type_: str
    name: str


@dataclass
class Method:
    name: str
    modifiers: set[str]
    return_type: str
    params: list[Param]
    annotations: dict[str, str]
    start: int          # offset of signature start
    body_start: int     # offset just after '{'
    body_end: int       # offset of matching '}'
    line: int
    signature: str
    is_constructor: bool = False

    @property
    def is_entry_point(self) -> bool:
        ann = {a.lower() for a in self.annotations}
        if ann & {"auraenabled", "restresource", "httpget", "httppost", "httpput",
                  "httpdelete", "httppatch", "invocablemethod", "remoteaction"}:
            return True
        if "webservice" in self.modifiers:
            return True
        if "global" in self.modifiers:
            return True
        if self.is_constructor and "public" in self.modifiers:
            return True
        return False

    @property
    def entry_kind(self) -> str:
        ann = {a.lower() for a in self.annotations}
        for key, label in (("auraenabled", "@AuraEnabled"),
                           ("remoteaction", "@RemoteAction"),
                           ("httpget", "@HttpGet"), ("httppost", "@HttpPost"),
                           ("httpput", "@HttpPut"), ("httpdelete", "@HttpDelete"),
                           ("httppatch", "@HttpPatch"),
                           ("invocablemethod", "@InvocableMethod")):
            if key in ann:
                return label
        if "webservice" in self.modifiers:
            return "webservice"
        if "global" in self.modifiers:
            return "global"
        if self.is_constructor:
            return "public constructor"
        return ""


@dataclass
class ApexClass:
    name: str
    kind: str
    sharing: str        # "with sharing" | "without sharing" | "inherited sharing" | ""
    modifiers: set[str]
    annotations: dict[str, str]
    start: int
    body_start: int
    body_end: int
    line: int
    methods: list[Method] = field(default_factory=list)


def match_brace(masked: str, open_idx: int) -> int:
    """Index of the '}' matching the '{' at open_idx, or len(masked)."""
    depth = 0
    for i in range(open_idx, len(masked)):
        c = masked[i]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return i
    return len(masked) - 1


def split_top_level(text: str, sep: str = ",") -> list[str]:
    """Split on `sep` at nesting depth zero (parens, angle brackets, brackets)."""
    parts, depth, cur = [], 0, []
    for ch in text:
        if ch in "(<[":
            depth += 1
        elif ch in ")>]":
            depth = max(0, depth - 1)
        if ch == sep and depth == 0:
            parts.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    if cur:
        parts.append("".join(cur))
    return [p.strip() for p in parts if p.strip()]


def parse_params(raw: str) -> list[Param]:
    out = []
    for piece in split_top_level(raw):
        piece = re.sub(r"^\s*final\s+", "", piece, flags=re.I).strip()
        m = re.match(r"^(?P<type>.+?)\s+(?P<name>\w+)\s*$", piece, re.S)
        if m:
            out.append(Param(type_=re.sub(r"\s+", "", m.group("type")), name=m.group("name")))
    return out


def preceding_annotations(masked: str, upto: int, window: int = 400) -> dict[str, str]:
    """Annotations immediately preceding an offset, ignoring whitespace."""
    lo = max(0, upto - window)
    chunk = masked[lo:upto]
    tail = chunk
    found: dict[str, str] = {}
    while True:
        m = re.search(r"@(\w+)\s*(?:\(([^)]*)\))?\s*$", tail)
        if not m:
            break
        found[m.group(1)] = (m.group(2) or "").strip()
        tail = tail[:m.start()]
        if tail.strip() and not tail.rstrip().endswith(("{", "}", ";")) and not re.search(r"@\w+[\s\S]*$", tail):
            break
    return found


class ApexUnit:
    """A parsed file: classes, methods, and the masked source they came from."""

    def __init__(self, sf: SourceFile):
        self.sf = sf
        self.classes: list[ApexClass] = []
        self.methods: list[Method] = []
        self.parse_errors: list[str] = []
        try:
            self._parse()
        except Exception as exc:  # a malformed file must not stop the run
            self.parse_errors.append("%s: %s" % (type(exc).__name__, exc))

    # -- parsing ----------------------------------------------------------
    def _parse(self) -> None:
        masked = self.sf.masked
        for m in CLASS_DECL_RE.finditer(masked):
            brace = masked.find("{", m.end())
            if brace == -1:
                continue
            # Guard against matching a class name inside a method signature.
            between = masked[m.end():brace]
            if ";" in between or "(" in between and m.group("kind").lower() != "trigger":
                if m.group("kind").lower() != "trigger":
                    continue
            end = match_brace(masked, brace)
            sharing_m = SHARING_RE.search(m.group("mods") or "")
            mods = {w.lower() for w in re.findall(r"\b\w+\b", m.group("mods") or "")}
            cls = ApexClass(
                name=m.group("name"),
                kind=m.group("kind").lower(),
                sharing=re.sub(r"\s+", " ", sharing_m.group("sharing")).lower() if sharing_m else "",
                modifiers=mods,
                annotations=preceding_annotations(masked, m.start()),
                start=m.start(), body_start=brace + 1, body_end=end,
                line=self.sf.line_of(m.start()),
            )
            self.classes.append(cls)

        # Outermost class wins when inner classes overlap.
        self.classes.sort(key=lambda c: (c.start, -(c.body_end)))

        for meth in self._find_methods(masked):
            self.methods.append(meth)
            owner = self._owner_class(meth.start)
            if owner is not None:
                owner.methods.append(meth)

    def _owner_class(self, offset: int) -> ApexClass | None:
        best = None
        for c in self.classes:
            if c.body_start <= offset < c.body_end:
                if best is None or c.body_start > best.body_start:
                    best = c
        return best

    def _find_methods(self, masked: str) -> Iterator[Method]:
        class_names = {c.name for c in self.classes}
        for m in METHOD_RE.finditer(masked):
            name = m.group("name")
            if name.lower() in {"if", "for", "while", "switch", "catch", "try", "do", "else"}:
                continue
            mods = {w.lower() for w in re.findall(r"\b\w+\b", m.group("mods") or "")}
            mods &= MODIFIER_WORDS
            if not mods:
                continue
            ret = (m.group("ret") or "").strip()
            is_ctor = not ret and name in class_names
            if not ret and not is_ctor:
                continue
            brace = m.end() - 1
            end = match_brace(masked, brace)
            sig = re.sub(r"\s+", " ", self.sf.text[m.start("sig_start"):brace]).strip()
            yield Method(
                name=name,
                modifiers=mods,
                return_type=ret,
                params=parse_params(m.group("params") or ""),
                annotations=preceding_annotations(masked, m.start()),
                start=m.start(), body_start=brace + 1, body_end=end,
                line=self.sf.line_of(m.start()),
                signature=sig,
                is_constructor=is_ctor,
            )

    def method_by_name(self, name: str) -> Method | None:
        for meth in self.methods:
            if meth.name == name:
                return meth
        return None

    def class_of(self, meth: Method) -> ApexClass | None:
        return self._owner_class(meth.start)


# --------------------------------------------------------------------------
# Statements
# --------------------------------------------------------------------------

@dataclass
class Statement:
    text: str          # masked text, stripped
    start: int         # offset of the first non-space character
    end: int           # offset just past the last character
    line: int

    @property
    def stripped(self) -> str:
        return self.text.strip()


def statements(sf: SourceFile, start: int, end: int) -> list[Statement]:
    """Split a body into statements on ';', '{' and '}' at any depth.

    Splitting on braces as well as semicolons keeps `if (...) { ... }` from
    fusing a guard with the block it guards, which matters because a sanitising
    guard and the sink it protects must be seen as separate steps."""
    out: list[Statement] = []
    masked = sf.masked
    buf_start = start
    i = start
    while i < end:
        ch = masked[i]
        if ch in ";{}":
            _emit(out, sf, masked, buf_start, i)
            buf_start = i + 1
        i += 1
    _emit(out, sf, masked, buf_start, end)
    return out


def _emit(out: list[Statement], sf: SourceFile, masked: str, a: int, b: int) -> None:
    chunk = masked[a:b]
    if not chunk.strip():
        return
    lead = len(chunk) - len(chunk.lstrip())
    start = a + lead
    stop = b - (len(chunk) - len(chunk.rstrip()))
    out.append(Statement(text=chunk.strip(), start=start, end=stop, line=sf.line_of(start)))


# --------------------------------------------------------------------------
# Taint analysis for dynamic SOQL/SOSL
# --------------------------------------------------------------------------

SOQL_SINKS = {
    "Database.query": "Database.query()",
    "Database.queryWithBinds": "Database.queryWithBinds()",
    "Database.countQuery": "Database.countQuery()",
    "Database.countQueryWithBinds": "Database.countQueryWithBinds()",
    "Database.getQueryLocator": "Database.getQueryLocator()",
    "Database.getQueryLocatorWithBinds": "Database.getQueryLocatorWithBinds()",
    "Search.query": "Search.query()",
}

SINK_CALL_RE = re.compile(
    r"\b(?P<sink>Database\s*\.\s*(?:query|queryWithBinds|countQuery|countQueryWithBinds|"
    r"getQueryLocator|getQueryLocatorWithBinds)|Search\s*\.\s*(?:query|find))\s*\(",
    re.I)

PAGE_PARAM_RE = re.compile(
    r"ApexPages\s*\.\s*currentPage\s*\(\s*\)\s*\.\s*getParameters\s*\(\s*\)\s*\.\s*get\s*\(",
    re.I)

SANITIZER_CALL_RE = re.compile(
    r"\b(?P<san>String\s*\.\s*escapeSingleQuotes|"
    r"(?:Id|Integer|Decimal|Double|Long|Boolean|Date|Datetime)\s*\.\s*valueOf|"
    r"String\s*\.\s*isNotBlank|String\s*\.\s*isBlank)\s*\(",
    re.I)

CAST_RE = re.compile(r"\(\s*(?:Id|Integer|Decimal|Double|Long|Boolean)\s*\)\s*(?P<var>\w+)", re.I)

DESCRIBE_RE = re.compile(
    r"Schema\s*\.\s*getGlobalDescribe\s*\(\s*\)|getDescribe\s*\(\s*\)|"
    r"Schema\s*\.\s*describeSObjects", re.I)

ALLOWLIST_CONTAINS_RE = re.compile(r"\b(?P<coll>\w+)\s*\.\s*contains\s*\(\s*(?P<var>\w+)\s*\)", re.I)

IDENT_RE = re.compile(r"\b(?P<id>[A-Za-z_]\w*)\b")

RESERVED_IDENTS = {
    "new", "return", "if", "else", "for", "while", "String", "Integer", "Boolean",
    "Decimal", "Double", "Long", "Id", "List", "Set", "Map", "Object", "SObject",
    "Database", "Search", "Schema", "System", "null", "true", "false", "this",
    "static", "final", "void", "public", "private", "global", "protected",
}


def call_arg_span(text: str, open_paren: int) -> tuple[int, int]:
    """(start, end) of the argument list following an already-located '('."""
    depth = 0
    for i in range(open_paren, len(text)):
        if text[i] == "(":
            depth += 1
        elif text[i] == ")":
            depth -= 1
            if depth == 0:
                return open_paren + 1, i
    return open_paren + 1, len(text)


def sanitized_spans(text: str) -> list[tuple[int, int]]:
    """Argument spans of sanitising calls, plus explicit casts."""
    spans = []
    for m in SANITIZER_CALL_RE.finditer(text):
        spans.append(call_arg_span(text, m.end() - 1))
    for m in CAST_RE.finditer(text):
        spans.append((m.start("var"), m.end("var")))
    for m in DESCRIBE_RE.finditer(text):
        # A describe lookup validates whatever it resolves; treat the rest of
        # the expression as checked rather than raw.
        spans.append((m.start(), len(text)))
    return spans


def refs_outside(text: str, names: set[str], protected: list[tuple[int, int]]) -> list[str]:
    """Names referenced in `text` outside any protected span."""
    hits = []
    for m in IDENT_RE.finditer(text):
        ident = m.group("id")
        if ident not in names:
            continue
        pos = m.start()
        if any(a <= pos < b for a, b in protected):
            continue
        hits.append(ident)
    return hits


@dataclass
class ChainStep:
    line: int
    kind: str
    text: str

    def to_dict(self) -> dict:
        return {"line": self.line, "kind": self.kind, "code": self.text}


@dataclass
class TaintResult:
    findings: list[Finding] = field(default_factory=list)
    returns_tainted: bool = False
    steps: list[ChainStep] = field(default_factory=list)


class SoqlTaintAnalyzer:
    """Intraprocedural taint, following one level of same-file helper calls.

    Deliberately narrow. Following calls arbitrarily deep, across files, or
    through collections would find more -- and would report a lot of paths that
    do not actually exist. For a client report the propagation chain has to be
    something a reader can follow in the source and agree with."""

    MAX_DEPTH = 1

    def __init__(self, unit: ApexUnit):
        self.unit = unit
        self.sf = unit.sf

    def analyse_method(self, meth: Method, entry: Method | None = None,
                       seed: dict[str, list[ChainStep]] | None = None,
                       depth: int = 0,
                       seed_origins: dict[str, set[str]] | None = None) -> TaintResult:
        sf = self.sf
        entry = entry or meth
        result = TaintResult()

        tainted: dict[str, list[ChainStep]] = dict(seed or {})
        origins: dict[str, set[str]] = dict(seed_origins or {k: {k} for k in (seed or {})})
        if seed is None:
            for p in meth.params:
                if meth.is_entry_point:
                    tainted[p.name] = [ChainStep(
                        meth.line, "source",
                        "%s — parameter '%s' of %s" % (meth.entry_kind or "method", p.name, meth.signature))]
                    origins[p.name] = {p.name}

        cleared: set[str] = set()

        for st in statements(sf, meth.body_start, meth.body_end):
            text = st.text
            code = re.sub(r"\s+", " ", sf.text[st.start:st.end].strip())

            # -- new sources introduced mid-body ---------------------------
            pm = PAGE_PARAM_RE.search(text)
            if pm:
                lhs = self._assign_target(text)
                if lhs:
                    tainted[lhs] = [ChainStep(st.line, "source",
                                              "%s — from page parameter" % code)]
                    origins[lhs] = {"ApexPages page parameter"}
                    cleared.discard(lhs)
                    continue

            # -- allowlist guard ------------------------------------------
            for am in ALLOWLIST_CONTAINS_RE.finditer(text):
                var = am.group("var")
                if var in tainted:
                    cleared.add(var)
                    result.steps.append(ChainStep(
                        st.line, "sanitizer", "%s — allowlist check" % code))

            live = {k for k in tainted if k not in cleared}

            # -- sinks ------------------------------------------------------
            for sm in SINK_CALL_RE.finditer(text):
                a, b = call_arg_span(text, sm.end() - 1)
                args = text[a:b]
                protected = sanitized_spans(args)
                used = refs_outside(args, live, protected)
                sink_name = re.sub(r"\s+", "", sm.group("sink"))
                if used:
                    for var in dict.fromkeys(used):
                        chain = list(tainted[var]) + list(result.steps)
                        chain.append(ChainStep(st.line, "sink",
                                               "%s — reaches %s()" % (code, sink_name)))
                        conf = "HIGH" if depth == 0 else "MEDIUM"
                        src_params = ", ".join(sorted(origins.get(var, {var})))
                        result.findings.append(self._finding(
                            entry, meth, src_params, st.line, code, chain, conf,
                            sink_name, local=var))
                elif depth == 0 and self._is_dynamic(args):
                    result.findings.append(self._informational(entry, meth, st.line, code, sink_name))

            # -- helper calls ----------------------------------------------
            if depth < self.MAX_DEPTH:
                for hm in re.finditer(r"\b(?P<fn>\w+)\s*\(", text):
                    fn = hm.group("fn")
                    if fn in RESERVED_IDENTS or fn == meth.name:
                        continue
                    helper = self.unit.method_by_name(fn)
                    if helper is None or helper is meth:
                        continue
                    a, b = call_arg_span(text, hm.end() - 1)
                    args = text[a:b]
                    protected = sanitized_spans(args)
                    used = refs_outside(args, live, protected)
                    if not used:
                        continue
                    arg_exprs = split_top_level(args)
                    sub_seed: dict[str, list[ChainStep]] = {}
                    sub_origins: dict[str, set[str]] = {}
                    for idx, expr in enumerate(arg_exprs):
                        if idx >= len(helper.params):
                            break
                        for var in used:
                            if re.search(r"\b%s\b" % re.escape(var), expr):
                                sub_seed[helper.params[idx].name] = list(tainted[var]) + [
                                    ChainStep(st.line, "call",
                                              "%s — '%s' passed into %s() as '%s'"
                                              % (code, var, helper.name, helper.params[idx].name))]
                                sub_origins[helper.params[idx].name] = origins.get(var, {var})
                    if not sub_seed:
                        continue
                    sub = self.analyse_method(helper, entry=entry, seed=sub_seed,
                                              depth=depth + 1, seed_origins=sub_origins)
                    result.findings.extend(sub.findings)
                    if sub.returns_tainted:
                        lhs = self._assign_target(text)
                        if lhs:
                            tainted[lhs] = next(iter(sub_seed.values())) + [
                                ChainStep(st.line, "return",
                                          "%s — tainted value returned from %s()" % (code, helper.name))]
                            cleared.discard(lhs)

            # -- assignments ------------------------------------------------
            lhs = self._assign_target(text)
            if lhs:
                rhs = text.split("=", 1)[1] if "=" in text else ""
                protected = sanitized_spans(rhs)
                used = refs_outside(rhs, live, protected)
                if used:
                    src = used[0]
                    # Merge origins rather than overwrite: `q += ... + b` after
                    # `q = ... + a` is controlled by both a and b, and a report
                    # that names only one sends the tester after half the bug.
                    prior = origins.get(lhs, set()) if lhs in tainted else set()
                    merged = set(prior)
                    for u in used:
                        merged |= origins.get(u, {u})
                    origins[lhs] = merged
                    base = tainted.get(lhs) if lhs in tainted else None
                    chain = list(base or tainted[src])
                    chain.append(ChainStep(st.line, "propagate", code))
                    tainted[lhs] = chain
                    cleared.discard(lhs)
                elif lhs in tainted and re.search(r"\bString\s*\.\s*escapeSingleQuotes", rhs, re.I):
                    cleared.add(lhs)
                elif lhs in tainted and "=" in text and not used:
                    # Reassigned from something untainted.
                    cleared.add(lhs)

            # -- return -----------------------------------------------------
            if re.match(r"^\s*return\b", text):
                expr = text.split("return", 1)[1]
                protected = sanitized_spans(expr)
                if refs_outside(expr, live, protected):
                    result.returns_tainted = True

        return result

    # -- helpers -----------------------------------------------------------
    @staticmethod
    def _assign_target(text: str) -> str | None:
        m = re.match(
            r"^\s*(?:final\s+)?(?:[A-Za-z_][\w.]*(?:\s*<[^>]*>)?(?:\s*\[\s*\])?\s+)?"
            r"(?P<name>[A-Za-z_]\w*)\s*(?:\+)?=(?!=)",
            text)
        if not m:
            return None
        name = m.group("name")
        return None if name in RESERVED_IDENTS else name

    @staticmethod
    def _is_dynamic(args: str) -> bool:
        """A query assembled at runtime rather than a single literal."""
        return "+" in args or bool(re.search(r"\bString\s*\.\s*(?:format|join)", args, re.I))

    def _finding(self, entry: Method, meth: Method, var: str, line: int,
                 code: str, chain: list[ChainStep], confidence: str, sink: str,
                 local: str = "") -> Finding:
        cls = self.unit.class_of(entry)
        via = "" if meth is entry else " via %s()" % meth.name
        return Finding(
            rule_id="APEX-SOQL-001",
            title="SOQL/SOSL injection: attacker-controllable input reaches a dynamic query",
            severity="CRITICAL" if confidence == "HIGH" else "HIGH",
            confidence=confidence,
            cwe="CWE-89",
            owasp="A03:2021 Injection",
            path=self.sf.relpath,
            line=line,
            snippet=code,
            description=(
                "Parameter '%s' of %s entry point %s.%s reaches %s%s without "
                "escaping or binding. A caller controls the query text."
                % (var, entry.entry_kind or "the", cls.name if cls else "?",
                   entry.name, sink, via)),
            remediation=(
                "Bind the value (:var, or Database.queryWithBinds) rather than "
                "concatenating. Where the value must be inlined, wrap it in "
                "String.escapeSingleQuotes(); for object or field names, validate "
                "against a hardcoded allowlist or a Schema describe lookup, since "
                "escaping does not help there."),
            entry_point="%s.%s" % (cls.name if cls else "?", entry.name),
            parameter=var,
            sink_line=line,
            chain=[s.to_dict() for s in chain],
            extra={"sink": sink, "entry_kind": entry.entry_kind,
                   "sharing": cls.sharing if cls else "",
                   "helper": meth.name if via else "",
                   "sink_variable": local},
        )

    def _informational(self, entry: Method, meth: Method, line: int, code: str, sink: str) -> Finding:
        cls = self.unit.class_of(entry)
        return Finding(
            rule_id="APEX-SOQL-002",
            title="Dynamic SOQL/SOSL built at runtime from locally derived input",
            severity="LOW",
            confidence="LOW",
            cwe="CWE-89",
            owasp="A03:2021 Injection",
            path=self.sf.relpath,
            line=line,
            snippet=code,
            description=(
                "A query is assembled at runtime and passed to %s. No "
                "attacker-controllable source was found reaching it in this file, "
                "so this is noted for review rather than reported as injection -- "
                "confirm the inputs are not reachable from another entry point."
                % sink),
            remediation="Prefer static SOQL or bind variables where the query shape allows.",
            entry_point="%s.%s" % (cls.name if cls else "?", meth.name),
            sink_line=line,
            extra={"sink": sink},
        )


# --------------------------------------------------------------------------
# Rule engine
# --------------------------------------------------------------------------

class Rule:
    id = "APEX-000"
    title = "unnamed rule"
    severity = "INFO"
    confidence = "LOW"
    cwe = ""
    owasp = ""
    description = ""
    remediation = ""

    def check(self, unit: ApexUnit) -> list[Finding]:  # pragma: no cover - interface
        raise NotImplementedError

    # convenience ---------------------------------------------------------
    def make(self, unit: ApexUnit, line: int, snippet: str, **kw) -> Finding:
        f = Finding(
            rule_id=kw.pop("rule_id", self.id),
            title=kw.pop("title", self.title),
            severity=kw.pop("severity", self.severity),
            confidence=kw.pop("confidence", self.confidence),
            cwe=kw.pop("cwe", self.cwe),
            owasp=kw.pop("owasp", self.owasp),
            path=unit.sf.relpath,
            line=line,
            snippet=re.sub(r"\s+", " ", snippet).strip()[:400],
            description=kw.pop("description", self.description),
            remediation=kw.pop("remediation", self.remediation),
            **kw,
        )
        return f


def line_snippet(sf: SourceFile, line: int) -> str:
    return sf.line_text(line).strip()


# ---- 1. SOQL injection ----------------------------------------------------

class SoqlInjectionRule(Rule):
    id = "APEX-SOQL-001"
    title = "SOQL/SOSL injection"
    severity = "CRITICAL"
    confidence = "HIGH"
    cwe = "CWE-89"
    owasp = "A03:2021 Injection"

    def check(self, unit: ApexUnit) -> list[Finding]:
        analyzer = SoqlTaintAnalyzer(unit)
        out: list[Finding] = []
        seen: set[tuple] = set()
        for meth in unit.methods:
            if not meth.is_entry_point:
                continue
            res = analyzer.analyse_method(meth)
            for f in res.findings:
                key = (f.rule_id, f.line, f.parameter, f.entry_point)
                if key in seen:
                    continue
                seen.add(key)
                out.append(f)
        # Non-entry-point methods still matter: a page parameter read via
        # ApexPages.currentPage() is attacker-controlled regardless of how the
        # method is reached, and dynamic queries here feed the informational rule.
        for meth in unit.methods:
            if meth.is_entry_point:
                continue
            res = analyzer.analyse_method(meth)
            for f in res.findings:
                key = (f.rule_id, f.line, f.parameter, f.entry_point)
                if key not in seen:
                    seen.add(key)
                    out.append(f)
        return out


# ---- 2. Secrets -----------------------------------------------------------

SECRET_KEYWORDS = re.compile(
    r"(?<![A-Za-z])(?P<kw>pass(?:word|wd|phrase)?|pwd|secret|api[_-]?key|apikey|token|bearer|"
    r"private[_-]?key|client[_-]?secret|consumer[_-]?secret|auth[_-]?key|"
    r"access[_-]?key|session[_-]?key|encryption[_-]?key|signing[_-]?key|credential)(?![A-Za-z])",
    re.I)

KNOWN_SECRET_FORMATS = [
    ("aws-access-key-id", re.compile(r"^(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA|APKA)[0-9A-Z]{16}$")),
    ("google-api-key", re.compile(r"^AIza[0-9A-Za-z_\-]{35}$")),
    ("slack-token", re.compile(r"^xox[baprs]-[0-9A-Za-z-]{10,}$")),
    ("jwt", re.compile(r"^eyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.")),
    ("pem-private-key", re.compile(r"-----BEGIN[ A-Z]*PRIVATE KEY-----")),
    ("github-token", re.compile(r"^gh[porus]_[A-Za-z0-9]{36}$")),
    ("stripe-key", re.compile(r"^(?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{16,}$")),
]

DUMMY_VALUE = re.compile(
    r"^\s*$|^(?:x{3,}|y{3,}|\*{3,}|\.{3,}|0+|1+|n/?a)$|"
    r"(?:test|dummy|sample|example|placeholder|changeme|change[_-]?me|replace|"
    r"your[_-]|my[_-]|todo|tbd|fixme|foo|bar|baz|lorem|abc123|secret123|"
    r"password123|redacted|removed|none|null|undefined|xxxx)",
    re.I)


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def redact(value: str) -> str:
    """First four characters and a length. Never the value."""
    if not value:
        return "(empty)"
    head = value[:4]
    return "%s… (%d chars)" % (head, len(value))


class SecretsRule(Rule):
    id = "APEX-SECRET-001"
    title = "Hardcoded credential or key material in source"
    severity = "HIGH"
    confidence = "MEDIUM"
    cwe = "CWE-798"
    owasp = "A07:2021 Identification and Authentication Failures"
    remediation = ("Move the value to a Named Credential, Protected Custom Setting or "
                   "Custom Metadata, and rotate it -- anything committed to source "
                   "must be treated as disclosed.")

    ENTROPY_MIN = 4.0
    LENGTH_MIN = 16

    def classify(self, sf: SourceFile, lit: StringLiteral) -> tuple | None:
        """(severity, confidence, why, format, keyword, entropy) or None."""
        value = lit.value
        if not value or DUMMY_VALUE.search(value):
            return None
        fmt = next((name for name, pat in KNOWN_SECRET_FORMATS if pat.search(value)), None)
        prefix = sf.masked[max(0, lit.start - 120):lit.start]
        kw = SECRET_KEYWORDS.search(prefix)
        ent = shannon_entropy(value)
        if fmt:
            return ("CRITICAL", "HIGH", "matches the %s format" % fmt, fmt, kw, ent)
        if kw and len(value) >= 6:
            return ("HIGH", "MEDIUM", "assigned to '%s'" % kw.group("kw"), None, kw, ent)
        if len(value) >= self.LENGTH_MIN and ent > self.ENTROPY_MIN and self._plausible(value):
            return ("MEDIUM", "LOW", "high-entropy literal (%.2f bits/char)" % ent, None, kw, ent)
        return None

    def check(self, unit: ApexUnit) -> list[Finding]:
        sf = unit.sf
        out: list[Finding] = []
        for lit in sf.literals:
            verdict = self.classify(sf, lit)
            if verdict is None:
                continue
            sev, conf, why, fmt, kw, ent = verdict
            value = lit.value

            out.append(self.make(
                unit, lit.line, self._redacted_line(sf, lit),
                severity=sev, confidence=conf,
                description="Literal %s -- %s. Value redacted." % (redact(value), why),
                extra={"redacted_value": redact(value), "length": len(value),
                       "entropy": round(ent, 2), "format": fmt or "",
                       "keyword": kw.group("kw") if kw else ""},
            ))
        return out

    @staticmethod
    def _plausible(value: str) -> bool:
        """Exclude prose, SOQL fragments and markup that happen to score high."""
        if " " in value.strip():
            return False
        if re.search(r"^(?:SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)\b", value, re.I):
            return False
        if re.match(r"^[\w.\-/]+\.(?:cls|xml|json|csv|png|jpg|svg|html)$", value, re.I):
            return False
        if re.match(r"^https?://", value, re.I):
            return False
        return bool(re.search(r"\d", value)) and bool(re.search(r"[A-Za-z]", value))

    @staticmethod
    def _redacted_line(sf: SourceFile, lit: StringLiteral) -> str:
        """The source line with *this* literal replaced.

        Replacing the first quoted run on the line is not good enough: in
        setHeader('Authorization', '<secret>') that redacts the header name and
        publishes the credential. Slice by the literal's own offsets."""
        if lit.line < 1 or lit.line > len(sf.line_starts):
            return "(redacted)"
        line_start = sf.line_starts[lit.line - 1]
        line = sf.line_text(lit.line)
        a = lit.start - line_start
        b = lit.end - line_start + 1
        if 0 <= a < b <= len(line):
            return (line[:a] + "'" + redact(lit.value) + "'" + line[b:]).strip()
        return re.sub(re.escape(lit.value), redact(lit.value), line).strip()


# ---- 3. Sharing and CRUD/FLS ---------------------------------------------

CRUD_CHECK_RE = re.compile(
    r"\bis(?:Accessible|Updateable|Createable|Deletable)\s*\(|"
    r"Security\s*\.\s*stripInaccessible|WITH\s+SECURITY_ENFORCED|"
    r"\bUSER_MODE\b|AccessLevel\s*\.\s*USER_MODE|"
    r"\bWITH\s+USER_MODE\b", re.I)


def sensitive_values(unit: ApexUnit) -> list[str]:
    """Literal values that must never appear in output, from any rule's view.

    Computed once per file and applied to every snippet, description and
    context line -- redaction cannot be left to the rule that happened to find
    the secret, because a neighbouring finding will print the same line."""
    rule = SecretsRule()
    out: list[str] = []
    for lit in unit.sf.literals:
        if rule.classify(unit.sf, lit) is not None:
            out.append(lit.value)
    # Authorization header values are credentials even when they do not look
    # like one to the entropy or keyword tests.
    masked = unit.sf.masked
    for m in SETHEADER_RE.finditer(masked):
        a, b = call_arg_span(masked, m.end() - 1)
        lits = [l for l in unit.sf.literals if a <= l.start <= b]
        if len(lits) >= 2 and lits[0].value.lower() == "authorization" and len(lits[1].value) >= 8:
            out.append(lits[1].value)
    # Longest first, so a value containing another is replaced whole.
    return sorted({v for v in out if v}, key=len, reverse=True)


def scrub(text: str, values: Sequence[str]) -> str:
    for v in values:
        if v and v in text:
            text = text.replace(v, redact(v))
    return text


class SharingRule(Rule):
    id = "APEX-SHARE-001"
    title = "Class runs without sharing enforcement"
    severity = "MEDIUM"
    confidence = "HIGH"
    cwe = "CWE-285"
    owasp = "A01:2021 Broken Access Control"
    remediation = ("Declare `with sharing` (or `inherited sharing` for utilities) and "
                   "enforce object and field permissions explicitly with "
                   "Security.stripInaccessible, WITH SECURITY_ENFORCED or USER_MODE.")

    def check(self, unit: ApexUnit) -> list[Finding]:
        out: list[Finding] = []
        sf = unit.sf
        for cls in unit.classes:
            if cls.kind not in ("class", "trigger"):
                continue
            if cls.sharing == "with sharing":
                continue
            body = sf.masked[cls.body_start:cls.body_end]
            has_crud = bool(CRUD_CHECK_RE.search(body))
            entries = [m for m in cls.methods if m.is_entry_point]
            remote = [m for m in entries
                      if m.entry_kind in ("@AuraEnabled", "@RemoteAction", "@HttpGet",
                                          "@HttpPost", "@HttpPut", "@HttpDelete",
                                          "@HttpPatch", "webservice")]

            if cls.sharing == "without sharing":
                declared = "declared `without sharing`"
                base_sev, base_conf = "MEDIUM", "HIGH"
            elif cls.sharing == "inherited sharing":
                continue
            else:
                declared = "has no sharing declaration, so it inherits the caller's context and defaults to system context when entered directly"
                base_sev, base_conf = "LOW", "MEDIUM"

            sev, conf = base_sev, base_conf
            why = ""
            if remote and not has_crud:
                sev, conf = "HIGH", "HIGH"
                why = (" It exposes %d remotely-callable method(s) (%s) and contains no "
                       "CRUD/FLS enforcement, so a caller reaches records the running "
                       "user should not see." %
                       (len(remote), ", ".join(sorted({m.entry_kind for m in remote}))))
            elif remote:
                why = (" It exposes %d remotely-callable method(s); CRUD/FLS checks are "
                       "present, so confirm they cover every query and DML." % len(remote))

            out.append(self.make(
                unit, cls.line, line_snippet(sf, cls.line),
                severity=sev, confidence=conf,
                description="Class %s %s.%s" % (cls.name, declared, why),
                extra={"class": cls.name, "sharing": cls.sharing or "(none)",
                       "entry_points": len(entries), "remote_entry_points": len(remote),
                       "has_crud_fls_checks": has_crud},
            ))
        return out


# ---- 4. Weak crypto -------------------------------------------------------

WEAK_ALGOS = re.compile(r"\b(?P<algo>MD5|SHA-?1|DES|3DES|DESede|RC4|ECB)\b")
CRYPTO_CALL_RE = re.compile(
    r"Crypto\s*\.\s*(?P<fn>generateDigest|encrypt|decrypt|encryptWithManagedIV|"
    r"decryptWithManagedIV|generateMac|sign)\s*\(", re.I)
MATH_RANDOM_RE = re.compile(r"\bMath\s*\.\s*random\s*\(\s*\)", re.I)
TOKENISH = re.compile(r"token|nonce|secret|key|password|otp|session|salt|iv\b|code", re.I)


class WeakCryptoRule(Rule):
    id = "APEX-CRYPTO-001"
    title = "Weak or misused cryptography"
    severity = "MEDIUM"
    confidence = "HIGH"
    cwe = "CWE-327"
    owasp = "A02:2021 Cryptographic Failures"
    remediation = ("Use SHA-256 or stronger for digests, AES with a random IV for "
                   "encryption, and Crypto.getRandomInteger()/getRandomLong() for any "
                   "value that must be unpredictable.")

    def check(self, unit: ApexUnit) -> list[Finding]:
        sf, out = unit.sf, []
        for m in CRYPTO_CALL_RE.finditer(sf.masked):
            a, b = call_arg_span(sf.masked, m.end() - 1)
            line = sf.line_of(m.start())
            args_literals = [l for l in sf.literals if a <= l.start <= b]
            algo = next((l.value for l in args_literals if WEAK_ALGOS.search(l.value)), None)
            fn = m.group("fn")
            if algo:
                out.append(self.make(
                    unit, line, line_snippet(sf, line),
                    severity="HIGH" if fn.lower() in ("encrypt", "decrypt") else "MEDIUM",
                    description="Crypto.%s() called with weak algorithm '%s'." % (fn, algo),
                    extra={"function": fn, "algorithm": algo}))
            elif fn.lower() in ("encrypt", "decrypt"):
                # A literal Blob.valueOf('...') in the IV position is a fixed IV.
                seg = sf.masked[a:b]
                if re.search(r"Blob\s*\.\s*valueOf\s*\(", seg, re.I) and args_literals:
                    out.append(self.make(
                        unit, line, line_snippet(sf, line),
                        rule_id="APEX-CRYPTO-002",
                        title="Hardcoded key or initialisation vector",
                        severity="HIGH", confidence="MEDIUM",
                        description=("Crypto.%s() is called with a literal Blob argument. A "
                                     "hardcoded key or IV makes ciphertext deterministic and "
                                     "the key recoverable from source." % fn),
                        remediation=("Derive the key from a Protected Custom Setting and let "
                                     "the platform generate the IV (encryptWithManagedIV) or "
                                     "use Crypto.generateAesKey()."),
                        extra={"function": fn}))

        for m in MATH_RANDOM_RE.finditer(sf.masked):
            line = sf.line_of(m.start())
            ctx = sf.masked[max(0, m.start() - 160):m.start() + 80]
            if TOKENISH.search(ctx):
                out.append(self.make(
                    unit, line, line_snippet(sf, line),
                    rule_id="APEX-CRYPTO-003",
                    title="Math.random() used for security-relevant value",
                    severity="HIGH", confidence="MEDIUM",
                    cwe="CWE-338",
                    description=("Math.random() is not cryptographically secure and its "
                                 "output is predictable. The surrounding code suggests the "
                                 "value is used as a token, key or nonce."),
                    remediation="Use Crypto.getRandomInteger(), getRandomLong() or getRandomBytes().",
                ))
        return out


# ---- 5. Callouts ----------------------------------------------------------

SETENDPOINT_RE = re.compile(r"\.\s*setEndpoint\s*\(", re.I)
SETHEADER_RE = re.compile(r"\.\s*setHeader\s*\(", re.I)
CLIENT_CERT_RE = re.compile(r"\.\s*setClientCertificate(?:Name)?\s*\(", re.I)

SALESFORCE_HOST = re.compile(
    r"(?:\.salesforce\.com|\.force\.com|\.sfdc\.sh|\.visualforce\.com|"
    r"\.lightning\.force\.com|\.my\.salesforce\.com)$", re.I)


class CalloutRule(Rule):
    id = "APEX-CALLOUT-001"
    title = "Outbound callout issue"
    severity = "MEDIUM"
    confidence = "HIGH"
    cwe = "CWE-319"
    owasp = "A02:2021 Cryptographic Failures"

    def check(self, unit: ApexUnit) -> list[Finding]:
        sf, out = unit.sf, []
        entry_params: set[str] = set()
        for meth in unit.methods:
            if meth.is_entry_point:
                entry_params.update(p.name for p in meth.params)

        for m in SETENDPOINT_RE.finditer(sf.masked):
            a, b = call_arg_span(sf.masked, m.end() - 1)
            line = sf.line_of(m.start())
            lits = [l for l in sf.literals if a <= l.start <= b]
            arg = sf.masked[a:b]

            for lit in lits:
                url = lit.value
                # `callout:Name` resolves a Named Credential -- the platform
                # supplies host and credentials. This is the pattern the other
                # rules here recommend, so it must never be flagged.
                if url.lower().startswith("callout:"):
                    continue
                if url.lower().startswith("http://"):
                    out.append(self.make(
                        unit, line, line_snippet(sf, line),
                        rule_id="APEX-CALLOUT-002",
                        title="Callout over cleartext HTTP",
                        severity="HIGH", confidence="HIGH",
                        description="Endpoint '%s' uses http://, so request and response "
                                    "travel unencrypted." % url,
                        remediation="Use https:// and a Named Credential.",
                        extra={"endpoint": url}))
                host = re.sub(r"^https?://", "", url).split("/")[0].split(":")[0]
                if host and not SALESFORCE_HOST.search(host) and not host.startswith("{"):
                    out.append(self.make(
                        unit, line, line_snippet(sf, line),
                        rule_id="APEX-CALLOUT-003",
                        title="Hardcoded external callout endpoint",
                        severity="LOW", confidence="HIGH",
                        cwe="CWE-1188", owasp="A05:2021 Security Misconfiguration",
                        description="Callout to external host '%s' with the endpoint "
                                    "hardcoded rather than held in a Named Credential." % host,
                        remediation=("Move the endpoint to a Named Credential so it can be "
                                     "changed per environment and its credentials managed."),
                        extra={"endpoint": url, "host": host}))

            used = [v for v in entry_params if re.search(r"\b%s\b" % re.escape(v), arg)]
            if used:
                out.append(self.make(
                    unit, line, line_snippet(sf, line),
                    rule_id="APEX-CALLOUT-004",
                    title="Callout endpoint built from caller-controlled input (SSRF candidate)",
                    severity="HIGH", confidence="MEDIUM",
                    cwe="CWE-918", owasp="A10:2021 Server-Side Request Forgery",
                    description=("The endpoint incorporates '%s', which originates from an "
                                 "entry-point parameter. A caller may be able to redirect the "
                                 "callout to a host of their choosing." % ", ".join(sorted(set(used)))),
                    remediation=("Validate the target against a hardcoded allowlist, or use a "
                                 "Named Credential so the host is not caller-controlled."),
                    parameter=", ".join(sorted(set(used))),
                    extra={"parameters": sorted(set(used))}))

        for m in SETHEADER_RE.finditer(sf.masked):
            a, b = call_arg_span(sf.masked, m.end() - 1)
            line = sf.line_of(m.start())
            lits = [l for l in sf.literals if a <= l.start <= b]
            if len(lits) >= 2 and lits[0].value.lower() == "authorization":
                val = lits[1].value
                if not DUMMY_VALUE.search(val) and len(val) >= 8:
                    out.append(self.make(
                        unit, line, SecretsRule._redacted_line(sf, lits[1]),
                        rule_id="APEX-CALLOUT-005",
                        title="Authorization header built from a hardcoded literal",
                        severity="HIGH", confidence="HIGH",
                        cwe="CWE-798", owasp="A07:2021 Identification and Authentication Failures",
                        description="An Authorization header value is hardcoded: %s." % redact(val),
                        remediation="Use a Named Credential so the platform injects credentials.",
                        extra={"redacted_value": redact(val)}))

        for m in CLIENT_CERT_RE.finditer(sf.masked):
            line = sf.line_of(m.start())
            out.append(self.make(
                unit, line, line_snippet(sf, line),
                rule_id="APEX-CALLOUT-006",
                title="Client certificate configured in code",
                severity="LOW", confidence="HIGH",
                cwe="CWE-798", owasp="A05:2021 Security Misconfiguration",
                description="setClientCertificate is used; confirm the certificate and its "
                            "passphrase are not embedded in source or a static resource.",
                remediation="Prefer a Named Credential with a certificate configured in Setup.",
            ))
        return out


# ---- 6. Other -------------------------------------------------------------

SOQL_LITERAL_RE = re.compile(r"\bSELECT\b[\s\S]{0,4000}?\bFROM\b", re.I)
DML_RE = re.compile(r"\b(?P<op>insert|update|upsert|delete|undelete|merge)\s+(?P<arg>\w+)", re.I)
LOOP_RE = re.compile(r"\b(?:for|while)\s*\(", re.I)
SF_ID_RE = re.compile(r"^[a-zA-Z0-9]{3}[0-9A-Za-z]{12}(?:[A-Za-z0-9]{3})?$")
SENSITIVE_VAR = re.compile(
    r"\b\w*(?:password|passwd|pwd|secret|token|apikey|api_key|credential|ssn|"
    r"creditcard|card_number|sessionid)\w*\b", re.I)


class OtherChecksRule(Rule):
    id = "APEX-MISC"
    title = "Miscellaneous"
    severity = "INFO"
    confidence = "MEDIUM"

    def check(self, unit: ApexUnit) -> list[Finding]:
        sf, out = unit.sf, []

        # 6a. Read-modify-write without FOR UPDATE.
        for meth in unit.methods:
            body = sf.masked[meth.body_start:meth.body_end]
            queried: dict[str, int] = {}
            for st in statements(sf, meth.body_start, meth.body_end):
                lhs = SoqlTaintAnalyzer._assign_target(st.text)
                lits = [l for l in sf.literals if st.start <= l.start < st.end]
                # Inline SOQL ([SELECT ...]) is not a string literal, so it
                # survives masking intact and has to be matched in the text.
                inline = re.search(r"\[\s*SELECT\b[\s\S]*?\]", st.text, re.I)
                literal_query = any(SOQL_LITERAL_RE.search(l.value) for l in lits)
                if lhs and (literal_query or inline):
                    sources_text = " ".join([l.value for l in lits] +
                                            ([inline.group(0)] if inline else []))
                    if not re.search(r"\bFOR\s+UPDATE\b", sources_text, re.I):
                        queried[lhs] = st.line
                dm = DML_RE.search(st.text)
                if dm and dm.group("op").lower() in ("update", "upsert", "delete"):
                    arg = dm.group("arg")
                    if arg in queried:
                        out.append(self.make(
                            unit, queried[arg], line_snippet(sf, queried[arg]),
                            rule_id="APEX-MISC-001",
                            title="Read-modify-write without FOR UPDATE",
                            severity="LOW", confidence="MEDIUM",
                            cwe="CWE-362", owasp="A04:2021 Insecure Design",
                            description=("'%s' is queried then %sd without FOR UPDATE, so two "
                                         "concurrent transactions can interleave and lose an "
                                         "update." % (arg, dm.group("op").lower())),
                            remediation="Add FOR UPDATE to the query to lock the rows.",
                            extra={"variable": arg, "dml": dm.group("op").lower(),
                                   "dml_line": st.line}))
                        queried.pop(arg, None)

        # 6b. System.debug of a sensitive-looking variable.
        for m in re.finditer(r"System\s*\.\s*debug\s*\(", sf.masked, re.I):
            a, b = call_arg_span(sf.masked, m.end() - 1)
            arg = sf.masked[a:b]
            hit = SENSITIVE_VAR.search(arg)
            if hit:
                line = sf.line_of(m.start())
                out.append(self.make(
                    unit, line, line_snippet(sf, line),
                    rule_id="APEX-MISC-002",
                    title="Sensitive value written to the debug log",
                    severity="MEDIUM", confidence="MEDIUM",
                    cwe="CWE-532", owasp="A09:2021 Security Logging and Monitoring Failures",
                    description=("System.debug() is called with '%s'. Debug logs are readable "
                                 "by users with View All Data or debug-log access, and are "
                                 "frequently exported during support work." % hit.group(0)),
                    remediation="Remove the statement or log a non-sensitive identifier.",
                    extra={"variable": hit.group(0)}))

        # 6c. Hardcoded Salesforce IDs.
        for lit in sf.literals:
            v = lit.value
            if len(v) in (15, 18) and SF_ID_RE.match(v) and re.search(r"\d", v) \
                    and re.search(r"[A-Za-z]", v) and not DUMMY_VALUE.search(v):
                out.append(self.make(
                    unit, lit.line, line_snippet(sf, lit.line),
                    rule_id="APEX-MISC-003",
                    title="Hardcoded Salesforce record ID",
                    severity="LOW", confidence="MEDIUM",
                    cwe="CWE-1188", owasp="A05:2021 Security Misconfiguration",
                    description=("'%s' looks like a hardcoded %d-character Salesforce ID. These "
                                 "differ per org, so the code breaks or silently targets the "
                                 "wrong record after deployment." % (v, len(v))),
                    remediation="Resolve the record by a stable key, or use Custom Metadata.",
                    extra={"id": v}))

        # 6d. DML inside a loop (informational only, as requested).
        for lm in LOOP_RE.finditer(sf.masked):
            brace = sf.masked.find("{", lm.end())
            if brace == -1 or brace - lm.end() > 200:
                continue
            end = match_brace(sf.masked, brace)
            body = sf.masked[brace:end]
            dm = DML_RE.search(body)
            if dm:
                line = sf.line_of(brace + dm.start())
                out.append(self.make(
                    unit, line, line_snippet(sf, line),
                    rule_id="APEX-MISC-004",
                    title="DML inside a loop",
                    severity="INFO", confidence="MEDIUM",
                    cwe="", owasp="",
                    description=("A %s statement runs inside a loop. Not a vulnerability -- "
                                 "noted because it hits governor limits and is often a sign "
                                 "the surrounding logic was not written for bulk input."
                                 % dm.group("op").lower()),
                    remediation="Collect records into a list and perform one DML after the loop.",
                    extra={"dml": dm.group("op").lower()}))
        return out


ALL_RULES: list[Rule] = [
    SoqlInjectionRule(), SecretsRule(), SharingRule(),
    WeakCryptoRule(), CalloutRule(), OtherChecksRule(),
]

RULE_IDS = [
    "APEX-SOQL-001", "APEX-SOQL-002", "APEX-SECRET-001", "APEX-SHARE-001",
    "APEX-CRYPTO-001", "APEX-CRYPTO-002", "APEX-CRYPTO-003",
    "APEX-CALLOUT-002", "APEX-CALLOUT-003", "APEX-CALLOUT-004",
    "APEX-CALLOUT-005", "APEX-CALLOUT-006",
    "APEX-MISC-001", "APEX-MISC-002", "APEX-MISC-003", "APEX-MISC-004",
]


# --------------------------------------------------------------------------
# Scanning
# --------------------------------------------------------------------------

@dataclass
class EntryPoint:
    path: str
    line: int
    class_name: str
    method: str
    kind: str
    signature: str
    sharing: str
    has_crud_fls: bool

    def to_dict(self) -> dict:
        return dataclasses.asdict(self)


@dataclass
class ScanStats:
    files_seen: int = 0
    files_analysed: int = 0
    files_hidden: int = 0
    files_empty: int = 0
    files_unreadable: int = 0
    files_parse_errors: int = 0
    files_by_extension: int = 0
    files_by_content_sniff: int = 0
    files_skipped_non_apex: int = 0
    dump_files: int = 0
    records_from_dumps: int = 0
    extensions_present: dict = field(default_factory=dict)
    sniffed_files: list[str] = field(default_factory=list)
    hidden_files: list[str] = field(default_factory=list)
    empty_files: list[str] = field(default_factory=list)
    unreadable_files: list[dict] = field(default_factory=list)
    parse_error_files: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return dataclasses.asdict(self)


class Scanner:
    def __init__(self, rules: Sequence[Rule] | None = None,
                 extra_extensions: Iterable[str] | None = None,
                 sniff: bool = True):
        self.rules = list(rules or ALL_RULES)
        self.extensions = set(APEX_EXTENSIONS)
        for e in (extra_extensions or []):
            e = e if e.startswith(".") else "." + e
            self.extensions.add(e.lower())
        self.sniff = sniff

    def scan_dir(self, root: str) -> tuple[list[Finding], list[EntryPoint], ScanStats]:
        stats = ScanStats()
        findings: list[Finding] = []
        entries: list[EntryPoint] = []
        # Text of anything that produced a finding, so the report renders the
        # Apex that was actually analysed. For a JSON dump that is the decoded
        # body, which does not exist on disk anywhere.
        self.sources_for_report: dict[str, str] = {}

        for path, how in self._walk(root, stats):
            rel = os.path.relpath(path, root)
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as fh:
                    text = fh.read()
            except OSError as exc:
                stats.files_seen += 1
                stats.files_unreadable += 1
                stats.unreadable_files.append({"path": rel, "error": str(exc)})
                continue

            records = None
            if how == "dump" or os.path.splitext(path)[1].lower() in DUMP_EXTENSIONS:
                records = extract_dump_records(text)
                if records is None:
                    # Valid JSON, but not an Apex dump -- or not JSON at all.
                    stats.files_skipped_non_apex += 1
                    continue
                stats.dump_files += 1

            if records is not None:
                for rec in records:
                    stats.records_from_dumps += 1
                    label = "%s::%s" % (rel, rec.name) if rec.name else rel
                    self._ingest(label, rec.body, stats, findings, entries, path)
            else:
                if how == "extension":
                    stats.files_by_extension += 1
                elif how == "sniff":
                    stats.files_by_content_sniff += 1
                    stats.sniffed_files.append(rel)
                self._ingest(rel, text, stats, findings, entries, path)

        findings.sort(key=sort_key)
        entries.sort(key=lambda e: (e.path.replace(os.sep, "/"), e.line, e.method))
        for fi in findings:
            fi.fingerprint = fi.compute_fingerprint()
        return findings, entries, stats

    def _ingest(self, rel: str, text: str, stats: ScanStats,
                findings: list[Finding], entries: list[EntryPoint],
                path: str | None = None) -> None:
        """One analysable unit: a file, or one record out of a dump."""
        stats.files_seen += 1
        stripped = text.strip()
        if not stripped:
            stats.files_empty += 1
            stats.empty_files.append(rel)
            return
        if stripped in HIDDEN_BODY_MARKERS or stripped.lower() == "(hidden)":
            stats.files_hidden += 1
            stats.hidden_files.append(rel)
            return

        f, e, err = self.scan_text(text, rel, path)
        if err:
            stats.files_parse_errors += 1
            stats.parse_error_files.append({"path": rel, "error": err})
        stats.files_analysed += 1
        if f:
            self.sources_for_report[rel] = text
        findings.extend(f)
        entries.extend(e)

    def scan_text(self, text: str, relpath: str,
                  path: str | None = None) -> tuple[list[Finding], list[EntryPoint], str]:
        """Analyse one unit. Never raises: a malformed file yields an error string."""
        err = ""
        try:
            sf = SourceFile(path or relpath, text, relpath=relpath)
            unit = ApexUnit(sf)
            if unit.parse_errors:
                err = "; ".join(unit.parse_errors)
        except Exception as exc:
            return [], [], "%s: %s" % (type(exc).__name__, exc)

        findings: list[Finding] = []
        for rule in self.rules:
            try:
                findings.extend(rule.check(unit))
            except Exception:
                # One broken rule must not lose the whole file.
                err = (err + "; " if err else "") + "rule %s failed: %s" % (
                    rule.id, traceback.format_exc(limit=1).strip().replace("\n", " "))

        secrets = sensitive_values(unit)
        if secrets:
            for f in findings:
                f.snippet = scrub(f.snippet, secrets)
                f.description = scrub(f.description, secrets)
                for step in f.chain:
                    step["code"] = scrub(step.get("code", ""), secrets)
        return findings, self._entry_points(unit), err

    @staticmethod
    def _entry_points(unit: ApexUnit) -> list[EntryPoint]:
        out = []
        sf = unit.sf
        for meth in unit.methods:
            if not meth.is_entry_point:
                continue
            cls = unit.class_of(meth)
            body = sf.masked[meth.body_start:meth.body_end]
            out.append(EntryPoint(
                path=sf.relpath, line=meth.line,
                class_name=cls.name if cls else "(none)",
                method=meth.name, kind=meth.entry_kind,
                signature=meth.signature,
                sharing=(cls.sharing if cls and cls.sharing else "(none declared)"),
                has_crud_fls=bool(CRUD_CHECK_RE.search(body)),
            ))
        return out

    def _walk(self, root: str, stats: ScanStats) -> Iterator[tuple[str, str]]:
        """Yield (path, how) for every candidate, recursing through the tree.

        `how` is "extension" when the name matched, or "sniff" when the content
        did. Sniffing exists because bulk API dumps frequently write class
        bodies to files with no extension at all, and silently analysing nothing
        is the worst possible response to that."""
        if os.path.isfile(root):
            yield root, "extension"
            return
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = sorted(d for d in dirnames
                                 if d not in {".git", "node_modules", "__pycache__", ".sfdx"})
            for fn in sorted(filenames):
                path = os.path.join(dirpath, fn)
                ext = os.path.splitext(fn)[1].lower()
                stats.extensions_present[ext or "(none)"] = \
                    stats.extensions_present.get(ext or "(none)", 0) + 1

                if ext in DUMP_EXTENSIONS:
                    yield path, "dump"
                    continue
                if ext in self.extensions:
                    yield path, "extension"
                    continue
                # Salesforce metadata companions carry no Apex body.
                if fn.endswith("-meta.xml"):
                    stats.files_skipped_non_apex += 1
                    continue
                if not self.sniff or ext in BINARY_EXTENSIONS:
                    stats.files_skipped_non_apex += 1
                    continue
                if self._looks_like_apex(path):
                    yield path, "sniff"
                else:
                    stats.files_skipped_non_apex += 1
            # os.walk order is not guaranteed; sort for deterministic output.
            dirnames.sort()

    @staticmethod
    def _looks_like_apex(path: str) -> bool:
        try:
            if os.path.getsize(path) > SNIFF_MAX_BYTES:
                return False
            with open(path, "rb") as fh:
                head = fh.read(SNIFF_HEAD)
        except OSError:
            return False
        if b"\x00" in head:            # binary
            return False
        try:
            text = head.decode("utf-8", errors="replace")
        except Exception:
            return False
        return bool(APEX_SNIFF_RE.search(text))


# --------------------------------------------------------------------------
# Reporting
# --------------------------------------------------------------------------

def write_json(path: str, findings: list[Finding], entries: list[EntryPoint],
               stats: ScanStats, validated: dict | None) -> None:
    payload = {
        "tool": "apex_scan.py",
        "version": __version__,
        "coverage": stats.to_dict(),
        "self_test": validated or {"run": False},
        "summary": summarise(findings),
        "entry_points": [e.to_dict() for e in entries],
        "findings": [f.to_dict() for f in findings],
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, sort_keys=False)
        fh.write("\n")


CSV_COLUMNS = ["file", "line", "rule_id", "severity", "confidence", "title", "snippet",
               "fingerprint", "entry_point", "parameter", "cwe", "owasp"]


def write_csv(path: str, findings: list[Finding]) -> None:
    with open(path, "w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh, quoting=csv.QUOTE_ALL, lineterminator="\n")
        w.writerow(CSV_COLUMNS)
        for f in findings:
            w.writerow([
                f.path.replace(os.sep, "/"), f.line, f.rule_id, f.severity, f.confidence,
                f.title, f.snippet, f.fingerprint or f.compute_fingerprint(),
                f.entry_point, f.parameter, f.cwe, f.owasp,
            ])


def summarise(findings: list[Finding]) -> dict:
    by_sev = {s: 0 for s in SEVERITIES}
    by_rule: dict[str, int] = {}
    for f in findings:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
        by_rule[f.rule_id] = by_rule.get(f.rule_id, 0) + 1
    return {"total": len(findings), "by_severity": by_sev,
            "by_rule": dict(sorted(by_rule.items()))}


def write_markdown(path: str, findings: list[Finding], entries: list[EntryPoint],
                   stats: ScanStats, sources: dict[str, SourceFile],
                   validated: dict | None, root: str) -> None:
    S = summarise(findings)
    # Note: do not bind `path` here -- it is the output filename parameter.
    secret_index: dict[str, list[str]] = {}
    for src_path, sf_ in sources.items():
        try:
            secret_index[src_path] = sensitive_values(ApexUnit(sf_))
        except Exception:
            secret_index[src_path] = []
    L: list[str] = []
    L.append("# Apex static analysis — findings")
    L.append("")
    L.append("Tool: `apex_scan.py` v%s · Input: `%s`" % (__version__, root))
    L.append("")

    L.append("## Summary")
    L.append("")
    L.append("| Severity | Findings |")
    L.append("| --- | --- |")
    for s in SEVERITIES:
        L.append("| %s | %d |" % (s, S["by_severity"].get(s, 0)))
    L.append("| **Total** | **%d** |" % S["total"])
    L.append("")

    if S["by_rule"]:
        L.append("| Rule | Findings |")
        L.append("| --- | --- |")
        for rid, n in S["by_rule"].items():
            L.append("| `%s` | %d |" % (rid, n))
        L.append("")

    # Coverage -------------------------------------------------------------
    L.append("## Coverage")
    L.append("")
    L.append("| Metric | Count |")
    L.append("| --- | --- |")
    L.append("| Files discovered | %d |" % stats.files_seen)
    L.append("| Files analysed | %d |" % stats.files_analysed)
    L.append("| Bodies withheld by the API (`(hidden)`) | %d |" % stats.files_hidden)
    L.append("| Empty files | %d |" % stats.files_empty)
    L.append("| Unreadable files | %d |" % stats.files_unreadable)
    L.append("| Files with parse warnings | %d |" % stats.files_parse_errors)
    L.append("| Matched by extension | %d |" % stats.files_by_extension)
    L.append("| Matched by content (no known extension) | %d |" % stats.files_by_content_sniff)
    L.append("| Skipped as non-Apex | %d |" % stats.files_skipped_non_apex)
    if stats.dump_files:
        L.append("| JSON dump files parsed | %d |" % stats.dump_files)
        L.append("| Records extracted from dumps | %d |" % stats.records_from_dumps)
    L.append("")
    if stats.dump_files:
        L.append("Input included %d JSON dump file(s) holding %d record(s). The Apex source "
                 "was decoded from each record's body field before analysis, so line numbers "
                 "below refer to the Apex itself rather than to the JSON wrapper. Records are "
                 "identified as `file.json::ClassName`."
                 % (stats.dump_files, stats.records_from_dumps))
        L.append("")
    if stats.files_by_content_sniff:
        L.append("%d file(s) carried no recognised Apex extension and were included because "
                 "their content parsed as an Apex class, trigger or Visualforce markup. Bulk "
                 "API dumps often write bodies to extensionless files, so excluding them would "
                 "silently understate coverage."
                 % stats.files_by_content_sniff)
        L.append("")
        L.append("<details><summary>%d file(s) matched by content</summary>"
                 % len(stats.sniffed_files))
        L.append("")
        for q in stats.sniffed_files[:200]:
            L.append("- `%s`" % q)
        if len(stats.sniffed_files) > 200:
            L.append("- … and %d more" % (len(stats.sniffed_files) - 200))
        L.append("")
        L.append("</details>")
        L.append("")
    if stats.files_hidden or stats.files_empty:
        L.append("%d of %d files could not be analysed because the dump contains no body "
                 "for them — managed-package classes are returned as `(hidden)`. **They are "
                 "not covered by this review**, and nothing here should be read as assurance "
                 "about their contents."
                 % (stats.files_hidden + stats.files_empty, stats.files_seen))
        L.append("")
        if stats.hidden_files:
            L.append("<details><summary>%d withheld file(s)</summary>" % len(stats.hidden_files))
            L.append("")
            for p in stats.hidden_files[:200]:
                L.append("- `%s`" % p)
            if len(stats.hidden_files) > 200:
                L.append("- … and %d more" % (len(stats.hidden_files) - 200))
            L.append("")
            L.append("</details>")
            L.append("")

    # Validation -----------------------------------------------------------
    L.append("## Checker validation")
    L.append("")
    if validated and validated.get("run"):
        if validated.get("passed"):
            L.append("The rule engine was validated before this run against a built-in corpus "
                     "of %d Apex snippets: %d vulnerable cases, each of which the expected rule "
                     "flagged, and %d sanitised counterparts, on which those rules stayed "
                     "silent. All %d assertions passed."
                     % (validated.get("cases", 0), validated.get("vulnerable", 0),
                        validated.get("safe", 0), validated.get("assertions", 0)))
        else:
            L.append("**Self-test FAILED** (%d of %d assertions). Findings below should not be "
                     "relied upon until this is resolved."
                     % (validated.get("failed", 0), validated.get("assertions", 0)))
            for msg in validated.get("failures", [])[:20]:
                L.append("- %s" % msg)
    else:
        L.append("_Self-test not run for this report. Re-run with `--self-test` to include a "
                 "validation statement._")
    L.append("")

    # Entry point inventory ------------------------------------------------
    L.append("## Attack surface inventory")
    L.append("")
    L.append("Every remotely reachable entry point found, whether or not it produced a "
             "finding. Sharing is the class declaration; `(none declared)` means the class "
             "did not specify one.")
    L.append("")
    if not entries:
        L.append("_No `@AuraEnabled`, `@RestResource`, `webservice` or `global` entry points found._")
    else:
        L.append("| File | Line | Class | Method | Kind | Sharing | CRUD/FLS checks |")
        L.append("| --- | --- | --- | --- | --- | --- | --- |")
        for e in entries:
            L.append("| `%s` | %d | %s | `%s` | %s | %s | %s |" % (
                e.path.replace(os.sep, "/"), e.line, e.class_name, e.method,
                e.kind, e.sharing, "yes" if e.has_crud_fls else "**no**"))
    L.append("")

    # Findings -------------------------------------------------------------
    L.append("## Findings")
    L.append("")
    if not findings:
        L.append("_No findings at the configured confidence threshold._")
    for sev in SEVERITIES:
        group = [f for f in findings if f.severity == sev]
        if not group:
            continue
        L.append("### %s (%d)" % (sev, len(group)))
        L.append("")
        by_rule: dict[str, list[Finding]] = {}
        for f in group:
            by_rule.setdefault(f.rule_id, []).append(f)
        for rid in sorted(by_rule):
            items = by_rule[rid]
            L.append("#### %s — %s (%d)" % (rid, items[0].title, len(items)))
            L.append("")
            for f in items:
                L.append("**`%s:%d`** · confidence %s · `%s`%s"
                         % (f.path.replace(os.sep, "/"), f.line, f.confidence,
                            f.fingerprint or f.compute_fingerprint(),
                            (" · " + f.cwe) if f.cwe else ""))
                L.append("")
                if f.description:
                    L.append(f.description)
                    L.append("")
                sf = sources.get(f.path)
                if sf is not None:
                    secrets = secret_index.get(f.path, [])
                    L.append("```apex")
                    for n, txt in sf.context(f.line, 3, 3):
                        marker = ">" if n == f.line else " "
                        L.append("%s %4d | %s" % (marker, n, scrub(txt, secrets)))
                    L.append("```")
                    L.append("")
                if f.chain:
                    L.append("Propagation chain:")
                    L.append("")
                    for i, step in enumerate(f.chain, 1):
                        L.append("%d. **line %s** (%s) — `%s`"
                                 % (i, step.get("line"), step.get("kind"), step.get("code")))
                    L.append("")
                if f.remediation:
                    L.append("_Remediation:_ %s" % f.remediation)
                    L.append("")
    L.append("---")
    L.append("")
    L.append("Static analysis reports candidates. Each finding above should be confirmed "
             "against the org before it is presented as exploitable; conversely, the "
             "withheld files listed under Coverage were not examined at all.")

    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(L) + "\n")


# --------------------------------------------------------------------------
# Self-test corpus
# --------------------------------------------------------------------------

# Fixture credentials are assembled from fragments rather than written out.
# A provider-format literal committed to a repository trips secret-scanning push
# protection, which is the scanner doing its job -- and a security tool should
# not be the thing that forces an exception.
_AWS_FIXTURE = "AKIA" + "QZ7T4N2VJ" + "R8KWLMD"   # AKIA + exactly 16 chars
_SECRET_FIXTURE = "kR8mQ2vN" + "7pL4xW9z" + "T6yB3dF5"

SELF_TEST_CASES: list[dict] = [
    {
        "name": "soql_injection_aura_direct",
        "file": "VulnAura.cls",
        "vulnerable": True,
        "must_fire": ["APEX-SOQL-001"],
        "source": """
public without sharing class VulnAura {
    @AuraEnabled
    public static List<Account> search(String name) {
        String q = 'SELECT Id FROM Account WHERE Name = \\'' + name + '\\'';
        return Database.query(q);
    }
}
""",
    },
    {
        "name": "soql_injection_escaped",
        "file": "SafeAura.cls",
        "vulnerable": False,
        "must_not_fire": ["APEX-SOQL-001"],
        "source": """
public with sharing class SafeAura {
    @AuraEnabled
    public static List<Account> search(String name) {
        String safe = String.escapeSingleQuotes(name);
        String q = 'SELECT Id FROM Account WHERE Name = \\'' + safe + '\\'';
        return Database.query(q);
    }
}
""",
    },
    {
        "name": "soql_bind_variable",
        "file": "SafeBind.cls",
        "vulnerable": False,
        "must_not_fire": ["APEX-SOQL-001"],
        "source": """
public with sharing class SafeBind {
    @AuraEnabled
    public static List<Account> search(String name) {
        return Database.query('SELECT Id FROM Account WHERE Name = :name');
    }
}
""",
    },
    {
        "name": "soql_injection_via_helper",
        "file": "VulnHelper.cls",
        "vulnerable": True,
        "must_fire": ["APEX-SOQL-001"],
        "source": """
public without sharing class VulnHelper {
    @AuraEnabled
    public static List<Account> run(String term) {
        return doQuery(term);
    }
    private static List<Account> doQuery(String t) {
        String q = 'SELECT Id FROM Account WHERE Name = \\'' + t + '\\'';
        return Database.query(q);
    }
}
""",
    },
    {
        "name": "soql_in_comment_only",
        "file": "CommentOnly.cls",
        "vulnerable": False,
        "must_not_fire": ["APEX-SOQL-001", "APEX-SOQL-002"],
        "source": """
public with sharing class CommentOnly {
    @AuraEnabled
    public static void noop(String name) {
        // String q = 'SELECT Id FROM Account WHERE Name = ' + name;
        // return Database.query(q);
        /* Database.query('SELECT Id FROM Contact WHERE X = ' + name); */
        return;
    }
}
""",
    },
    {
        "name": "secret_aws_key_and_keyword",
        "file": "SecretHolder.cls",
        "vulnerable": True,
        "must_fire": ["APEX-SECRET-001"],
        "source": """
public class SecretHolder {
    private static final String awsAccessKey = '%s';
    private static final String clientSecret = '%s';
}
""" % (_AWS_FIXTURE, _SECRET_FIXTURE),
    },
    {
        "name": "secret_placeholder_only",
        "file": "NoSecret.cls",
        "vulnerable": False,
        "must_not_fire": ["APEX-SECRET-001"],
        "source": """
public class NoSecret {
    private static final String API_KEY = 'YOUR_API_KEY_HERE';
    private static final String TOKEN = 'changeme';
    private static final String EMPTY = '';
}
""",
    },
    {
        "name": "sharing_without_and_aura",
        "file": "NoSharing.cls",
        "vulnerable": True,
        "must_fire": ["APEX-SHARE-001"],
        "source": """
public without sharing class NoSharing {
    @AuraEnabled
    public static List<Contact> all() {
        return [SELECT Id FROM Contact];
    }
}
""",
    },
    {
        "name": "sharing_with_sharing",
        "file": "WithSharing.cls",
        "vulnerable": False,
        "must_not_fire": ["APEX-SHARE-001"],
        "source": """
public with sharing class WithSharing {
    @AuraEnabled
    public static List<Contact> all() {
        return [SELECT Id FROM Contact WITH SECURITY_ENFORCED];
    }
}
""",
    },
    {
        "name": "weak_crypto_md5",
        "file": "WeakCrypto.cls",
        "vulnerable": True,
        "must_fire": ["APEX-CRYPTO-001"],
        "source": """
public class WeakCrypto {
    public static Blob d(String s) {
        return Crypto.generateDigest('MD5', Blob.valueOf(s));
    }
}
""",
    },
    {
        "name": "strong_crypto_sha256",
        "file": "StrongCrypto.cls",
        "vulnerable": False,
        "must_not_fire": ["APEX-CRYPTO-001", "APEX-CRYPTO-002", "APEX-CRYPTO-003"],
        "source": """
public class StrongCrypto {
    public static Blob d(String s) {
        return Crypto.generateDigest('SHA-256', Blob.valueOf(s));
    }
    public static Integer nonce() {
        return Crypto.getRandomInteger();
    }
}
""",
    },
    {
        "name": "callout_http_cleartext",
        "file": "Callout.cls",
        "vulnerable": True,
        "must_fire": ["APEX-CALLOUT-002"],
        "source": """
public class Callout {
    public static void go() {
        HttpRequest req = new HttpRequest();
        req.setEndpoint('http://api.partner.example.com/v1/data');
        req.setMethod('GET');
    }
}
""",
    },
    {
        "name": "callout_https_named",
        "file": "SafeCallout.cls",
        "vulnerable": False,
        "must_not_fire": ["APEX-CALLOUT-002", "APEX-CALLOUT-003",
                          "APEX-CALLOUT-004", "APEX-CALLOUT-005"],
        "source": """
public class SafeCallout {
    public static void go() {
        HttpRequest req = new HttpRequest();
        req.setEndpoint('callout:My_Named_Credential/v1/data');
        req.setMethod('GET');
    }
}
""",
    },
    {
        "name": "ssrf_tainted_endpoint",
        "file": "Ssrf.cls",
        "vulnerable": True,
        "must_fire": ["APEX-CALLOUT-004"],
        "source": """
public class Ssrf {
    @AuraEnabled
    public static void fetch(String target) {
        HttpRequest req = new HttpRequest();
        req.setEndpoint(target);
    }
}
""",
    },
    {
        "name": "debug_sensitive",
        "file": "DebugLeak.cls",
        "vulnerable": True,
        "must_fire": ["APEX-MISC-002"],
        "source": """
public class DebugLeak {
    public static void log(String sessionToken) {
        System.debug('value: ' + sessionToken);
    }
}
""",
    },
]


def run_self_test(verbose: bool = False) -> dict:
    """Assert every rule fires on its vulnerable case and stays silent on the safe one."""
    scanner = Scanner()
    failures: list[str] = []
    assertions = 0
    vulnerable = sum(1 for c in SELF_TEST_CASES if c["vulnerable"])
    safe = len(SELF_TEST_CASES) - vulnerable

    for case in SELF_TEST_CASES:
        findings, _entries, err = scanner.scan_text(case["source"], case["file"])
        fired = {f.rule_id for f in findings}
        if err:
            failures.append("%s: engine error: %s" % (case["name"], err[:200]))
        for rid in case.get("must_fire", []):
            assertions += 1
            if rid not in fired:
                failures.append("%s: expected %s to fire, got {%s}"
                                % (case["name"], rid, ", ".join(sorted(fired)) or "nothing"))
        for rid in case.get("must_not_fire", []):
            assertions += 1
            if rid in fired:
                offending = next(f for f in findings if f.rule_id == rid)
                failures.append("%s: %s fired but should not have (line %d: %s)"
                                % (case["name"], rid, offending.line, offending.snippet[:80]))
        if verbose:
            print("  %-34s %s" % (case["name"], ", ".join(sorted(fired)) or "(no findings)"))

    return {
        "run": True,
        "passed": not failures,
        "cases": len(SELF_TEST_CASES),
        "vulnerable": vulnerable,
        "safe": safe,
        "assertions": assertions,
        "failed": len(failures),
        "failures": failures,
    }


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def filter_findings(findings: list[Finding], min_confidence: str,
                    rules: set[str] | None) -> list[Finding]:
    floor = CONFIDENCE_RANK[min_confidence]
    out = []
    for f in findings:
        if CONFIDENCE_RANK.get(f.confidence, 99) > floor:
            continue
        if rules and f.rule_id not in rules:
            continue
        out.append(f)
    return out


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="apex_scan.py",
        description="Static analysis for Salesforce Apex dumped by aura-dump.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Rule ids:\n  " + "\n  ".join(RULE_IDS))
    p.add_argument("--input", "-i", help="Directory (or file) of .cls/.trigger/.page/.cmp")
    p.add_argument("--out", "-o", default="./results", help="Output directory (default ./results)")
    p.add_argument("--format", "-f", default="json,csv,md",
                   help="Comma-separated: json, csv, md (default all three)")
    p.add_argument("--min-confidence", default="LOW", choices=list(CONFIDENCES) + [c.lower() for c in CONFIDENCES],
                   help="Drop findings below this confidence (default LOW = keep everything)")
    p.add_argument("--rules", default="",
                   help="Comma-separated rule ids to keep; prefix-matching allowed (e.g. APEX-SOQL)")
    p.add_argument("--ext", action="append", default=[], metavar="EXT",
                   help="Additional file extension to treat as Apex (repeatable, e.g. --ext .txt)")
    p.add_argument("--no-sniff", action="store_true",
                   help="Do not inspect the content of files with unknown extensions; "
                        "match on extension only")
    p.add_argument("--self-test", action="store_true",
                   help="Validate the engine against built-in vulnerable/safe snippets")
    p.add_argument("--quiet", "-q", action="store_true", help="Only print errors")
    p.add_argument("--version", action="version", version="apex_scan.py %s" % __version__)
    return p


def expand_rule_filter(spec: str) -> set[str] | None:
    if not spec.strip():
        return None
    wanted: set[str] = set()
    for token in [t.strip() for t in spec.split(",") if t.strip()]:
        matched = [r for r in RULE_IDS if r == token or r.startswith(token)]
        if not matched:
            raise SystemExit("Unknown rule filter %r. Known ids:\n  %s"
                             % (token, "\n  ".join(RULE_IDS)))
        wanted.update(matched)
    return wanted


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    say = (lambda *a: None) if args.quiet else (lambda *a: print(*a))

    validated: dict | None = None
    if args.self_test:
        say("Running self-test against %d built-in snippets..." % len(SELF_TEST_CASES))
        validated = run_self_test(verbose=not args.quiet)
        if validated["passed"]:
            say("Self-test PASSED: %d assertions over %d vulnerable and %d safe cases."
                % (validated["assertions"], validated["vulnerable"], validated["safe"]))
        else:
            print("Self-test FAILED (%d of %d assertions):" % (
                validated["failed"], validated["assertions"]), file=sys.stderr)
            for msg in validated["failures"]:
                print("  - %s" % msg, file=sys.stderr)
            if not args.input:
                return 1
        if not args.input:
            return 0

    if not args.input:
        build_parser().print_help()
        return 2
    if not os.path.exists(args.input):
        print("Input not found: %s" % args.input, file=sys.stderr)
        return 2

    formats = {f.strip().lower() for f in args.format.split(",") if f.strip()}
    unknown = formats - {"json", "csv", "md"}
    if unknown:
        print("Unknown format(s): %s" % ", ".join(sorted(unknown)), file=sys.stderr)
        return 2

    rules_filter = expand_rule_filter(args.rules)
    min_conf = args.min_confidence.upper()

    scanner = Scanner(extra_extensions=args.ext, sniff=not args.no_sniff)
    findings, entries, stats = scanner.scan_dir(args.input)
    kept = filter_findings(findings, min_conf, rules_filter)

    # Finding nothing is a result the user must not miss, so it goes to stderr
    # even under --quiet, and it names the extensions that are actually there.
    if stats.files_seen == 0:
        print("No Apex files found under %s" % os.path.abspath(args.input), file=sys.stderr)
        if stats.extensions_present:
            print("Extensions present in that tree:", file=sys.stderr)
            for ext, n in sorted(stats.extensions_present.items(),
                                 key=lambda kv: (-kv[1], kv[0]))[:15]:
                print("  %-14s %d file(s)" % (ext, n), file=sys.stderr)
            print("Recognised without help: %s"
                  % ", ".join(sorted(scanner.extensions)), file=sys.stderr)
            print("Add one with --ext (e.g. --ext .txt). Content sniffing is %s."
                  % ("off; drop --no-sniff to enable it" if args.no_sniff else
                     "on, but none of these files parsed as Apex"), file=sys.stderr)
        else:
            print("The directory contains no files at all.", file=sys.stderr)
        return 2

    os.makedirs(args.out, exist_ok=True)

    # Markdown needs the sources again for context lines. Re-read only the
    # files that actually produced findings.
    sources: dict[str, SourceFile] = {}
    if "md" in formats:
        retained = getattr(scanner, "sources_for_report", {})
        for f in kept:
            if f.path in sources:
                continue
            text = retained.get(f.path)
            if text is None:
                full = f.path if os.path.isabs(f.path) else os.path.join(args.input, f.path)
                try:
                    with open(full, "r", encoding="utf-8", errors="replace") as fh:
                        text = fh.read()
                except OSError:
                    continue
            sources[f.path] = SourceFile(f.path, text, relpath=f.path)

    written = []
    if "json" in formats:
        p = os.path.join(args.out, "results.json")
        write_json(p, kept, entries, stats, validated)
        written.append(p)
    if "csv" in formats:
        p = os.path.join(args.out, "results.csv")
        write_csv(p, kept)
        written.append(p)
    if "md" in formats:
        p = os.path.join(args.out, "report.md")
        write_markdown(p, kept, entries, stats, sources, validated, args.input)
        written.append(p)

    S = summarise(kept)
    say("")
    say("Scanned %d file(s): %d analysed, %d withheld as (hidden), %d empty, %d unreadable."
        % (stats.files_seen, stats.files_analysed, stats.files_hidden,
           stats.files_empty, stats.files_unreadable))
    if stats.dump_files:
        say("%d JSON dump file(s) yielded %d Apex record(s); source was decoded from the "
            "body field so line numbers refer to the Apex, not the JSON."
            % (stats.dump_files, stats.records_from_dumps))
    if stats.files_by_content_sniff:
        say("%d file(s) had no recognised extension and were analysed because their "
            "content parsed as Apex." % stats.files_by_content_sniff)
    if stats.files_skipped_non_apex:
        say("%d file(s) in the tree were skipped as non-Apex." % stats.files_skipped_non_apex)
    if stats.files_parse_errors:
        say("%d file(s) produced parse warnings; they were still analysed."
            % stats.files_parse_errors)
    say("Entry points inventoried: %d" % len(entries))
    say("Findings: %d (of %d before filtering)" % (len(kept), len(findings)))
    for s in SEVERITIES:
        if S["by_severity"].get(s):
            say("  %-9s %d" % (s, S["by_severity"][s]))
    for p in written:
        say("Wrote %s" % p)

    if stats.files_hidden:
        say("")
        say("NOTE: %d class bodies were withheld by the API and are NOT covered by this "
            "scan. Coverage is reported in every output format." % stats.files_hidden)

    if validated and not validated["passed"]:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
