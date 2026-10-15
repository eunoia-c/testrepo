#!/usr/bin/env python3
"""
pivscan - static insecurity scanner for PROIV Client .PIV session files
========================================================================

A .PIV file is the PROIV Windows Client's session definition (PROIV's answer to
.rdp / .ica). It carries connection settings, credentials, protocol selection,
startup parameters, client-side lockdown settings and path references. Because
the PROIV Client registers a Windows file association for .PIV and supports
drag-and-drop launching, a .PIV is also a *launchable attacker-deliverable
artifact*, which raises the impact of everything found inside it.

This tool is READ-ONLY and OFFLINE. It never connects anywhere, never launches
the client, and never modifies the input file. It parses, decodes, scores and
reports. Verification steps are printed with each finding so you drive the
actual testing yourself.

Usage
-----
  python3 pivscan.py scan   session.piv [--json out.json] [--min-len 4] [--all-strings]
  python3 pivscan.py strings session.piv [--min-len 4]
  python3 pivscan.py diff   before.piv after.piv
  python3 pivscan.py carve  session.piv --out ./carved

Workflow suggestion
-------------------
  1. scan  - triage one PIV, get the finding list.
  2. diff  - toggle ONE checkbox in the client's Session Properties GUI, save to
             a second PIV, diff the two. This is how you map undocumented binary
             offsets to semantic settings without reversing the EXE.
  3. carve - pull out embedded blobs (certs, keys, archives) for separate review.

Author's note: PROIV's PIV layout is proprietary and version-dependent (e.g.
"service encryption" is signalled by PIV version 501 vs unencrypted 500). The
rule set below is therefore keyword/structure driven rather than offset driven,
and works on both the INI-ish text variants and the binary variants. Treat low
confidence hits as leads, not conclusions.
"""

import argparse
import base64
import binascii
import json
import math
import os
import re
import sys
from collections import Counter, OrderedDict

VERSION = "1.0"

SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

# ---------------------------------------------------------------------------
# Low level extraction
# ---------------------------------------------------------------------------


def read_file(path):
    with open(path, "rb") as fh:
        return fh.read()


def shannon_entropy(data):
    if not data:
        return 0.0
    counts = Counter(data)
    n = float(len(data))
    return -sum((c / n) * math.log(c / n, 2) for c in counts.values())


def extract_strings(data, min_len=4):
    """Return [(offset, encoding, text)] for ASCII and UTF-16LE runs.

    The PROIV Client is a Windows application, so UTF-16LE is at least as
    likely as ASCII for anything the GUI wrote. Missing UTF-16 is the classic
    reason people think a config file 'has no strings in it'.
    """
    out = []

    ascii_re = re.compile(rb"[\x20-\x7e\t]{%d,}" % min_len)
    for m in ascii_re.finditer(data):
        out.append((m.start(), "ascii", m.group().decode("ascii", "replace")))

    utf16_re = re.compile((rb"(?:[\x20-\x7e]\x00){%d,}" % min_len))
    for m in utf16_re.finditer(data):
        try:
            txt = m.group().decode("utf-16-le")
        except UnicodeDecodeError:
            continue
        out.append((m.start(), "utf-16le", txt))

    out.sort(key=lambda t: t[0])
    return out


KV_RE = re.compile(
    r"^\s*(?P<key>[A-Za-z_][A-Za-z0-9 _.\-]{1,48})\s*[=:]\s*(?P<val>.*?)\s*$"
)


def extract_kv(strings):
    """Pull key=value / key:value pairs out of the extracted strings."""
    pairs = []
    for off, enc, text in strings:
        for line in text.splitlines():
            m = KV_RE.match(line)
            if m:
                pairs.append(
                    {
                        "offset": off,
                        "encoding": enc,
                        "key": m.group("key").strip(),
                        "value": m.group("val").strip(),
                    }
                )
    return pairs


CAMEL_1 = re.compile(r"([a-z0-9])([A-Z])")
CAMEL_2 = re.compile(r"([A-Z]+)([A-Z][a-z])")


def normalise_for_match(line):
    """Split CamelCase/concatenated config keys into spaced tokens.

    Real config keys are written RememberUsernameAndPassword,
    ActivateUserRuntimeInterface, PromptForSecurity, DebugTrace. Keyword
    regexes with word boundaries silently miss every one of them, which is the
    classic reason a config scanner reports a clean file that is not clean.
    Rules are matched against BOTH the raw line and this normalised form.
    """
    s = CAMEL_2.sub(r"\1 \2", line)
    s = CAMEL_1.sub(r"\1 \2", s)
    return s.replace("_", " ").replace("-", " ")


def entropy_map(data, window=256):
    """Sliding window entropy, for spotting encrypted/compressed regions."""
    regions = []
    for i in range(0, len(data), window):
        chunk = data[i : i + window]
        if len(chunk) < 32:
            continue
        regions.append((i, len(chunk), shannon_entropy(chunk)))
    return regions


# ---------------------------------------------------------------------------
# Obfuscation / weak-crypto analysis of credential-looking values
# ---------------------------------------------------------------------------

PRINTABLE = set(range(0x20, 0x7F))


def looks_printable(b, threshold=0.9):
    if not b:
        return False
    good = sum(1 for c in b if c in PRINTABLE)
    return (good / len(b)) >= threshold


def try_base64(value):
    s = value.strip()
    if len(s) < 8 or len(s) % 4 != 0:
        return None
    if not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", s):
        return None
    try:
        raw = base64.b64decode(s, validate=True)
    except (binascii.Error, ValueError):
        return None
    if looks_printable(raw):
        return raw.decode("ascii", "replace")
    return None


def try_hex(value):
    s = value.strip()
    if len(s) < 8 or len(s) % 2 != 0:
        return None
    if not re.fullmatch(r"[0-9a-fA-F]+", s):
        return None
    raw = bytes.fromhex(s)
    if looks_printable(raw):
        return raw.decode("ascii", "replace")
    return None


COMMON_BIGRAMS = (b"th", b"he", b"in", b"er", b"an", b"re", b"on", b"at", b"en",
                  b"nd", b"ti", b"es", b"or", b"te", b"of", b"ed", b"is", b"it",
                  b"al", b"ar", b"st", b"to", b"nt", b"ng", b"se", b"ha", b"as",
                  b"ou", b"io", b"le", b"ve", b"co", b"me", b"de", b"hi", b"ri",
                  b"ro", b"ic", b"ne", b"ea", b"ra", b"ce", b"li", b"ch", b"ll",
                  b"be", b"ma", b"si", b"om", b"ur")


def plaintext_likeness(cand):
    """Rough 'does this look like a human-written value' score.

    Needed because the brute forces below used to return the first N printable
    results in key order, and plenty of wrong keys produce printable garbage.
    A high-numbered correct key was pushed off the list by low-numbered noise:
    with the real key 0x5A, the five keys returned were 0x01-0x05 and the
    answer never appeared. Rank first, cap second.
    """
    score = 0
    runs = re.findall(rb"[A-Za-z]{2,}", cand)
    score += sum(len(r) * len(r) for r in runs)          # long letter runs dominate
    score += 3 * len(re.findall(rb"[A-Za-z][a-z]{2,}", cand))   # word-shaped
    score -= 2 * len(re.findall(rb"[^\x20-\x7e]", cand))        # unprintables hurt
    score -= len(re.findall(rb"[!-/:-@\[-`{-~]{3,}", cand))     # punctuation soup

    # Letter-run shape alone cannot separate "Winter" from "Uklvgp" -- both are
    # six letters and both look word-shaped. English bigrams can, and they are
    # what makes the correct key rank first rather than merely appear.
    low = cand.lower()
    score += 4 * sum(low.count(bg) for bg in COMMON_BIGRAMS)
    for run in runs:
        vowels = sum(run.lower().count(v) for v in b"aeiou")
        if vowels == 0:
            score -= len(run)                # no vowels in a long run: not a word
    return score


def _ranked(hits, limit):
    hits.sort(key=lambda kv: -plaintext_likeness(kv[1]))
    return [(k, v.decode("ascii", "replace")) for k, v in hits[:limit]]


def try_single_byte_xor(raw, limit=5):
    """Classic 'encrypted and stored in the file' = single byte XOR. Check it."""
    hits = []
    for key in range(1, 256):
        cand = bytes(c ^ key for c in raw)
        if looks_printable(cand, 0.95) and re.search(rb"[A-Za-z]{3,}", cand):
            hits.append((key, cand))
    return _ranked(hits, limit)


def try_rot_add(raw, limit=3):
    hits = []
    for shift in range(1, 256):
        cand = bytes((c + shift) & 0xFF for c in raw)
        if looks_printable(cand, 0.95) and re.search(rb"[A-Za-z]{3,}", cand):
            hits.append((shift, cand))
    return _ranked(hits, limit)


def analyse_secret_value(value):
    """Given a value that sits next to a password-ish key, try cheap reversals."""
    notes = []
    b64 = try_base64(value)
    if b64:
        notes.append(("base64", b64))
    hx = try_hex(value)
    if hx:
        notes.append(("hex", hx))

    raw_candidates = []
    try:
        raw_candidates.append(value.encode("latin-1"))
    except UnicodeEncodeError:
        pass
    hx_raw = re.fullmatch(r"[0-9a-fA-F]+", value.strip())
    if hx_raw and len(value.strip()) % 2 == 0:
        raw_candidates.append(bytes.fromhex(value.strip()))

    for raw in raw_candidates:
        for key, plain in try_single_byte_xor(raw):
            notes.append(("xor:0x%02x" % key, plain))
        for shift, plain in try_rot_add(raw):
            notes.append(("add:0x%02x" % shift, plain))

    # dedupe, keep order
    seen = set()
    uniq = []
    for scheme, plain in notes:
        if plain in seen:
            continue
        seen.add(plain)
        uniq.append((scheme, plain))
    return uniq[:8]


# ---------------------------------------------------------------------------
# Whole-file deobfuscation
# ---------------------------------------------------------------------------
# A real PIV turned out to be UTF-16LE text XOR'd with a single byte, behind a
# plaintext magic. Every rule in this tool runs over extracted strings, so a
# byte-wise transform makes the file read as perfectly clean -- zero strings,
# zero findings. That is the worst possible failure for a scanner: silence that
# looks like a pass.
#
# The good news is that this class of obfuscation gives up its key for free.
# In UTF-16LE text every ASCII character is stored as XX 00, so the most common
# plaintext byte is 0x00 -- which means the most common CIPHERTEXT byte *is*
# the key. No brute force needed, and the same trick recovers a repeating
# multi-byte key column by column.

# Property names seen in PROIV session files. Used to score a candidate
# decode: text that looks like English is encouraging, text that names actual
# session properties is proof.
PROIV_KEYWORDS = [
    b"proiv", b"hostname", b"username", b"password", b"sessiontype", b"telnet",
    b"version", b"remember", b"prompt", b"security", b"runtime", b"interface",
    b"toolbar", b"default", b"properties", b"application", b"definitions",
    b"appdef", b"script", b"xfer", b"upload", b"download", b"transfer",
    b"trace", b"debug", b"logfile", b"font", b"colour", b"color", b"connect",
    b"server", b"port", b"proxy", b"connector", b"openclient", b"session",
    b"customis", b"customiz", b"lockdown", b"timeout", b"keyboard", b"printer",
]


def flatten_text(data, min_len=4):
    """All recoverable text in one lowercase blob, for scoring."""
    return b" ".join(
        t.encode("latin-1", "replace").lower()
        for _, _, t in extract_strings(data, min_len)
    )


def text_score(data):
    """How much readable configuration does this byte string contain?

    Two things here are not obvious and both were learned the hard way.

    A UTF-16LE character occupies two bytes but counts as one extracted
    character, while ASCII counts one per byte. Summing raw character counts
    therefore scores printable garbage at roughly double a correct UTF-16
    decode: on a 100 KB session file the right key scored 51,930 and a wrong
    one 101,789, and no amount of keyword weighting closed a gap that size.
    So coverage is measured in BYTES accounted for, and normalised by file
    length so the number means the same thing at any size.

    And keyword hits are not a bonus, they are the decision. "Looks like text"
    is cheap -- XOR-ing with any byte in the printable range produces text.
    "Names actual PROIV session properties" is what distinguishes a decode from
    a coincidence, so one keyword outweighs total coverage.
    """
    strings = extract_strings(data, 4)
    ascii_chars = sum(len(t) for _, enc, t in strings if enc == "ascii")
    utf16_chars = sum(len(t) for _, enc, t in strings if enc == "utf-16le")
    flat = b" ".join(t.encode("latin-1", "replace").lower() for _, _, t in strings)
    hits = sorted({k.decode() for k in PROIV_KEYWORDS if k in flat})
    coverage = (ascii_chars + 2 * utf16_chars) / max(len(data), 1)
    return {
        "score": 1000 * len(hits) + int(1000 * min(coverage, 1.0)),
        "keyword_hits": hits,
        "coverage": round(coverage, 3),
        "ascii_chars": ascii_chars,
        "utf16_chars": utf16_chars,
        "string_count": len(strings),
    }


def xor_bytes(data, key):
    if not key:
        return bytes(data)
    n = len(key)
    return bytes(b ^ key[i % n] for i, b in enumerate(data))


def add_bytes(data, k):
    return bytes((b + k) & 0xFF for b in data)


def smallest_period(key):
    """xor:3b3b3b is xor:3b. Collapse it so the candidate list is not padded
    with the same answer at four different lengths."""
    n = len(key)
    for plen in range(1, n + 1):
        if n % plen == 0 and key == key[:plen] * (n // plen):
            return key[:plen]
    return key


def recover_xor_key_modal(data, klen):
    """Modal byte per column -- the cheap version.

    For UTF-16LE text the most common plaintext byte is 0x00, so the most
    common ciphertext byte in a column is the key byte for that column. It is
    the classic 'null bytes leak the keystream' observation and it solves the
    single-byte case outright.

    It has one blind spot, which is why recover_xor_key_columns exists: with an
    EVEN key length every null in UTF-16LE text lands in the same column, so
    the other columns contain no nulls at all and their modal byte is just the
    commonest character -- a wrong key byte. A 2-byte key defeats this method
    half-way and the candidate never surfaces.
    """
    key = bytearray()
    for r in range(klen):
        col = data[r::klen]
        if not col:
            return None
        key.append(Counter(col).most_common(1)[0][0])
    return bytes(key)


def _column_key_byte(col):
    """Best single key byte for one column of a repeating-XOR ciphertext.

    Columns are independent under a repeating key, so each can be solved on its
    own -- 256 tries per column instead of 256**klen for the whole key. Scoring
    accepts the two shapes a legitimate column takes in a PIV: mostly printable
    (the character halves of UTF-16LE, or plain ASCII) or mostly 0x00 (the null
    halves). Nulls are weighted highest because a column of them is unambiguous.
    """
    scored = []
    for k in range(256):
        dec = bytes(b ^ k for b in col)
        score = 0
        for b in dec:
            if b == 0x00:
                score += 3
            elif b in PRINTABLE or b in (0x09, 0x0A, 0x0D):
                score += 1
            else:
                score -= 2
        scored.append((score, k, dec))

    # Printability cannot resolve the last bit: with the true key 0x3b, trying
    # 0x3a turns every 'C' into 'B' and the column is still perfectly
    # printable, so the two tie and the lower key wins by accident. Break ties
    # linguistically -- under an even-length key the character column is the
    # plaintext in reading order, so English bigrams separate "CustomToolBar"
    # from "BtrunlUnnm" cleanly.
    top = max(sc for sc, _, _ in scored)
    margin = max(1, abs(top) // 50)
    close = [(k, dec) for sc, k, dec in scored if sc >= top - margin]
    if len(close) == 1:
        return close[0][0]
    return max(close, key=lambda kd: plaintext_likeness(kd[1]))[0]


def recover_xor_key_columns(data, klen):
    """Per-column recovery. Handles any key length, even or odd."""
    key = bytearray()
    for r in range(klen):
        col = data[r::klen]
        if not col:
            return None
        key.append(_column_key_byte(col))
    return bytes(key)


REFINE_MAX_KEYLEN = 4
# Refinement is the expensive step -- klen * 256 whole-file scorings per round.
# Two bounds keep it honest: only the few best cheap candidates are refined,
# and only against a sample of the body. Property names cluster at the start of
# a session file, so a sample is as informative as the whole thing and the cost
# stops growing with file size.
REFINE_CANDIDATES = 3
REFINE_SAMPLE = 8 * 1024
REFINE_SKIP_IF_KEYWORDS = 5

# Candidate SEARCH also scores against a sample rather than the whole file.
# Without this the cheap pass alone is 510 full-file scorings, which on a 44 KB
# session file took 13 seconds -- all of it spent proving that 509 wrong keys
# are wrong. The winner is re-scored against the full file afterwards, so the
# numbers in the report are not sampled.
SCORE_SAMPLE = 8 * 1024


def refine_key(body, key, rounds=2):
    """Hill-climb a recovered key against whole-file keyword scoring.

    Per-column scoring gets the key *almost* right and then loses to local
    noise: structure bytes (the 0x01 field separators) landing in a character
    column pull it one bit off, because turning them into 0x00 scores better
    locally than leaving them as 0x01. No amount of per-column cleverness fixes
    that -- the information that settles it is "hostname" being a word and
    "gostname" not, which only exists at whole-file level.

    So: take the per-column estimate as a starting point and greedily improve
    one column at a time against text_score, which counts recovered PROIV
    property names. Columns are independent under a repeating key, so this
    converges in one or two passes.
    """
    key = bytearray(key)
    for _ in range(rounds):
        changed = False
        for r in range(len(key)):
            original = key[r]
            best_k, best_s = original, None
            for k in range(256):
                key[r] = k
                sc = text_score(xor_bytes(body, bytes(key)))["score"]
                if best_s is None or sc > best_s:
                    best_s, best_k = sc, k
            key[r] = best_k
            if best_k != original:
                changed = True
        if not changed:
            break
    return bytes(key)


def parse_spec(spec):
    """'xor:3b', 'xor:3b2f', 'add:05', 'none' -> ('xor', b'\x3b')."""
    if not spec or spec == "none":
        return ("none", b"")
    kind, _, val = spec.partition(":")
    kind = kind.lower()
    if kind == "xor":
        return ("xor", bytes.fromhex(val))
    if kind == "add":
        return ("add", bytes([int(val, 16) & 0xFF]))
    raise ValueError("unknown transform spec: %s" % spec)


def format_spec(kind, key):
    if kind == "none":
        return "none"
    return "%s:%s" % (kind, binascii.hexlify(key).decode())


def apply_transform(data, kind, key):
    if kind == "xor":
        return xor_bytes(data, key)
    if kind == "add":
        # Decoding an additive cipher means subtracting.
        return add_bytes(data, (-key[0]) & 0xFF)
    return bytes(data)


def deobfuscate_candidates(data, skip=0, top=5):
    """Rank plausible whole-file transforms best-first.

    `skip` leaves a plaintext header alone -- a magic like PRO4VS sits outside
    the obfuscation because the client has to read it to identify the file, and
    including it would poison the modal-byte statistics.
    """
    body = data[skip:]
    search_body = body[:SCORE_SAMPLE]
    seen, cands = set(), []

    def add(kind, key):
        spec = format_spec(kind, key)
        if spec in seen:
            return
        seen.add(spec)
        info = text_score(apply_transform(search_body, kind, key))
        info.update({"transform": spec, "kind": kind, "key": key})
        cands.append(info)

    # Cheap pass: every single-byte transform, plus one recovered key per
    # length from each method.
    add("none", b"")
    for k in range(1, 256):
        add("xor", bytes([k]))
        add("add", bytes([k]))
    # Key recovery runs on the sample too. _column_key_byte tries all 256 keys
    # against every byte of its column, so recovering 8 key lengths from a
    # 104 KB file meant ~27 MB of byte operations per length and took 19
    # seconds -- while 8 KB is already far more than enough to recover a key of
    # 8 bytes or less. The sample starts at offset 0, so column alignment is
    # identical to the full body.
    recovered = []
    for klen in range(1, 9):
        for recover in (recover_xor_key_columns, recover_xor_key_modal):
            key = recover(search_body, klen)
            if key and any(key):
                key = smallest_period(key)
                add("xor", key)
                if len(key) <= REFINE_MAX_KEYLEN and key not in recovered:
                    recovered.append(key)

    cands.sort(key=lambda c: -c["score"])

    # Expensive pass, only if the cheap one did not already recover plenty of
    # property names.
    best_cheap = next((c for c in cands if c["kind"] != "none"), None)
    if best_cheap and len(best_cheap["keyword_hits"]) < REFINE_SKIP_IF_KEYWORDS:
        for key in recovered[:REFINE_CANDIDATES]:
            add("xor", smallest_period(refine_key(body[:REFINE_SAMPLE], key)))
        cands.sort(key=lambda c: -c["score"])

    # Re-score the shortlist against the whole file so the reported string and
    # keyword counts describe the real thing, not the sample.
    out = []
    for c in cands[:top]:
        full = text_score(apply_transform(body, c["kind"], c["key"]))
        full.update({"transform": c["transform"], "kind": c["kind"], "key": c["key"]})
        out.append(full)
    out.sort(key=lambda c: -c["score"])
    return out


# A decode is only accepted automatically when it is not a close call: it has
# to name real PROIV properties that the raw file does not. Anything less is
# reported as a candidate for the tester to judge, never applied silently.
#
# Note what is deliberately NOT a gate here: "the decoded text scores N times
# higher than the raw file". XOR-ing UTF-16LE with a byte in the 0x20-0x7e
# range leaves the ciphertext fully printable, so the raw file already scores
# well on text volume and a ratio test rejects the correct decode. Recovered
# property names are the only signal that separates text from configuration.
AUTO_DECODE_MIN_KEYWORDS = 2


def detect_obfuscation(data, skip=0):
    """Return (decision, candidates). decision is None when the raw file is
    already readable or nothing convincing was found."""
    cands = deobfuscate_candidates(data, skip=skip)
    raw = next((c for c in cands if c["kind"] == "none"), None)
    if raw is None:
        raw = text_score(data[skip:])
        raw.update({"transform": "none", "kind": "none", "key": b""})
    best = next((c for c in cands if c["kind"] != "none"), None)
    if best is None:
        return None, cands
    if len(best["keyword_hits"]) < AUTO_DECODE_MIN_KEYWORDS:
        return None, cands
    if len(best["keyword_hits"]) <= len(raw["keyword_hits"]):
        return None, cands
    if best["score"] <= raw["score"]:
        return None, cands
    return best, cands


MAGIC_RE = re.compile(rb"^[A-Za-z][A-Za-z0-9_.+-]{2,15}")


def header_skip(data, limit=16):
    """Length of the leading plaintext magic, so it is not fed to key recovery.

    "walk while the byte is printable" does not work here, which is the whole
    difficulty: XOR'd UTF-16LE text is *also* printable, so that walk runs
    straight past the magic and into the body (PRO4VS became PRO4VSx;N;H;O...).

    So: match a magic-shaped token, then cut it short where the obfuscation's
    rhythm begins. The body of XOR'd UTF-16LE alternates char, KEY, char, KEY,
    so the first occurrence of the file's modal byte is the first lit-up null,
    one byte into the body.
    """
    m = MAGIC_RE.match(data)
    if not m:
        return 0
    run = m.end()
    if data:
        modal = Counter(data).most_common(1)[0][0]
        idx = data.find(bytes([modal]))
        if 4 < idx <= limit + 1:
            return min(run, idx - 1)
    return run if run <= limit else 0


# ---------------------------------------------------------------------------
# Rule set
# ---------------------------------------------------------------------------
# Each rule: id, title, severity, pattern (case-insensitive regex over strings),
# impact, verify (how YOU confirm it), refs.

RULES = [
    {
        "id": "PIV-CRED-001",
        "recommendation": (
            "Remove stored credentials from the session file entirely and require "
            "interactive authentication at connect time. Where unattended launch is a "
            "business requirement, bind the session to the Windows user via SSO/Kerberos "
            "or a per-user credential in DPAPI-protected per-user storage rather than a "
            "file that is copied with the profile. If a shared service account is "
            "unavoidable, scope its privileges to the minimum the session needs and "
            "rotate it on a defined schedule."
        ),
        "cvss_hint": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
        "internal_adjust": -1,
        "context_note": (
            "Reading the PIV needs an existing foothold on a workstation or share, so "
            "this is post-access credential theft rather than an unauthenticated path. "
            "Raise it back to the original severity if the PIV is readable from an open "
            "file share, ships inside the installer/GPO, or holds a shared privileged "
            "account."
        ),
        "title": "Stored login credential in session file",
        "severity": "CRITICAL",
        "pattern": r"\b(proiv[_ ]?password|unix[_ ]?password|host[_ ]?password|password|passwd|pwd|secret|passphrase)\b",
        "impact": (
            "PROIV session properties can carry a PROIV password and/or a Unix OS "
            "password for automatic login. Anyone with read access to the PIV "
            "(file share, roaming profile, backup, Citrix home drive, helpdesk "
            "ticket attachment) inherits the application identity, and on the Unix "
            "session type that is an OS credential, not just an app credential."
        ),
        "verify": (
            "Locate the value, run the decode candidates this tool prints, then "
            "confirm by replaying it manually against the login prompt. Check ACLs "
            "on the PIV's actual deployment path and whether it ships in the "
            "installer / GPO / login script."
        ),
        "refs": ["OWASP ASVS V2.10", "CWE-522", "CWE-256", "MITRE ATT&CK T1552.001"],
    },
    {
        "id": "PIV-CRED-002",
        "recommendation": (
            "Disable the Remember Username/Password option in the deployed configuration "
            "and enforce that choice centrally (GPO or a locked-down default template) "
            "rather than relying on each user leaving it unchecked. PROIV exposes a "
            "'Remove Remember Password Checkbox' setting - use it so the option cannot be "
            "re-enabled from the UI."
        ),
        "cvss_hint": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
        "internal_adjust": -1,
        "context_note": (
            "Same reasoning as the stored-credential finding: exploitation presumes "
            "access to the file."
        ),
        "title": "Credential persistence enabled (Remember Username/Password)",
        "severity": "HIGH",
        "pattern": r"\b(remember(user|username|password|pass)?|savepassword|save[_ ]?pwd|autologin|auto[_ ]?login|automaticlogin)\b",
        "impact": (
            "'Remember Username and Password' writes reusable secrets into the PIV "
            "rather than prompting at connect time. Combined with the file "
            "association this turns the PIV into a portable, self-authenticating "
            "credential."
        ),
        "verify": (
            "Toggle the checkbox in Session Properties, save, and diff the two PIVs "
            "(pivscan diff) to confirm which byte/field encodes it and whether the "
            "secret is written in the same operation."
        ),
        "refs": ["CWE-522", "OWASP ASVS V2.10.1"],
    },
    {
        "id": "PIV-CRED-003",
        "recommendation": (
            "Enable Prompt for Security so each user authenticates with their own "
            "identity at connection. This is also what makes server-side logs "
            "attributable - without it every session shares one account and incident "
            "response loses the ability to tie an action to a person."
        ),
        "cvss_hint": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N",
        "internal_adjust": 0,
        "context_note": (
            "Scored on accountability loss rather than network exposure, so internal "
            "placement does not reduce it."
        ),
        "title": "Interactive security prompt disabled",
        "severity": "MEDIUM",
        "pattern": r"\b(prompt[_ ]?for[_ ]?security|promptsecurity|prompt[_ ]?user|securityprompt)\b",
        "impact": (
            "'Prompt for Security' controls whether the client asks for username and "
            "password at connection. Disabled means the stored credential path is in "
            "use; the user never has an opportunity to supply their own identity, and "
            "accountability in server-side logs collapses to a shared account."
        ),
        "verify": "Confirm the flag's value, then launch and observe whether a prompt appears.",
        "refs": ["CWE-306", "OWASP ASVS V2.2"],
    },
    {
        "id": "PIV-AUTH-004",
        "recommendation": (
            "Do not rely on the client-side runtime-interface lock as a security control. "
            "Enforce every capability it hides (configuration changes, access to "
            "restricted functions) server-side against the authenticated user's role. The "
            "client lock is acceptable as a usability guard to stop accidental "
            "misconfiguration, but it must not be the only thing preventing a user from "
            "reaching functionality they are not entitled to."
        ),
        "cvss_hint": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N",
        "internal_adjust": 0,
        "context_note": (
            "A client-side authorisation control fails identically on an internal network "
            "- the attacker is the legitimate user of the workstation. Network position "
            "is irrelevant, so no downgrade."
        ),
        "title": "Client-side lockdown password stored in file (security by UI)",
        "severity": "HIGH",
        "pattern": r"\b(runtime[_ ]?(user)?[_ ]?interface|activate[_ ]?user[_ ]?runtime|default[_ ]?properties|customisation|customization|lockdown|adminpassword|admin[_ ]?pass)\b",
        "impact": (
            "'Activate User Runtime Interface' hides the Default Properties menu and "
            "restricts Session Properties, protected by a password that PROIV "
            "documents as encrypted and stored in the PIV itself. A control whose "
            "secret ships inside the artifact it protects is a client-side control. "
            "Recovering or zeroing it restores full configuration access, which is "
            "the pivot into every other setting in this file."
        ),
        "verify": (
            "Identify the stored verifier, then test three independent bypasses: "
            "(a) decode/crack it offline, (b) copy the field from a known-password "
            "PIV you generate yourself, (c) clear the enable flag so the check is "
            "never reached. (c) succeeding is the strongest finding - it proves the "
            "gate is purely presentational."
        ),
        "refs": ["CWE-602", "CWE-656", "OWASP ASVS V1.4", "MASVS-RESILIENCE"],
    },
    {
        "id": "PIV-NET-005",
        "recommendation": (
            "Move the session to the encrypted PROIV service type and disable the "
            "unencrypted variant server-side so a client-side downgrade cannot be "
            "honoured. Retire Telnet-based session types; if the host still requires "
            "them, terminate them inside an encrypted tunnel (IPsec or SSH) and block the "
            "cleartext port at the host firewall."
        ),
        "cvss_hint": "CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "internal_adjust": -1,
        "context_note": (
            "Capture requires an adjacent network position on the internal LAN. Keep it "
            "at the original severity where the traffic crosses site links, VPN "
            "concentrators, or any segment shared with lower-trust users - and note that "
            "credentials cross the wire on every launch, which makes this attractive once "
            "an attacker has any LAN presence."
        ),
        "title": "Cleartext transport / telnet session type",
        "severity": "HIGH",
        "pattern": r"\b(telnet|sessiontype|session[_ ]?type|protocol|unencrypted|plaintext|nossl|ssl\s*=\s*(0|false|no|off))\b",
        "impact": (
            "PROIV session types include Telnet with host login. Where encryption is "
            "signalled by the PIV service/version value (e.g. 501 encrypted vs 500 "
            "unencrypted), a downgrade is a single field edit. The automatic-login "
            "flow literally scans the telnet stream for a password prompt and then "
            "writes the password to it, so a cleartext session type exposes the "
            "credential on the wire every single launch."
        ),
        "verify": (
            "Record the version/protocol fields, then confirm on the wire from your "
            "own test host. Separately test whether flipping the field downgrades a "
            "session the server would otherwise encrypt - server-side enforcement is "
            "the question that matters."
        ),
        "refs": ["CWE-319", "OWASP ASVS V9.1", "MITRE ATT&CK T1040"],
    },
    {
        "id": "PIV-NET-006",
        "recommendation": (
            "Low priority on its own. Treat as hygiene: avoid shipping internal hostnames "
            "in files distributed more widely than necessary, and make sure the finding "
            "is tracked alongside the session-redirection issue rather than fixed in "
            "isolation."
        ),
        "cvss_hint": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N",
        "internal_adjust": -1,
        "context_note": (
            "Internal hostnames disclosed to internal users is close to informational on "
            "its own. It matters as a precursor to other findings, not as a standalone "
            "issue."
        ),
        "title": "Server endpoint / internal infrastructure disclosure",
        "severity": "MEDIUM",
        "pattern": r"\b(hostname|host|ipaddress|ip[_ ]?address|server|port|\d{1,3}(\.\d{1,3}){3}|[a-z0-9\-]+\.(local|internal|corp|lan|intra))\b",
        "impact": (
            "Hostnames, internal IPs and ports map the application tier for anyone "
            "who obtains a PIV. Low severity alone, but it is the reconnaissance "
            "half of the redirection finding below."
        ),
        "verify": "Catalogue endpoints; cross-reference against the agreed scope before touching any of them.",
        "refs": ["CWE-200"],
    },
    {
        "id": "PIV-TAMPER-007",
        "recommendation": (
            "Sign or MAC the session file and have the client reject one that fails "
            "validation, or - more practically for most deployments - stop treating the "
            "PIV as trusted input: pin the permitted server endpoints in a location the "
            "user cannot write (HKLM policy or a managed configuration), and validate the "
            "connection target against that allowlist before connecting. Additionally, "
            "require server certificate validation so a redirected client cannot complete "
            "a session."
        ),
        "cvss_hint": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",
        "internal_adjust": 0,
        "context_note": (
            "Phishing a .piv works the same internally, and internal users are more "
            "likely to open one that looks like a legitimate internal session file. No "
            "downgrade; if the client auto-sends stored credentials to the redirected "
            "host with no prompt, this is the highest-impact finding in the set."
        ),
        "title": "Session redirection: no integrity protection on connection target",
        "severity": "HIGH",
        "pattern": r"\b(host|hostname|ip[_ ]?address|server|port|proxy|connector|url|gateway)\b",
        "impact": (
            "If the PIV carries no signature or MAC, an attacker who can write one "
            "(or who can get a user to open one) controls where the client connects "
            "and what it sends. With automatic login configured, the client will "
            "transmit the stored username and password to the attacker-chosen host "
            "with no user interaction. The Windows file association makes a .piv a "
            "double-clickable phishing payload."
        ),
        "verify": (
            "Point a copy of the PIV at a listener you own, open it, and observe what "
            "the client sends before any user action. Then check whether any "
            "signature/checksum field exists by flipping one benign byte and seeing "
            "whether the client still loads the file."
        ),
        "refs": ["CWE-345", "CWE-494", "OWASP ASVS V10.3", "MITRE ATT&CK T1204.002"],
    },
    {
        "id": "PIV-PATH-008",
        "recommendation": (
            "Validate every path read from the session file before use: reject UNC paths "
            "outright unless the deployment genuinely needs them, canonicalise and "
            "confirm the resolved path sits inside an expected directory, and require "
            "that loadable components (OCX/CAB/DLL) are Authenticode-signed by the "
            "vendor. Store the Application Definitions path in a user-unwritable "
            "location, since it controls client-side logical filename mappings."
        ),
        "cvss_hint": "CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:N",
        "internal_adjust": 0,
        "context_note": (
            "Do NOT downgrade this one for being internal - forced authentication and "
            "NTLM relay are internal-network attacks by nature. An internal position "
            "makes this more exploitable, not less."
        ),
        "title": "External file / script / UNC path reference",
        "severity": "HIGH",
        "pattern": r"(\\\\[^\s\"<>|]+|[A-Za-z]:\\\\?[^\s\"<>|*?]+|/(etc|tmp|home|usr|opt)/[^\s\"<>|]+|\b(scriptfile|script[_ ]?path|command|commandline|cmd|exe|dll|ocx|cab|applicationdefinitions|appdef|logfile|logpath)\b)",
        "impact": (
            "The PIV selects which Application Definitions file is used (font, colour "
            "and client-side logical filename mappings - any legal name, any "
            "directory) and can reference connection script files and OCX/CAB "
            "components. Each is an attacker-controlled path: redirect it to a UNC "
            "share for forced authentication / NTLM relay, or to a writable local "
            "path to control client-side filename mappings and component loading. "
            "Logical filename remapping is especially interesting - it changes what "
            "data the session reads and writes without touching the server."
        ),
        "verify": (
            "For each path: test UNC substitution against your own SMB listener "
            "(captures NetNTLM), test traversal sequences, and test whether the "
            "client validates that a referenced component is signed or in an expected "
            "directory before loading it."
        ),
        "refs": ["CWE-22", "CWE-427", "CWE-73", "MITRE ATT&CK T1187"],
    },
    {
        "id": "PIV-PARAM-009",
        "recommendation": (
            "Re-validate authorisation server-side for any function or task reached via "
            "startup parameters, using the same checks that gate the menu. Treat the "
            "parameter as untrusted input: whitelist permitted values and reject control "
            "characters rather than filtering them."
        ),
        "cvss_hint": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
        "internal_adjust": 0,
        "context_note": (
            "Authorisation bypass is scored on the trust boundary crossed, not network "
            "placement. If a standard user reaches a privileged function this way, it is "
            "a High regardless of where the tester stood."
        ),
        "title": "Startup parameter injection surface (Xfer In / startup command)",
        "severity": "MEDIUM",
        "pattern": r"\b(xfer[_ ]?in|xferin|startup|startupcommand|start[_ ]?command|parameters?|args?|commandline|function|menu|task)\b",
        "impact": (
            "Xfer In passes parameters into the PROIV session at startup. Two tests "
            "fall out of this: whether the value is injectable into the host command "
            "or telnet negotiation, and whether it can name a function/menu directly "
            "and thereby skip the menu hierarchy that PROIV's multi-level security "
            "facility uses to express access control. Server-side authorisation must "
            "re-check the user's right to that function; if it only checks at menu "
            "render time, this is a straight authorisation bypass."
        ),
        "verify": (
            "Enumerate function/task names from documentation or the server side, "
            "then attempt to launch one your test account should not reach. Also "
            "fuzz the parameter with shell and telnet control characters, newlines "
            "and separators, and watch the host's behaviour."
        ),
        "refs": ["CWE-88", "CWE-285", "OWASP ASVS V4.1", "OWASP Top 10 A01"],
    },
    {
        "id": "PIV-XFER-010",
        "recommendation": (
            "Enforce transfer limits and the enabled/disabled state of file transfer on "
            "the server. Client-supplied limits should be treated as a hint for the UI "
            "only."
        ),
        "cvss_hint": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:L",
        "internal_adjust": 0,
        "context_note": (
            "Depends on server-side enforcement, which is unaffected by the tester's "
            "network position."
        ),
        "title": "File transfer configuration (upload limits / send-receive)",
        "severity": "MEDIUM",
        "pattern": r"\b(upload[_ ]?max|uploadmax|download|filesend|file[_ ]?receive|transfer|maxsize|max[_ ]?bytes)\b",
        "impact": (
            "Upload limits and transfer toggles configured client-side are advisory "
            "only. If the server trusts the client's declared limit, raising it in "
            "the PIV turns into resource exhaustion or an oversized-upload path; if "
            "transfer is 'disabled' only in the PIV, re-enabling it restores a data "
            "egress/ingress channel the client believes is off."
        ),
        "verify": "Raise the limit, re-enable the toggle, and test whether the server independently enforces its own ceiling.",
        "refs": ["CWE-602", "CWE-770"],
    },
    {
        "id": "PIV-CRYPT-011",
        "recommendation": (
            "Revoke and reissue the exposed key material immediately - it must be "
            "considered compromised from the moment it was distributed. Move keys and "
            "tokens to per-machine protected storage (DPAPI machine scope, the Windows "
            "certificate store with a non-exportable private key, or a hardware-backed "
            "store) and never ship them in a file that is copied to every workstation."
        ),
        "cvss_hint": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N",
        "internal_adjust": 0,
        "context_note": (
            "Do NOT downgrade. A private key distributed to every workstation is "
            "compromised whether the network is internal or not, and the blast radius "
            "extends to whatever the key authenticates to."
        ),
        "title": "Embedded key material or certificate",
        "severity": "CRITICAL",
        "pattern": r"(BEGIN (RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY|BEGIN CERTIFICATE|PuTTY-User-Key-File|\bkeystore\b|\btruststore\b|\.pfx\b|\.p12\b|\.jks\b|\bapikey\b|\bapi[_ ]?key\b|\btoken\b|\bbearer\b)",
        "impact": (
            "Private keys, keystores or API tokens embedded in a file distributed to "
            "every workstation are compromised by definition. A keystore password "
            "sitting beside its keystore path is the same finding twice."
        ),
        "verify": "Carve the blob (pivscan carve), identify the type, and confirm it is live rather than a sample. Do not exfiltrate - report the fingerprint.",
        "refs": ["CWE-321", "CWE-798", "OWASP ASVS V6.4"],
    },
    {
        "id": "PIV-CRYPT-012",
        "recommendation": (
            "Stop storing recoverable secrets client-side; that is the actual fix, not a "
            "stronger cipher. Where a secret must persist for the user's convenience, use "
            "the platform's per-user protected storage (DPAPI with a user-specific "
            "entropy value) so the secret cannot be decrypted from another account or "
            "another machine. A key compiled into the client is equivalent to plaintext "
            "because every installation shares it."
        ),
        "cvss_hint": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
        "internal_adjust": -1,
        "context_note": (
            "Scored as an amplifier on the stored-credential finding rather than "
            "separately, unless the recovered secret unlocks something the tester's "
            "account could not otherwise reach."
        ),
        "title": "Weak or reversible protection of stored secrets",
        "severity": "HIGH",
        "pattern": r"\b(encrypt(ed|ion)?|encode[d]?|obfuscat|cipher|md5|sha1|des|rc4|crc|checksum|base64)\b",
        "impact": (
            "Vendor documentation describing a value as 'encrypted and stored' "
            "usually means symmetric encryption with a key compiled into the client, "
            "or an encoding. Either way every installation shares the key, so the "
            "protection is reversible by anyone holding the client - which is "
            "everyone. This tool automatically tries base64, hex, single-byte XOR and "
            "additive shifts against credential-adjacent values."
        ),
        "verify": (
            "Set a known password (e.g. 'AAAAAAAA' then 'AAAAAAAB') via the GUI, save, "
            "and diff. Structural change tells you the scheme: same-length output "
            "means a stream cipher or encoding; a one-byte input change rippling "
            "through the whole output means a block cipher or hash; a one-byte change "
            "altering exactly one output byte means XOR-class and you are done."
        ),
        "refs": ["CWE-261", "CWE-327", "CWE-798", "OWASP MASVS-CRYPTO-1"],
    },
    {
        "id": "PIV-DEBUG-013",
        "recommendation": (
            "Ship with trace and verbose logging off by default, require elevated rights "
            "to enable it, and ensure credentials and record contents are redacted from "
            "any log the client does write. Write logs to a per-user location with "
            "restrictive ACLs, not a shared or world-readable path."
        ),
        "cvss_hint": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
        "internal_adjust": -1,
        "context_note": (
            "Requires local access to the workstation holding the log. Keep the original "
            "severity if logs land on a shared path, a roaming profile, or a server-side "
            "collection point readable by other users."
        ),
        "title": "Debug, trace or diagnostic setting enabled",
        "severity": "MEDIUM",
        "pattern": r"\b(debug|trace|verbose|diagnostic|logging|loglevel|log[_ ]?level|dumpfile|devmode|testmode)\b",
        "impact": (
            "Client-side trace/logging frequently captures the full session stream, "
            "including the automatic-login credential exchange, into a world-readable "
            "file on a shared workstation."
        ),
        "verify": "Enable it, launch, and inspect the resulting log for credentials, SQL, or record contents. Note file permissions.",
        "refs": ["CWE-532", "CWE-489"],
    },
    {
        "id": "PIV-DB-014",
        "recommendation": (
            "Remove direct database connectivity from the client. The client should reach "
            "data only through the PROIV application tier, so that application-layer "
            "authorisation cannot be bypassed by connecting to the database directly. If "
            "a direct connection is architecturally required, the account must be "
            "restricted to the minimum objects and operations needed, and network ACLs "
            "should prevent workstations from reaching the database port at all."
        ),
        "cvss_hint": "CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H",
        "internal_adjust": 0,
        "context_note": (
            "Do NOT downgrade for internal context - a direct DB path from a workstation "
            "is exploitable precisely because the tester is already inside. Confirm the "
            "account's privileges and whether the DB port is reachable from a standard "
            "workstation; both determine the final score far more than exposure does."
        ),
        "title": "Database connection detail exposed to client",
        "severity": "CRITICAL",
        "pattern": r"\b(oracle|mysql|sqlserver|mssql|postgres|odbc|jdbc|dsn|tns|proisam|c-isam|cisam|datasource|data[_ ]?source|connectionstring|connect[_ ]?string|uid=|pwd=|user id=|initial catalog|database=)\b",
        "impact": (
            "PROIV logical files map onto physical stores including Oracle, MySQL and "
            "SQL Server, with the database section named in configuration. If any "
            "direct DSN or connection string reaches the client, the thick client's "
            "entire application-layer authorisation model is bypassable by connecting "
            "to the database directly with the same credential."
        ),
        "verify": (
            "Extract the connection details, then determine whether the account is a "
            "shared application account and what privileges it holds. Direct DB "
            "connection testing needs explicit scope confirmation first."
        ),
        "refs": ["CWE-522", "CWE-284", "OWASP Top 10 A01"],
    },
    {
        "id": "PIV-UI-015",
        "recommendation": (
            "Enforce each restriction server-side against the authenticated user's role. "
            "Hiding or disabling a control in the client is a usability measure; the "
            "server must independently reject the action for a user who is not entitled "
            "to it."
        ),
        "cvss_hint": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N",
        "internal_adjust": 0,
        "context_note": (
            "Client-side control failure is independent of network position. Severity "
            "should instead be driven by what the unlocked functionality actually does - "
            "report only the flags you confirmed the server does not enforce."
        ),
        "title": "Client-side-only restriction flag",
        "severity": "MEDIUM",
        "pattern": r"\b(disable|disabled|enable[d]?|hide|hidden|readonly|read[_ ]?only|allow|deny|restrict|visible|greyed|grayed|locked|noedit|nomenu)\b",
        "impact": (
            "Every boolean in a client config that gates a capability is a candidate "
            "for the same test: flip it and see whether the server cares. In a thick "
            "client with a scriptable session definition, these are the fastest route "
            "to a privilege finding and the easiest for a developer to have assumed "
            "was safe."
        ),
        "verify": (
            "Flip each flag one at a time, relaunch, and look for functionality that "
            "should be unreachable. Confirm server-side rejection, not just UI "
            "reappearance - a visible button that errors server-side is correct "
            "behaviour, a visible button that works is the finding."
        ),
        "refs": ["CWE-602", "OWASP ASVS V1.4.1", "OWASP Top 10 A01"],
    },
    {
        "id": "PIV-NET-017",
        "recommendation": (
            "Enable transport encryption between the client and the PROIV service, and "
            "enforce it server-side so a client that omits it is refused. On the Windows "
            "thick client this is the 'Use Secure Socket:SSL' check box in Connection "
            "Settings together with the SSL port; on Open Client / client services it is "
            "Connection Protocol = Https (default port 8804), over either the WebSocket "
            "or HTTP transport; and PROIV Service Settings has a separate Service "
            "Encryption option. Where the session reaches the server through an SSH "
            "local port forward, TLS still terminates at the real server rather than at "
            "the forwarder, so enabling it is what makes the loopback leg unreadable."
        ),
        "cvss_hint": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
        "internal_adjust": 0,
        "context_note": (
            "Do not downgrade this by assuming an SSH tunnel covers it. A tunnel "
            "protects the hop between hosts; the client-to-forwarder hop on the "
            "workstation stays in whatever the application speaks, so on a multi-user "
            "host (Citrix, RDS) the plaintext is exposed to every other session's "
            "administrator and to anything running locally. On a single-user "
            "workstation capturing your own loopback is close to informational -- the "
            "severity here is set by how many identities share the host."
        ),
        "title": "Transport encryption not enabled on the client connection",
        "severity": "HIGH",
        "pattern": r"\b(usesecuresocket|use[_ ]?secure[_ ]?socket|securesocket|ssl|tls|https?|websocket|transport|connectionprotocol|connection[_ ]?protocol)\b",
        "impact": (
            "PROIV offers transport encryption for the client connection in several "
            "places -- 'Use Secure Socket:SSL' on the thick client, Https as the Open "
            "Client connection protocol, and a Service Encryption option whose state "
            "the PIV service/version value reflects (501 encrypted, 500 unencrypted). "
            "With none of them on, the PROIV protocol is cleartext TCP, including the "
            "application login that follows connection setup. An SSH tunnel does not "
            "substitute: it encrypts one hop, and the client-to-forwarder hop on the "
            "workstation remains readable to anything on that host."
        ),
        "verify": (
            "Read the decoded PIV (pivscan plaintext) for the service/version value and "
            "any secure-socket or protocol field, then confirm on the wire. Where a "
            "local SSH forward is in play, capture the loopback hop and the external "
            "hop separately -- they can differ. Then test whether the SERVER refuses an "
            "unencrypted client, which is the question that decides whether this is "
            "configuration or enforcement."
        ),
        "refs": ["CWE-319", "OWASP ASVS V9.1", "MITRE ATT&CK T1040"],
    },
    {
        "id": "PIV-CRED-018",
        "recommendation": (
            "Do not ship SSH credentials in the session file. Use key authentication "
            "with a passphrase, store the private key in a per-user location the user "
            "cannot copy wholesale, and keep the passphrase out of the PIV. Restrict "
            "the server-side account to exactly what the session needs: a forced "
            "command or no-shell account, AllowTcpForwarding limited and permitopen "
            "scoped to the application port, so a recovered credential cannot become a "
            "shell or a pivot. Keep strict host key checking on."
        ),
        "cvss_hint": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "internal_adjust": 0,
        "context_note": (
            "This is usually MORE severe than an application password, not less, and "
            "the application login that appears after the tunnel comes up is not a "
            "mitigation for it -- the two authenticate to different things. SSH "
            "credentials are operating-system access to the application server plus, "
            "unless forwarding is restricted, a route to anything that host can reach. "
            "The deciding factor is what the account is permitted to do, not where the "
            "tester is standing."
        ),
        "title": "SSH credentials in session file (OS access, not just application access)",
        "severity": "CRITICAL",
        "pattern": r"\b(ssh|sshlink|privatekey|private[_ ]?key|keyfile|key[_ ]?file|passphrase|identityfile|knownhosts|known[_ ]?hosts|stricthostkey|strict[_ ]?host[_ ]?key|port[_ ]?forward|localforward|tunnel)\b",
        "impact": (
            "Where the client reaches the server by establishing an SSH session and "
            "forwarding a local port, the credentials in the PIV are SSH credentials. "
            "Recovering them yields access to the host operating system, not to the "
            "application -- and the application login presented after the tunnel is "
            "established authenticates a different thing entirely, so it does not "
            "contain this. Unless the account is restricted to a forced command with "
            "forwarding scoped, the same credential grants a shell and the ability to "
            "forward arbitrary ports to anything the server can reach, which turns a "
            "session file into an internal-network pivot."
        ),
        "verify": (
            "With the recovered credential, establish an SSH session yourself and "
            "answer three questions: does it yield an interactive shell; can you "
            "forward a port to a host other than the application server (ssh -L to "
            "something unrelated); and is the account shared across users rather than "
            "per person. A restricted no-shell account with permitopen scoped to the "
            "application port is a far smaller finding than a general-purpose login, "
            "and the difference is worth establishing before scoring it. "
            "A 'permission denied' from your own SSH client does not settle it and is "
            "not evidence the credential is safe -- it is equally explained by the "
            "server disallowing password authentication (key only), by the account "
            "being restricted to a source address or a forced command, by the client "
            "sending something additional such as a key or a specific KEX or cipher, "
            "or by the field holding an application credential rather than an SSH one. "
            "Confirm which, by reading the server's sshd_config or auth log with the "
            "client's cooperation, or by watching your own attempt with ssh -vvv and "
            "comparing the offered authentication methods against what the client "
            "does. Report the credential as exposed either way: what it unlocks is "
            "unresolved, not disproven."
        ),
        "refs": ["CWE-522", "CWE-798", "CWE-306", "MITRE ATT&CK T1021.004",
                 "MITRE ATT&CK T1572"],
    },
    {
        "id": "PIV-NET-019",
        "recommendation": (
            "Replace dynamic forwarding with a local forward to the single host and "
            "port the session actually needs (-L 127.0.0.1:port:apphost:appport, never "
            "-D), and bind it to the loopback address explicitly. Constrain it "
            "server-side too, so a client cannot widen it: set AllowTcpForwarding to "
            "local, or no, and scope permitopen to the application endpoint on the "
            "account the client authenticates as. Where several users share a "
            "workstation, a per-user listener on a per-user port stops one session "
            "borrowing another's tunnel."
        ),
        "cvss_hint": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H",
        "internal_adjust": 0,
        "context_note": (
            "Do NOT downgrade for internal context -- an internal position is what "
            "makes this useful. The proxy's reach is whatever the SSH server can route "
            "to, so severity is set by the server's network position, not the tester's. "
            "Note also that this needs no credential: the tunnel is stood up by the "
            "legitimate client, so a recovered SSH password that does not work is "
            "irrelevant to exploiting it."
        ),
        "title": "Dynamic (SOCKS) port forwarding: unauthenticated internal pivot",
        "severity": "CRITICAL",
        "pattern": r"(\b(socks|socks4|socks5|dynamic[_ ]?forward|dynamicforward|proxyport|proxy[_ ]?port)\b|(?<![\w-])-D(?![\w-]))",
        "impact": (
            "SSH's -D option is dynamic forwarding: the client becomes a SOCKS4/5 "
            "proxy, and anything that speaks to it reaches ANY host and port the SSH "
            "server can route to -- not just the application server. That is a "
            "general-purpose route into the internal network sitting on the "
            "workstation, and it is unauthenticated: the SOCKS listener does not ask "
            "for the SSH credential, because the session is already established by the "
            "legitimate client. Any local process, any other user on a shared host, "
            "and any malware running as that user inherits the reach of the service "
            "account's host. A local forward (-L) to one endpoint has none of this "
            "breadth, which is why the distinction matters more than it looks."
        ),
        "verify": (
            "Read the running command line to confirm the flag and the bind address "
            "(wmic process get commandline, or Get-CimInstance Win32_Process), then "
            "check the listener with netstat -ano. Point a SOCKS-aware client at the "
            "port and connect to an internal host that has nothing to do with PROIV: "
            "if that succeeds, the finding is a network pivot rather than an "
            "application issue. A listener on 0.0.0.0 rather than 127.0.0.1 makes the "
            "proxy reachable from the network and should be reported separately."
        ),
        "refs": ["CWE-306", "CWE-923", "CWE-441", "MITRE ATT&CK T1572",
                 "MITRE ATT&CK T1090.001"],
    },
    {
        "id": "PIV-MISC-016",
        "recommendation": (
            "Treat the proxy/connector account as a privileged service identity: unique "
            "per environment, least-privileged, rotated, and stored in a secrets manager "
            "or protected store rather than a client-readable configuration file. It "
            "should never be a shared administrative account."
        ),
        "cvss_hint": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N",
        "internal_adjust": -1,
        "context_note": (
            "Downgraded for file-access prerequisite, but restore or exceed the original "
            "severity if the account turns out to be administrative or shared across "
            "environments."
        ),
        "title": "Proxy / connector credentials",
        "severity": "HIGH",
        "pattern": r"\b(proxy|connector|openclient|open[_ ]?client|service[_ ]?account|svc[_ ]?account)\b",
        "impact": (
            "The Open Client proxy connector can be configured with its own username "
            "and password to handle login negotiation with the application server. "
            "That is a service account, typically higher-privileged and shared, "
            "sitting in a client-readable file."
        ),
        "verify": "Identify the account, then confirm its privilege level with the client's administrators before any use.",
        "refs": ["CWE-522", "CWE-798"],
    },
]

COMPILED = [(r, re.compile(r["pattern"], re.IGNORECASE)) for r in RULES]

SECRET_KEY_RE = re.compile(
    r"(pass|pwd|secret|key|token|cred|auth|pin)", re.IGNORECASE
)

BLOB_SIGNATURES = [
    (b"-----BEGIN ", "PEM block"),
    (b"MZ\x90\x00", "PE executable"),
    (b"PK\x03\x04", "ZIP/OOXML archive"),
    (b"\x1f\x8b\x08", "gzip stream"),
    (b"\x30\x82", "DER/ASN.1 sequence (cert or key)"),
    (b"<?xml", "XML document"),
    (b"{\\rtf", "RTF document"),
    (b"\xfe\xed\xfe\xed", "Java KeyStore"),
]


# ---------------------------------------------------------------------------
# Scanning
# ---------------------------------------------------------------------------


SEV_SCALE = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


def adjust_severity(sev, steps):
    """Move a severity along the scale, clamped at both ends.

    `steps` is the rule's own adjustment value: negative steps move *down* the
    scale (CRITICAL -> HIGH), positive steps move up. The rules express a
    context downgrade as internal_adjust: -1.
    """
    i = max(0, min(len(SEV_SCALE) - 1, SEV_SCALE.index(sev) - steps))
    return SEV_SCALE[i]


def load_decoded(path, spec=None, auto_decode=True):
    """Read a PIV and return (raw, decoded, skip, obf).

    Everything downstream works on the decoded bytes. A byte-wise transform
    preserves length, so offsets stay valid against the file on disk -- which
    is what makes the output usable in a hex editor.
    """
    raw = read_file(path)
    skip = header_skip(raw)

    if spec:
        kind, key = parse_spec(spec)
        body = apply_transform(raw[skip:], kind, key)
        obf = text_score(body)
        obf.update({"transform": format_spec(kind, key), "kind": kind,
                    "key": key, "source": "user-specified"})
        return raw, raw[:skip] + body, skip, obf

    if auto_decode:
        decision, _cands = detect_obfuscation(raw, skip=skip)
        if decision:
            obf = dict(decision, source="auto-detected")
            body = apply_transform(raw[skip:], obf["kind"], obf["key"])
            return raw, raw[:skip] + body, skip, obf

    return raw, raw, skip, None


def scan(path, min_len=4, show_all_strings=False, context="internal",
         auto_decode=True, spec=None, show_plaintext=False):
    raw, data, skip, obf = load_decoded(path, spec, auto_decode)

    strings = extract_strings(data, min_len)
    kv = extract_kv(strings)

    report = OrderedDict()
    report["tool"] = "pivscan %s" % VERSION
    report["file"] = os.path.abspath(path)
    report["size"] = len(raw)
    report["sha_like_prefix"] = binascii.hexlify(raw[:16]).decode()
    report["overall_entropy"] = round(shannon_entropy(raw), 3)
    report["header"] = raw[:skip].decode("ascii", "replace") if skip else ""
    if obf:
        report["obfuscation"] = {
            "detected": True,
            "transform": obf["transform"],
            "source": obf.get("source", "auto-detected"),
            "keywords_recovered": obf["keyword_hits"],
            "strings_after_decode": obf["string_count"],
            "header_left_as_is": report["header"],
            "note": ("Findings below are from the DECODED bytes. Offsets are "
                     "unchanged, so they still address the original file."),
        }
    else:
        report["obfuscation"] = {"detected": False}
    report["context"] = context
    report["string_count"] = len(strings)
    report["kv_count"] = len(kv)

    # --- format characterisation -------------------------------------------
    printable_ratio = sum(1 for b in raw if b in PRINTABLE or b in (9, 10, 13)) / max(
        len(raw), 1
    )
    if printable_ratio > 0.85:
        fmt = "predominantly text (INI/KV-like) - edit directly in a text editor"
    elif printable_ratio > 0.30:
        fmt = "mixed binary with embedded text - use a hex editor, strings survive"
    else:
        fmt = "opaque binary - likely packed/encrypted; rely on diffing to map fields"
    report["format_guess"] = fmt
    report["printable_ratio"] = round(printable_ratio, 3)

    # --- integrity surface --------------------------------------------------
    integrity_terms = re.compile(
        r"(signature|signed|hmac|mac\b|digest|hash|checksum|crc)", re.IGNORECASE
    )
    has_integrity_hint = any(integrity_terms.search(t) for _, _, t in strings)
    report["integrity_field_hint"] = bool(has_integrity_hint)

    # --- blobs --------------------------------------------------------------
    blobs = []
    for sig, label in BLOB_SIGNATURES:
        start = 0
        while True:
            idx = data.find(sig, start)
            if idx == -1:
                break
            blobs.append({"offset": idx, "type": label})
            start = idx + 1
    report["embedded_blobs"] = blobs[:50]

    # --- high entropy regions ----------------------------------------------
    hot = [
        {"offset": o, "length": l, "entropy": round(e, 2)}
        for o, l, e in entropy_map(raw)
        if e > 7.2
    ]
    report["high_entropy_regions"] = hot[:40]

    # --- rule matching ------------------------------------------------------
    findings = []
    for rule, rx in COMPILED:
        evidence = []
        for off, enc, text in strings:
            for line in text.splitlines():
                if rx.search(line) or rx.search(normalise_for_match(line)):
                    evidence.append(
                        {
                            "offset": off,
                            "encoding": enc,
                            "excerpt": line[:200],
                        }
                    )
                if len(evidence) >= 12:
                    break
            if len(evidence) >= 12:
                break
        if evidence:
            base_sev = rule["severity"]
            adj = rule.get("internal_adjust", 0) if context == "internal" else 0
            sev = adjust_severity(base_sev, adj)
            findings.append(
                {
                    "id": rule["id"],
                    "title": rule["title"],
                    "severity": sev,
                    "base_severity": base_sev,
                    "adjusted": sev != base_sev,
                    "context_note": rule.get("context_note", ""),
                    "cvss_hint": rule.get("cvss_hint", ""),
                    "impact": rule["impact"],
                    "verify": rule["verify"],
                    "recommendation": rule.get("recommendation", ""),
                    "refs": rule["refs"],
                    "evidence": evidence,
                    "evidence_count": len(evidence),
                }
            )

    findings.sort(key=lambda f: (SEV_ORDER[f["severity"]], f["id"]))
    report["findings"] = findings

    # --- secret value decode attempts --------------------------------------
    secrets = []
    for pair in kv:
        if SECRET_KEY_RE.search(pair["key"]) and pair["value"]:
            decodes = analyse_secret_value(pair["value"])
            v = pair["value"]
            if v in ("0", "1", "true", "false", "True", "False", "yes", "no"):
                assessment = "boolean flag, not a secret - flip it and test server-side enforcement"
            elif re.fullmatch(r"[0-9a-fA-F]{32}", v):
                assessment = "32 hex chars - MD5-shaped; try a hash cracker before assuming encryption"
            elif re.fullmatch(r"[0-9a-fA-F]{40}", v):
                assessment = "40 hex chars - SHA-1-shaped"
            elif re.fullmatch(r"[A-Za-z0-9 !-/:-@\[-`{-~]+", v) and not try_base64(v) and not try_hex(v):
                assessment = (
                    "STORED IN PLAINTEXT - no decoding needed, this is the finding"
                )
            else:
                assessment = "encoded or encrypted - see candidates below and use the diff method to confirm"
            secrets.append(
                {
                    "offset": pair["offset"],
                    "key": pair["key"],
                    "value": pair["value"][:120],
                    "value_len": len(pair["value"]),
                    "assessment": assessment,
                    "decode_candidates": [
                        {"scheme": s, "plaintext": p[:120]} for s, p in decodes
                    ],
                }
            )
    report["credential_candidates"] = secrets

    if show_plaintext:
        report["plaintext"] = plaintext_lines(data, skip)
    report["key_value_pairs"] = kv if show_all_strings else kv[:200]
    if show_all_strings:
        report["strings"] = [
            {"offset": o, "encoding": e, "text": t} for o, e, t in strings
        ]

    return report


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

BAR = "=" * 72
SUB = "-" * 72


def render(report):
    L = []
    a = L.append
    a(BAR)
    a(" pivscan %s - PROIV .PIV session file analysis" % VERSION)
    a(BAR)
    a(" File              : %s" % report["file"])
    a(" Size              : %d bytes" % report["size"])
    a(" First 16 bytes    : %s" % report["sha_like_prefix"])
    a(" Overall entropy   : %s" % report["overall_entropy"])
    a(" Format            : %s" % report["format_guess"])
    a(" Severity context  : %s%s" % (
        report.get("context", "internal"),
        " (severities calibrated for an internal thick-client engagement)"
        if report.get("context") == "internal" else ""))
    obf = report.get("obfuscation") or {}
    if obf.get("detected"):
        a(" Obfuscation       : DEFEATED - %s (%s)" % (obf["transform"], obf["source"]))
        a("                     plaintext header left as-is: %r"
          % (obf.get("header_left_as_is") or ""))
        a("                     recovered property names: %s"
          % ", ".join(obf["keywords_recovered"][:10]))
        a("                     %s" % obf["note"])
        a("                     full decoded contents: pivscan plaintext <file>")
    a(" Strings / KV pairs: %d / %d" % (report["string_count"], report["kv_count"]))
    a(
        " Integrity field   : %s"
        % (
            "possible signature/checksum keyword present - verify it is enforced"
            if report["integrity_field_hint"]
            else "NONE FOUND - treat the file as freely tamperable until disproven"
        )
    )
    a("")

    sev_counts = Counter(f["severity"] for f in report["findings"])
    a(" Findings: " + ", ".join(
        "%s=%d" % (s, sev_counts[s]) for s in sorted(sev_counts, key=lambda x: SEV_ORDER[x])
    ) if sev_counts else " Findings: none matched (see caveats at the end)")
    a("")

    for f in report["findings"]:
        a(SUB)
        if f.get("adjusted"):
            a("[%s] %s  (%s)   [adjusted from %s for %s context]"
              % (f["severity"], f["title"], f["id"], f["base_severity"], report.get("context", "internal")))
        else:
            a("[%s] %s  (%s)" % (f["severity"], f["title"], f["id"]))
        a(SUB)
        a("Why it matters:")
        a("  " + wrap(f["impact"], 68, "  "))
        a("How to verify:")
        a("  " + wrap(f["verify"], 68, "  "))
        if f.get("recommendation"):
            a("RECOMMENDATION:")
            a("  " + wrap(f["recommendation"], 68, "  "))
        if f.get("context_note"):
            a("Severity rationale (%s context):" % report.get("context", "internal"))
            a("  " + wrap(f["context_note"], 68, "  "))
        if f.get("cvss_hint"):
            a("CVSS v3.1 starting vector (adjust to what you actually proved):")
            a("  " + f["cvss_hint"])
        a("References: " + ", ".join(f["refs"]))
        a("Evidence (%d hit%s, showing up to 12):" % (f["evidence_count"], "" if f["evidence_count"] == 1 else "s"))
        for ev in f["evidence"]:
            a("  0x%08x [%-8s] %s" % (ev["offset"], ev["encoding"], ev["excerpt"]))
        a("")

    if report["credential_candidates"]:
        a(BAR)
        a(" CREDENTIAL-SHAPED VALUES AND OFFLINE DECODE ATTEMPTS")
        a(BAR)
        for s in report["credential_candidates"]:
            a("  0x%08x  %s = %s  (len %d)" % (s["offset"], s["key"], s["value"], s["value_len"]))
            a("      ASSESSMENT: %s" % s["assessment"])
            if s["assessment"].startswith(("STORED IN PLAINTEXT", "boolean flag")):
                pass  # brute-forcing a value you can already read is noise
            elif s["decode_candidates"]:
                a("      Brute-force candidates (base64/hex are reliable; xor/add are")
                a("      exhaustive guesses and mostly noise - treat as leads only):")
                for d in s["decode_candidates"]:
                    a("      -> %-10s %s" % (d["scheme"], d["plaintext"]))
            else:
                a("      -> no trivial reversal; use the known-plaintext diff method")
        a("")

    if report.get("plaintext"):
        a(BAR)
        a(" DEOBFUSCATED CONTENTS (offsets address the original file)")
        a(BAR)
        for r in report["plaintext"]:
            for i, line in enumerate(r["text"].splitlines() or [""]):
                if i == 0:
                    a("  %08x  [%-8s] %s" % (r["offset"], r["encoding"], line))
                else:
                    a("  %8s  %10s %s" % ("", "", line))
        a("")

    if report["embedded_blobs"]:
        a(BAR)
        a(" EMBEDDED BLOBS")
        a(BAR)
        for b in report["embedded_blobs"]:
            a("  0x%08x  %s" % (b["offset"], b["type"]))
        a("")

    if report["high_entropy_regions"]:
        a(BAR)
        a(" HIGH ENTROPY REGIONS (>7.2 bits/byte - encrypted, compressed or random)")
        a(BAR)
        for r in report["high_entropy_regions"]:
            a("  0x%08x  %4d bytes  entropy %.2f" % (r["offset"], r["length"], r["entropy"]))
        a("  These are where stored secrets usually live in a binary PIV.")
        a("  Use 'pivscan diff' with a known-plaintext change to confirm.")
        a("")

    a(BAR)
    a(" NEXT STEPS")
    a(BAR)
    a("  1. Known-plaintext mapping: in the PROIV Client, open Session Properties,")
    a("     change ONE setting, Apply (writes to the PIV), save a copy, then run")
    a("     'pivscan diff before.piv after.piv'. Repeat per setting to build a")
    a("     field map without reversing the executable.")
    a("  2. Integrity test: flip one benign byte and reopen. If it still loads, the")
    a("     file has no integrity protection - that promotes every client-side flag")
    a("     in this report to an exploitable control.")
    a("  3. Server-side enforcement test: for each restrictive flag, flip it and")
    a("     check whether the SERVER rejects the action. UI reappearing is not the")
    a("     finding; the action succeeding is.")
    a("  4. Delivery vector: because the client registers a .PIV file association,")
    a("     document the phishing scenario (user opens attacker-supplied .piv ->")
    a("     client auto-connects to attacker host -> stored credential transmitted).")
    a("")
    if not report["findings"] and not obf.get("detected"):
        a(" NOTHING MATCHED - before concluding the file is clean, try:")
        a("   pivscan decode session.piv            # rank candidate transforms")
        a("   pivscan decode session.piv --out plain.bin && pivscan scan plain.bin")
        a(" A real PIV can be UTF-16LE text under a byte-wise XOR behind a plaintext")
        a(" magic, which defeats every string-based rule in this tool. Auto-detection")
        a(" only accepts a decode it is confident about; 'decode' shows the rest.")
        a("")
    a(" CAVEATS: the PIV layout is proprietary and version-dependent. Keyword hits")
    a(" are leads, not proof. An empty result does not mean the file is clean - an")
    a(" opaque binary PIV hides everything from a string scan, which is exactly")
    a(" what the diff workflow is for.")
    a(BAR)
    return "\n".join(L)


def wrap(text, width, indent):
    words = text.split()
    lines, cur = [], ""
    for w in words:
        if len(cur) + len(w) + 1 > width:
            lines.append(cur)
            cur = w
        else:
            cur = (cur + " " + w).strip()
    if cur:
        lines.append(cur)
    return ("\n" + indent).join(lines)


# ---------------------------------------------------------------------------
# Diff
# ---------------------------------------------------------------------------


def diff(path_a, path_b):
    a_data, b_data = read_file(path_a), read_file(path_b)
    out = []
    out.append(BAR)
    out.append(" pivscan diff - known-plaintext field mapping")
    out.append(BAR)
    out.append(" A: %s (%d bytes)" % (path_a, len(a_data)))
    out.append(" B: %s (%d bytes)" % (path_b, len(b_data)))
    out.append("")

    if len(a_data) != len(b_data):
        out.append(" Size differs by %+d bytes - the field is length-variable," % (len(b_data) - len(a_data)))
        out.append(" which argues for text/TLV storage rather than fixed-offset records.")
        out.append("")

    n = min(len(a_data), len(b_data))
    changed = [i for i in range(n) if a_data[i] != b_data[i]]
    out.append(" Differing byte positions (first %d bytes compared): %d" % (n, len(changed)))

    if changed:
        # group into runs
        runs, start, prev = [], changed[0], changed[0]
        for i in changed[1:]:
            if i == prev + 1:
                prev = i
                continue
            runs.append((start, prev))
            start = prev = i
        runs.append((start, prev))

        out.append("")
        out.append(" Changed runs:")
        for s, e in runs[:60]:
            length = e - s + 1
            seg_a = a_data[s : e + 1]
            seg_b = b_data[s : e + 1]
            out.append("  0x%08x .. 0x%08x  (%d byte%s)" % (s, e, length, "" if length == 1 else "s"))
            out.append("      A: %s | %s" % (hexdump_line(seg_a), printable(seg_a)))
            out.append("      B: %s | %s" % (hexdump_line(seg_b), printable(seg_b)))
        if len(runs) > 60:
            out.append("  ... %d more runs" % (len(runs) - 60))

        out.append("")
        out.append(" Interpretation guide:")
        out.append("   1 byte changed, 1 byte input changed   -> XOR/substitution, trivially reversible")
        out.append("   whole region changed, same length      -> stream cipher or keyed encoding")
        out.append("   whole region changed, 8/16-byte blocks -> block cipher (note the block size)")
        out.append("   fixed-length output, any input length  -> hash or truncated digest")
        out.append("   plaintext visible in B                 -> no protection at all")

    # string level diff
    sa = {t for _, _, t in extract_strings(a_data)}
    sb = {t for _, _, t in extract_strings(b_data)}
    only_b = sorted(sb - sa)
    only_a = sorted(sa - sb)
    if only_a or only_b:
        out.append("")
        out.append(" Strings only in A:")
        for s in only_a[:40]:
            out.append("   - %s" % s[:160])
        out.append(" Strings only in B:")
        for s in only_b[:40]:
            out.append("   + %s" % s[:160])

    out.append(BAR)
    return "\n".join(out)


def hexdump_line(b, limit=16):
    h = " ".join("%02x" % c for c in b[:limit])
    if len(b) > limit:
        h += " .."
    return h


def printable(b, limit=16):
    return "".join(chr(c) if c in PRINTABLE else "." for c in b[:limit])


# ---------------------------------------------------------------------------
# Carve
# ---------------------------------------------------------------------------


def carve(path, outdir):
    data = read_file(path)
    os.makedirs(outdir, exist_ok=True)
    written = []

    # PEM blocks
    for m in re.finditer(rb"-----BEGIN [^-]+-----.*?-----END [^-]+-----", data, re.S):
        name = os.path.join(outdir, "pem_%08x.pem" % m.start())
        with open(name, "wb") as fh:
            fh.write(m.group())
        written.append(name)

    # ZIP
    for m in re.finditer(rb"PK\x03\x04", data):
        name = os.path.join(outdir, "zip_%08x.bin" % m.start())
        with open(name, "wb") as fh:
            fh.write(data[m.start():])
        written.append(name)
        break

    # high entropy regions
    for off, length, ent in entropy_map(data):
        if ent > 7.4:
            name = os.path.join(outdir, "entropy_%08x.bin" % off)
            with open(name, "wb") as fh:
                fh.write(data[off : off + length])
            written.append(name)

    if not written:
        return "No carvable regions found."
    return "Carved %d region(s) to %s:\n" % (len(written), outdir) + "\n".join(
        "  " + w for w in written
    )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def plaintext_lines(data, skip=0):
    """The decoded file as readable lines: [(offset, encoding, text)].

    Adjacent UTF-16LE runs separated only by structure bytes are kept as
    separate entries rather than glued together -- in a PIV those boundaries
    are the field boundaries, and losing them loses the structure.
    """
    out = []
    if skip:
        out.append((0, "magic", data[:skip].decode("ascii", "replace")))
    for off, enc, text in extract_strings(data, 4):
        if off < skip:
            continue
        out.append((off, enc, text))
    return [{"offset": o, "encoding": e, "text": t} for o, e, t in out]


def render_plaintext(path, spec=None, auto_decode=True, as_hex=False, width=16):
    raw, data, skip, obf = load_decoded(path, spec, auto_decode)
    L = []
    a = L.append
    a(BAR)
    a(" pivscan plaintext - deobfuscated contents of %s" % os.path.basename(path))
    a(BAR)
    if obf:
        a(" Transform : %s (%s)" % (obf["transform"], obf["source"]))
        a(" Magic     : %r (plaintext in the original)"
          % data[:skip].decode("ascii", "replace"))
        a(" Note      : offsets below address the ORIGINAL file; a byte-wise")
        a("             transform does not move anything.")
    else:
        a(" Transform : none applied - this is the file as it sits on disk.")
        a("             If it should have been decoded, try: pivscan decode %s"
          % os.path.basename(path))
    a("")

    if as_hex:
        a(" Decoded hexdump (ASCII column shows UTF-16 text as every other byte):")
        a("")
        for off in range(0, len(data), width):
            chunk = data[off:off + width]
            a("  %08x  %-*s  |%s|" % (
                off, width * 3, " ".join("%02x" % c for c in chunk),
                "".join(chr(c) if c in PRINTABLE else "." for c in chunk)))
    else:
        rows = plaintext_lines(data, skip)
        a(" %d text run%s recovered:" % (len(rows), "" if len(rows) == 1 else "s"))
        a("")
        for r in rows:
            for i, line in enumerate(r["text"].splitlines() or [""]):
                if i == 0:
                    a("  %08x  [%-8s] %s" % (r["offset"], r["encoding"], line))
                else:
                    a("  %8s  %10s %s" % ("", "", line))
    a("")
    a(BAR)
    return "\n".join(L)


def decode_report(path, spec=None, out=None, top=5):
    raw = read_file(path)
    skip = header_skip(raw)
    L = []
    a = L.append
    a(BAR)
    a(" pivscan decode - whole-file transform recovery")
    a(BAR)
    a(" File   : %s (%d bytes)" % (path, len(raw)))
    a(" Header : %r (left out of key recovery)" % raw[:skip].decode("ascii", "replace"))
    a("")

    if spec:
        kind, key = parse_spec(spec)
        body = apply_transform(raw[skip:], kind, key)
        info = text_score(body)
        a(" Applied %s as instructed." % format_spec(kind, key))
        a("   strings recovered : %d" % info["string_count"])
        a("   property names    : %s" % (", ".join(info["keyword_hits"]) or "none"))
        chosen = raw[:skip] + body
    else:
        cands = deobfuscate_candidates(raw, skip=skip, top=top)
        a(" Candidate transforms, best first:")
        a("")
        a("   %-14s %8s %7s %7s  %s" % ("transform", "score", "strings", "names", "property names found"))
        for c in cands:
            a("   %-14s %8d %7d %7d  %s" % (
                c["transform"], c["score"], c["string_count"],
                len(c["keyword_hits"]), ", ".join(c["keyword_hits"][:6]) or "-"))
        a("")
        best = cands[0] if cands else None
        if best and best["kind"] != "none" and len(best["keyword_hits"]) >= 2:
            a(" Best candidate recovers real PROIV property names, so the file is")
            a(" obfuscated rather than opaque. How the key was recovered, in case you")
            a(" need to do this by hand: in UTF-16LE text every ASCII character is")
            a(" stored as XX 00, so the most common plaintext byte is 0x00 -- which")
            a(" makes the most common CIPHERTEXT byte the key itself. The '::;;' or")
            a(" ';;;;' rhythm in a strings dump is exactly those lit-up null bytes.")
            chosen = raw[:skip] + apply_transform(raw[skip:], best["kind"], best["key"])
        else:
            a(" No candidate recovered recognisable PROIV properties. The file may use")
            a(" a stream cipher, compression, or a structure this tool does not model.")
            a(" Fall back to the known-plaintext diff workflow.")
            chosen = None

    if out and chosen is not None:
        with open(out, "wb") as fh:
            fh.write(chosen)
        a("")
        a(" Decoded bytes written to %s" % out)
        a(" Offsets are unchanged, so they still address the original file.")
        a(" Next: pivscan scan %s" % out)
    a(BAR)
    return "\n".join(L)


def main():
    p = argparse.ArgumentParser(
        description="Static insecurity scanner for PROIV Client .PIV session files",
        epilog="Read-only and offline. Use only against files you are authorised to test.",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="analyse a single .piv file")
    s.add_argument("file")
    s.add_argument("--json", dest="json_out", help="also write machine-readable JSON")
    s.add_argument("--min-len", type=int, default=4)
    s.add_argument("--all-strings", action="store_true")
    s.add_argument(
        "--context",
        choices=["internal", "external", "raw"],
        default="internal",
        help="deployment context for severity calibration; 'raw' disables adjustment",
    )
    s.add_argument("--no-auto-decode", action="store_true",
                   help="do not attempt whole-file deobfuscation before scanning")
    s.add_argument("--spec",
                   help="apply a known transform instead of detecting one, "
                        "e.g. xor:3b, xor:3b2f, add:05")
    s.add_argument("--show-plaintext", action="store_true",
                   help="append the full deobfuscated contents to the report")

    st = sub.add_parser("strings", help="dump ASCII + UTF-16LE strings with offsets")
    st.add_argument("file")
    st.add_argument("--min-len", type=int, default=4)

    d = sub.add_parser("diff", help="byte and string diff of two .piv files")
    d.add_argument("before")
    d.add_argument("after")

    dc = sub.add_parser("decode", help="recover a whole-file XOR/add transform")
    dc.add_argument("file")
    dc.add_argument("--spec", help="apply this transform instead of detecting one")
    dc.add_argument("--out", help="write the decoded bytes here")
    dc.add_argument("--top", type=int, default=5, help="candidates to list")

    pt = sub.add_parser("plaintext",
                        help="print the whole file deobfuscated and readable")
    pt.add_argument("file")
    pt.add_argument("--spec", help="apply this transform instead of detecting one")
    pt.add_argument("--no-auto-decode", action="store_true")
    pt.add_argument("--hex", action="store_true",
                    help="annotated hexdump of the decoded bytes")
    pt.add_argument("--out", help="write the rendered text here")

    c = sub.add_parser("carve", help="extract embedded blobs and high-entropy regions")
    c.add_argument("file")
    c.add_argument("--out", default="./carved")

    args = p.parse_args()

    if args.cmd == "scan":
        rep = scan(args.file, args.min_len, args.all_strings, args.context,
                   auto_decode=not args.no_auto_decode, spec=args.spec,
                   show_plaintext=args.show_plaintext)
        print(render(rep))
        if args.json_out:
            with open(args.json_out, "w") as fh:
                json.dump(rep, fh, indent=2)
            print("\nJSON written to %s" % args.json_out)

    elif args.cmd == "plaintext":
        text = render_plaintext(args.file, args.spec,
                                auto_decode=not args.no_auto_decode,
                                as_hex=args.hex)
        if args.out:
            with open(args.out, "w", encoding="utf-8") as fh:
                fh.write(text + "\n")
            print("Wrote %s" % args.out)
        else:
            print(text)

    elif args.cmd == "decode":
        print(decode_report(args.file, args.spec, args.out, args.top))

    elif args.cmd == "strings":
        for off, enc, text in extract_strings(read_file(args.file), args.min_len):
            print("0x%08x [%-8s] %s" % (off, enc, text))

    elif args.cmd == "diff":
        print(diff(args.before, args.after))

    elif args.cmd == "carve":
        print(carve(args.file, args.out))


if __name__ == "__main__":
    try:
        main()
    except FileNotFoundError as e:
        sys.exit("File not found: %s" % e.filename)
    except KeyboardInterrupt:
        sys.exit(130)
