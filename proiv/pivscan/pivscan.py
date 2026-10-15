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


def try_single_byte_xor(raw):
    """Classic 'encrypted and stored in the file' = single byte XOR. Check it."""
    hits = []
    for key in range(1, 256):
        cand = bytes(c ^ key for c in raw)
        if looks_printable(cand, 0.95) and re.search(rb"[A-Za-z]{3,}", cand):
            hits.append((key, cand.decode("ascii", "replace")))
    return hits[:5]


def try_rot_add(raw):
    hits = []
    for shift in range(1, 256):
        cand = bytes((c + shift) & 0xFF for c in raw)
        if looks_printable(cand, 0.95) and re.search(rb"[A-Za-z]{3,}", cand):
            hits.append((shift, cand.decode("ascii", "replace")))
    return hits[:3]


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


def scan(path, min_len=4, show_all_strings=False, context="internal"):
    data = read_file(path)
    strings = extract_strings(data, min_len)
    kv = extract_kv(strings)

    report = OrderedDict()
    report["tool"] = "pivscan %s" % VERSION
    report["file"] = os.path.abspath(path)
    report["size"] = len(data)
    report["sha_like_prefix"] = binascii.hexlify(data[:16]).decode()
    report["overall_entropy"] = round(shannon_entropy(data), 3)
    report["context"] = context
    report["string_count"] = len(strings)
    report["kv_count"] = len(kv)

    # --- format characterisation -------------------------------------------
    printable_ratio = sum(1 for b in data if b in PRINTABLE or b in (9, 10, 13)) / max(
        len(data), 1
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
        for o, l, e in entropy_map(data)
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

    st = sub.add_parser("strings", help="dump ASCII + UTF-16LE strings with offsets")
    st.add_argument("file")
    st.add_argument("--min-len", type=int, default=4)

    d = sub.add_parser("diff", help="byte and string diff of two .piv files")
    d.add_argument("before")
    d.add_argument("after")

    c = sub.add_parser("carve", help="extract embedded blobs and high-entropy regions")
    c.add_argument("file")
    c.add_argument("--out", default="./carved")

    args = p.parse_args()

    if args.cmd == "scan":
        rep = scan(args.file, args.min_len, args.all_strings, args.context)
        print(render(rep))
        if args.json_out:
            with open(args.json_out, "w") as fh:
                json.dump(rep, fh, indent=2)
            print("\nJSON written to %s" % args.json_out)

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
