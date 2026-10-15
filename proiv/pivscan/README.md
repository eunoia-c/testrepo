# pivscan

Static insecurity scanner for PROIV Client `.PIV` session files. Read-only and
offline: it never connects anywhere, never launches the client, and never
modifies the input.

## What a .PIV is, and why it matters

The PROIV Windows Client stores each configured session in a `.PIV` file —
PROIV's equivalent of `.rdp` or `.ica`. It holds the connection target,
protocol/service selection, optional stored credentials, startup parameters,
client-side lockdown settings, and path references to Application Definitions,
connection scripts and OCX/CAB components.

Two properties make it worth a tool of its own:

**It is a credential store.** Session properties can carry a PROIV password
*and* a Unix OS password for automatic login. On the Telnet session type the
automatic-login flow watches the stream for a password prompt and writes the
password into it — so a cleartext session type leaks the credential on every
single launch.

**It is a launchable artifact.** The client registers a Windows file
association for `.PIV` and supports drag-and-drop launching. That turns a
session file into a double-clickable payload: if nothing validates the
connection target, an attacker-supplied `.piv` makes the client connect to a
host of their choosing and — with automatic login configured — send the stored
credentials there before the user touches anything. Every other finding in a
PIV is amplified by this delivery vector, which is why the integrity question
is checked first.

## It is probably obfuscated, and that is recoverable

Run `strings` on a real PIV and you may get something like this:

```
PRO4VSx;N;H;O;T;V;o;T;T;W;y;Z;I;
```

That is not binary noise and it is not a separator-delimited format. It is
**UTF-16LE text XOR'd with a single byte, behind a plaintext magic**. XOR with
`0x3b` and it reads `CustomToolBar`.

The `;` characters are the tell. In UTF-16LE every ASCII character is stored as
`XX 00`, so a file full of `0x00` bytes XOR'd with `0x3b` shows `;` at every
other position — the nulls, lit up. An occasional `:` is a plaintext `0x01`,
the structure bytes between string fields. That rhythm, `;X;X;X`, is the
signature of this whole class of obfuscation.

Two consequences:

**The key is free.** Never brute-force a file like this. The most common
plaintext byte in UTF-16LE text is `0x00`, so the most common *ciphertext* byte
**is the key**. `recover_xor_key_modal` is that one-liner. For repeating
multi-byte keys the columns are independent, so each is solved on its own
(`recover_xor_key_columns`) — 256 tries per column instead of 256^n for the
whole key.

**The magic stays plaintext.** The client has to read it to identify the file,
so it sits outside the obfuscation. `header_skip` keeps it out of key recovery,
where it would poison the statistics. Note that "advance while the byte is
printable" does **not** find it — XOR'd UTF-16LE is printable too, so that walk
runs straight past `PRO4VS` and into the body.

### What `scan` does about it

`scan` auto-decodes before doing anything else, and says so loudly:

```
 Obfuscation       : DEFEATED - xor:3b (auto-detected)
                     plaintext header left as-is: 'PRO4VS'
                     recovered property names: appdef, application, debug, default, ...
                     Findings below are from the DECODED bytes. Offsets are
                     unchanged, so they still address the original file.
```

A byte-wise transform preserves length, so **every offset in the report still
addresses the file on disk** — paste it straight into a hex editor.

Auto-decode is deliberately conservative: it requires at least two distinct
PROIV property names that the raw file does not contain. It is never applied
silently, and `--no-auto-decode` turns it off. What it explicitly does *not*
use as a gate is "the decoded text scores much higher than the raw file" —
XOR-ing UTF-16LE with any byte in the printable range leaves the ciphertext
fully printable, so the raw file already scores well on text volume and a ratio
test rejects the correct answer.

Use `decode` when `scan` declines. It has no keyword gate, ranks every
candidate, explains how the key was recovered, and will write the decoded bytes
out with `--out` for your own `strings`/hex work:

```
   transform         score strings   names  property names found
   xor:3b             1397      13      22  appdef, application, debug, default, ...
   xor:32              600      19       0  -
```

If no candidate recovers recognisable properties, it says so rather than
guessing — then it is a stream cipher, compression, or a structure this tool
does not model, and the diff workflow is the way in.

## Usage

```bash
python3 pivscan.py scan    session.piv [--json out.json] [--min-len 4] [--all-strings]
python3 pivscan.py scan    session.piv --context raw     # no severity calibration
python3 pivscan.py scan    session.piv --spec xor:3b     # apply a known transform
python3 pivscan.py scan    session.piv --no-auto-decode  # scan the raw bytes
python3 pivscan.py decode  session.piv [--out plain.bin] [--spec xor:3b] [--top 5]
python3 pivscan.py strings session.piv [--min-len 4]
python3 pivscan.py diff    before.piv after.piv
python3 pivscan.py carve   session.piv --out ./carved
```

Standard library only, Python 3.6+. No install, no dependencies, no network.

## The three-step workflow

**1. `scan`** — triage one PIV. Characterises the format, reports whether any
integrity field exists, runs 16 rules, lists credential-shaped values with
offline decode attempts, flags embedded blobs and high-entropy regions.

**2. `diff`** — the part that actually solves the hard problem. The PIV layout
is proprietary and version-dependent, so rather than reversing the executable:
open Session Properties in the client, change **one** setting, Apply, save a
copy, and diff the two files. The changed byte range is that setting's field.
Repeat per setting and you have a field map in an afternoon.

The same trick recovers the obfuscation scheme. Set a password to `AAAAAAAA`,
then `AAAAAAAB`, and read the diff:

| What the diff shows | What it means |
| --- | --- |
| 1 byte changed for a 1-byte input change | XOR or substitution — trivially reversible, you're done |
| whole region changed, same length | stream cipher or keyed encoding |
| whole region changed in 8/16-byte blocks | block cipher — note the block size |
| fixed-length output regardless of input length | hash or truncated digest |
| plaintext visible | no protection at all |

**3. `carve`** — extract PEM blocks, archives and high-entropy regions for
separate review. Use this on binary PIVs where the string scan comes up empty.

## Rules

16 rules, keyword- and structure-driven rather than offset-driven so they work
on both the INI-ish text variants and the binary ones.

| ID | Finding | Base severity |
| --- | --- | --- |
| `PIV-CRED-001` | Stored login credential in session file | CRITICAL |
| `PIV-CRED-002` | Credential persistence (Remember Username/Password) | HIGH |
| `PIV-CRED-003` | Interactive security prompt disabled | MEDIUM |
| `PIV-AUTH-004` | Client-side lockdown password stored in the file it protects | HIGH |
| `PIV-NET-005` | Cleartext transport / Telnet session type | HIGH |
| `PIV-NET-006` | Server endpoint / internal infrastructure disclosure | MEDIUM |
| `PIV-TAMPER-007` | Session redirection: no integrity protection on the target | HIGH |
| `PIV-PATH-008` | External file / script / UNC path reference | HIGH |
| `PIV-PARAM-009` | Startup parameter injection (Xfer In) | MEDIUM |
| `PIV-XFER-010` | File transfer configuration enforced client-side | MEDIUM |
| `PIV-CRYPT-011` | Embedded key material or certificate | CRITICAL |
| `PIV-CRYPT-012` | Weak or reversible protection of stored secrets | HIGH |
| `PIV-DEBUG-013` | Debug, trace or diagnostic setting enabled | MEDIUM |
| `PIV-DB-014` | Database connection detail exposed to the client | CRITICAL |
| `PIV-UI-015` | Client-side-only restriction flag | MEDIUM |
| `PIV-MISC-016` | Proxy / connector service credentials | HIGH |

Every finding prints why it matters, how to verify it yourself, a
remediation recommendation for the client report, a CVSS v3.1 starting vector,
and CWE/ASVS/ATT&CK references.

### Severity is calibrated, and says so

`--context internal` (the default) downgrades findings whose exploitation
presumes you already have the file — stored credentials, cleartext capture,
debug logs — because "CRITICAL: password in a file only reachable from a
workstation you already own" is the kind of rating that gets a whole report
argued down. The report prints `[adjusted from CRITICAL for internal context]`
so the original is never hidden, and each rule carries the reason plus the
conditions under which you should put it back up.

Rules marked `internal_adjust: 0` deliberately do **not** downgrade:

- **`PIV-PATH-008`** — forced authentication and NTLM relay *are* internal
  attacks. An internal position makes this more exploitable, not less.
- **`PIV-DB-014`** — a direct DB path from a workstation is exploitable
  precisely because the tester is already inside.
- **`PIV-AUTH-004`, `PIV-UI-015`** — a client-side authorisation control fails
  identically on any network, because the attacker is the legitimate user of
  the workstation.
- **`PIV-CRYPT-011`** — a private key shipped to every workstation is
  compromised regardless of network position.
- **`PIV-TAMPER-007`** — phishing a `.piv` works the same internally, and
  internal users are *more* likely to open one that looks legitimate.

Use `--context raw` when you want the uncalibrated base severities.

## Two things the tool does that are easy to get wrong

**UTF-16LE strings.** The PROIV Client is a Windows application, so anything
the GUI wrote is at least as likely to be UTF-16LE as ASCII. Scanning only for
ASCII runs is the usual reason someone concludes a config file "has no strings
in it". Both encodings are extracted, and each hit is labelled with which one
it came from.

**CamelCase key names.** Real keys are written `RememberUsernameAndPassword`,
`ActivateUserRuntimeInterface`, `PromptForSecurity`, `DebugTrace`. A keyword
regex with word boundaries — `\b(password)\b` — matches none of them, and the
file reads as clean. Every rule is matched against both the raw line and a
CamelCase-split normalisation of it.

## Limits

Read these before reporting a clean result.

**Credential-shaped values in binary PIVs are missed.** Key/value extraction
works on printable runs, so where an obfuscated password sits as raw bytes
after an ASCII key name, the key is recovered with an *empty* value and the
pair is dropped before any decode is attempted. The settings still get flagged
by the rules, so the file does not read as clean — but the secret itself will
not appear under *credential-shaped values*. On a binary PIV, use `carve` plus
the known-plaintext diff workflow instead. (Pinned by
`test_known_gap_binary_obfuscated_secret_is_missed`.)

Note this does **not** apply to the obfuscated-UTF-16 case above: once decoded,
such a file *is* text, so `ProivPassword=` is recovered with its value and the
credential analysis runs normally.

**Auto-decode needs two property names.** A PIV holding only one recognisable
property (or using names this tool does not know) will not be decoded
automatically — the gate exists so a plausible-looking wrong key is never
applied behind your back. `decode` has no such gate and will still rank it
first; check there before concluding a file is opaque.

**Deobfuscation only models byte-wise transforms.** Repeating XOR and additive
shifts are covered. A stream cipher, a block cipher, compression, or a
position-dependent scheme is not, and no amount of key recovery will touch it.
The diff workflow is the fallback and will tell you which of those you are
looking at.

**Keyword hits are leads, not proof.** `PIV-NET-006` and `PIV-UI-015` in
particular match broadly by design; confirm before anything reaches a report.

**An empty result does not mean the file is clean.** An opaque binary PIV hides
everything from a string scan. When nothing matches, the report now points at
`decode` before it points at the diff workflow, because an obfuscated file is
far more common than a genuinely opaque one.

**The format is proprietary and version-dependent.** Encryption is signalled by
the PIV service/version value (e.g. 501 encrypted vs 500 unencrypted) rather
than by a named field, so version numbers you see may not mean the same thing
across releases. Confirm against the client you are actually testing.

## Tests

```bash
python3 -m unittest test_pivscan        # 98 tests
```

Fixtures are generated at run time by `tests/make_fixtures.py` — nothing
credential-shaped is committed, since a scanner cannot tell a deliberately fake
password from a live one. The fixtures cover a text/INI session, a mixed binary
session with UTF-16LE strings and a single-byte-XOR password, a before/after
pair differing by one known character, and an opaque PIV with nothing in it
(to prove the tool reports "none matched" rather than inventing findings).

Fixtures also include an obfuscated PIV (`PRO4VS` magic + XOR `0x3b` over
UTF-16LE) and one under a repeating two-byte key, which is the case single-byte
recovery alone cannot solve.

Several tests exist only because the bug they guard against appeared at a size
the small fixtures could not reach — scoring that preferred printable garbage
to a correct UTF-16 decode, and key recovery whose cost grew with file size.
Those assert behaviour on a ~100 KB generated file; keep them.

One test asserts a **false negative** on purpose, pinning the binary-secret gap
documented above. If it starts failing, the gap has been fixed — delete the
test and update the Limits section.

## Posture

This tool produces candidates. Everything it reports is evidence about the
client-side artifact and says nothing about what the server enforces, which is
the question that decides whether a client-side flag is a finding at all. The
three tests that matter are printed at the end of every scan:

1. Does flipping one benign byte break loading? If not, there is no integrity
   protection, and every client-side flag in the file becomes an exploitable
   control.
2. For each restrictive flag — does the *server* reject the action? A button
   reappearing in the UI is not the finding. The action succeeding is.
3. Does the client send stored credentials to a redirected host before any user
   interaction? Point a copy at a listener you own and watch.

Use only against files you are authorised to test.
