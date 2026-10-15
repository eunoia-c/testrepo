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

### Seeing the whole file

`plaintext` prints the entire deobfuscated file, field by field, with offsets
that still address the original:

```
 Transform : xor:3b (auto-detected)
 Magic     : 'PRO4VS' (plaintext in the original)

  00000000  [magic   ] PRO4VS
  00000006  [utf-16le] CustomToolBar
  00000044  [utf-16le] HostName=proiv-app03.corp.internal
  0000009a  [utf-16le] SessionType=Telnet
  000000ee  [utf-16le] ProivPassword=...
  00000122  [utf-16le] RememberUsernameAndPassword=1
  0000015e  [utf-16le] PromptForSecurity=0
  00000186  [utf-16le] ActivateUserRuntimeInterface=1
  000001c4  [utf-16le] ApplicationDefinitions=\\fileserver02\proiv$\appdef.ini
```

Adjacent runs are kept separate rather than glued together — in a PIV those
boundaries are the field boundaries, and a string-level view has no other
structure to offer. `--hex` gives an annotated hexdump of the decoded bytes
instead, with the UTF-16 text visible as every other byte in the ASCII column.
`scan --show-plaintext` appends the same listing to the end of a normal report,
which is what you want when the dump is going into an appendix.

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
python3 pivscan.py plaintext session.piv [--hex] [--spec xor:3b] [--out dump.txt]
python3 pivscan.py scan    session.piv --show-plaintext
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

## The SSH-tunnel deployment

A common architecture: a helper executable establishes an SSH session to the
application server and sets up a **local port forward**, after which the client
speaks the PROIV protocol to `127.0.0.1:<port>` and the application login
appears. Two things follow, and both are easy to score wrongly.

### The credentials in the PIV are SSH credentials, which is worse

The instinct is that this is *less* of a problem than an application password,
because an application login still appears once the tunnel is up. That reads
the trust boundary backwards. The application login and the SSH login
authenticate to **different things**: one to the application, one to the host
operating system. Recovering SSH credentials from a PIV gives a shell on the
application server and — unless forwarding is restricted — the ability to
forward arbitrary ports to anything that server can reach. The application
login does not contain any of that, so it is not a mitigation.

Three questions set the severity, and they are worth answering before scoring
it (`PIV-CRED-018` prints them):

1. Does the credential yield an **interactive shell**?
2. Can you `ssh -L` to a host **other** than the application server — i.e. is
   it a network pivot?
3. Is the account **shared** across users, or per person?

A `nologin` account with a forced command and `permitopen` scoped to the
application port is a far smaller finding than a general-purpose login. A
shared service account with a shell is about as large as findings get.

Also check whether the private key path *and* its passphrase are both in the
PIV — a passphrase-protected key stops being passphrase-protected when the
passphrase ships beside it.

### Cleartext on the loopback hop: yes, PROIV can encrypt it

The tunnel protects the hop between hosts. The hop from the client to the local
forwarder is whatever the application speaks, so a loopback capture shows the
PROIV protocol in the clear — including the application login that follows.

**PROIV does support encrypting it**, in up to three separate places depending
on client and version:

| Where | Setting |
| --- | --- |
| Windows thick client | **Use Secure Socket:SSL** check box in Connection Settings, with the SSL port — note an SSL connection may use a different port than the standard Telnet port ([Connection Settings](https://support.proiv.com/V8_Help/openclientadmin/proiv_client_and_open_client_-_connection_settings.htm)) |
| Open Client / client services | **Connection Protocol = Https**, described as HTTP "where the data is encrypted using the Secure Socket Layer (SSL)", default port 8804 ([Open Client Service Settings](https://support.proiv.com/V8_Help/openclientadmin/open_client_service_settings.htm)) |
| Service definition | **Service Encryption**, "whether the service will be encrypted (PIV version 501) or unencrypted (PIV version 500)" ([PROIV Service Settings](https://support.proiv.com/V8_Help/clientadministration/proiv_service_settings.htm)) |

The transport underneath is separately selectable — WebSocket (the default in
current versions) or HTTP, for both Lite Client and Open Client
([Open Client Transport Protocol](https://support.proiv.com/V14_Help/desktop/openclientadmin/open_client_transport_protocol.htm)).

The part that makes this work through a tunnel: **TLS terminates at the real
server, not at the forwarder.** SSH local forwarding is transparent TCP, so an
encrypted PROIV session stays encrypted across the loopback hop as well —
enabling it is exactly what makes the capture useless, with no change to the
tunnel.

So the finding is not "the protocol has no encryption available". It is "the
available encryption is switched off", which is a much stronger sentence in a
report because the remediation is a check box. `PIV-NET-017` flags the relevant
fields; read the decoded PIV for the service/version value and any
secure-socket field with `pivscan plaintext`.

Severity depends almost entirely on **how many identities share the
workstation**. On a single-user machine, capturing your own loopback needs
local administrator rights and a loopback-capable capture driver, so on its own
it sits near informational. On a multi-user host — Citrix or RDS, which is
where thick clients like this usually live — the plaintext is exposed to every
other session's administrator and to anything running locally, and the
credentials of every user on that host cross it.

### The stronger finding on that host

While looking at the loopback hop, check what the forwarder's listening socket
actually permits. A local forward is **an unauthenticated entrance to the
tunnel**: any process that can connect to it reaches the application server
without presenting an SSH credential at all. So:

```
netstat -ano | findstr LISTENING
```

- Bound to `127.0.0.1:<port>` — reachable by every process and every user on
  that host. On a shared host that is a cross-user path into the backend.
- Bound to `0.0.0.0:<port>` — reachable from the **network**. Anyone who can
  route to the workstation gets a tunnel into the application server, and that
  is a far more serious finding than the capture.

That question is usually worth more than the packet capture, and it is answered
by one command.

## Can the vendor fix this? Not by encrypting the file

Worth settling before you write the recommendation, because the obvious advice
("encrypt it properly") is wrong.

**No file format can be made non-recoverable while the client decrypts it
unattended.** If the PROIV Client opens a PIV on double-click with no secret
from the user, then every input the decryption needs is already on the
workstation — so anyone holding the client holds the key. Replacing XOR `0x3b`
with AES-256 changes the work from "one byte" to "find the key in the binary",
which is a speed bump, not a control. This is Kerckhoffs's principle, and it is
why the finding's recommendation has to be *remove the secret*, not *strengthen
the cipher*.

### The setting that sounds like the fix, and is not

PROIV's **Service Encryption** option decides "whether the service will be
encrypted (PIV version 501) or unencrypted (PIV version 500)"
([PROIV Service Settings](https://support.proiv.com/V8_Help/clientadministration/proiv_service_settings.htm)).
That is **transport** encryption for the service connection. It does nothing to
protect the contents of the PIV file at rest. Expect to have to say this
explicitly: a client who has ticked Service Encryption may believe the session
file is covered, and a `plaintext` dump of a version 501 PIV is the fastest way
to show that it is not.

Equally, PROIV's own wording for session password protection is that "the
password is encrypted and stored in the PIV"
([General Properties](https://support.proiv.com/V8_Help/openclientadmin/proiv_client_and_open_client_-_general_properties.htm)).
Vendor documentation saying "encrypted and stored" is the pattern `PIV-CRYPT-012`
exists to flag — it is a statement about storage, not about who can reverse it.

### What actually fixes it, in order of effect

1. **Store no credential.** Enable **Prompt for Security**, which makes the
   client "prompt the user for user name and password at connection", and
   disable **Remember Username and Password**
   ([Session Connection Settings](https://support.proiv.com/V13_Help/desktop/windowsclient/session_connection_settings.htm)).
   Then the obfuscation is irrelevant because there is nothing in the file to
   recover. This is the only remediation that removes the finding rather than
   raising its cost. Enforce it centrally — PROIV's *Remove Remember Password
   Checkbox* setting stops a user re-enabling it.
2. **Keep credential-bearing PIVs out of distribution entirely.** PROIV reads
   session values "first from the PIV file, if no PIV file has yet been loaded,
   the values are read from the current users registry hive"
   ([Session Properties](https://support.proiv.com/V8_Help/windowsclient/session_properties.htm)).
   So sessions can be provisioned per user without shipping a file that travels
   with the roaming profile, the backup and the helpdesk ticket. The registry is
   not encrypted either — the gain is per-user ACLs and a much smaller blast
   radius, not secrecy.
3. **Move to key-based authentication.** The Open Client supports SSH with
   either password or key authentication, where key mode takes a private key
   file path plus an optional passphrase, and supports strict host key checking
   against `known_hosts`
   ([Open Client SSH Connections](https://support.proiv.com/V14_Help/desktop/client_services/open_client_ssh_connections.htm)).
   A passphrase-protected key is not a reusable password, strict host key
   checking blunts the redirection finding, and it replaces the Telnet
   session type that leaks the credential on every launch.
4. **Bind any stored secret to the user and machine.** If credentials must
   persist for unattended launch, the protection has to use a key the attacker
   does not get by copying the file: DPAPI at user scope with an application
   entropy value, or a hardware-backed store. Copying the PIV to another
   account or machine then yields nothing. PROIV does not appear to offer this,
   so it is a vendor change request rather than a configuration change — worth
   raising as one.
5. **Sign the file.** This does not stop decryption and is not a fix for the
   credential finding, but it is the fix for `PIV-TAMPER-007`: without a
   signature or MAC that the client enforces, an attacker-supplied `.piv`
   controls where the client connects. Pin permitted endpoints somewhere the
   user cannot write (HKLM policy) and validate before connecting.

### What to write in the report

Treat the obfuscation as an **aggravating detail of the stored-credential
finding, not a finding of its own**. "The password is XOR-obfuscated with a
single byte and recovered in milliseconds" is the sentence that makes the
severity stick; "they should use stronger encryption" is a recommendation that
cannot be implemented correctly and invites a fix that changes nothing. The
recoverability is not a weakness of their cipher choice — it is inherent to
storing a secret that the client must use on its own.

### Research limits

The citations above are from PROIV's own help site, reached through search
result extracts; direct access to `support.proiv.com` was blocked from the
environment this was written in, so the pages were not read in full. The
mapping of 501/500 to service encryption, the "encrypted and stored in the PIV"
wording, the PIV-then-registry precedence and the SSH authentication modes are
all quoted from those extracts. **No PROIV documentation was found that
describes the PIV file's own obfuscation scheme** — unsurprising, since the
format is proprietary, and consistent with it being obfuscation rather than
documented cryptography. Verify against the version of the client you are
testing before quoting any of it to a client.

## Rules

18 rules, keyword- and structure-driven rather than offset-driven so they work
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
| `PIV-NET-017` | Transport encryption not enabled on the client connection | HIGH |
| `PIV-CRED-018` | SSH credentials in session file (OS access, not application access) | CRITICAL |
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
- **`PIV-CRED-018`** — SSH credentials are host access; the application login
  that follows the tunnel authenticates something else and does not contain it.
- **`PIV-NET-017`** — an SSH tunnel protects one hop, not the client-to-
  forwarder hop on the workstation.

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
python3 -m unittest test_pivscan        # 116 tests
```

Fixtures are generated at run time by `tests/make_fixtures.py` — nothing
credential-shaped is committed, since a scanner cannot tell a deliberately fake
password from a live one. The fixtures cover a text/INI session, a mixed binary
session with UTF-16LE strings and a single-byte-XOR password, a before/after
pair differing by one known character, and an opaque PIV with nothing in it
(to prove the tool reports "none matched" rather than inventing findings).

Fixtures also include an SSH-tunnel session (SSH credentials, a private key
path with its passphrase beside it, strict host key checking off, no transport
encryption) and an obfuscated PIV (`PRO4VS` magic + XOR `0x3b` over
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
