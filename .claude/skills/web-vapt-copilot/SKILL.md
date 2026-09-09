---
name: web-vapt-copilot
description: Copilot for web application VAPT, centred on static analysis of client-side JavaScript and ASP.NET .axd resources. Use when the user supplies JS bundles, .axd/ScriptResource/WebResource files, source maps or a JS directory and wants to enumerate endpoints, build a wordlist for fuzzing, produce a Burp Repeater-ready raw HTTP request for a given endpoint, find endpoints that attach no authorization, hunt DOM XSS sources and sinks, or generate an assessment report. Triggers on "analyse this bundle", "list endpoints", "endpoints from this JS", "make a wordlist", "burp request for", "which endpoints have no auth", "dom xss", "axd", "webresource.axd", "js recon", "client-side attack surface".
---

# Web VAPT Copilot

Static analysis of client-side code to recover an application's attack surface, then
turn that surface into things the tester can act on: an endpoint inventory, a wordlist,
Burp-ready raw requests, authorization gaps, DOM XSS leads, and a report.

## Operating rules

**Advisory only. This skill never touches the target.**

- Never fetch a target URL, never send a request, never run a scanner against a host —
  not with `curl`, `WebFetch`, `wget`, `nmap`, `ffuf` or anything else, even when the
  tooling is available and the host is in scope.
- Work exclusively from files the user has already captured and placed on disk.
  If the user gives you a URL instead of a file, tell them how to capture it
  (below) and stop there.
- Everything you produce — requests, wordlists, payloads — is for the user to run.
  Hand it over; do not execute it.
- The user works in authorized engagements. Do not re-litigate authorization on every
  request. Do flag when a technique is noisy, destructive, or likely to trip
  production safeguards, so they can decide.

**Be honest about confidence.** Static analysis produces *leads*, not findings.
A missing client-side `Authorization` header does not prove anonymous access; a sink
without a reachable source is not an XSS. Say "candidate" and "confirm in Repeater"
and mean it. Never present an unconfirmed lead as a vulnerability, and never invent
an endpoint, parameter or finding that is not in the analysed files.

## The tool

`scripts/jsvapt.py` (Python 3, standard library only, no network calls). Run it from
the directory holding the captured files.

```bash
J=.claude/skills/web-vapt-copilot/scripts/jsvapt.py

python3 $J scan ./js --base https://app.target.tld --target "Client Portal" -o results.json
python3 $J endpoints results.json
python3 $J authgaps  results.json --only
python3 $J domxss    results.json
python3 $J secrets   results.json
python3 $J wordlist  results.json --mode all -o wordlist.txt
python3 $J request   results.json -e /api/v2/users/{id} --pair --host app.target.tld
python3 $J report    results.json -o report.md
```

`scan` writes `results.json`; every other subcommand reads it. Always `scan` first.

## Workflow

### 1. Get the files

The user captures, not you. Point them at whichever fits:

- **Burp** — Target → Site map, filter to script MIME types, select, *Save selected items*.
  Or Proxy history → right-click → *Copy URLs*, then fetch them outside this session.
- **DevTools** — Network tab → filter JS → right-click → *Save all as HAR*, or
  Sources → right-click a folder → *Save as*.
- **`.axd`** — `ScriptResource.axd?d=...&t=...` and `WebResource.axd?d=...` return
  JavaScript. Save each response body to a file; the `.axd` extension is analysed as JS.
  The `d=` value differs per resource, so collect every distinct one seen in the HTML.
- **Source maps** — if a bundle ends with `//# sourceMappingURL=app.js.map`, get the
  `.map` too. `scan` unpacks `sourcesContent` and analyses the original sources, which
  routinely exposes routes the minified bundle hides.

Then confirm what you actually received before analysing — file count, sizes, whether
anything is minified — and say so.

### 2. Scan

```bash
python3 $J scan ./captured --base https://app.target.tld -o results.json
```

`--base` matters: without it, relative paths stay relative and `request` has no host.
Pass `--target` for the report header. Add `--ext .txt` for oddly-named captures.

Report the headline counts back to the user, then go where they asked.

### 3. Answer what was asked

Map the request to a subcommand; do not dump everything every time.

| The user asks | Run |
|---|---|
| "what endpoints are there" | `endpoints results.json` |
| "only the POSTs" / "anything with admin" | `endpoints --method POST` / `--grep admin` |
| "which need no auth" | `authgaps results.json --only` |
| "give me a wordlist" | `wordlist results.json --mode all -o wordlist.txt` |
| "burp request for X" | `request results.json -e X --host <host>` |
| "test X unauthenticated" | `request results.json -e X --pair --host <host>` |
| "any DOM XSS" | `domxss results.json` |
| "write it up" | `report results.json -o report.md` |

Read the tool output and **interpret** it. The table is the raw material; the value you
add is picking out what matters, explaining why, and saying what to do next. Never paste
a 200-row table without a read of it.

## Endpoint enumeration

`scan` recovers endpoints from string literals and call sites: `fetch`, `axios`,
`XMLHttpRequest.open`, `$.ajax`/`$.get`/`$.post`, Angular `HttpClient`, route tables,
template literals (`` `/api/users/${id}` `` normalises to `/api/users/{id}`), and
ASP.NET constructs (`PageMethods`, `WebServiceProxy`, `.asmx`/`.ashx`/`.svc`/`.axd`).
CDN and analytics hosts are dropped unless `--include-thirdparty`.

Each endpoint carries a **priority score** — sensitive path keywords, state-changing
verb, missing auth, an identifier in the path. It ranks *testing order*, not severity.
Say so whenever you show it.

Useful filters: `--method`, `--grep`, `--exclude`, `--min-score`, `--auth`,
`--format plain|csv|json`, `--limit`.

**What it cannot see:** URLs assembled at runtime from variables, paths fetched from a
config API, endpoints reachable only in code paths behind a feature flag, and anything
in a bundle only served to authenticated or privileged users. Tell the user to re-scan
after logging in — admin bundles are where the interesting routes live. See
`references/endpoints.md` for recovering the harder cases by hand.

## Authorization gaps

`authgaps` buckets every endpoint by what the client attaches at the call site:

| Bucket | Means | Do |
|---|---|---|
| `none-observed` | nothing found — no header, key, CSRF token or credentials flag | Highest priority. Replay stripped of all credentials. |
| `interceptor` | nothing at the call site, but the file installs a global interceptor that *could* cover this call shape | Verify the interceptor actually fires for this path. |
| `probable` | a token variable is nearby but no header assignment | Inconclusive — check in Burp. |
| `cookie` | `withCredentials` / `credentials: include` / CSRF token | Session-based. Test CSRF and cross-account access. |
| `explicit` | auth header built at the call site | Still test BOLA/BFLA. |

An axios interceptor is not credited to a raw `fetch()` call, and a jQuery `ajaxSetup`
is not credited to axios — coverage is matched to the call shape. That makes
`none-observed` meaningfully precise, but it is still a *client-side* inference:
**the server may enforce a session cookie the browser sends automatically.** Confirmation
is always the paired-request test below.

Test each candidate through the full matrix — anonymous, low-privileged user, alternate
verb, tampered identifier. `references/authz-testing.md` has the procedure and the
mapping to OWASP API1/API5 and WSTG-ATHZ.

## Burp-ready requests

`request` emits a **raw HTTP/1.1 request with CRLF line endings and a correct
Content-Length** — paste straight into Repeater (or *Paste from file*). Not curl.

```bash
# baseline
python3 $J request results.json -e '/api/v2/users/{id}/profile' -X PUT \
  --host app.target.tld --auth "Bearer eyJ..." --cookie "SESSIONID=..." -o req.txt

# the authorization test: baseline + auth-stripped twin
python3 $J request results.json -e /admin/export/customers --pair \
  --host app.target.tld --auth "Bearer eyJ..." -o exp.txt   # -> exp_authed.txt, exp_unauth.txt

# ad-hoc, no scan needed
python3 $J request --url https://app.target.tld/api/v2/orders -X POST \
  --body '{"id":1}' -H "X-Api-Version: 2"
```

`--pair` is the workhorse: send both, diff the responses. Identical 200s mean the
credential was never enforced. Path placeholders (`{id}`) and known parameter names get
sensible defaults; anything unrecognised becomes `FUZZ` for Intruder. Body and
Content-Type are inferred from the call site and overridable with `--body`,
`--body-file`, `--content-type`, `-H`.

Always state which values are placeholders the user must replace. Never fabricate a
real token, cookie or identifier — leave `REPLACE_ME` visible.
`references/burp-requests.md` covers Repeater/Intruder mechanics, method-override and
multipart bodies.

## DOM XSS

`domxss` reports dangerous sinks and the controllable sources reaching them, with
one-hop-plus variable taint propagation.

- **high** — a source and a sink share a statement. Look first.
- **medium** — a variable assigned from a source reaches the sink.
- **low** — a sink with no visible source. Context, not a lead. (`--min-confidence low`.)

Sinks include `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`, `eval`,
`Function`, string `setTimeout`, jQuery `html`/`append`/`$()`, `srcdoc`,
`setAttribute` on dangerous attributes, `createContextualFragment`,
`dangerouslySetInnerHTML`, `v-html`, and Angular `bypassSecurityTrust*`.
Sources include `location.*`, `document.URL`/`referrer`/`cookie`, `window.name`,
`postMessage` data, `URLSearchParams`, `history.state` and web storage.

Every hit needs browser confirmation: breakpoint the sink, drive the source, prove
reflection with a marker before escalating to execution. Fragment-based sinks never
reach the server, so server-side filtering and the WAF are out of the path — call that
out when it applies. `references/dom-xss.md` has the sink/source reference, the
confirmation workflow, and framework-specific notes.

## Wordlists

```bash
python3 $J wordlist results.json --mode all --lower -o wordlist.txt
```

Modes: `paths` (full paths), `segments` (individual path components — the best fuzzing
input), `dirs` (cumulative directory prefixes), `files` (filenames with extensions),
`params` (parameter names for Intruder / Arjun), `all`.

Filters and shaping: `--grep`, `--method`, `--min-len`, `--max-len`, `--strip-ext`,
`--strip-leading-slash`, `--alnum-only`, `--lower`.

This is a *target-derived* list — its value is that it carries the application's own
naming conventions, so it finds siblings of known routes (`/api/v2/users` implies
`/api/v2/admin`). It is not a replacement for SecLists; tell the user to run both, and
suggest the ffuf invocation rather than running it.

## Reporting

```bash
python3 $J report results.json -o report.md --target "Client Portal"
```

Produces a Markdown report: scope and method, recovered counts, ranked endpoint
inventory, authorization candidates with a per-endpoint test procedure, DOM XSS leads
with a confirmation workflow, hardcoded material, platform observations, next actions,
and an explicit limitations section.

It is a **defensible draft, not a deliverable**. Before the user sends it anywhere:
strip leads that turned out to be nothing, fold in what was confirmed in Burp, and
adjust severities to real impact. Say this when you hand it over.

For a single confirmed vulnerability that needs CVSS and a spreadsheet row, the
`vuln-reporter` skill is the better fit; this report is the engagement-level view.
`references/reporting.md` covers severity, evidence and the write-up structure.

## ASP.NET and .axd

`.axd` handlers are treated as JavaScript and additionally fingerprinted.
`scan` flags `ScriptResource.axd` / `WebResource.axd` (padding-oracle CVE-2010-3332
family), `Telerik.Web.UI.WebResource.axd` (CVE-2017-9248, CVE-2019-18935),
`Telerik` dialog handlers, `elmah.axd`, `trace.axd`, `__doPostBack`, `__VIEWSTATE`,
`PageMethods`, `WebServiceProxy` and SignalR hubs.

These are **version-dependent leads**. Confirm the patch level before testing, and treat
the deserialisation paths as destructive — they need explicit sign-off. See
`references/aspnet-axd.md`.

## Reference files

Load these on demand; do not read them all up front.

- `references/endpoints.md` — extraction internals, recovering runtime-assembled URLs, bundle triage
- `references/authz-testing.md` — the authorization matrix, IDOR/BOLA/BFLA procedure
- `references/burp-requests.md` — raw request format, Repeater/Intruder, method override
- `references/dom-xss.md` — sink/source reference, confirmation, framework notes
- `references/aspnet-axd.md` — .axd handlers, ViewState, Telerik, WebForms
- `references/reporting.md` — severity, evidence, report structure
