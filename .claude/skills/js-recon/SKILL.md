---
name: js-recon
description: Static analysis copilot for web VAPT — analyses a single JavaScript file in depth (what it is, which libraries and versions it ships, and what matters in it) or mines whole corpora of JavaScript, .axd resources, bundles and Burp exports for HTTP endpoints, hardcoded secrets and API keys, and interesting parameters; builds fuzzing wordlists; generates Burp Repeater-ready raw HTTP requests (never curl); flags endpoints with no authorization evidence; finds DOM XSS source-to-sink paths; ranks the attack surface with concrete suggested tests per endpoint and parameter; and writes it all up as a Markdown findings report. Use this whenever someone is doing a web application penetration test, security assessment, bug bounty or code review and mentions JavaScript files, JS bundles, .axd / ScriptResource.axd / WebResource.axd, minified scripts, a Burp sitemap or proxy export, endpoint discovery or enumeration, hidden or undocumented API routes, building a wordlist for ffuf/feroxbuster/dirsearch, hardcoded credentials, leaked API keys or tokens in frontend code, JWTs, source maps, interesting or dangerous parameters, what to attack or where to start on a target, testing for missing authorization or broken access control, IDOR, SSRF, mass assignment, DOM XSS or dangerous sinks like innerHTML and eval, or asks for a request they can paste into Repeater. Trigger on single-file requests too — "do static analysis on this js file", "what can you say about this script", "what is this bundle", "is this library version vulnerable", "review this .js" — and on whole folders, or when they simply hand over .js files and ask what is interesting in there, even if they never say the words static analysis.
---

# JS Recon — static analysis copilot for web VAPT

Client-side code is the most honest map of an application's server-side surface
that you can read without touching the target. Bundles name endpoints the UI
never renders, routes gated only by a hidden menu item, and admin calls shipped
to every user. This skill turns that code into a tested attack surface.

## Operating principle: analysis, not interaction

Everything here reads files that are already on disk. Nothing in this skill
contacts a target, and it should stay that way — the user supplies the JS,
either saved manually or exported from Burp, and receives artifacts they run
themselves. If asked to fetch JS from a live host, say that the skill works on
supplied files and let the user decide whether to fetch it; do not quietly turn
an analysis request into traffic against someone's application.

Assume authorized testing. Do not re-litigate authorization each time a
capability comes up; the useful contribution is accurate technique.

## The pipeline

Five scripts in `scripts/`, each doing one job. Run them in this order — later
stages consume earlier output.

```
one file ─────> analyse_file.py ──> a briefing you read

Burp export ──> parse_burp.py ──> burp_js/ + burp_index.json
                                        │
saved .js/.axd files ───────────────────┴──> extract_endpoints.py ──> endpoints.json
                                                                          │
                        ┌──────────────────┬──────────────────┬───────────┤
                        ▼                  ▼                  ▼           │
                gen_wordlist.py     make_request.py    suggest_attacks.py  │
                                                               │          │
JS/HTML files ──> dom_xss_scan.py ──> domxss.json ─────────────┼──────────┤
                                                               │          ▼
JS/config files ─> find_secrets.py ──> secrets.json ───────────┴──> gen_report.py
```

All scripts are stdlib-only Python 3 and take `--help`.

### 1. Ingest a Burp export (when there is one)

```bash
python3 scripts/parse_burp.py export.xml --out-dir burp_js --index burp_index.json
```

Burp exports are worth more than loose files for two reasons: they contain
bundles served *behind authentication* that you cannot fetch anonymously, and
they record real request headers. That header data is what later lets you say
"this path was observed answering without a credential" rather than merely
"the client didn't attach one" — a much stronger claim.

Then run the extractor over `burp_js/` as well as any manually saved files.

### 2. Extract endpoints

```bash
python3 scripts/extract_endpoints.py ./js ./burp_js --out endpoints.json
```

Recognises `fetch`, `XMLHttpRequest`, jQuery AJAX, axios, Angular `HttpClient`,
`sendBeacon`, WebSocket/EventSource, ASP.NET `WebServiceProxy`/`PageMethods`/
`__doPostBack`, plus endpoint-shaped string literals with no call site.

Each endpoint carries an **auth verdict** describing only what the client shows:

| Verdict | Meaning |
| --- | --- |
| `explicit_no_credentials` | Call site sets `credentials: 'omit'` — test first |
| `no_auth_indicator` | Nothing authorization-shaped anywhere near the call |
| `unknown_no_callsite` | Bare string literal; no call to judge |
| `csrf_only` | CSRF token but no authentication header |
| `no_callsite_auth_global_present` | Bare call, but the bundle installs auth globally |
| `cookie_auth_likely` | Sends cookies; probably session-authenticated |
| `auth_at_callsite` | Authorization header set right there |

These rank testing effort. They are **not** findings — the server may enforce
authorization perfectly regardless of what the client sends. Keep that
distinction in every summary you write; it is the difference between a report
that survives review and one that does not.

`--calls-only` drops bare string literals when the inventory is noisy.

### 3. Wordlists on request

```bash
python3 scripts/gen_wordlist.py endpoints.json --mode paths   > paths.txt
python3 scripts/gen_wordlist.py endpoints.json --mode dirs    > dirs.txt
python3 scripts/gen_wordlist.py endpoints.json --mode params  > params.txt
```

`--mode` is `paths` (full paths, `{param}` → `FUZZ`), `dirs` (every path prefix,
for directory brute-forcing), `params` (parameter names for mining), `files`
(last segments), or `all`. Leading slashes are stripped by default because
`ffuf -u https://host/FUZZ` wants them off; `--leading-slash` keeps them.
Filter with `--verdict` / `--method` to fuzz just the interesting subset.

### 4. Burp-ready requests

```bash
python3 scripts/make_request.py endpoints.json --list
python3 scripts/make_request.py endpoints.json --id e004 --burp-index burp_index.json --both
python3 scripts/make_request.py endpoints.json --verdict no_auth_indicator --both --out-dir reqs/
```

Emits raw HTTP with CRLF line endings and a correct `Content-Length`, ready to
paste into Repeater. **Never emit curl for this** — the user asked for requests
they can drop straight into Burp, and a curl command forces them to translate.

`--both` is the workhorse for authorization testing: it prints the request twice,
once with credentials and once with `Authorization`, `Cookie` and API-key headers
stripped. Comparing those two responses is the actual test; a materially
identical response without credentials is broken access control.

With `--burp-index`, headers come from a real captured request to that path, so
the request looks like application traffic instead of a synthetic guess. See
`references/burp-requests.md` for the details that trip people up.

### 5. DOM XSS

```bash
python3 scripts/dom_xss_scan.py ./js --out domxss.json
```

Ranks by evidence: `high` = a source inside the sink's own argument, `medium` =
a variable assigned from a source reaches the sink, `low` = a sink with no
visible source. Sanitizer-adjacent hits are marked for review rather than
dropped, because `DOMPurify.sanitize()` with the wrong config still bites.

Regex cannot do interprocedural taint analysis. Treat every hit as a lead to
confirm in a browser — `references/dom-xss.md` covers how to do that and which
sinks mislead.

### 6. Secrets and API keys

```bash
python3 scripts/find_secrets.py ./js ./burp_js --out secrets.json
python3 scripts/find_secrets.py ./js --out secrets.json --redact   # for shared reports
```

Tiered by what the pattern itself proves — `confirmed` is a provider-specific
format that cannot plausibly be anything else (`AKIA…`, `ghp_…`, `sk_live_…`, a
PEM block), `probable` is a credential-shaped assignment whose value passes an
entropy check and is not a placeholder, `possible` is weaker, `info` covers
disclosures that are not credentials.

The tiering exists because secret scanners fail by crying wolf: a report with
300 hits, nearly all placeholders and minified identifiers, gets skimmed and
binned. Placeholders (`YOUR_API_KEY_HERE`, `${process.env.KEY}`, `changeme`) and
low-entropy noise are filtered out by design.

Worth knowing about the `info` tier (shown with `--min-tier info`):

- **JWTs are decoded** — header and payload, no signature verification. The
  claims usually matter more than the token: `alg=none`, an HMAC algorithm
  inviting key-confusion testing, expiry, and any role or scope claim.
- **Source map references** — if the `.map` is actually served, it reconstructs
  original sources with comments and real names. Fetch it and re-run the
  extractor over the result; it is the single biggest coverage win available.
- **Internal hostnames and private IPs** — targets for the SSRF testing that
  `suggest_attacks.py` proposes.

Use `--redact` whenever output will reach anyone who should not hold live
credentials. And if a confirmed credential turns out to be live, that is not a
routine report row — tell the client when you find it.

### 7. Interesting parameters and suggested attacks

```bash
python3 scripts/suggest_attacks.py endpoints.json --secrets secrets.json --out attacks.json
```

Ranks endpoints by testing value and proposes concrete tests. Three signal
sources: parameter names matched against attack classes (IDOR, SSRF, traversal,
SQLi, mass assignment, SSTI, JSONP, debug flags, business-logic values, and
more), path segments (`admin`, `debug`, `swagger`, `graphql`, auth flows,
export), and request shape (destructive methods, WebSocket handshakes, ASMX
proxies, path-embedded object references).

Each suggestion carries *why the name warrants the test* and *how to run it*, so
the output is a working queue rather than a checklist of attack names.

Two design points worth preserving if you edit the catalog:

- **The score orders a queue; it is not a severity.** Say so when presenting
  results. It reflects how much a name and shape justify a look, nothing more.
- **`legacy-version` only fires when the inventory actually contains more than
  one API version.** Flagging every `/v1/` path is noise; flagging a `/v1/` that
  sits beside a `/v2/` is a real lead, because the older route keeps the
  authorization model it shipped with.

Depth for each class lives in `references/attack-playbook.md`. The one habit
that matters most is in there too: **confirm a parameter reaches server-side
behaviour before spending payloads on it.** Change it to something benign and
different, and look for any response change at all. Client bundles are full of
dead parameters.

### 8. One file, in depth

```bash
python3 scripts/analyse_file.py path/to/app.bundle.js
python3 scripts/analyse_file.py app.js --json --out app-analysis.json
```

For "here is one file, what can you tell me about it" — a different question
from "what is the whole attack surface", and it deserves a different answer.
Prints a briefing rather than JSON: what the file *is* first, then libraries and
versions, endpoints, secrets, DOM XSS, and a **What stands out** section.

Two things it adds over running the other scripts separately:

**Fingerprinting.** Bundler, framework, and third-party library versions,
checked against a short list of well-known advisories (jQuery below 3.5,
lodash below 4.17.21, Moment below 2.29.4, AngularJS 1.x, and a few more). On a
vendor bundle this is often *the* finding, because an outdated library with a
published CVE is concrete in a way that "this path showed no Authorization
header" is not. The advisory list is deliberately short — a stale or wrong entry
costs more credibility than a missing one. Always confirm the version actually
loaded at runtime, since bundles frequently ship a version string that a shim
then replaces.

**Cross-cutting observations.** A token in web storage is unremarkable; an
`innerHTML` sink is unremarkable; both in one file is a session-theft chain.
Admin paths in a bundle served to everyone, endpoints spanning two API versions,
a referenced source map — these joins are the whole reason to look at a file as
a unit, and they are what someone actually wants when they hand you one file.

Reach for this when the input is one file, when someone asks what a file is or
does, or as a first look before deciding whether the full pipeline is warranted.
Use the pipeline instead when the input is a directory or a Burp export, since
the corpus-wide inventory and ranking are what matter there.

### 9. The report

```bash
python3 scripts/gen_report.py --endpoints endpoints.json --domxss domxss.json \
    --secrets secrets.json --attacks attacks.json --burp-index burp_index.json \
    --target "Client name — app" --out report.md
```

Produces a Markdown report: summary, credentials and disclosures, authorization
candidates cross-referenced against observed Burp traffic, the prioritised
attack surface with per-endpoint suggested tests, parameters worth attacking,
DOM XSS candidates, ASP.NET-specific surface, full inventory, and an explicit
limitations section. Every row carries a `file:line`.

Optional inputs can be omitted and sections renumber themselves. Credentials
come first because a live key outranks everything else in the document.

## Working with the output

The scripts produce inventory; the judgment is yours. What actually earns
attention:

**Endpoints the user's role should not know about.** The single highest-value
move is to analyse the bundle served to a *low-privilege* account. Anything it
names that the account's UI never exposes is an authorization test case with a
built-in privilege boundary to cross. Say this when someone hands over a bundle
without mentioning which account it came from — it changes what the results mean.

**Version and path structure over individual URLs.** `/api/v1/` alongside
`/api/v3/` suggests deprecated versions still routed. Admin path segments in a
non-admin bundle are worth more than a long list of ordinary CRUD routes.

**Parameter names as a hypothesis source.** `params` mode output feeds mass
assignment, IDOR and hidden-flag testing — parameters the UI never sends but the
server may still bind.

**Where auth is attached.** A bundle-wide interceptor means one place gets it
wrong for everything; per-call headers mean each call site can be missed
individually. That shapes how broadly to test.

**A token in `localStorage` next to an XSS finding.** Those two facts together
are session theft, and worth stating explicitly in the report rather than
leaving as two separate rows.

**One file versus a corpus.** If someone hands you a single file and asks what
it is, `analyse_file.py` answers that directly and reads in under a minute. The
JSON pipeline is for corpora, where the value is in the inventory and the
ranking rather than in any one file.

**Cross-referencing the separate outputs.** The individual artifacts are less
than their combination, and connecting them is judgement the scripts cannot do:
an internal hostname from the secrets scan is the target for an SSRF candidate
from the attack ranking; a source map means re-running everything over recovered
sources; a JWT with `alg=none` beside an endpoint showing `no_auth_indicator` is
a specific, testable chain rather than two unrelated rows. Say these out loud
when summarising — it is the main thing a person gets from you over reading the
JSON.

## Framework specifics

- **ASP.NET / WebForms / `.axd`** — read `references/aspnet.md`. Covers
  `ScriptResource.axd` and `WebResource.axd`, ViewState, postback forgery,
  ASMX/WCF proxies, and what the `d` parameter is.
- **DOM XSS sinks and confirmation** — read `references/dom-xss.md`.
- **Raw request construction and Repeater workflow** — read
  `references/burp-requests.md`.
- **Parameter classes, path signals and how to test each** — read
  `references/attack-playbook.md`.

Read a reference when the target actually involves it; they are detail, not
prerequisites.

## Reporting honestly

Static analysis is evidence about surface, not about enforcement. Two habits keep
the output trustworthy:

Say *candidate* until something is confirmed against the running application.
A report that calls unconfirmed static hits "vulnerabilities" gets one finding
disproved and then the whole document is doubted.

State the coverage gaps rather than letting them be assumed away. Runtime-built
URLs, lazy-loaded chunks, minified names and dead code in bundles all bound what
this can see. `gen_report.py` writes a limitations section for exactly this
reason — keep it, and add anything specific to the engagement.
