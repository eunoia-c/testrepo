---
name: js-recon
description: Static analysis copilot for web VAPT — mines JavaScript, .axd resources, bundles and Burp exports for HTTP endpoints, builds fuzzing wordlists, generates Burp Repeater-ready raw HTTP requests (never curl), flags endpoints with no authorization evidence, and finds DOM XSS source-to-sink paths, then writes it all up as a Markdown findings report. Use this whenever someone is doing a web application penetration test, security assessment, bug bounty or code review and mentions JavaScript files, JS bundles, .axd / ScriptResource.axd / WebResource.axd, minified scripts, a Burp sitemap or proxy export, endpoint discovery or enumeration, hidden or undocumented API routes, building a wordlist for ffuf/feroxbuster/dirsearch, testing for missing authorization or broken access control, IDOR hunting, DOM XSS or dangerous sinks like innerHTML and eval, or asks for a request they can paste into Repeater. Also use it when they simply hand over a folder of .js files and ask what is interesting in there, or ask to "look at this bundle", even if they never say the words static analysis.
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
Burp export ──> parse_burp.py ──> burp_js/ + burp_index.json
                                        │
saved .js/.axd files ───────────────────┴──> extract_endpoints.py ──> endpoints.json
                                                                          │
                                    ┌─────────────────────────────────────┤
                                    ▼                     ▼               ▼
                            gen_wordlist.py       make_request.py    gen_report.py
                                                                          ▲
JS/HTML files ──────────> dom_xss_scan.py ──> domxss.json ────────────────┘
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

### 6. The report

```bash
python3 scripts/gen_report.py --endpoints endpoints.json --domxss domxss.json \
    --burp-index burp_index.json --target "Client name — app" --out report.md
```

Produces a Markdown report: summary, authorization candidates cross-referenced
against observed Burp traffic, DOM XSS candidates, ASP.NET-specific surface,
full inventory, and an explicit limitations section. Every row carries a
`file:line`.

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

## Framework specifics

- **ASP.NET / WebForms / `.axd`** — read `references/aspnet.md`. Covers
  `ScriptResource.axd` and `WebResource.axd`, ViewState, postback forgery,
  ASMX/WCF proxies, and what the `d` parameter is.
- **DOM XSS sinks and confirmation** — read `references/dom-xss.md`.
- **Raw request construction and Repeater workflow** — read
  `references/burp-requests.md`.

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
