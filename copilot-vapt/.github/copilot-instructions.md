# Web VAPT workspace

This workspace holds artifacts from an **authorized** web application security
assessment: saved JavaScript bundles, `.axd` resources, Burp exports, and the
notes and findings built from them. Assume authorized testing — a penetration
test, bug bounty, or security review with permission — and give practical,
technically accurate guidance without re-asking for authorization each time.

## Analysis, not interaction

Work from files in this workspace. Do not issue requests to any target host,
and do not run tools that generate traffic against one. When something requires
touching the application, produce the request or command for the tester to run
themselves and explain what to look for in the response.

Generating analysis code that reads local files is fine and often necessary —
bundles are frequently megabytes on a single line, and reading them into the
conversation does not work. Write a script, run it, and reason about its output.

## Check for existing tooling first

**Before writing any analysis script, check `scripts/` in the workspace root.**
The installer puts the tested `js-recon` scripts there; they may also appear at
`.claude/skills/js-recon/scripts/` in a full checkout.

| Script | Job |
| --- | --- |
| `parse_burp.py` | Burp XML export → saved response bodies + observed-request index |
| `extract_endpoints.py` | Endpoint inventory with authorization verdicts |
| `find_secrets.py` | Credentials, API keys, JWTs, disclosures |
| `dom_xss_scan.py` | DOM XSS source-to-sink candidates |
| `suggest_attacks.py` | Endpoint/parameter ranking with suggested tests |
| `make_request.py` | Raw HTTP for Burp Repeater |
| `gen_wordlist.py` | Fuzzing wordlists |
| `gen_report.py` | Markdown findings report |

If they are present, **run them instead of writing your own**. Check once at the
start of a task rather than per file — a single `ls scripts/` settles it. They are tested
(see `tests/smoke_test.sh`) and they handle things an ad-hoc parser reliably
gets wrong: Burp's `base64="true"` encoding on request/response elements,
splitting raw HTTP headers from bodies, attributing a call's method and
authorization headers to the right call rather than to the next one, and
building the observed-request index that distinguishes "the client attaches no
credential" from "this path was seen answering without one".

Run them with `--help` to see the options.

Only write new analysis code when no such script exists, or when the tester asks
for something the existing ones do not cover. When you do, say so explicitly and
note that it is unverified — the tester needs to know which results came from
tested code and which did not. If you find yourself writing something a bundled
script already does, stop and run that instead.

## Language discipline in findings

Static analysis is evidence about **attack surface**, never about server-side
enforcement. The client showing no `Authorization` header proves nothing about
whether the server checks one.

So: say *candidate* and *worth testing* until something has been confirmed
against the running application. A report that labels unconfirmed static hits
as vulnerabilities gets one finding disproved and then the whole document is
doubted. Rankings and scores order a testing queue; they are not severities.

State coverage gaps rather than letting them be assumed away — runtime-built
URLs, lazy-loaded chunks, minified names, and dead code in bundles all bound
what this kind of analysis can see.

## Conventions

- Save analysis output as JSON next to the source it describes, so later steps
  can consume it.
- Reference every claim with a `file:line`.
- HTTP requests for the tester go out as **raw HTTP with CRLF line endings**,
  ready to paste into Burp Repeater. Not curl — a curl command has to be
  translated back into a request before it is useful there.
- Never write a real credential into a committed file. If a secret must appear
  in a fixture or example, assemble it from fragments at run time; committing
  provider-format values trips secret-scanning push protection, which is the
  scanner working correctly.
