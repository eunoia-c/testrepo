# Web VAPT tooling

Static analysis and reconnaissance tooling built for authorised web application
security assessment. Organised by target technology: anything tied to a specific
platform lives in that platform's folder, and anything platform-agnostic sits at
the top level.

## Layout

| Path | What it is | Target |
| --- | --- | --- |
| [`.claude/skills/js-recon/`](.claude/skills/js-recon/) | JavaScript/bundle static analysis skill for Claude Code — endpoints, secrets, DOM XSS, hidden parameters, attack-surface ranking | any web app |
| [`copilot-vapt/`](copilot-vapt/) | The same capability packaged for GitHub Copilot in VS Code, with an installer | any web app |
| [`browser-extensions/dom-param-finder/`](browser-extensions/dom-param-finder/) | Chromium MV3 extension: live-DOM parameter and insertion-point inventory, reveal/enable, and a never-sent comparison against observed traffic | any web app |
| [`burp-extensions/`](burp-extensions/) | Jython extensions for Burp Suite | any web app |
| [`salesforce/apex-scan/`](salesforce/apex-scan/) | Apex static analysis: SOQL injection taint checker, secrets, sharing/CRUD-FLS, crypto, callouts | Salesforce |
| [`servicenow/snowpick/`](servicenow/snowpick/) | ServiceNow exposure scanner — Python port of BishopFox/snowpick | ServiceNow |
| [`proiv/pivscan/`](proiv/pivscan/) | PROIV Client `.PIV` session-file scanner: recovers the XOR obfuscation real PIVs use, then reports stored credentials, cleartext transport, client-side lockdown and UNC paths; plus a known-plaintext diff workflow for mapping the binary format | PROIV |
| [`pega/`](pega/) | Pega Infinity content-discovery wordlist and notes | Pega |

## Quick start

```bash
# Claude Code: the js-recon skill loads automatically in a session on this repo.
#   "analyse this bundle", "find hidden parameters", "build me a wordlist"

# GitHub Copilot in VS Code:
python3 copilot-vapt/install.py /path/to/engagement-workspace --verify

# Salesforce Apex dump:
python3 salesforce/apex-scan/apex_scan.py --input ./apex_dump --out ./results \
    --format json,csv,md --self-test

# Chromium extension (live DOM, post-JavaScript):
#   chrome://extensions -> Developer mode -> Load unpacked
#     -> browser-extensions/dom-param-finder/

# PROIV Client session file:
python3 proiv/pivscan/pivscan.py decode    session.piv       # recover the obfuscation
python3 proiv/pivscan/pivscan.py plaintext session.piv       # whole file, readable
python3 proiv/pivscan/pivscan.py scan      session.piv --json piv.json

# ServiceNow instance (authorised targets only):
python3 servicenow/snowpick/snowpick.py --target devNNNNN.service-now.com \
    --rate 500ms --fingerprint --table-api
```

## Tests

Every tool ships its own suite. All of these should pass before you rely on any
of it in an engagement:

```bash
cd salesforce/apex-scan  && python3 -m unittest test_apex_scan   && cd -   # 80 tests
cd servicenow/snowpick   && python3 -m unittest test_snowpick     && cd -   # 111 tests
cd proiv/pivscan         && python3 -m unittest test_pivscan      && cd -   # 108 tests
bash .claude/skills/js-recon/tests/smoke_test.sh                            # 58 assertions
bash servicenow/snowpick/tests/run_integration.sh                           # TLS mock, no real target
python3 copilot-vapt/sync_scripts.py --check                                # copy-drift guard
cd browser-extensions/dom-param-finder && node test/run_test.js && cd -      # 56 checks, needs playwright
```

`copilot-vapt/scripts/` is a copy of the js-recon skill's scripts, so the folder
can be downloaded and installed on its own. The skill is the source of truth and
`sync_scripts.py --check` fails the smoke test if the two drift.

## Scope and posture

These are analysis tools for authorised testing. Two conventions run through all
of them, and are worth keeping if you extend anything here:

**Static analysis reports candidates, not findings.** It shows what the client
does, which is evidence about attack surface and none at all about server-side
enforcement. Every output says so. A tool that calls an unconfirmed static hit a
vulnerability gets one finding disproved and then the whole report is doubted.

**Coverage gaps are stated, not implied.** Withheld managed-package bodies,
unreadable files, bundles behind authentication — each is counted and named in
the output. A clean result over a corpus that was 60% unreadable is not a clean
result.

`servicenow/snowpick/` is the exception in kind: it sends requests to hosts you
name. Read its README before pointing it anywhere.
