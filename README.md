# web-vapt-copilot

A Claude Code skill: a copilot for web application VAPT, centred on **static analysis of
client-side JavaScript and ASP.NET `.axd` resources**.

It recovers an application's attack surface from captured bundles and turns it into
things a tester can act on:

- **Endpoint inventory** — from `fetch`, `axios`, `XMLHttpRequest`, jQuery, Angular
  `HttpClient`, route tables, template literals and ASP.NET constructs
- **Authorization gaps** — endpoints whose call sites attach no credential material,
  bucketed by how confident that inference is
- **Burp-ready raw HTTP requests** — CRLF, correct `Content-Length`, paste straight into
  Repeater. Not curl. `--pair` emits the baseline and its auth-stripped twin for
  authorization testing
- **Wordlists** — target-derived paths, segments, directories, filenames and parameter
  names for ffuf / Burp Intruder
- **DOM XSS leads** — source-to-sink matching with variable taint propagation
- **Reports** — a Markdown assessment draft with an explicit limitations section

## Install

Copy the skill into a project or into your user skills directory:

```bash
cp -r .claude/skills/web-vapt-copilot ~/.claude/skills/
```

Claude invokes it automatically when you bring it JS bundles, or explicitly with
`/web-vapt-copilot`.

## Standalone use

The engine works on its own — Python 3, standard library only:

```bash
J=.claude/skills/web-vapt-copilot/scripts/jsvapt.py

python3 $J scan ./captured-js --base https://app.target.tld -o results.json
python3 $J endpoints results.json
python3 $J authgaps  results.json --only
python3 $J domxss    results.json
python3 $J wordlist  results.json --mode all -o wordlist.txt
python3 $J request   results.json -e /api/v2/orders --pair --host app.target.tld
python3 $J report    results.json -o report.md
```

## Scope and intent

For authorized security testing: penetration tests, vulnerability assessments, bug
bounty programmes with a published scope, CTFs, and lab work.

**The tooling never touches the target.** It performs no network I/O of any kind. It
reads files you captured and prints requests for you to send. Confirmation happens in
your proxy, under your authorization — which is also why the output is deliberately
phrased as *leads*, not findings. A missing client-side `Authorization` header does not
prove anonymous access, and a sink without a reachable source is not an XSS.
