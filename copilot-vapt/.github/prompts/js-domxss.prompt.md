---
mode: agent
description: 'Find DOM XSS candidates — attacker-controllable sources reaching HTML or script execution sinks.'
tools: ['codebase', 'search', 'editFiles', 'runCommands']
---

# DOM XSS source-to-sink analysis

Find places where attacker-controllable data can reach a sink that parses HTML
or executes script.

## Rank by evidence, not by hope

- **high** — a source appears inside the sink's own argument
- **medium** — a variable assigned from a source is used in the sink
- **low** — a sink with no visible source in scope (still worth a pass; data can
  arrive from a caller, a framework binding, or a server-rendered value)

Downgrade to *needs review* rather than dropping when a sanitizer appears in the
same expression — `DOMPurify.sanitize()` with a permissive config still bites,
so the config has to be read.

Most static DOM XSS candidates do not reproduce. That is fine: the ones that do
are usually clean, high-severity findings. Never report from analysis alone.

## Sources, by how easily they are controlled

Trivially, via a crafted link: `location.hash`, `location.search`,
`location.href`, `location.pathname`, `document.URL`, `document.documentURI`.

`location.hash` is the classic — the fragment never reaches the server, so
WAFs, request logging and server-side validation are all bypassed by
construction. Prefer it when you have a choice.

With setup: `document.referrer`, `window.name` (survives navigation), and
`postMessage` event data. For `postMessage`, check whether the handler validates
`event.origin` at all — a handler that trusts any origin and routes `event.data`
into a sink is cross-origin XSS, and it is common in embedded widgets and
payment iframes.

Needing a prior foothold: `localStorage`, `sessionStorage`, `document.cookie`,
`history.state`. These are how a stored XSS persists across sessions.

## Sinks

**HTML parsing** — `innerHTML`, `outerHTML`, `insertAdjacentHTML`,
`document.write`/`writeln`, jQuery `.html()` `.append()` `.prepend()` `.after()`
`.before()` `.replaceWith()`, `Range.createContextualFragment`,
`DOMParser.parseFromString`, `iframe.srcdoc`.

Note that `innerHTML` will not execute a bare `<script>` — which is why
`<img src=x onerror=...>` and `<svg onload=...>` are the standard payloads.

**Script execution** — `eval`, `new Function`, `setTimeout`/`setInterval` with a
string, `$.globalEval`, `importScripts`. No markup filtering to worry about.

**Navigation** — `location` assignment, `location.assign`/`replace`,
`window.open`, `a.href`, `form.action`. Open redirect, or XSS if `javascript:`
survives.

**Resource loading** — `script.src`, `link.href`, `object.data`,
`setAttribute('src'|'href'|'formaction')`.

**Framework trust escapes** — `dangerouslySetInnerHTML` (React), `v-html` (Vue),
`$sce.trustAsHtml` (AngularJS), `bypassSecurityTrust*` (Angular). High signal:
a developer deliberately opted out of the framework's escaping, so trace every
one to its input.

## Sinks that mislead

- `.src =` with a hardcoded literal — only interesting if attacker-influenced.
- `$(x)` — jQuery treats a leading `<` as HTML, so `$(userInput)` is a real
  sink, but `$(element)` and `$('#' + id)` mostly are not.
- `.append(document.createElement('div'))` is safe; `.append('<div>'+x+'</div>')`
  is not.

## Confirming — this is the actual work

1. Trace back from the sink to an input you can influence.
2. **Prove reachability with a harmless unique marker first.** If the marker
   never lands in the DOM, the path is dead and no payload is needed. This one
   habit saves more time than anything else here.
3. Then escalate: `<img src=x onerror=alert(document.domain)>` for HTML sinks.
   Use `document.domain` rather than `alert(1)` — it evidences the origin in the
   screenshot, which reviewers ask for.
4. Record the exact URL or steps, and verify it reproduces from a cold session.

## Severity inputs

Capture these, because they are what separates a medium from a high:

- Pre-auth or authenticated-only?
- Delivered by URL alone, or does it need stored state another user must view?
- Is the session cookie `HttpOnly`? Is a bearer token readable in web storage?
- Is there a CSP, and does it meaningfully constrain the payload?
- Whose session executes it — same privilege, or does it cross a role boundary?

A token in `localStorage` plus a confirmed XSS is session theft. State that
explicitly rather than leaving it as two separate observations.

## Output

Write `domxss.json` with confidence, sink, source, `file:line` and snippet.
Present the high and medium rows in chat with the reaching input for each, and
say plainly which ones you would try to confirm first.
