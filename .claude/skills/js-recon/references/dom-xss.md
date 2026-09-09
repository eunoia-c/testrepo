# DOM XSS: sinks, sources and confirmation

Reference for interpreting `dom_xss_scan.py` output and confirming what it finds.

## Why confirmation is the whole job

The scanner reports where attacker-controllable data *could* reach a dangerous
sink. It cannot tell you whether the code path executes, whether a framework
escapes the value downstream, or whether the server rejects the input first.
Roughly speaking, most static DOM XSS candidates do not reproduce — which is
fine, because the ones that do are usually clean, high-severity findings.

What that means in practice: never report from scan output alone. Reproduce it
in a browser, capture the popped payload, then write it up.

## Sources, ranked by controllability

**Directly attacker-controlled, no interaction beyond a link:**
`location.hash`, `location.search`, `location.href`, `location.pathname`,
`document.URL`, `document.documentURI`

`location.hash` is the classic because the fragment never reaches the server —
so server-side WAFs, request logging and input validation are all bypassed by
construction. If you have a choice of source, start there.

**Controlled with a little more setup:**
`document.referrer` (attacker controls it by linking from their own page),
`window.name` (survives navigation — set it on your page, then navigate the
victim to the target), `postMessage` event data (requires a permissive or
missing origin check).

**Controlled only via a prior foothold:**
`localStorage` / `sessionStorage`, `document.cookie`, `history.state`. These
need an existing injection point to write to them — but they are exactly how a
stored XSS becomes persistent across sessions, so they matter when chaining.

`postMessage` deserves its own pass: check whether the handler validates
`event.origin` at all. A handler that trusts any origin and routes `event.data`
into a sink is cross-origin XSS, and it is common in embedded widgets, chat
components and payment iframes.

## Sinks, by what they actually do

**HTML parsing sinks** — the payload becomes markup:
`innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`/`writeln`,
jQuery `.html()`, `.append()`, `.prepend()`, `.after()`, `.before()`,
`.replaceWith()`, `Range.createContextualFragment()`, `iframe.srcdoc`

Note that `innerHTML` will not execute a bare `<script>` tag — that is why
`<img src=x onerror=...>` and `<svg onload=...>` are the standard payloads.

**Script execution sinks** — the payload becomes code:
`eval`, `new Function`, `setTimeout`/`setInterval` with a string argument,
`$.globalEval`, `importScripts`. These need no HTML context and no markup
filtering to worry about.

**Navigation sinks** — usually open redirect, XSS if `javascript:` survives:
`location` assignment, `location.assign`/`replace`, `window.open`,
`a.href`, `form.action`

**Resource sinks** — script or content loading from a controlled URL:
`script.src`, `link.href`, `object.data`, `setAttribute('src'|'href'|'formaction')`

**Framework trust escapes** — the framework's own "I know what I'm doing" hatch:
`dangerouslySetInnerHTML` (React), `v-html` (Vue), `$sce.trustAsHtml` (AngularJS),
`bypassSecurityTrustHtml`/`...Script`/`...Url`/`...ResourceUrl` (Angular)

These are high-signal precisely because a developer had to deliberately opt out
of the framework's default escaping. Every one is worth tracing to its input.

## Sinks that mislead

- **`.src =` on an image or script with a hardcoded literal.** The scanner
  filters obvious cases but concatenated URLs still show up. Only interesting if
  the value is attacker-influenced.
- **`$(selector)` with a variable.** jQuery treats a string starting with `<` as
  HTML, so `$(userInput)` is a real sink — but `$(someElement)` and
  `$('#' + id)` mostly are not. Check what the variable holds.
- **`.append()` with a constructed element.** `$el.append(document.createElement('div'))`
  is safe; `$el.append('<div>' + x + '</div>')` is not.
- **A sanitizer that is present but wrong.** `DOMPurify.sanitize()` called with
  `{ALLOWED_TAGS: [...]}` that permits event handlers, or with `RETURN_DOM_FRAGMENT`
  misused, still bites. The scanner marks these `needs-review-sanitizer-present`
  rather than dropping them — read the config.

## Confirming a candidate

1. **Find the reaching input.** Work backwards from the sink to a URL, fragment,
   message or stored value you can influence.
2. **Prove reachability first, with a harmless marker.** Put a unique string in
   and confirm it lands in the DOM at the sink. If the marker never arrives, the
   path is dead and you are done — no payload needed.
3. **Then escalate to execution.** `<img src=x onerror=alert(document.domain)>`
   for HTML sinks; for script sinks the source value is already code. Use
   `document.domain` rather than a bare `alert(1)` — it evidences the origin in
   the screenshot, which reviewers ask for.
4. **Record the exact URL or steps.** A DOM XSS PoC is a URL; make sure the one
   you record actually reproduces from a cold session.
5. **Check what it can reach.** Is the session cookie `HttpOnly`? Is there a
   token in `localStorage`? Is there a CSP, and does it actually block inline
   execution? Those three answers set the severity.

## Severity inputs

A DOM XSS on a page nobody visits with no session to steal is not the same
finding as one on an authenticated dashboard with a bearer token in
`localStorage` and no CSP. State these explicitly:

- Does it require authentication to reach, or is it pre-auth?
- Is the payload delivered by URL alone (fragment/query), or does it need stored
  state that another user must view?
- Is the session credential reachable from script? (`HttpOnly` or not; token in
  web storage or not.)
- Is there a CSP, and does it meaningfully constrain the payload?
- Whose session executes it — same-privilege, or does it cross a role boundary?

That last one is what turns a medium into a high.
