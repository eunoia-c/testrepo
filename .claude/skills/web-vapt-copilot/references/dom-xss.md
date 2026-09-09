# DOM-based XSS

A DOM XSS exists when attacker-controllable data (**source**) reaches a dangerous
JavaScript operation (**sink**) without adequate encoding. Both halves are required;
a sink alone is not a finding.

## Confidence levels in the output

- **high** — a source and a sink appear in the same statement. Look at these first.
- **medium** — a variable assigned from a source (possibly through a couple of hops)
  reaches the sink.
- **low** — a sink with no visible source. Context for manual review only; shown with
  `--min-confidence low`.

## Sources

| Source | Reaches the server? | Note |
|---|---|---|
| `location.hash` | **No** | No server-side filter or WAF in the path. Best case. |
| `location.search` | Yes | Query string; server-side controls may apply. |
| `location.pathname`, `location.href` | Yes | |
| `document.URL`, `documentURI`, `baseURI` | Yes | |
| `document.referrer` | No | Controlled by making the victim arrive from your page. |
| `window.name` | No | Persists across navigation — a strong cross-origin carrier. |
| `postMessage` event data | No | Check the `origin` validation; missing checks are common. |
| `document.cookie` | Partly | Needs a cookie-write primitive or a sibling subdomain. |
| `localStorage` / `sessionStorage` | No | Needs another write primitive first. |
| `history.state`, `pushState` data | No | |
| `URLSearchParams(location.search)` | Yes | |

## Sinks

**Execution** — `eval`, `new Function`, `setTimeout`/`setInterval` with a string,
`jQuery.globalEval`, `execScript`.

**HTML injection** — `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`,
`document.writeln`, `srcdoc`, `Range.createContextualFragment`, `DOMParser` output
inserted into the document, jQuery `html()` `append()` `prepend()` `before()` `after()`
`replaceWith()` `wrap()` `parseHTML()`, and `$(userInput)` where the input can start
with `<`.

**URL / attribute** — `location` assignment, `location.assign`/`replace`,
`element.src` on a script or iframe, `setAttribute` with `href`/`src`/`action`/
`formaction`/`on*`, `window.open`. `javascript:` URLs are the payload here.

**Framework escapes** — React `dangerouslySetInnerHTML`, Vue `v-html`,
Angular `bypassSecurityTrustHtml`/`TrustScript`/`TrustResourceUrl`,
AngularJS `$sce.trustAsHtml` and `$sceProvider.enabled(false)`.

## Confirming a lead

1. Open DevTools → Sources, set a breakpoint on the sink line (or a
   `debugger` statement via an override).
2. Drive the source: append `#marker` to the URL, set `window.name`, post a message
   from a scratch page, or write the storage key from the console.
3. Step to the sink and read the value. If your marker arrives intact, the flow is real.
4. Escalate to execution. Prefer a payload that proves execution without noise —
   `<img src=x onerror=console.log(document.domain)>` over `alert()` in a shared
   environment.
5. Record the minimal reproducing URL or message payload.

## Payload notes by sink

- `innerHTML` does not execute a plain `<script>`. Use `<img src=x onerror=...>`,
  `<svg onload=...>`, or `<iframe srcdoc=...>`.
- Sinks reached from `location.hash` bypass server-side filtering entirely — the
  fragment is never sent. Say so explicitly in the write-up; it changes the severity
  argument and defeats "the WAF blocks it".
- For `postMessage` handlers, test the missing-origin-check case first: host a page that
  frames the target and posts the payload. That is usually the whole vulnerability.
- For `location` sinks, `javascript:alert(1)` is the classic; check for a scheme
  allowlist and for `\x00`/whitespace-prefix bypasses of a naive one.
- jQuery `$(input)` treats a leading `<` as HTML construction. Older jQuery is more
  permissive here; check the version.

## Mitigations that change the verdict

Before reporting, check whether these apply — they affect exploitability and severity:

- A **CSP** without `unsafe-inline` and without a wildcard/JSONP-able allowlisted host
  may block execution. Read the actual header; most real-world policies have a hole.
- **Trusted Types** (`require-trusted-types-for 'script'`) blocks string assignment to
  these sinks outright.
- **DOMPurify** or an equivalent sanitiser in the flow — check the version and the
  configuration. `RETURN_DOM_FRAGMENT`, `ALLOW_UNKNOWN_PROTOCOLS` and a stale version
  are all worth examining rather than assuming the sanitiser is effective.

Report what you observed, and note the mitigation and its state either way.

## Remediation to recommend

Prefer `textContent` over `innerHTML`. Where HTML is genuinely required, sanitise with a
maintained library at the point of insertion. Never pass a string to `setTimeout`, `eval`
or `Function`. Validate `event.origin` in every `postMessage` handler. Adopt Trusted
Types and a CSP without `unsafe-inline` as defence in depth, not as the primary fix.
