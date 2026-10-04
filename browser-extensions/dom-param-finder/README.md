# DOM Param Finder

A Chromium extension (Manifest V3) that inventories parameters, buttons and
insertion points in the **live DOM** — after JavaScript has run — and shows
which of them the page never actually sends.

## Why a browser extension and not a Burp extension

A Burp extension sees bytes on the wire: the HTTP response body as the server
sent it. Fields a framework mounted at runtime, a modal built from a template,
an admin button injected after `/me` returned `role: admin` — none of that
exists in any HTTP response, so no Montoya or Jython extension can reach it.
Burp's own answer to this problem, DOM Invader, works precisely *because* it is
a browser extension living inside the embedded browser.

So the DOM work happens here, and results go back to Burp as raw requests on
the clipboard rather than by running inside it.

## What it finds that other reveal extensions do not

Revealing `input[type=hidden]` is a solved problem — several store extensions
and [XnlReveal](https://github.com/xnl-h4ck3r/XnlReveal) do it. Three things
here are not:

**Never sent.** The extension hooks `fetch`, `XMLHttpRequest`, `sendBeacon`,
`HTMLFormElement.prototype.submit` and the `submit` event, and records every
parameter name the application actually transmits while you click around. The
inventory then splits three ways:

| Class | Meaning |
| --- | --- |
| **in the DOM, never sent** | The deliverable. Mass assignment, forgotten debug switches, a `role` field the UI doesn't submit. |
| **sent, not in the DOM** | Added by JavaScript at request time — reading the HTML would never find these. |
| both | The UI's normal traffic. Deprioritise. |

This is the same definition the `js-recon` skill's `find_hidden_params.py` uses
for static analysis (in the bundle, absent from captured traffic), except the
traffic side comes for free here, with no Burp export needed. The two halves
complement each other: static analysis finds names in the bundle, this finds
what is actually rendered and wired up.

**Closed shadow roots.** `Element.prototype.attachShadow` is hooked at
`document_start` and every closed root is kept in a registry. Nothing can
enumerate a closed root after the fact, so this is the only way to see inside
one — and it is the best hiding place on a modern page.

**Markup no visibility check can see.** `<template>` contents live in a
`DocumentFragment`, so no CSS applies and no visibility API will ever mention
them; frameworks park whole unreleased views there. `<noscript>` contents are
parsed as text when JavaScript is on. And `<!-- <input name="debugMode"> -->`
is dead markup that the server frequently still accepts. All three are walked
separately and labelled.

## Install

```
chrome://extensions → Developer mode → Load unpacked → this folder
```

Chromium 116+ (needs `world: "MAIN"` in `chrome.scripting`). Firefox is not
supported yet; MV3 `world: "MAIN"` landed in Firefox 128, so the port is small
but untested.

## Scope gating

Nothing is injected anywhere until you say so. The manifest declares **no**
`content_scripts` and **no** `host_permissions` — only
`optional_host_permissions`. Click the toolbar icon on a target and press
**Add & instrument**: host permission is requested for that origin alone, a
`document_start` script pair is registered for it, and the tab reloads so the
hooks are in place before the page's own scripts run. **Remove scope** reverses
all three.

This matters more than it looks. An extension that hooks `window.fetch` with
`<all_urls>` is instrumenting your mail and your bank alongside the target.
Scope it the way you would scope Burp.

## Using it

The popup lists the inventory, filtered to **never sent** by default. Per row:

- **Inspect** — scrolls to the node and draws an overlay around it. Works from
  the popup with no DevTools open.
- **Reveal** — forces the node visible.
- **Enable** — strips `disabled`, `readonly`, `maxlength`, `pattern`,
  `required`, `inert`, `aria-disabled`, and unhides `<option>` elements. This is
  how you reach the action the frontend tried to withhold.
- **Copy request** — serialises the node's form the way the browser would
  (action, method, enctype, **every** hidden and disabled control included) as a
  raw HTTP request, ready to paste into Repeater. Not curl.
- **Copy selector** — a CSS selector for the node.

Global: **Reveal all**, **Enable all**, **Revert**, and **keep revealed**, which
re-applies the reveal on DOM mutations — frameworks re-render and re-hide, so
without it a reveal lasts until the next render.

Footer: **Export JSON** (full inventory with classifications), **Copy names**
(a wordlist of the current filter, for Arjun/ffuf/Param Miner), **Reset
traffic** (forget the observed parameters and start a fresh comparison).

### The DevTools panel

A second UI under DevTools → **DOM Params**, which exists for one reason: **no
extension API opens DevTools or selects a node in the Elements panel.**
`inspect()` and `getEventListeners()` are DevTools console APIs, reachable only
from code running inside DevTools via `inspectedWindow.eval`. So:

- Popup **Inspect** → in-page overlay. No DevTools needed. Use this normally.
- Panel **Inspect** → jumps the Elements panel to the node. DevTools must
  already be open (you press F12 yourself).
- Panel **Listeners** → which event types are bound to the node. Which handler
  sits on a hidden admin button is frequently the actual finding.

Selector-addressed nodes only, so shadow-DOM nodes cannot be reached from the
panel — use the popup's overlay for those.

## How hiding is detected

Not by matching a list of CSS tricks. The classifier asks the browser:

```js
el.checkVisibility({ checkOpacity: true, checkVisibilityCSS: true,
                     contentVisibilityAuto: true })
```

That one call collapses `display:none`, `visibility`, `opacity`,
`content-visibility` and all ancestor effects, and will not rot as new
properties land. On top of it: zero-area boxes, off-screen positioning, clip /
`clip-path` (the `sr-only` pattern), transparent text, `pointer-events:none`,
null `offsetParent`, `hidden`/`inert`, `aria-hidden`, `tabindex=-1`,
`disabled`/`readonly`, collapsed `<details>`, unopened `<dialog>` — plus the
four cases above that computed style cannot see at all. Every finding carries
the mechanism that hid it, so a report can say *how* a field was hidden rather
than just that it was.

Reveal works by injecting one stylesheet of `!important` overrides keyed on a
`data-dpf-revealed` attribute, not by editing inline styles — the page keeps its
own `style` attribute intact and reverting means removing one attribute.

## Architecture

| File | World | Why |
| --- | --- | --- |
| `src/main-world.js` | MAIN, `document_start` | Hooks, closed-root registry, the walker, reveal/enable/highlight, raw-request builder |
| `src/bridge.js` | ISOLATED, `document_start` | Pure relay between `chrome.runtime` and `window.postMessage` |
| `src/background.js` | service worker | Scope list, permission requests, script registration, per-tab traffic record |
| `src/popup/` | extension page | Inventory UI |
| `src/devtools/` | DevTools page | `inspect()` and `getEventListeners()` |

The world split is forced, not stylistic: the ISOLATED world shares the DOM but
not the page's JavaScript objects, so it cannot hook `window.fetch`; the MAIN
world can, but has no `chrome.*` APIs. Keeping the walker in MAIN alongside the
hooks means one implementation rather than two that drift, and it is the only
world that can see the closed-root registry.

**Trade-off:** MAIN-world code is reachable by the page, which could detect or
tamper with it, and the `__dpf_v1` postMessage channel is not authenticated
against a hostile page. That is acceptable for a tool pointed at a target you
are authorised to test, and there is no other world where the work can be done.

## Tests

```bash
npm i playwright
CHROME_PATH=/path/to/chrome node test/run_test.js
```

`test/hiding-mechanisms.html` carries every mechanism in one page — 25 hiding
techniques, an open and a **closed** shadow root, template/noscript/comment
markup, a field added 800 ms after load, and buttons that send parameters which
never appear in the DOM. `run_test.js` loads `main-world.js` as a
`document_start` init script (the same place the extension runs it) and drives
the same postMessage API the bridge uses, asserting the walker, the classifier,
the hooks, the never-sent split, reveal/enable, and the raw-request output.

Run it after touching the walker or the classifier. The fixture's validation
attributes are load-bearing: `requestSubmit()` runs interactive validation
first, so an invalid control means no `submit` event fires and the traffic
assertions silently stop testing anything.

## Limits

- **Reload after adding scope.** The hooks install at `document_start`; a page
  already open when you added the origin has unhooked globals.
- Traffic observed is per tab and lives in the service worker, so it is lost
  when the tab closes or the worker is evicted. It deliberately survives
  navigation — the useful question is what the application sent at any point in
  the session.
- A parameter absent from the sent set means *not sent yet*. Exercise the
  feature before trusting it.
- Cross-origin iframes are instrumented separately (`allFrames: true`) but only
  for origins in scope.
- Reveal cannot resurrect content that was never rendered: a `<template>` or a
  commented-out field is reported, not shown.
