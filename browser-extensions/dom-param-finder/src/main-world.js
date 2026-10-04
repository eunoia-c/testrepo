// MAIN world, document_start. Everything that needs the page's own globals.
//
// Why the whole walk lives here rather than in the ISOLATED content script:
// the ISOLATED world shares the DOM but not the page's JavaScript objects, so
// it cannot hook window.fetch and -- more importantly -- cannot see the closed
// shadow roots this file registers. Keeping hooks and walker together means one
// implementation instead of two that drift.
//
// The trade-off: code in the MAIN world is reachable by the page, which could
// detect or tamper with it. That is acceptable for a tool pointed at a target
// you are authorised to test, and it is the only place the work can be done.
(() => {
  if (window.__DPF__) return;
  const CH = "__dpf_v1";

  // ---------------------------------------------------------------- registry
  // Closed shadow roots are the best hiding place on a modern page and nothing
  // can enumerate them after the fact -- so capture them as they are created,
  // which is why this file must run at document_start.
  const closedRoots = [];
  const nativeAttachShadow = Element.prototype.attachShadow;
  Element.prototype.attachShadow = function (init) {
    const root = nativeAttachShadow.call(this, init);
    if (init && init.mode === "closed") closedRoots.push(root);
    return root;
  };

  // ------------------------------------------------------------- sent params
  // What the application actually transmits. A name present in the DOM and
  // absent from this set is the thing worth testing: no amount of clicking
  // through the UI would have revealed it.
  const sentNames = new Set();
  const sentUrls = new Set();
  let pending = false;

  function flush() {
    if (pending) return;
    pending = true;
    setTimeout(() => {
      pending = false;
      window.postMessage(
        { ch: CH, dir: "up", type: "sent-params",
          names: [...sentNames], urls: [...sentUrls] }, "*");
    }, 300);
  }

  function noteUrl(u) {
    try {
      const url = new URL(String(u), location.href);
      sentUrls.add(url.origin + url.pathname);
      for (const k of url.searchParams.keys()) sentNames.add(k);
    } catch (_) { /* opaque or relative-to-nothing; the body still counts */ }
    flush();
  }

  function noteBody(body) {
    try {
      if (!body) return;
      if (typeof body === "string") {
        const t = body.trim();
        if (t.startsWith("{") || t.startsWith("[")) {
          walkJson(JSON.parse(t));
        } else {
          for (const k of new URLSearchParams(body).keys()) sentNames.add(k);
        }
      } else if (body instanceof URLSearchParams || body instanceof FormData) {
        for (const k of body.keys()) sentNames.add(k);
      } else if (body && typeof body === "object" && !(body instanceof Blob)) {
        walkJson(body);
      }
    } catch (_) { /* unparseable body; names from the URL still landed */ }
    flush();
  }

  function walkJson(o, depth = 0) {
    if (!o || typeof o !== "object" || depth > 6) return;
    for (const k of Object.keys(o)) {
      sentNames.add(k);
      walkJson(o[k], depth + 1);
    }
  }

  const nativeFetch = window.fetch;
  if (nativeFetch) {
    window.fetch = function (input, init) {
      try {
        noteUrl(input instanceof Request ? input.url : input);
        noteBody(init && init.body);
      } catch (_) {}
      return nativeFetch.apply(this, arguments);
    };
  }

  const xhrOpen = XMLHttpRequest.prototype.open;
  const xhrSend = XMLHttpRequest.prototype.send;
  XMLHttpRequest.prototype.open = function (m, u) {
    try { this.__dpfUrl = u; } catch (_) {}
    return xhrOpen.apply(this, arguments);
  };
  XMLHttpRequest.prototype.send = function (body) {
    try { noteUrl(this.__dpfUrl); noteBody(body); } catch (_) {}
    return xhrSend.apply(this, arguments);
  };

  if (navigator.sendBeacon) {
    const beacon = navigator.sendBeacon.bind(navigator);
    navigator.sendBeacon = function (u, data) {
      try { noteUrl(u); noteBody(data); } catch (_) {}
      return beacon(u, data);
    };
  }

  const formSubmit = HTMLFormElement.prototype.submit;
  HTMLFormElement.prototype.submit = function () {
    try { noteFormSubmit(this); } catch (_) {}
    return formSubmit.apply(this, arguments);
  };
  // requestSubmit() and a user clicking a submit button both fire the submit
  // event rather than calling .submit(), so the prototype hook alone misses
  // most real submissions.
  addEventListener("submit", (e) => {
    try { noteFormSubmit(e.target); } catch (_) {}
  }, true);

  function noteFormSubmit(form) {
    if (!form || !form.elements) return;
    noteUrl(form.getAttribute("action") || location.href);
    for (const el of form.elements) if (el.name && !el.disabled) sentNames.add(el.name);
    flush();
  }

  // -------------------------------------------------------------- visibility
  // Asking the browser beats maintaining a list of CSS tricks: checkVisibility
  // collapses display:none, visibility, opacity, content-visibility and
  // ancestor effects into one call that will not rot as new properties land.
  // What it cannot see is handled explicitly below -- templates, comments,
  // noscript and closed shadow roots.
  const HIDE_REASONS = {
    HIDDEN_INPUT: "input[type=hidden]",
    HIDDEN_ATTR: "hidden / inert attribute",
    CSS: "not visible per checkVisibility",
    ZERO_AREA: "zero-area box",
    OFFSCREEN: "positioned off-screen",
    CLIPPED: "clipped (clip-path / clip / sr-only)",
    TRANSPARENT: "transparent text or colour",
    NO_LAYOUT: "no layout box (offsetParent null)",
    ARIA: "aria-hidden",
    UNFOCUSABLE: "tabindex=-1",
    NO_POINTER: "pointer-events:none",
    DISABLED: "disabled",
    READONLY: "readonly",
    TEMPLATE: "inside <template>",
    COMMENT: "inside an HTML comment",
    NOSCRIPT: "inside <noscript>",
    CLOSED_SHADOW: "inside a closed shadow root",
    DIALOG_CLOSED: "inside a closed <dialog>",
    DETAILS_CLOSED: "inside a collapsed <details>",
  };

  function hideReasons(el) {
    const r = [];
    if (el.tagName === "INPUT" && el.type === "hidden") r.push(HIDE_REASONS.HIDDEN_INPUT);
    if (el.hasAttribute("hidden") || el.hasAttribute("inert")) r.push(HIDE_REASONS.HIDDEN_ATTR);
    if (el.getAttribute("aria-hidden") === "true") r.push(HIDE_REASONS.ARIA);
    if (el.getAttribute("tabindex") === "-1") r.push(HIDE_REASONS.UNFOCUSABLE);
    if (el.disabled) r.push(HIDE_REASONS.DISABLED);
    if (el.readOnly) r.push(HIDE_REASONS.READONLY);

    if (el.closest && el.closest("dialog:not([open])")) r.push(HIDE_REASONS.DIALOG_CLOSED);
    if (el.closest && el.closest("details:not([open])")) r.push(HIDE_REASONS.DETAILS_CLOSED);

    // A hidden input legitimately has no box, so the layout checks below would
    // fire on every one of them and say nothing.
    const isHiddenInput = el.tagName === "INPUT" && el.type === "hidden";
    if (!isHiddenInput) {
      const visible = typeof el.checkVisibility === "function"
        ? el.checkVisibility({ checkOpacity: true, checkVisibilityCSS: true,
                               contentVisibilityAuto: true })
        : !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length);
      if (!visible) r.push(HIDE_REASONS.CSS);

      const cs = getComputedStyle(el);
      const box = el.getBoundingClientRect();
      if (box.width < 2 || box.height < 2) r.push(HIDE_REASONS.ZERO_AREA);
      if (box.right < 0 || box.bottom < 0 ||
          box.left > (innerWidth + 2000) || box.top > (innerHeight + 20000)) {
        r.push(HIDE_REASONS.OFFSCREEN);
      }
      if (/inset\(1?00%\)|circle\(0/.test(cs.clipPath) || /rect\(0px,? 0px/.test(cs.clip)) {
        r.push(HIDE_REASONS.CLIPPED);
      }
      if (cs.color === "transparent" || cs.fontSize === "0px") r.push(HIDE_REASONS.TRANSPARENT);
      if (cs.pointerEvents === "none") r.push(HIDE_REASONS.NO_POINTER);
      if (el.offsetParent === null && cs.position !== "fixed" && cs.display !== "contents") {
        r.push(HIDE_REASONS.NO_LAYOUT);
      }
    }
    return [...new Set(r)];
  }

  // ------------------------------------------------------------------- walker
  const SELECTOR = [
    "input", "select", "textarea", "button", "form",
    "[contenteditable]", "[role=button]", "[role=switch]", "[role=checkbox]",
    "a[href*='?']", "a[href*='#']",
  ].join(",");

  let uid = 0;
  const byId = new Map();          // our id -> element (for inspect/highlight)

  function selectorFor(el) {
    if (el.id) return "#" + CSS.escape(el.id);
    const parts = [];
    let n = el;
    while (n && n.nodeType === 1 && parts.length < 5) {
      let s = n.localName;
      if (n.id) { parts.unshift("#" + CSS.escape(n.id)); break; }
      const parent = n.parentNode;
      if (parent) {
        const sibs = [...parent.children].filter((c) => c.localName === n.localName);
        if (sibs.length > 1) s += ":nth-of-type(" + (sibs.indexOf(n) + 1) + ")";
      }
      parts.unshift(s);
      n = parent && parent.host ? parent.host : parent;
    }
    return parts.join(" > ");
  }

  function describe(el, context, extraReasons) {
    const form = el.form || (el.closest && el.closest("form"));
    const id = ++uid;
    byId.set(id, el);
    return {
      id,
      tag: el.localName,
      type: el.getAttribute ? (el.getAttribute("type") || "") : "",
      name: (el.getAttribute && (el.getAttribute("name") || el.getAttribute("id"))) || "",
      value: el.tagName === "INPUT" || el.tagName === "TEXTAREA" || el.tagName === "SELECT"
        ? String(el.value == null ? "" : el.value).slice(0, 200) : "",
      label: (el.getAttribute && (el.getAttribute("aria-label") ||
              el.getAttribute("placeholder") || el.getAttribute("title"))) ||
              (el.textContent || "").trim().slice(0, 80),
      context,                                     // light | shadow | closed-shadow | template | comment | noscript
      reasons: [...(extraReasons || []), ...(el.getAttribute ? hideReasons(el) : [])],
      selector: selectorFor(el),
      insertion: form ? {
        method: (form.getAttribute("method") || "GET").toUpperCase(),
        action: form.getAttribute("action") || location.pathname,
        enctype: form.getAttribute("enctype") ||
                 "application/x-www-form-urlencoded",
      } : null,
      attrs: el.getAttributeNames ? Object.fromEntries(
        el.getAttributeNames()
          .filter((a) => /^(data-|aria-)|^(pattern|maxlength|required|min|max|step|autocomplete|formaction)$/.test(a))
          .map((a) => [a, el.getAttribute(a).slice(0, 120)])) : {},
    };
  }

  function walkRoot(root, context, out, extraReasons) {
    let nodes = [];
    try { nodes = [...root.querySelectorAll(SELECTOR)]; } catch (_) { return; }
    for (const el of nodes) {
      out.push(describe(el, context, extraReasons));
      // Open shadow roots recurse; closed ones are picked up from the registry.
      if (el.shadowRoot) walkRoot(el.shadowRoot, "shadow", out, extraReasons);
    }
    // Any element can host a shadow root, not only ones matching SELECTOR.
    try {
      for (const el of root.querySelectorAll("*")) {
        if (el.shadowRoot && !nodes.includes(el)) walkRoot(el.shadowRoot, "shadow", out, extraReasons);
      }
    } catch (_) {}
  }

  function walkTemplates(out) {
    // <template> contents live in a DocumentFragment, so no CSS applies to them
    // and no visibility check will ever mention them. Frameworks park whole
    // unreleased views here.
    for (const tpl of document.querySelectorAll("template")) {
      walkRoot(tpl.content, "template", out, [HIDE_REASONS.TEMPLATE]);
    }
  }

  function walkNoscript(out) {
    for (const ns of document.querySelectorAll("noscript")) {
      // With JS enabled the contents are parsed as text, not elements.
      parseFragment(ns.textContent, "noscript", [HIDE_REASONS.NOSCRIPT], out);
    }
  }

  function walkComments(out) {
    // <!-- <input name="debugMode"> --> is dead markup that the server often
    // still accepts. Nothing in the DOM API treats it as an element.
    const it = document.createNodeIterator(document.documentElement, NodeFilter.SHOW_COMMENT);
    let c;
    while ((c = it.nextNode())) {
      const t = c.nodeValue || "";
      if (!/<\s*(input|select|textarea|button|form|a)\b/i.test(t)) continue;
      parseFragment(t, "comment", [HIDE_REASONS.COMMENT], out);
    }
  }

  function parseFragment(html, context, reasons, out) {
    try {
      const doc = new DOMParser().parseFromString("<body>" + html + "</body>", "text/html");
      for (const el of doc.querySelectorAll(SELECTOR)) {
        out.push({
          id: ++uid, tag: el.localName,
          type: el.getAttribute("type") || "",
          name: el.getAttribute("name") || el.getAttribute("id") || "",
          value: el.getAttribute("value") || "",
          label: (el.textContent || "").trim().slice(0, 80),
          context, reasons, selector: null, insertion: null, attrs: {},
        });
      }
    } catch (_) {}
  }

  function scan() {
    uid = 0;
    byId.clear();
    const out = [];
    walkRoot(document, "light", out, []);
    for (const root of closedRoots) walkRoot(root, "closed-shadow", out, [HIDE_REASONS.CLOSED_SHADOW]);
    walkTemplates(out);
    walkNoscript(out);
    walkComments(out);
    return { url: location.href, items: out, sent: [...sentNames] };
  }

  // ------------------------------------------------------------------ actions
  const STYLE_ID = "__dpf_reveal_style";
  const REVEAL_CSS = `
    [data-dpf-revealed] {
      display: revert !important; visibility: visible !important;
      opacity: 1 !important; content-visibility: visible !important;
      clip-path: none !important; clip: auto !important;
      pointer-events: auto !important; position: static !important;
      transform: none !important; filter: none !important;
      width: auto !important; height: auto !important;
      max-height: none !important; max-width: none !important;
      font-size: revert !important; color: revert !important;
      text-indent: 0 !important; z-index: 2147483000 !important;
      outline: 2px dashed #d33 !important; outline-offset: 1px !important;
    }
    input[type="hidden"][data-dpf-revealed] { display: inline-block !important; }
    [data-dpf-revealed]::after {
      content: attr(data-dpf-note); font: 10px/1.4 monospace;
      background: #d33; color: #fff; padding: 0 3px; margin-left: 4px;
    }`;

  function ensureStyle() {
    if (document.getElementById(STYLE_ID)) return;
    const s = document.createElement("style");
    s.id = STYLE_ID;
    s.textContent = REVEAL_CSS;
    (document.head || document.documentElement).appendChild(s);
  }

  // One stylesheet with !important beats editing inline styles: the page keeps
  // its own style attribute intact, and reverting is removing one attribute.
  let revealed = [];
  function reveal(ids) {
    ensureStyle();
    const targets = ids && ids.length ? ids.map((i) => byId.get(i)).filter(Boolean)
                                      : [...byId.values()];
    for (const el of targets) {
      if (!el.setAttribute) continue;
      if (el.tagName === "INPUT" && el.type === "hidden") el.type = "text";
      el.setAttribute("data-dpf-note", (el.getAttribute("name") || el.localName));
      el.setAttribute("data-dpf-revealed", "1");
      revealed.push(el);
    }
    return { count: targets.length };
  }

  function unreveal() {
    for (const el of revealed) {
      el.removeAttribute("data-dpf-revealed");
      el.removeAttribute("data-dpf-note");
    }
    const n = revealed.length;
    revealed = [];
    return { count: n };
  }

  // Frameworks re-render and re-hide. Rather than fight every mutation, the
  // reveal is re-applied on a debounce while the observer is on.
  let observer = null;
  function watch(on) {
    if (!on) { if (observer) observer.disconnect(); observer = null; return { watching: false }; }
    if (observer) return { watching: true };
    let t = 0;
    observer = new MutationObserver(() => {
      clearTimeout(t);
      t = setTimeout(() => { if (revealed.length) reveal(revealed.map((el) => {
        for (const [k, v] of byId) if (v === el) return k;
        return null;
      }).filter(Boolean)); }, 250);
    });
    observer.observe(document.documentElement, { childList: true, subtree: true, attributes: true });
    return { watching: true };
  }

  function enable(ids) {
    const targets = ids && ids.length ? ids.map((i) => byId.get(i)).filter(Boolean)
                                      : [...byId.values()];
    let n = 0;
    for (const el of targets) {
      if (!el.removeAttribute) continue;
      for (const a of ["disabled", "readonly", "maxlength", "minlength",
                       "pattern", "required", "inert", "aria-disabled"]) {
        if (el.hasAttribute(a)) { el.removeAttribute(a); n++; }
      }
      if (el.localName === "option") el.hidden = false;
      if (el.tabIndex === -1) el.tabIndex = 0;
    }
    return { count: n };
  }

  function highlight(id) {
    const el = byId.get(id);
    if (!el || !el.scrollIntoView) return { ok: false };
    el.scrollIntoView({ block: "center", behavior: "smooth" });
    const box = el.getBoundingClientRect();
    const mark = document.createElement("div");
    Object.assign(mark.style, {
      position: "fixed", zIndex: "2147483647", pointerEvents: "none",
      left: (box.left - 2) + "px", top: (box.top - 2) + "px",
      width: Math.max(box.width, 8) + 4 + "px",
      height: Math.max(box.height, 8) + 4 + "px",
      border: "2px solid #d33", background: "rgba(221,51,51,.12)",
      boxShadow: "0 0 0 9999px rgba(0,0,0,.25)", transition: "opacity .3s",
    });
    document.documentElement.appendChild(mark);
    setTimeout(() => { mark.style.opacity = "0"; setTimeout(() => mark.remove(), 400); }, 1600);
    return { ok: true, selector: selectorFor(el) };
  }

  // A form serialised the way the browser would send it, as a raw request --
  // paste straight into Repeater. Disabled and hidden controls are included on
  // purpose: the whole point is to send what the UI would not.
  function rawRequest(id) {
    const el = byId.get(id);
    if (!el) return { ok: false };
    const form = el.localName === "form" ? el : (el.form || el.closest("form"));
    const url = new URL((form && form.getAttribute("action")) || location.href, location.href);
    const method = ((form && form.getAttribute("method")) || "GET").toUpperCase();
    const pairs = [];
    if (form && form.elements) {
      for (const c of form.elements) {
        if (!c.name) continue;
        if (c.type === "checkbox" || c.type === "radio") {
          if (c.checked) pairs.push([c.name, c.value || "on"]);
        } else if (c.type !== "file") {
          pairs.push([c.name, c.value == null ? "" : String(c.value)]);
        }
      }
    } else if (el.name) {
      pairs.push([el.name, String(el.value || "")]);
    }
    const body = new URLSearchParams(pairs).toString();
    const headers = [
      "Host: " + url.host,
      "User-Agent: " + navigator.userAgent,
      "Accept: text/html,application/xhtml+xml,*/*",
      "Referer: " + location.href,
    ];
    let target = url.pathname + (url.search || "");
    let out;
    if (method === "GET") {
      const q = new URLSearchParams(url.search);
      for (const [k, v] of pairs) q.set(k, v);
      target = url.pathname + (q.toString() ? "?" + q.toString() : "");
      out = `GET ${target} HTTP/1.1\r\n${headers.join("\r\n")}\r\n\r\n`;
    } else {
      const ct = (form && form.getAttribute("enctype")) || "application/x-www-form-urlencoded";
      out = `${method} ${target} HTTP/1.1\r\n${headers.join("\r\n")}\r\n` +
            `Content-Type: ${ct}\r\nContent-Length: ${body.length}\r\n\r\n${body}`;
    }
    return { ok: true, raw: out };
  }

  // ------------------------------------------------------------------ channel
  const HANDLERS = { scan, reveal, unreveal, enable, highlight, rawRequest, watch };

  addEventListener("message", (ev) => {
    const d = ev.data;
    if (!d || d.ch !== CH || d.dir !== "down") return;
    let result;
    try {
      const fn = HANDLERS[d.type];
      result = fn ? fn(d.ids != null ? d.ids : d.id != null ? d.id : d.on) : { error: "unknown " + d.type };
    } catch (e) {
      result = { error: String(e && e.message || e) };
    }
    window.postMessage({ ch: CH, dir: "up", type: "result", rid: d.rid, result }, "*");
  });

  window.__DPF__ = true;
})();
