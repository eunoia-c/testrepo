// Popup: scope gate, the inventory, and the three-way split that is the point
// of the tool -- in the DOM and never sent, sent and not in the DOM, both.

const $ = (s) => document.querySelector(s);
let TAB = null, ITEMS = [], SENT = new Set(), PATTERN = null;

function patternFor(url) {
  try { const u = new URL(url); return u.protocol + "//" + u.host + "/*"; }
  catch (_) { return null; }
}

const send = (msg) => chrome.runtime.sendMessage(msg);
const page = (dpf, extra) =>
  chrome.tabs.sendMessage(TAB.id, { dpf, ...extra }).catch(() => ({ error: "not instrumented" }));

async function init() {
  [TAB] = await chrome.tabs.query({ active: true, currentWindow: true });
  PATTERN = patternFor(TAB.url);
  $("#origin").textContent = PATTERN || TAB.url;

  if (!PATTERN) { $("#status").textContent = "Not an http(s) page."; return; }

  const { scope } = await send({ type: "get-scope" });
  const inScope = scope.includes(PATTERN);
  $("#scope-bar").classList.toggle("hidden", inScope);
  for (const id of ["#controls", "#filters", "#foot"]) {
    $(id).classList.toggle("hidden", !inScope);
  }
  if (inScope) {
    $("#status").textContent = "In scope. Reload the page if it was open before "
      + "it was added -- the hooks install at document start.";
    scan();
  } else {
    $("#status").textContent = "Nothing is injected until you add this origin.";
  }
}

async function scan() {
  $("#status").textContent = "Scanning...";
  const res = await page("scan");
  if (!res || res.error) {
    $("#status").textContent = "Could not reach the page (" +
      ((res && res.error) || "no response") + "). Reload it and try again.";
    return;
  }
  ITEMS = res.items || [];
  const sent = await send({ type: "get-sent", tabId: TAB.id });
  SENT = new Set([...(sent.names || []), ...(res.sent || [])]);
  render();
}

function classify(it) {
  const named = !!it.name;
  return {
    hidden: it.reasons.length > 0,
    neverSent: named && !SENT.has(it.name),
  };
}

function render() {
  const mode = document.querySelector('input[name=f]:checked').value;
  const q = $("#q").value.trim().toLowerCase();

  let rows = ITEMS.filter((it) => {
    const c = classify(it);
    if (mode === "never-sent" && !(c.neverSent && it.name)) return false;
    if (mode === "hidden" && !c.hidden) return false;
    if (q && !((it.name + " " + it.label + " " + it.tag).toLowerCase().includes(q))) return false;
    return true;
  });

  // The interesting rows first: never sent, then hidden, then the rest.
  rows.sort((a, b) => {
    const ca = classify(a), cb = classify(b);
    return (cb.neverSent - ca.neverSent) || (cb.hidden - ca.hidden) ||
           (a.name || "").localeCompare(b.name || "");
  });

  const names = new Set(ITEMS.filter((i) => i.name).map((i) => i.name));
  const sentOnly = [...SENT].filter((n) => !names.has(n));

  $("#status").innerHTML =
    `${rows.length} shown of ${ITEMS.length} nodes · ` +
    `${ITEMS.filter((i) => classify(i).neverSent).length} named-but-never-sent · ` +
    `${sentOnly.length} sent but not in the DOM`;

  const list = $("#list");
  list.textContent = "";

  for (const it of rows) {
    const c = classify(it);
    const row = document.createElement("div");
    row.className = "row" + (c.neverSent ? " never-sent" : "");

    const h = document.createElement("h4");
    h.textContent = it.name || "(unnamed)";
    const tag = document.createElement("span");
    tag.className = "tag";
    tag.textContent = ` ${it.tag}${it.type ? "[" + it.type + "]" : ""}`;
    h.appendChild(tag);
    if (c.neverSent) h.appendChild(badge("never sent", true));
    if (it.context !== "light") h.appendChild(badge(it.context));
    row.appendChild(h);

    if (it.value) row.appendChild(line("value: " + it.value));
    if (it.label) row.appendChild(line(it.label));
    if (it.reasons.length) row.appendChild(line("hidden by: " + it.reasons.join("; ")));
    if (it.insertion) {
      row.appendChild(line(`insertion: ${it.insertion.method} ${it.insertion.action}`));
    }
    const extra = Object.entries(it.attrs || {});
    if (extra.length) row.appendChild(line(extra.map(([k, v]) => k + "=" + v).join(" ")));

    const acts = document.createElement("div");
    acts.className = "acts";
    if (it.selector) {
      acts.appendChild(btn("Inspect", () => page("highlight", { id: it.id })));
      acts.appendChild(btn("Reveal", () => page("reveal", { ids: [it.id] })));
      acts.appendChild(btn("Enable", () => page("enable", { ids: [it.id] })));
      acts.appendChild(btn("Copy request", async () => {
        const r = await page("rawRequest", { id: it.id });
        if (r && r.raw) copy(r.raw, "Raw request copied -- paste into Repeater.");
      }));
      acts.appendChild(btn("Copy selector", () => copy(it.selector, "Selector copied.")));
    } else {
      acts.appendChild(line("not a live node -- " + it.context + ", nothing to click"));
    }
    row.appendChild(acts);
    list.appendChild(row);
  }

  if (mode !== "hidden" && sentOnly.length) {
    const d = document.createElement("div");
    d.className = "row";
    d.appendChild(Object.assign(document.createElement("h4"),
      { textContent: "Sent but never in the DOM (" + sentOnly.length + ")" }));
    d.appendChild(line("Added by JavaScript at request time; reading the HTML "
      + "would never have found these."));
    d.appendChild(line(sentOnly.join(", ")));
    list.appendChild(d);
  }
}

function badge(text, hot) {
  const b = document.createElement("span");
  b.className = "badge" + (hot ? " hot" : "");
  b.textContent = text;
  return b;
}
function line(text) {
  const p = document.createElement("div");
  p.className = "why";
  p.textContent = text;
  return p;
}
function btn(label, fn) {
  const b = document.createElement("button");
  b.textContent = label;
  b.addEventListener("click", fn);
  return b;
}
async function copy(text, note) {
  await navigator.clipboard.writeText(text);
  $("#status").textContent = note;
}

$("#add-scope").addEventListener("click", async () => {
  const r = await send({ type: "add-scope", pattern: PATTERN });
  if (!r.ok) { $("#status").textContent = "Permission declined."; return; }
  await chrome.tabs.reload(TAB.id);          // hooks must be present from document_start
  window.close();
});
$("#remove-scope").addEventListener("click", async () => {
  await send({ type: "remove-scope", pattern: PATTERN });
  window.close();
});
$("#scan").addEventListener("click", scan);
$("#reveal-all").addEventListener("click", async () => {
  const r = await page("reveal", { ids: [] });
  $("#status").textContent = "Revealed " + ((r && r.count) || 0) + " nodes.";
});
$("#enable-all").addEventListener("click", async () => {
  const r = await page("enable", { ids: [] });
  $("#status").textContent = "Cleared " + ((r && r.count) || 0) + " blocking attributes.";
});
$("#unreveal").addEventListener("click", async () => {
  await page("unreveal");
  $("#status").textContent = "Reverted.";
});
$("#watch").addEventListener("change", (e) => page("watch", { on: e.target.checked }));
$("#q").addEventListener("input", render);
for (const r of document.querySelectorAll('input[name=f]')) {
  r.addEventListener("change", render);
}
$("#export").addEventListener("click", () => {
  const payload = {
    url: TAB.url, scanned: new Date().toISOString(),
    sent: [...SENT],
    items: ITEMS.map((it) => ({ ...it, ...classify(it) })),
  };
  copy(JSON.stringify(payload, null, 2), "Inventory JSON copied.");
});
$("#wordlist").addEventListener("click", () => {
  const mode = document.querySelector('input[name=f]:checked').value;
  const names = [...new Set(ITEMS
    .filter((it) => it.name && (mode !== "never-sent" || classify(it).neverSent))
    .map((it) => it.name))].sort();
  copy(names.join("\n"), names.length + " names copied.");
});
$("#clear-sent").addEventListener("click", async () => {
  await send({ type: "clear-sent", tabId: TAB.id });
  SENT = new Set();
  render();
});

init();
