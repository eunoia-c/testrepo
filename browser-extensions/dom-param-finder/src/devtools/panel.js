// DevTools panel. This exists for one reason: no extension API opens DevTools
// or selects a node in the Elements panel from a popup. Only code running
// inside DevTools can call inspect(), via inspectedWindow.eval -- so the
// "jump to this node in Elements" feature has to live here, and DevTools has
// to already be open. The popup's own Inspect button draws an in-page overlay
// instead, which needs none of this.

const $ = (s) => document.querySelector(s);
const tabId = chrome.devtools.inspectedWindow.tabId;
let ITEMS = [];

function evalInPage(expr) {
  return new Promise((resolve) =>
    chrome.devtools.inspectedWindow.eval(expr, (res, err) => resolve({ res, err })));
}

async function scan() {
  $("#status").textContent = "Scanning...";
  let res;
  try {
    res = await chrome.tabs.sendMessage(tabId, { dpf: "scan" });
  } catch (_) {
    $("#status").textContent =
      "Page is not instrumented. Add the origin to scope from the toolbar popup, then reload.";
    return;
  }
  if (!res || res.error) {
    $("#status").textContent = "No response from the page.";
    return;
  }
  ITEMS = res.items || [];
  render();
}

function render() {
  const onlyHidden = $("#only-hidden").checked;
  const rows = ITEMS.filter((it) => it.selector && (!onlyHidden || it.reasons.length));
  $("#status").textContent = rows.length + " of " + ITEMS.length + " nodes";
  const list = $("#list");
  list.textContent = "";
  for (const it of rows) {
    const row = document.createElement("div");
    row.className = "row";
    const h = document.createElement("h4");
    h.textContent = (it.name || "(unnamed)") + " ";
    const t = document.createElement("span");
    t.className = "tag";
    t.textContent = it.tag + (it.type ? "[" + it.type + "]" : "");
    h.appendChild(t);
    row.appendChild(h);
    if (it.reasons.length) {
      const w = document.createElement("div");
      w.className = "why";
      w.textContent = "hidden by: " + it.reasons.join("; ");
      row.appendChild(w);
    }

    const acts = document.createElement("div");
    acts.className = "acts";

    const insp = document.createElement("button");
    insp.textContent = "Inspect";
    insp.addEventListener("click", async () => {
      // inspect() is a DevTools console API, not page JavaScript; eval runs in
      // the DevTools context where it is defined.
      const sel = JSON.stringify(it.selector);
      const { err } = await evalInPage(`inspect(document.querySelector(${sel}))`);
      if (err) $("#status").textContent = "Could not select that node (" +
        (err.value || err.code) + "). Shadow-DOM nodes are not reachable by selector.";
    });
    acts.appendChild(insp);

    const listeners = document.createElement("button");
    listeners.textContent = "Listeners";
    listeners.addEventListener("click", async () => {
      // Which handler is bound to a hidden button is often the actual finding,
      // and getEventListeners() is another DevTools-only API.
      const sel = JSON.stringify(it.selector);
      const { res, err } = await evalInPage(
        `Object.keys(getEventListeners(document.querySelector(${sel})) || {}).join(", ") || "(none)"`);
      $("#status").textContent = err ? "Unavailable here." : "listeners: " + res;
    });
    acts.appendChild(listeners);

    row.appendChild(acts);
    list.appendChild(row);
  }
}

$("#scan").addEventListener("click", scan);
$("#only-hidden").addEventListener("change", render);
scan();
