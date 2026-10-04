// Service worker: scope management and the per-tab record of what the page sent.
//
// There are deliberately no `content_scripts` in the manifest. A tool that
// hooks window.fetch on every site you visit is instrumenting your mail and
// your bank alongside the target, so nothing is injected until an origin is
// explicitly added to the scope list -- at which point host permission for
// that origin alone is requested and a document_start script is registered for
// it. Removing the origin unregisters the script and drops the permission.

const SCOPE_KEY = "scope";          // array of origin patterns, e.g. "https://app.example.com/*"
const sent = new Map();             // tabId -> { names:Set, urls:Set }

async function getScope() {
  const o = await chrome.storage.local.get(SCOPE_KEY);
  return o[SCOPE_KEY] || [];
}

function scriptId(pattern) {
  // Registration ids must be stable across service-worker restarts, so derive
  // them from the pattern rather than a counter.
  return "dpf-" + pattern.replace(/[^a-z0-9]+/gi, "-");
}

async function registerFor(patterns) {
  if (!patterns.length) return;
  const existing = await chrome.scripting.getRegisteredContentScripts();
  const have = new Set(existing.map((s) => s.id));
  const wanted = [];
  for (const p of patterns) {
    const id = scriptId(p);
    if (have.has(id)) continue;
    // Two scripts per origin, and the split is not optional. The MAIN world can
    // reach the page's own window.fetch and Element.prototype.attachShadow but
    // has no chrome.* APIs; the ISOLATED world has chrome.* but sees only a
    // clean copy of the globals. They talk over window.postMessage.
    wanted.push(
      { id, js: ["src/main-world.js"], matches: [p], runAt: "document_start",
        allFrames: true, world: "MAIN" },
      { id: id + "-bridge", js: ["src/bridge.js"], matches: [p],
        runAt: "document_start", allFrames: true, world: "ISOLATED" },
    );
  }
  if (wanted.length) await chrome.scripting.registerContentScripts(wanted);
}

async function unregisterFor(pattern) {
  const id = scriptId(pattern);
  const existing = await chrome.scripting.getRegisteredContentScripts();
  const ids = existing.map((s) => s.id).filter((x) => x === id || x === id + "-bridge");
  if (ids.length) await chrome.scripting.unregisterContentScripts({ ids });
}

// Re-register on startup: registered scripts persist, but the stored scope is
// the source of truth and the two can drift if an update is interrupted.
chrome.runtime.onStartup.addListener(async () => registerFor(await getScope()));
chrome.runtime.onInstalled.addListener(async () => registerFor(await getScope()));

async function addScope(pattern) {
  const granted = await chrome.permissions.request({ origins: [pattern] });
  if (!granted) return { ok: false, error: "permission declined" };
  const scope = await getScope();
  if (!scope.includes(pattern)) {
    scope.push(pattern);
    await chrome.storage.local.set({ [SCOPE_KEY]: scope });
  }
  await registerFor([pattern]);
  return { ok: true, scope };
}

async function removeScope(pattern) {
  const scope = (await getScope()).filter((p) => p !== pattern);
  await chrome.storage.local.set({ [SCOPE_KEY]: scope });
  await unregisterFor(pattern);
  await chrome.permissions.remove({ origins: [pattern] });
  return { ok: true, scope };
}

function record(tabId, payload) {
  if (tabId == null) return;
  let e = sent.get(tabId);
  if (!e) sent.set(tabId, (e = { names: new Set(), urls: new Set() }));
  for (const n of payload.names || []) e.names.add(n);
  for (const u of payload.urls || []) e.urls.add(u);
}

// A navigation is a new page, but the traffic record is deliberately kept: the
// point of the tool is the names the application sent at some point during the
// session, not just since the last route change. Clearing is explicit, from the
// popup.
chrome.tabs.onRemoved.addListener((tabId) => sent.delete(tabId));

chrome.runtime.onMessage.addListener((msg, sender, reply) => {
  const tabId = sender.tab ? sender.tab.id : msg.tabId;
  switch (msg.type) {
    case "sent-params":
      record(tabId, msg);
      return false;
    case "get-sent":
      { const e = sent.get(msg.tabId);
        reply({ names: e ? [...e.names] : [], urls: e ? [...e.urls] : [] }); }
      return false;
    case "clear-sent":
      sent.delete(msg.tabId);
      reply({ ok: true });
      return false;
    case "get-scope":
      getScope().then((scope) => reply({ scope }));
      return true;
    case "add-scope":
      addScope(msg.pattern).then(reply);
      return true;
    case "remove-scope":
      removeScope(msg.pattern).then(reply);
      return true;
    default:
      return false;
  }
});
