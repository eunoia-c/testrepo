// ISOLATED world, document_start. Pure relay.
//
// The MAIN world has the page's globals but no chrome.* APIs; this half has
// chrome.* but cannot see the page's fetch or its closed shadow roots. So all
// the work happens over there and all the messaging happens here.
(() => {
  const CH = "__dpf_v1";
  const waiting = new Map();
  let rid = 0;

  window.addEventListener("message", (ev) => {
    const d = ev.data;
    if (!d || d.ch !== CH || d.dir !== "up") return;

    if (d.type === "result") {
      const r = waiting.get(d.rid);
      if (r) { waiting.delete(d.rid); r(d.result); }
      return;
    }
    if (d.type === "sent-params") {
      // Fire and forget; the service worker keeps the per-tab record.
      chrome.runtime.sendMessage({ type: "sent-params", names: d.names, urls: d.urls })
        .catch(() => { /* worker asleep or context torn down */ });
    }
  });

  function ask(type, arg) {
    return new Promise((resolve) => {
      const id = ++rid;
      waiting.set(id, resolve);
      window.postMessage({ ch: CH, dir: "down", type, rid: id, ...arg }, "*");
      // A page that has stomped on postMessage should not hang the popup.
      setTimeout(() => {
        if (waiting.has(id)) { waiting.delete(id); resolve({ error: "timeout" }); }
      }, 4000);
    });
  }

  chrome.runtime.onMessage.addListener((msg, _sender, reply) => {
    if (!msg || !msg.dpf) return false;
    ask(msg.dpf, msg).then(reply);
    return true;                    // async reply
  });
})();
