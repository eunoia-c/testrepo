// Headless check of the parts that are easy to get wrong: the walker (closed
// shadow roots, templates, comments, noscript), the visibility classifier, and
// the request hooks. It loads src/main-world.js as a document_start init script
// in the page's own world -- the same place the extension runs it -- and drives
// the postMessage API the bridge would use.
//
//   node test/run_test.js
//
// Needs playwright. If a Chromium is already on disk, point CHROME_PATH at it
// rather than downloading one:
//
//   CHROME_PATH=/opt/pw-browsers/chromium-1194/chrome-linux/chrome \
//     node test/run_test.js

const { chromium } = require("playwright");
const path = require("path");
const fs = require("fs");

const ROOT = path.join(__dirname, "..");
const MAIN = fs.readFileSync(path.join(ROOT, "src", "main-world.js"), "utf8");
const PAGE = "file://" + path.join(__dirname, "hiding-mechanisms.html");

let failures = 0;
function check(desc, actual, expected) {
  const ok = JSON.stringify(actual) === JSON.stringify(expected);
  console.log(`  ${ok ? "ok  " : "FAIL"} ${desc}` +
    (ok ? "" : `  (got ${JSON.stringify(actual)}, want ${JSON.stringify(expected)})`));
  if (!ok) failures++;
}
function has(desc, set, name) { check(desc, set.includes(name), true); }

(async () => {
  // A pinned Chromium is often already on disk (CI images, this project's
  // container) while the installed playwright package expects a different
  // build. CHROME_PATH points at the one to use instead of downloading.
  const launch = {};
  if (process.env.CHROME_PATH) launch.executablePath = process.env.CHROME_PATH;
  const browser = await chromium.launch(launch);
  const page = await browser.newPage();
  await page.addInitScript(MAIN);          // document_start, page world
  const errors = [];
  page.on("pageerror", (e) => errors.push(String(e)));
  await page.goto(PAGE);
  await page.waitForTimeout(1200);          // the m_added_later timeout

  const ask = (type, arg = {}) => page.evaluate(([type, arg]) => new Promise((resolve) => {
    const rid = Math.random();
    const on = (ev) => {
      const d = ev.data;
      if (d && d.ch === "__dpf_v1" && d.dir === "up" && d.type === "result" && d.rid === rid) {
        removeEventListener("message", on);
        resolve(d.result);
      }
    };
    addEventListener("message", on);
    postMessage({ ch: "__dpf_v1", dir: "down", type, rid, ...arg }, "*");
  }), [type, arg]);

  console.log("== walker ==");
  const scan = await ask("scan");
  const names = scan.items.map((i) => i.name).filter(Boolean);

  check("no page errors from the hooks", errors, []);
  has("plain visible control", names, "m_visible");
  has("input[type=hidden]", names, "m_type_hidden");
  has("hidden attribute", names, "m_hidden_attr");
  has("display:none", names, "m_display_none");
  has("sr-only clip", names, "m_sr_only");
  has("off-screen", names, "m_offscreen");
  has("disabled", names, "m_disabled");
  has("inside collapsed details", names, "m_details_closed");
  has("inside closed dialog", names, "m_dialog_closed");
  has("added after load", names, "m_added_later");
  has("open shadow root", names, "m_open_shadow");
  has("CLOSED shadow root", names, "m_closed_shadow");
  has("inside <template>", names, "m_in_template");
  has("inside <noscript>", names, "m_in_noscript");
  has("inside an HTML comment", names, "m_in_comment");
  has("commented-out admin form field", names, "m_override_approval");

  console.log("== visibility classifier ==");
  const by = (n) => scan.items.find((i) => i.name === n) || { reasons: [] };
  check("visible control has no hide reason", by("m_visible").reasons, []);
  check("display:none is flagged", by("m_display_none").reasons.length > 0, true);
  check("hidden input names its own mechanism",
    by("m_type_hidden").reasons.includes("input[type=hidden]"), true);
  check("hidden input is not also 'zero-area'",
    by("m_type_hidden").reasons.includes("zero-area box"), false);
  check("disabled is flagged", by("m_disabled").reasons.includes("disabled"), true);
  check("readonly is flagged", by("m_readonly").reasons.includes("readonly"), true);
  check("closed shadow is labelled",
    by("m_closed_shadow").reasons.includes("inside a closed shadow root"), true);
  check("template content is labelled",
    by("m_in_template").reasons.includes("inside <template>"), true);
  check("context recorded for closed shadow", by("m_closed_shadow").context, "closed-shadow");

  console.log("== insertion points ==");
  const vis = by("m_visible");
  check("form method captured", vis.insertion.method, "POST");
  check("form action captured", vis.insertion.action, "/submit");
  check("validation attributes kept", by("m_pattern").attrs.pattern, "[0-9]{4}");

  console.log("== request hooks ==");
  await page.route("**/*", (r) => r.fulfill({ status: 200, body: "{}" }));
  await page.click("#xhr");
  await page.click("#json");
  await page.click("#beacon");
  await page.waitForTimeout(600);
  const after = await ask("scan");
  has("XHR query param observed", after.sent, "s_from_url");
  has("XHR urlencoded body observed", after.sent, "s_xhr_body");
  has("JSON body key observed", after.sent, "s_json_top");
  has("nested JSON key observed", after.sent, "s_json_nested");
  has("sendBeacon param observed", after.sent, "s_beacon");
  check("a hidden field was NOT sent", after.sent.includes("m_type_hidden"), false);

  // The whole point: named in the DOM, never transmitted.
  const neverSent = after.items
    .filter((i) => i.name && !after.sent.includes(i.name)).map((i) => i.name);
  has("hidden field lands in never-sent", neverSent, "m_type_hidden");
  has("commented field lands in never-sent", neverSent, "m_override_approval");
  check("the visible field that was submitted is excluded",
    neverSent.includes("m_visible"), true);   // not submitted in this run

  console.log("== form submit observation ==");
  // requestSubmit() runs interactive validation first, so an invalid control
  // means no submit event at all -- which is also why the fixture's pattern
  // field has to hold a valid value. preventDefault keeps the page loaded.
  await page.evaluate(() => {
    const f = document.getElementById("main");
    f.addEventListener("submit", (e) => e.preventDefault());
    f.requestSubmit();
  });
  await page.waitForTimeout(600);
  const post = await ask("scan");
  has("submit event names the visible field", post.sent, "m_visible");
  has("submit event names hidden fields too", post.sent, "m_type_hidden");
  check("disabled field is not reported as sent", post.sent.includes("m_disabled"), false);

  console.log("== reveal / enable ==");
  const rv = await ask("reveal", { ids: [] });
  check("reveal touched every node", rv.count > 25, true);
  const nowVisible = await page.evaluate(() =>
    document.querySelector('[name="m_display_none"]').checkVisibility(
      { checkOpacity: true, checkVisibilityCSS: true }));
  check("display:none field is visible after reveal", nowVisible, true);
  const hiddenBecameText = await page.evaluate(() =>
    document.querySelector('[name="m_type_hidden"]').type);
  check("hidden input became a text input", hiddenBecameText, "text");

  await ask("enable", { ids: [] });
  const stillDisabled = await page.evaluate(() =>
    document.querySelector('[name="m_disabled"]').disabled);
  check("disabled attribute cleared", stillDisabled, false);
  const maxlen = await page.evaluate(() =>
    document.querySelector('[name="m_pattern"]').hasAttribute("maxlength"));
  check("maxlength cleared", maxlen, false);

  await ask("unreveal");
  const reverted = await page.evaluate(() =>
    document.querySelector('[name="m_display_none"]').hasAttribute("data-dpf-revealed"));
  check("revert removes the marker attribute", reverted, false);

  console.log("== raw request ==");
  const target = post.items.find((i) => i.name === "m_visible");
  const raw = await ask("rawRequest", { id: target.id });
  check("builds a POST request line", /^POST \/submit HTTP\/1\.1/.test(raw.raw), true);
  check("includes a Host header", /\r\nHost: /.test(raw.raw), true);
  check("body carries the hidden field", /m_type_hidden=1/.test(raw.raw), true);
  check("body carries the disabled field", /m_disabled=1/.test(raw.raw), true);
  check("Content-Length matches the body",
    (() => {
      const m = raw.raw.match(/Content-Length: (\d+)\r\n\r\n([\s\S]*)$/);
      return m && Number(m[1]) === m[2].length;
    })(), true);

  await browser.close();
  console.log(failures ? `\n${failures} check(s) failed.` : "\nAll checks passed.");
  process.exit(failures ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(2); });
