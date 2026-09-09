# ASP.NET, WebForms and `.axd` surface

Reference for targets built on ASP.NET. Read when the app serves `.aspx`,
`.asmx`, `.ashx`, `.svc` or `.axd`, or when the extractor reports postback
targets.

## `.axd` resource handlers

`ScriptResource.axd` and `WebResource.axd` are HTTP handlers that serve
resources embedded in assemblies — scripts, images, CSS compiled into a DLL
rather than living on disk.

A typical reference:

```
/ScriptResource.axd?d=<encrypted-payload>&t=<timestamp>
```

The `d` parameter identifies the resource and is encrypted with the machine
key. That fact is the reason these handlers matter:

- **They serve real application JavaScript.** The Microsoft AJAX client
  libraries and any embedded custom scripts arrive this way. Save the responses
  and run them through `extract_endpoints.py` — WebForms apps often expose their
  service proxies here and nowhere else.
- **They leak framework internals.** Resource names and assembly references
  disclose the framework version and sometimes third-party component versions,
  which is your input for version-to-CVE mapping.
- **They have exploit history.** The `d` parameter is machine-key-encrypted,
  which historically made these handlers the delivery point for padding-oracle
  attacks against ASP.NET (notably the 2010 padding oracle work, MS10-070).
  Whether a given target is affected depends entirely on the framework version
  and patch level — establish that first rather than assuming.

Practical checks: request a handler with a malformed `d`, a truncated `d`, and
a `d` from a different page, and compare the error responses. Distinct errors
for "cannot decrypt" versus "decrypted but resource not found" is the shape of
an oracle. Confirm the version before drawing any conclusion.

## ViewState

`__VIEWSTATE` carries serialized page state in a hidden form field.

- **Is it MAC-protected?** `enableViewStateMac` has been enforced by default
  since the mid-2010s patches, but legacy apps and explicit config overrides
  exist. Unprotected ViewState is a deserialization sink and a well-known path
  to RCE.
- **Is it encrypted?** Unencrypted ViewState is base64 and readable — decode it
  and look for what the developer stashed there. Application state, user
  identifiers, role flags and connection details all turn up in ViewState more
  often than anyone would like.
- **`__VIEWSTATEGENERATOR`** identifies the page class and is useful for
  correlating pages.

Decode first, then decide. A readable ViewState carrying a role or permission
value is a tampering test even when the MAC is intact — the question becomes
whether the MAC actually covers the field you want to change.

## Postback forgery

`__doPostBack('ctl00$Main$btnDelete','')` names a server-side control. The
browser posts to the current page with `__EVENTTARGET` set to that control ID.

The test: submit a postback for a control the UI never renders for your role.
WebForms authorization is frequently implemented by conditionally rendering
controls — `btnApprove.Visible = user.IsManager` — with no check in the handler
itself. If the server processes `__EVENTTARGET=ctl00$Main$btnApprove` from a
non-manager, the control was the only gate.

Build such a request from a captured legitimate postback: keep `__VIEWSTATE`,
`__VIEWSTATEGENERATOR` and `__EVENTVALIDATION` intact and change only
`__EVENTTARGET`. Note that `__EVENTVALIDATION`, when enabled, is precisely the
control designed to stop this, so a rejection there is the framework working —
and its *absence* is itself worth reporting.

## ASMX and WCF service proxies

`Sys.Net.WebServiceProxy.invoke("/Services/Account.asmx", "GetBalance", ...)`
in client script maps to a callable endpoint:

```
POST /Services/Account.asmx/GetBalance HTTP/1.1
Content-Type: application/json; charset=utf-8

{"acct":"FUZZ"}
```

Things worth testing on these:

- **The service description.** `GET /Services/Account.asmx` usually renders a
  human-readable operation list, and `?WSDL` gives the full contract — including
  operations the client script never calls. That is free enumeration.
- **Per-operation authorization.** Service classes commonly carry one
  authorization attribute at class level, or none at all, with the developer
  assuming the client only calls what the UI exposes.
- **Protocol switching.** An operation reachable as JSON POST may also accept
  SOAP or an HTTP GET, and the alternate binding sometimes skips filters
  attached to the primary one.

`PageMethods.<Name>()` is the same idea scoped to a page: a `[WebMethod]` on the
code-behind, called as `POST /page.aspx/<Name>` with a JSON body. Static methods
with `[WebMethod]` bypass page-level lifecycle checks, which is exactly why
authorization is often missing on them.

## Handlers and services

- `.ashx` — generic handlers. Often used for file download and image serving,
  which makes them a recurring source of IDOR and path traversal.
- `.svc` — WCF endpoints; check for a `?wsdl` or `/mex` metadata endpoint.
- `Trace.axd` — the ASP.NET trace viewer. If it is enabled and reachable it
  dumps request details, session contents and server variables for recent
  requests. Always worth a single request to check; it is a serious information
  disclosure when left on.
- `elmah.axd` — ELMAH error log. Not part of the framework but extremely common,
  and frequently unauthenticated. It exposes full stack traces and often session
  and form data captured at the time of the error.

Both `Trace.axd` and `elmah.axd` are single-request checks with high payoff —
include them in any wordlist for an ASP.NET target.
