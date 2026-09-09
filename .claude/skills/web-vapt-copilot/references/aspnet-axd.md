# ASP.NET, WebForms and `.axd` handlers

`.axd` paths are handlers registered in `web.config`, not files on disk. They serve
JavaScript, images and diagnostics, and they are a distinctive part of the ASP.NET
attack surface.

## Capturing `.axd` content

`ScriptResource.axd?d=<encrypted>&t=<timestamp>` and `WebResource.axd?d=<encrypted>`
return embedded assembly resources — usually JavaScript. Each distinct `d=` value is a
different resource, so collect every one referenced in the page HTML:

```bash
grep -oE '(ScriptResource|WebResource)\.axd\?[^"'\'']+' page.html | sort -u
```

Save each response body as a separate file. `scan` analyses `.axd` as JavaScript, so the
extracted endpoints, sinks and secrets flow into the same report.

## Handlers worth checking

| Handler | Why |
|---|---|
| `ScriptResource.axd` | Padding oracle in unpatched builds (CVE-2010-3332). Also enumerable resource references. |
| `WebResource.axd` | Same family; embedded resource enumeration. |
| `Telerik.Web.UI.WebResource.axd` | CVE-2017-9248 (weak dialog parameter encryption) and CVE-2019-18935 (insecure deserialisation → RCE). Version-dependent. |
| `Telerik.Web.UI.DialogHandler.aspx` | File manager / upload dialogs; historic arbitrary upload. |
| `Telerik.Web.UI.SpellCheckHandler.axd` | Part of the same deserialisation chain. |
| `elmah.axd` | Error log. Frequently unauthenticated; leaks stack traces, cookies, session IDs. Check `/elmah.axd/download` for the full CSV. |
| `trace.axd` | ASP.NET trace viewer. Leaks headers, cookies and server variables per request. |
| `Reserved.ReportViewerWebControl.axd` | SSRS ReportViewer; information disclosure history. |
| `CrystalImageHandler.aspx` | Crystal Reports; directory traversal history. |

`elmah.axd` and `trace.axd` are the highest-value quick wins: both are pure information
disclosure, non-destructive to check, and often left enabled in production.

**All of these are version-dependent.** Establish the framework and control versions
before testing. The deserialisation paths (CVE-2019-18935 in particular) execute code on
the target — treat them as destructive and get explicit written sign-off first.

## WebForms

**`__doPostBack(target, argument)`** — every control that calls it is a server-side entry
point. `__EVENTTARGET` and `__EVENTARGUMENT` are attacker-controlled form fields. Enumerate
the targets from the bundle:

```bash
grep -oE '__doPostBack\([^)]*\)' *.js *.axd | sort -u
```

Then post an `__EVENTTARGET` for a control the UI does not render for your role — the
server may still dispatch it. That is a function-level authorization test.

**ViewState** — `__VIEWSTATE` plus `__VIEWSTATEGENERATOR` and `__EVENTVALIDATION`.

- Decode it first (`viewstate` tooling or base64 + BinaryFormatter parsing) to see what
  the app round-trips through the client. Sensitive data in ViewState is a finding on
  its own.
- If MAC is disabled (older `enableViewStateMac="false"`), it is tamperable.
- Deserialisation gadget chains require a known `machineKey`, which usually means a
  separate disclosure (a leaked `web.config`, a public key from a shared hosting image).
  Do not attempt without sign-off.

**`PageMethods.X`** — ASP.NET AJAX page methods. Each is a `[WebMethod]` on the hosting
`.aspx`, callable directly:

```
POST /Admin/Users.aspx/DeleteUser HTTP/1.1
Content-Type: application/json; charset=utf-8

{"userId":1}
```

`[WebMethod]` authorization is declared per method, so a page-level check does not
necessarily protect it. This is a frequent BFLA source — test every recovered method
unauthenticated.

**`Sys.Net.WebServiceProxy`** — the generated proxy for an `.asmx`/`.svc` service. The
generated JavaScript lists every operation and its arity, which is a free API inventory.
Also try `/Service.asmx?WSDL` and `/Service.asmx?op=Method` for the built-in
documentation pages.

**SignalR** — `/signalr/hubs` returns the generated hub proxy naming every server method.
Authorization on hub methods is separate from the HTTP surface and is often weaker.

## Fingerprinting notes

`X-AspNet-Version`, `X-AspNetMvc-Version` and `X-Powered-By` response headers pin the
version. `.aspx`, `.asmx`, `.ashx`, `.svc` extensions and an `ASP.NET_SessionId` cookie
confirm the stack. Report verbose version headers as an information-disclosure finding
in their own right.

## Path variants to try on any ASP.NET route

Cookieless session paths (`/(S(...))/`), the `:80` port suffix trick, trailing dots, and
`%20` before the extension have all historically bypassed path-based authorization rules
in IIS. Worth a quick pass against any endpoint that returns 401/403.
