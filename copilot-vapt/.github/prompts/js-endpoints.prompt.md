---
mode: agent
description: 'Recover every HTTP endpoint from JavaScript, .axd resources, bundles and Burp exports, annotated with authorization evidence.'
tools: ['codebase', 'search', 'editFiles', 'runCommands']
---

# Recover the endpoint inventory

Build a complete inventory of HTTP endpoints referenced by the client-side code
in this workspace, and record what authorization evidence sits at each call.

Ask which files to analyse if it is not obvious. If the tester has a Burp
export, handle that first — see the last section.

## Approach

Read the files directly if they are small and formatted. If they are minified
(one very long line, mangled names), do **not** try to read them into context:
write a Python script, run it, and work from its JSON output. Save the script
as `analyse_endpoints.py` so it can be re-run as new bundles arrive.

## What to extract

**Request call sites** — these are the highest-confidence records because they
carry the method and the authorization context:

- `fetch(...)`, `XMLHttpRequest` with `.open(METHOD, url)`
- jQuery: `$.ajax({url, type})`, `$.get`, `$.post`, `$.getJSON`, `$.load`
- `axios.get/post/put/patch/delete/request`, bare `axios(...)`
- Angular `HttpClient`: `http.get/post/...`
- `navigator.sendBeacon`, `new WebSocket`, `new EventSource`
- ASP.NET: `Sys.Net.WebServiceProxy.invoke("/Svc.asmx", "Operation", ...)`,
  `PageMethods.<Name>()`, `__doPostBack('<control>', ...)`

**Endpoint-shaped string literals** with no call site — paths starting `/`,
absolute URLs, and anything containing `api/`, `/v1/`, `.aspx`, `.asmx`,
`.ashx`, `.svc`, `.axd`, `.json`, `.do`.

**One technique worth getting right:** to attribute a method and its
authorization headers to the correct call, capture the call's own argument list
by walking balanced parentheses (skipping over string bodies), not by taking a
fixed number of characters after the call. A fixed window reaches into the
*next* call and confidently mislabels it — an options object 300 characters
later belongs to something else.

## Normalizing

Collapse dynamic segments so endpoints group sensibly: `${...}` and
`'/users/' + id` become `{param}`, `/:id` becomes `{param}`, long numeric
segments become `{id}`, GUIDs become `{guid}`.

Watch for truncated concatenation fragments. `'/api/users/' + id` produces both
a literal `/api/users/` and a call-site `/api/users/{param}`; report only the
latter. The tell is a trailing `/`, `=`, `?` or `&` — a complete path rarely
ends that way. Do not over-apply this: `/api/cases` next to `/api/cases/{param}`
is two genuine endpoints and both should survive.

## Authorization annotation

For each endpoint, record what the client shows and classify it:

| Verdict | Condition |
| --- | --- |
| `auth_at_callsite` | `Authorization`, `X-API-Key`, or a `Bearer`/`Basic` literal in this call |
| `cookie_auth_likely` | `credentials: 'include'`/`'same-origin'`, or `withCredentials: true` |
| `csrf_only` | CSRF/XSRF/RequestVerificationToken header but no authentication header |
| `explicit_no_credentials` | `credentials: 'omit'` or `withCredentials: false` |
| `no_callsite_auth_global_present` | Nothing at the call, but the bundle installs auth globally |
| `no_auth_indicator` | Nothing at the call and no global mechanism |
| `unknown_no_callsite` | Bare string literal, no call to judge |

Also scan for **bundle-wide mechanisms**, which explain why most call sites look
bare: `axios.interceptors.request.use`, `axios.defaults.headers`,
`$.ajaxSetup`, `beforeSend`, Angular `HttpInterceptor`, MSAL/ADAL token
acquisition, and tokens read from `localStorage`/`sessionStorage`.

These verdicts rank **testing effort**, not risk. The server may enforce
authorization perfectly regardless of what the client sends — say so when
presenting the results.

## Burp exports

If a Burp sitemap or proxy XML export is present, process it first. Each `item`
carries base64 `request` and `response` elements. Two reasons it outranks loose
files: it contains bundles served *behind authentication* that cannot be fetched
anonymously, and it records real request headers.

Write every script/JSON response body to a directory, then analyse those files
too. Build a second index of observed requests — method, path, headers, status —
recording for each path whether it was ever seen carrying an authorization
header or cookie. An endpoint observed answering *without* a credential is far
stronger evidence than the client merely not attaching one.

## Output

Write `endpoints.json`: each endpoint with id, method (and whether the method
was explicit or inferred), normalized path, raw path, parameters, source
`file:line`, discovery mechanism, and the authorization verdict. Include the
bundle-wide mechanisms, `.axd` references, and postback/PageMethods targets as
separate lists.

Then summarise in chat: how many endpoints, the verdict breakdown, anything
that stands out (admin paths, multiple API versions, a source map reference),
and what you would test first.
