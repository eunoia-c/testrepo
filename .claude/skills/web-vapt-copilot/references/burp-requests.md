# Burp-ready raw requests

`request` emits a raw HTTP/1.1 message, not a curl command: CRLF line endings, a blank
line before the body, and a `Content-Length` computed over the UTF-8 encoded body.

## Getting it into Burp

- **Repeater** — select the request pane and paste. Or *right-click → Paste from file*
  when you used `-o`.
- **New tab from scratch** — Repeater → `+` → paste over the placeholder. Set the target
  host/port and the TLS checkbox in the top-right panel; the `Host` header alone does not
  set the connection target.
- **Intruder** — paste, then mark positions. `FUZZ` placeholders are there to be marked.
- **From the file** — `-o req.txt` writes exactly what goes on the wire.

Repeater recalculates `Content-Length` on edit by default, but the emitted value is
already correct, so an unmodified paste is safe to send as-is.

## Options

| Flag | Use |
|---|---|
| `-e`, `--endpoint` | look the path up in `results.json` (params and method come with it) |
| `--url` | build from a literal URL, no scan needed |
| `-X` | override the method |
| `--host` | set the `Host` header when the endpoint was relative |
| `--auth` | `Authorization` value, e.g. `"Bearer eyJ..."` |
| `--cookie` | `Cookie` value |
| `-H` | extra header, repeatable |
| `--body` / `--body-file` | explicit body |
| `--content-type` | override the inferred type |
| `--no-auth` | emit only the credential-stripped variant |
| `--pair` | emit both variants as `<name>_authed.txt` and `<name>_unauth.txt` |
| `--referer`, `--accept` | override those headers |
| `--http2-style` | `Connection: close` instead of `keep-alive` |

## What gets filled in

- Path placeholders (`/users/{id}`) get a sensible default — `id`→`1`, `email`→
  `test@example.com`, `page`→`1`. Unknown names become `FUZZ`.
- Query parameters recovered from the literal are preserved verbatim; they are not
  duplicated into the body.
- For `POST`/`PUT`/`PATCH`, body parameters found at the call site become a JSON object.
  With no recovered parameters the body is `{}` — replace it with a real one captured
  from the app.
- `X-Requested-With: XMLHttpRequest` is included because most of these endpoints are
  XHR-only and some frameworks reject requests without it.

**Every credential in the output is a placeholder.** Replace `REPLACE_ME` and any
example token with material captured from the live session. Do not ship a request that
still contains a placeholder and expect a meaningful response.

## The paired-request test

```bash
python3 jsvapt.py request results.json -e /api/v2/invoices --pair \
  --host app.target.tld --auth "Bearer <real token>" --cookie "SESSION=<real>" -o inv.txt
```

Send `inv_authed.txt` first to establish the baseline, then `inv_unauth.txt`. Use
Comparer on the responses. Equal responses carrying real data is the finding; differing
status or an error body is the control working.

`--pair` strips `Authorization`, `Cookie`, `X-Api-Key`, `X-Auth-*` and `X-CSRF-*` from
the second request, including any you passed with `-H`.

## Hand edits worth making

**Method override** — when `PUT`/`DELETE` are blocked at the proxy:

```
POST /api/v2/users/1 HTTP/1.1
X-HTTP-Method-Override: DELETE
```

Also try `X-Method-Override`, `X-HTTP-Method`, and a `_method=DELETE` body field.

**Multipart upload** — for `.ashx`/upload handlers, build the body by hand:

```
Content-Type: multipart/form-data; boundary=----X

------X
Content-Disposition: form-data; name="file"; filename="t.txt"
Content-Type: text/plain

marker
------X--
```

Let Repeater fix `Content-Length` after editing, or recount it.

**Content-type confusion** — resend a JSON body as
`application/x-www-form-urlencoded`, or a form body as JSON. Different parsers behind
one route sometimes have different authorization filters.

**Header case and duplication** — some stacks read the first `Authorization` header and
others the last; sending two is a quick check for a proxy/app disagreement.

## Scope discipline

Only send requests to hosts named in the engagement scope. Check the `Host` line before
sending — a copied request that still points at a previous target is the classic
out-of-scope incident. Destructive verbs (`DELETE`, bulk `POST`) on production need
explicit sign-off first.
