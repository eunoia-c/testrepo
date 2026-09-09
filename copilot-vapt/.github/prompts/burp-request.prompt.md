---
mode: agent
description: 'Build raw HTTP requests ready to paste into Burp Repeater, including credential-stripped variants for authorization testing.'
tools: ['codebase', 'search', 'editFiles']
---

# Build a Burp Repeater request

Produce **raw HTTP**, never curl. Repeater takes a pasted request verbatim; a
curl command has to be translated back into a request before it is useful there,
and the translation loses exactly the details that matter — header order,
duplicate headers, unusual whitespace, a deliberately wrong `Content-Length`.

Ask which endpoint if it is not clear. Read `endpoints.json` for the path,
method and parameters, and `burp_index.json` for real observed headers if it
exists.

## Format

```
POST /api/v1/cases/42 HTTP/1.1
Host: app.example.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36
Accept: application/json, text/javascript, */*; q=0.01
X-Requested-With: XMLHttpRequest
Content-Type: application/json
Cookie: SESSION=...
Connection: close
Content-Length: 24

{"status":"approved"}
```

Details that break things when wrong:

- **CRLF line endings**, including the blank line before the body. If you write
  the request to a file, write `\r\n` explicitly.
- **`Content-Length` must match the body's byte count**, not character count —
  they differ as soon as the body has non-ASCII. Burp's "Update Content-Length"
  fixes this on send and is on by default; turn it off deliberately when the
  mismatch *is* the test (smuggling, parser differentials).
- **No `Accept-Encoding: gzip`** unless compressed responses are wanted.
- `Host` must match the target actually being sent to.

## Always offer the credential-stripped pair

This is the point of the exercise for authorization testing. Emit the request
twice: once as captured, once with `Authorization`, `Cookie`, API-key and
CSRF-token headers removed. The comparison is the test.

How to read the result:

- Same status, same body → the credential is not being checked. Verify it is not
  public by design, then it is broken access control.
- 401/403 without credentials → enforcement is working on this path.
- Different status but similar body length → look closely. A 200 carrying an
  error document, or a 302 to a login page, is a denial.
- 500 without credentials → the handler dereferenced an identity it assumed was
  there. Not access control, but a real bug and often a stack trace worth reading.

Change one thing at a time: strip only `Authorization` keeping `Cookie`, then
the reverse, to learn which credential the server actually reads.

## Prefer real captured headers

When a Burp export is available, lift headers from an actual observed request to
that path. Some frameworks reject AJAX routes without `X-Requested-With`; WAFs
profile `User-Agent` and header ordering; custom headers like `X-Tenant-Id` are
often load-bearing and cannot be guessed. If a generated request behaves oddly,
capture a real one and diff before concluding anything about the endpoint.

## Bodies

Build from recovered parameter names, matching the content type — JSON object,
form encoding, or a SOAP envelope for ASMX. Say clearly that a generated body is
a starting point: real APIs want correct types, required fields not yet
discovered, and often nested structure. Expect to fix it against a real captured
example.

## Placeholders

For IDOR testing, generate with a **known-good identifier from the tester's own
account** first and confirm the request works. Generating with a guessed ID and
getting a 404 tells you nothing about authorization. Pivot the ID in Repeater
once the baseline is established.
