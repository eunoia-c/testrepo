# Raw HTTP requests for Burp Repeater

Reference for `make_request.py` output and the workflow around it.

## Why raw HTTP and not curl

Repeater accepts a pasted raw HTTP message directly. A curl command has to be
mentally translated back into a request before it is useful there, and the
translation loses exactly the details that matter in testing — header order,
duplicate headers, unusual whitespace, a deliberately wrong `Content-Length`.
When a tester asks for something to paste into Burp, give them the message.

## What a well-formed request needs

```
POST /api/v1/cases/42 HTTP/1.1
Host: app.example.com
User-Agent: Mozilla/5.0 ...
Accept: application/json
Content-Type: application/json
Cookie: SESSION=...
Content-Length: 27

{"status":"approved"}
```

The details that break things when wrong:

- **CRLF line endings** (`\r\n`), including the blank line separating headers
  from body. The generator writes these; if you hand-edit in another tool,
  check it did not normalize them to LF.
- **`Content-Length` must match the body's byte count**, not its character
  count — they differ as soon as the body contains non-ASCII. Burp will fix
  this for you on send if "Update Content-Length" is enabled, which is the
  default and usually what you want. Turn it off deliberately when the
  mismatch *is* the test (request smuggling, parser differentials).
- **`Host` must match the target** you are sending to, or you will get a
  virtual-host mismatch rather than the response you expected.
- **No `Accept-Encoding: gzip`** unless you want to read compressed responses.
  The generator omits it.

## The authorization test

This is the primary workflow the tool exists for:

```bash
python3 scripts/make_request.py endpoints.json \
    --burp-index burp_index.json --id e004 --both
```

`--both` emits the same request twice — once as captured with credentials,
once with `Authorization`, `Cookie`, API-key and CSRF-token headers removed.
Send both, compare.

Interpreting the comparison:

- **Same status, same body** → the credential is not being checked. Broken
  access control; verify it is not a public endpoint by design before reporting.
- **401/403 without credentials** → enforcement is working on this path.
- **Different status, similar body length** → look closely. A 200 with an error
  document is a denial; a 302 to a login page is a denial. Neither is a finding.
- **500 without credentials** → the handler is dereferencing an identity it
  assumed was there. Not access control, but a real robustness bug and often a
  stack trace worth reading.

Change one thing at a time. Strip only `Authorization` and keep `Cookie`, then
the reverse, to learn which credential the server actually reads. A request
that fails with both removed tells you far less than two that isolate each.

## Getting realistic headers

Pass `--burp-index` and headers are lifted from a real captured request to that
path. This matters more than it seems:

- Some frameworks reject requests without `X-Requested-With` on AJAX routes.
- WAFs profile `User-Agent` and header ordering; a synthetic set can get you
  blocked in a way that looks like the endpoint denying you.
- Custom headers (`X-Tenant-Id`, `X-App-Version`, correlation IDs) are often
  load-bearing, and you will not guess them.

If a generated request behaves oddly, capture a real one in Proxy and diff the
two before concluding anything about the endpoint.

## Filling parameters

`{param}`, `{id}` and `{guid}` in a path are placeholders the extractor
inserted where the client concatenated a variable. `--param-value` sets what
they become (default `FUZZ`):

```bash
--param-value 1001          # a plausible ID for IDOR testing
--param-value FUZZ          # a marker for Intruder positions
```

For IDOR work, generate with a known-good ID from your own account first,
confirm the request works, then pivot the ID in Repeater. Generating with a
guessed ID and getting a 404 tells you nothing about authorization.

## Batch generation

```bash
python3 scripts/make_request.py endpoints.json --burp-index burp_index.json \
    --verdict no_auth_indicator --verdict explicit_no_credentials \
    --both --out-dir reqs/
```

One `.txt` per request per variant. Paste them into Repeater tabs, or feed the
directory to whatever harness you use. Keeping the authed and no-auth variants
as separate files makes the comparison reproducible when you write it up —
attach both to the finding.

## A note on generated bodies

When there is no observed body to reuse, the generator builds one from the
parameter names it recovered, filling each with the marker value. That is a
starting point, not a valid request: real APIs want correct types, required
fields you have not discovered, and often a nested structure. Expect to fix the
body by hand against a real captured example. `--regenerate-body` forces a
synthetic body even when a real one was captured, which is occasionally what
you want when the captured body is huge.
