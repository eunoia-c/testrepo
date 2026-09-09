# Authorization testing from the recovered surface

Static analysis nominates candidates. This is how the tester confirms them.
Everything here is executed by the tester in Burp, not by the assistant.

## Why `none-observed` is a lead, not a finding

The bucket means *the client attaches no credential material at this call site*. It does
not mean the server allows anonymous access, because:

- a session cookie is sent by the browser automatically, with nothing in the JS
- a reverse proxy or API gateway may inject the credential upstream
- the header may be attached by a helper the analysis could not associate with the call

The inference is still worth acting on: it is the shortlist, ordered by how much the
endpoint would matter if it really is open.

## The matrix

For each candidate, run every row and record the status code, length, and whether real
data came back.

| # | Request | A pass looks like | A finding looks like |
|---|---|---|---|
| 1 | As the intended user | 200 with data | (baseline) |
| 2 | All credentials removed | 401/403 | 200 with real data → **broken function-level authz** (API5, WSTG-ATHZ-01) |
| 3 | As a different user, same role | 403, or only their own data | victim's data → **BOLA** (API1, WSTG-ATHZ-04) |
| 4 | As a lower-privileged user | 403 | 200 → **privilege escalation** (WSTG-ATHZ-02) |
| 5 | Identifier changed to another tenant's | 403/404 | 200 → cross-tenant BOLA |
| 6 | Alternate verb on the same path | 405 | 200 → verb-specific gating gap |
| 7 | `X-HTTP-Method-Override: DELETE` on a POST | ignored | executed → override bypass |

Generate rows 1 and 2 directly:

```bash
python3 jsvapt.py request results.json -e /admin/export/customers --pair \
  --host app.target.tld --auth "Bearer <token>" -o exp.txt
```

## Diffing responses honestly

A 200 alone is not the finding. Check that the body actually contains the protected
resource — many apps return 200 with an empty list or a generic shell to anonymous
callers. In Burp, use Comparer on the two responses and confirm the *data* is present,
then re-fetch as the victim to prove it is their record.

Watch for soft failures: a 302 to `/login`, a 200 carrying a login page, or a JSON
`{"error":"unauthorized"}` with a 200 status. Judge by body, not status line.

## Identifier tampering

Endpoints whose path carries `{id}` are scored higher for exactly this reason.

- **Sequential integers** — walk them; a hit on a record you do not own is BOLA.
- **UUIDs** — not a control by themselves. Look for the ID leaking in a list endpoint,
  a search response, an export, or another user's public profile, then replay it.
- **Encoded IDs** — base64, hex or a hashid is obfuscation, not authorization. Decode,
  increment, re-encode.
- **Mass assignment** — add `role`, `isAdmin`, `userId`, `tenantId`, `ownerId` to a body
  the client does not send and see whether the server honours them. Body parameter names
  from the bundle (`wordlist --mode params`) are the input for this.

## Verb and path variants worth trying

Only one shape is often protected:

```
GET  /api/v2/users/1        200
PUT  /api/v2/users/1        401   <- protected
POST /api/v2/users/1/update 200   <- not
```

Also try: trailing slash, `.json` suffix, `%2e%2e`, case changes (`/Admin` vs `/admin`),
duplicated slashes, and the path with a matrix parameter appended. These probe the gap
between the routing layer and the authorization filter.

## Client-side authorization checks

`scan` flags `isAdmin`, `hasRole`, `canEdit`, `permissions.includes` and similar. Any UI
element gated only by these is a direct test case: the endpoint behind the hidden button
is reachable regardless of what the client renders. Extract the gated call and run the
matrix on it.

## Recording the result

For each confirmed finding capture: the exact request (both variants), both responses,
the identity used, and the specific data that crossed a boundary. That evidence set is
what the write-up needs — see `reporting.md`.
