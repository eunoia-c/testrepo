---
mode: agent
description: 'Rank endpoints and parameters by testing value and suggest concrete attacks for each.'
tools: ['codebase', 'search', 'editFiles', 'runCommands']
---

# Prioritise the attack surface

Turn the endpoint inventory into an ordered testing queue with concrete tests.
Read `endpoints.json` (and `secrets.json` if present); if they do not exist,
run `/js-endpoints` first.

## The habit that matters most

Before spending payloads on any parameter, **confirm it reaches server-side
behaviour**: change it to something benign but different and look for any change
at all in status, length, content or timing. Client bundles are full of dead
parameters, renamed fields and leftovers from previous versions. A parameter
that changes nothing is not worth a payload.

Lead with this when presenting results.

## Parameter classes

Match parameter names against these. A name is circumstantial evidence that
justifies a test — it is never a finding.

**Object references** — `id`, `user_id`, `case_id`, `ref`, `guid`, and any path
segment the client fills from a variable. **Path-based references count as much
as query ones**: `/api/cases/{id}` is the same bug shape as `?case_id=`, and it
is the most common form. Test every method: read is often authorized where
write and delete are not. GUIDs are not access control — they raise enumeration
cost, so look for a listing, export or notification endpoint leaking other
users' identifiers.

**URL parameters** — `url`, `redirect`, `next`, `callback`, `target`, `webhook`,
`image_url`, and short forms `u`, `r`, `to`. Two distinct tests: SSRF is the
*server* dereferencing the value, open redirect is the *browser* following it.
For SSRF, prove a fetch happens against your own listener, then try cloud
metadata (`169.254.169.254`), loopback, RFC1918, and any internal hostnames the
secrets pass found. Bypasses: alternate schemes, `http://allowed@evil`,
`http://evil#allowed`, decimal/octal IPs, double encoding. For open redirect,
test protocol-relative `//evil.com` (frequently missed) and `javascript:`.

**File parameters** — `file`, `path`, `template`, `download`, `page`,
`include`. Traversal at varying depths, encoded and double-encoded, both
separators on Windows, `....//` where `../` is stripped non-recursively.
Differing error text between "not found" and "access denied" is an oracle that
maps the filesystem without reading a file.

**Query construction** — `q`, `filter`, `sort`, `order_by`, `column`, `where`.
**Sort and column parameters are the highest-yield**: they land in `ORDER BY` or
a projection where placeholders cannot be used, so they get concatenated even in
codebases that parameterise everything else. For NoSQL, try operator injection
as both JSON (`{"$ne":null}`) and bracketed syntax (`param[$ne]=`).

**Privilege flags** — `role`, `is_admin`, `status`, `approved`, `enabled`,
`scope`, `tier`. Add the field to a request that legitimately updates your own
object even though the UI never sends it, then confirm persistence with a read.
To find candidates, diff what the client *receives* against what it *submits* —
fields in responses but never in requests are exactly the ones a binder may
accept anyway. Try nested placement and form-vs-JSON encoding switches.

**Value fields** — `amount`, `price`, `quantity`, `discount`, `balance`.
Negative, zero, extreme, high-precision, currency substitution. Does the server
recompute or trust? Also consider a race between concurrent submissions.

**Auth material** — `token`, `sig`, `otp`, `code`, `state`, `nonce`. Remove it
and see if the request still works. Replay another session's value. Truncate or
bit-flip a signature to learn whether it is verified or merely present.
Credential material in a query string is reportable on its own — it lands in
server logs, proxy logs, history and `Referer`.

**Pagination** — `limit`, `offset`, `page_size`, `take`. Raise well past what
the UI offers; negative or zero sometimes disables the bound entirely. Confirm
scope before pulling volume — an uncapped limit is also a denial of service and
demonstrating it is usually unnecessary.

**Callbacks** — `callback`, `jsonp`, `cb`. The finding needs all four of:
response served as JavaScript, callback name reflected, per-user data returned,
cookie authentication. Then any origin can read it. The callback name may also
be unescaped.

**Debug flags** — `debug`, `test`, `verbose`, `bypass`, `skip`, `force`. Try
`true`/`1` on requests that fail or that hide detail. Cheap, occasionally
decisive.

**Content type** — `format`, `output`, `alt`. Alternative serializers have
different escaping and sometimes different authorization wrappers.

## Path signals

- `admin`, `internal`, `manage`, `backoffice` — highest value in a
  non-administrative bundle, because the privilege boundary is already identified
- `swagger`, `openapi`, `api-docs`, `graphiql`, `?wsdl`, `$metadata` — best
  request-to-value ratio in recon; enumerates operations the client never calls
- `actuator`, `metrics`, `health`, `env`, `debug`, `trace`, and on ASP.NET
  `Trace.axd` / `elmah.axd` — routinely exempted from the auth filter
- `graphql` — introspection first; if disabled, error-message field suggestions
  often rebuild the schema. Then per-field authorization and depth limits
- auth flows (`login`, `reset`, `oauth`, `sso`, `mfa`) — highest-impact logic
  bugs: reset tokens not bound to the requesting account, unvalidated `state`,
  skippable MFA steps
- `export`, `download`, `report`, `bulk` — return more than the UI shows

**Multiple API versions** — only interesting when more than one is actually
present. A lone `/v1/` says nothing; a `/v1/` beside a `/v2/` is a real lead,
because the older route keeps the authorization model it shipped with and fixes
frequently land in only one. Check before flagging.

## Request shape

Destructive methods (`DELETE`, `PUT`, `PATCH`) deserve their own check plus verb
tampering (`X-HTTP-Method-Override`). WebSocket handshakes are not covered by
CORS, so replay one from an unrelated `Origin` — if it upgrades, that is
cross-site WebSocket hijacking; also check whether authorization exists
per-message or only at handshake. ASMX/WCF proxies: request the service root and
`?WSDL`, then call an operation the client never uses, and try alternate
bindings against operations filtered over JSON POST.

## Output

Write `attacks.json` and present a ranked table. For the top entries, give the
suggested tests with **why the name warrants it** and **how to run it**.

Say explicitly that the score orders a queue and is not a severity.

## Suggested order of work

1. Live credentials from the secrets pass — outranks everything, tell the client now
2. Unauthenticated access on anything administrative or destructive
3. IDOR on object references, especially across a privilege boundary
4. The named parameter classes, working down the ranking
5. DOM XSS candidates, which need browser confirmation and take longer
