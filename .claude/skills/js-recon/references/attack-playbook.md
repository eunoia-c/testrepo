# Attack playbook: parameter names and path signals

Reference behind `suggest_attacks.py`. The script inlines the relevant guidance
per endpoint; this is the longer form, plus the reasoning for the ranking.

## How to use a name-based signal

A parameter called `redirect_url` earns an SSRF and open-redirect test. It does
not constitute one, and it does not mean the server reads the parameter at all —
client code carries dead parameters, renamed fields and leftovers from previous
versions.

So the first move on any suggestion is always the same: **confirm the parameter
reaches server-side behaviour.** Change it to something benign but different and
look for any change in the response — status, length, content, timing. A
parameter that changes nothing is not worth a payload. This one check saves more
time than any other habit in this workflow.

## Parameter classes

### Object references — IDOR

`id`, `user_id`, `case_id`, `ref`, `guid`, and any path segment the client fills
from a variable.

Path-based references matter as much as query ones, and are easier to miss:
`/api/v1/cases/{id}` is the same bug shape as `?case_id=`.

Method matters. Applications commonly authorize the read and forget the write —
test `GET`, then `PUT`/`PATCH`/`DELETE` on the same reference. Also test the
*collection* endpoint alongside the item one; a properly authorized
`/cases/{id}` sitting next to an unfiltered `/cases?all=true` is common.

GUIDs are not an access control. They raise the cost of enumeration, nothing
more — look for a listing, export, search or notification endpoint that leaks
identifiers belonging to other users, then feed those in.

### URL parameters — SSRF and open redirect

`url`, `redirect`, `next`, `callback`, `target`, `image_url`, `webhook`, and the
short forms `u`, `r`, `to`.

Distinguish the two cases: SSRF is the *server* dereferencing the value, open
redirect is the *browser* following it. Same parameter names, different tests.

For SSRF, start with a listener you control to prove the server fetches at all,
then move to internal targets: cloud metadata (`169.254.169.254`), loopback,
RFC1918 ranges, and any internal hostnames the secrets scan turned up. Bypass
attempts worth trying when a filter blocks you: alternative schemes (`file://`,
`gopher://`, `dict://`), credential-in-host tricks (`http://allowed@evil`),
fragment tricks (`http://evil#allowed`), DNS rebinding, decimal and octal IP
encodings, and double URL-encoding.

For open redirect, test an absolute external URL, then protocol-relative
`//evil.com` (frequently missed by validators checking for `http`), then
`javascript:` — which turns the redirect into XSS where it survives.

### File parameters — path traversal

`file`, `path`, `template`, `download`, `page`, `include`.

Traversal at varying depths, URL-encoded and double-encoded, both separators on
Windows targets. Absolute paths sometimes work where relative traversal is
filtered. Where a filter strips `../` non-recursively, `....//` reconstitutes it.

The error text is often an oracle: "file not found" versus "access denied"
versus a generic failure distinguishes a path that resolved from one that did
not, which lets you map the filesystem without ever reading a file.

### Query construction — SQL and NoSQL injection

`q`, `filter`, `sort`, `order_by`, `column`, `where`.

**Sort and column parameters are the highest-yield in this class** and are worth
calling out separately: they land in `ORDER BY` or a column projection where
prepared-statement placeholders cannot be used, so developers concatenate them
even in codebases that parameterise everything else.

Confirm reachability with a valid alternative value first (sort by a different
real column), then escalate. For NoSQL, try operator injection as both JSON
(`{"$ne": null}`) and bracketed query syntax (`param[$ne]=`), since the two
reach different parsers.

### Privilege flags — mass assignment

`role`, `is_admin`, `status`, `approved`, `enabled`, `scope`, `tier`.

The reliable technique: take a request that legitimately updates your own
object, add the field even though the UI never sends it, and check persistence
in a subsequent read. To find candidate field names, diff what the client
*receives* against what it *submits* — fields present in responses but never in
requests are exactly the ones a binder may accept anyway.

Try nested placement (`{"user":{"role":"admin"}}`) and encoding switches
(form vs JSON), which sometimes bypass an allowlist applied at one level only.

### Value fields — business logic

`amount`, `price`, `quantity`, `discount`, `balance`.

Negative values, zero, extreme magnitudes, high-precision decimals, currency
substitution. The question is whether the server recomputes or trusts. Also
consider concurrency: two simultaneous submissions applying the same credit is a
race that single-request testing never finds.

### Auth material

`token`, `sig`, `otp`, `code`, `state`, `nonce`.

Remove it and see whether the request still works — that is the whole test more
often than it should be. Then: replay another session's value, truncate or
bit-flip a signature to learn whether it is verified or merely present, and for
OTP and reset codes check rate limiting and whether the code is bound to the
account it was issued for.

Credential material in a query string is worth reporting on its own: it lands in
server logs, proxy logs, browser history and `Referer` headers.

### Pagination

`limit`, `offset`, `page_size`, `take`.

Raise the bound well past what the UI offers and see whether the server caps it.
Negative and zero values sometimes disable the limit entirely. Confirm your
engagement scope before pulling large volumes — an uncapped limit is also a
denial-of-service, and demonstrating it is usually unnecessary.

### Callback parameters — JSONP and XSSI

`callback`, `jsonp`, `cb`.

If the response is served as JavaScript, reflects the callback name, returns
per-user data, and authenticates by cookie, then any origin can read that data
by including it as a script. That combination is the finding — check all four.
The callback name may also be unescaped, which is XSS in its own right.

### Debug flags

`debug`, `test`, `verbose`, `bypass`, `skip`, `force`.

Try `true`/`1`/`yes` on requests that currently fail or that hide detail. These
flags expand errors into stack traces, disable rate limits, or skip validation
steps. Cheap to test, occasionally decisive.

## Path signals

**`admin`, `internal`, `manage`, `backoffice`** — the highest-value signal in a
non-administrative bundle, because the privilege boundary to cross is already
identified. Test with your lowest-privilege account.

**`swagger`, `openapi`, `api-docs`, `graphiql`, `?wsdl`, `$metadata`** — the
single best request-to-value ratio in recon. A served API description enumerates
every operation including those the client never calls.

**`actuator`, `metrics`, `health`, `env`, `debug`, `trace`** — diagnostic
endpoints leak configuration and environment, and are routinely exempted from
the application's authentication filter because they are "just monitoring".
On ASP.NET specifically, check `Trace.axd` and `elmah.axd`.

**`graphql`** — try introspection; if disabled, field suggestions in error
messages often rebuild the schema anyway. Then check per-field authorization
(commonly enforced at the query root only) and query depth limits.

**Authentication flows** (`login`, `reset`, `oauth`, `sso`, `mfa`) — the
highest-impact logic bugs live here: reset tokens not bound to the requesting
account, `state` parameters unvalidated, MFA steps skippable by requesting the
post-MFA endpoint directly.

**`export`, `download`, `report`, `bulk`** — return more than the UI shows and
often accept wider filters than the screen offers.

**Multiple API versions** — an older version alongside a newer one is worth
testing precisely because it kept the authorization model it shipped with.
Compare the same operation across versions; the fix frequently landed in only
one. `suggest_attacks.py` flags this only when more than one version is actually
present, since `/v1/` alone says nothing.

## Ordering your work

The score orders a queue; it is not a severity. A sensible sequence:

1. **Credentials from the secrets scan.** If a key is live, that outranks
   everything else and the client needs to know now.
2. **Unauthenticated access on anything administrative or destructive.** Highest
   impact, cheapest test.
3. **IDOR on object references**, especially where a privilege boundary exists
   between your accounts.
4. **The named-parameter classes**, working down the score.
5. **DOM XSS candidates**, which need browser confirmation and take longer.

Confirm reachability before payloads throughout. Most of the value in this list
comes from the first two steps.
