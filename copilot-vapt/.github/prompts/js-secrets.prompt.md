---
mode: agent
description: 'Find hardcoded credentials, API keys, JWTs and sensitive disclosures in client-side code.'
tools: ['codebase', 'search', 'editFiles', 'runCommands']
---

# Find secrets and sensitive disclosures

Everything in client-side code is downloaded by anyone who can reach the
application, so anything embedded there should be treated as public.

## Tier findings by what the evidence actually proves

This matters more than coverage. A report with 300 hits, nearly all
placeholders and minified identifiers, gets skimmed and binned — so be
deliberate about what you promote.

**confirmed** — a provider-specific format that essentially cannot be anything
else:

- AWS access key ID: `(AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA|APKA)[0-9A-Z]{16}`
- GitHub: `gh[porus]_[A-Za-z0-9]{36}`, `github_pat_...`; GitLab `glpat-...`
- Slack: `xox[baprs]-...`, and `hooks.slack.com/services/T.../B.../...`
- Google: `AIza[0-9A-Za-z_\-]{35}`, `*.apps.googleusercontent.com`
- Stripe `(sk|rk)_(live|test)_...`, SendGrid `SG.<22>.<43>`, Twilio `SK[0-9a-f]{32}`
- npm `npm_...`, Shopify `shp(at|ss|pa|ca)_...`, Square `sq0(atp|csp)-...`
- OpenAI `sk-...`, Anthropic `sk-ant-api...`, Mapbox `sk.eyJ...`
- `-----BEGIN ... PRIVATE KEY-----`
- Connection strings: `mongodb+srv://user:pass@`, `postgres://`, `mysql://`,
  and .NET `Data Source=...;Password=...`
- Any `scheme://user:pass@host` credential-in-URL

**probable** — a credential-shaped assignment (`apiKey`, `client_secret`,
`password`, `access_token`, `private_key`, …) whose value survives filtering:
length ≥ 12, Shannon entropy ≥ ~3.2, mixed character classes, and not a
placeholder.

**possible** — keyword match with weak value evidence. Skim these.

**info** — not credentials, but useful. Covered below.

## Filter aggressively

Reject: `YOUR_API_KEY_HERE`, `changeme`, `xxxxx`, `example`, `placeholder`,
`TODO`, `REDACTED`, `${process.env.X}`, `import.meta.env.X`, `{{...}}`,
`<...>`, `%ENV_VAR%`, `null`, `undefined`; short lowercase identifiers from
minification; MIME types, locales, colour codes, filenames.

A short low-entropy value assigned to something named `password` is still a
hardcoded password — keep those even though they fail the entropy test.

## Informational disclosures — do not skip these

**JWTs** (`eyJ...eyJ...`) — decode the header and payload (base64url, no
signature verification needed). The claims usually matter more than the token:

- `alg: none` → test whether the server accepts an unsigned token
- `alg: HS*` → key-confusion (RS→HS) and weak-secret cracking are on the table
- `exp` → still valid, or expired?
- `role`, `roles`, `scope`, `groups`, `sub`, `email` → what it asserts

**Source map references** (`//# sourceMappingURL=`) — flag prominently. If the
`.map` is actually served it reconstructs the original sources with comments and
real names. Recovering it and re-running every other analysis over the result is
the biggest single coverage win available on a minified target.

**Internal hostnames and private IPs** — `*.internal`, `*.corp`, `*.local`,
`10.x`, `192.168.x`, `172.16-31.x`, `localhost`. These become the targets for
SSRF testing later.

**Cloud storage URLs** — S3, Azure Blob, GCS buckets. Check whether they are
publicly listable.

**ASP.NET `<machineKey>`** — validation and decryption keys are catastrophic if
exposed: ViewState forgery and, on many versions, RCE.

## Output

Write `secrets.json` with tier, type, value, `file:line` and surrounding
snippet. Deduplicate by value, keeping the strongest tier and noting the other
patterns it matched — a connection string is also a credential-in-URL, and
reporting it twice inflates the count.

Offer a redacted variant (mask the middle, keep 4 characters each end) for any
output that will be shared, and say why: a report circulating with live
credentials in it is its own incident.

## When you find something confirmed

Say plainly that the tester should establish whether the credential is **live**
and what it grants before reporting. A revoked or scope-limited key is a hygiene
finding; a working one with production access is an incident, and the client
should hear about it immediately rather than at report delivery.
