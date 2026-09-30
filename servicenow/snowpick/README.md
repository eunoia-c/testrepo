# snowpick.py — Python port of BishopFox/snowpick

A ServiceNow exposure scanner. Identifies misconfigured access controls by
obtaining an unauthenticated session token from `/login.do` and probing two
surfaces: Service Portal widgets (`/api/now/sp/widget/`) and the Table REST API
(`/api/now/table/`).

Ported from [BishopFox/snowpick](https://github.com/BishopFox/snowpick) (Go, MIT)
for environments where a GPO blocks the Go module proxy and the original cannot
be built. Same request formats, same JSON schema, same exit codes.

**Authorised testing only.** This sends requests to the hosts you name.

## Install

```bash
pip install requests
pip install "requests[socks]"   # only if you need a SOCKS proxy
```

## Usage

```bash
python3 snowpick.py --target acme.service-now.com
python3 snowpick.py --targets hosts.txt --proxy socks5://127.0.0.1:1080 --insecure
python3 snowpick.py --target acme.service-now.com --fingerprint --table-api
python3 snowpick.py --target acme.service-now.com --output results.json --quiet
```

Single-dash flags (`-target`, `-proxy`, `-table-api`, …) are accepted too, so
runbooks and wrapper scripts written for the Go tool work unchanged. The one
difference is boolean negation: Go's `-tables=false` is `--no-tables` here.

| Exit code | Meaning |
| --- | --- |
| 0 | No findings |
| 1 | Scan errors (target unreachable, or bootstrap failed) |
| 2 | Findings present |

## What it reports

- **exposed** — a record count *and* populated fields came back. Data is readable.
- **count_oracle** — a count came back with no rows. No record was disclosed, but
  the count responds to `filterText`, so the data is still queryable one
  character at a time. Each of these carries an `oracle_hint` with two curl
  commands whose differing counts demonstrate the oracle.
- **not_exposed / widget_not_found / token_error / error** — everything else.

Each finding includes a `reproduction` block with a ready-to-run curl command.

## Fidelity to the original

The port preserves the things that would make output incomparable if they drifted:

- **Request formats** — widget POST body `{"payload":{"start":0,"end":N}}`, the
  `widget-simple-list?t=&f=` table probe with a `{}` body, `X-UserToken` plus the
  `/login.do` cookies on every request.
- **Query-string ordering** — parameters are sorted, matching Go's
  `url.Values.Encode()`, so generated URLs and curl commands are identical.
- **JSON schema** — field for field, including `omitempty` behaviour, so output
  from either implementation can be diffed or fed to the same parser. Serialised
  by hand rather than by reflection for exactly this reason.
- **Status and hint logic** — the classification tables, content patterns, the
  observed-vs-inferred `basis` distinction, and the severity weights used to rank
  targets.
- **Redirects are not followed**, matching the Go client's `ErrUseLastResponse`.
  A 302 to a login page is a meaningful result; chasing it would turn a clear
  "not exposed" into a confusing 200.

### Deliberate differences

- **`requests` instead of a hand-rolled client.** A standard-library-only
  transport is possible, and was tried, but hand-written HTTP parsing is exactly
  where a scanner silently misreports. If an environment blocks PyPI as well as
  the Go proxy, that trade-off is worth revisiting deliberately rather than by
  default.
- **One `requests.Session` per thread.** `requests.Session` is not documented as
  thread-safe and this scanner probes tables concurrently. Per-thread sessions
  keep connection pooling without shared mutable state.
- **Cookies are sent as an explicit header**, not via a cookie jar — the
  reproduction curl commands need that exact `Cookie` string, and a jar would
  double up with the explicit header.
- **`trust_env = False`.** Ambient `HTTP_PROXY`/`REQUESTS_CA_BUNDLE` variables are
  ignored unless you pass `--proxy`. On a corporate laptop those are usually set,
  and silently routing an engagement's traffic through an unexpected proxy is
  worse than failing to connect.
- **Interrupt handling.** Ctrl-C stops further probing and reports the targets
  that finished, rather than discarding the run.

## Tests

```bash
python3 -m unittest test_snowpick      # 111 tests
```

Assertions on request format, status classification and hint basis are taken from
the Go implementation's own test suite, so a divergence between the port and the
original fails here rather than in a client report.

```bash
bash tests/run_integration.sh          # end-to-end, no real target contacted
```

`tests/mock_servicenow.py` serves the response shapes the Go implementation
expects, over TLS, and rejects any request whose `X-UserToken` or session cookie
is wrong — so a passing run proves the headers actually go out correctly, which
the fake-client unit tests cannot. It checks:

- session bootstrap, token and cookie replay
- exposed widget with samples, and count-oracle detection
- table enumeration via `widget-simple-list`
- Table API including `X-Total-Count`
- version fingerprinting from `stats.do` (release inference)
- `--rate` spacing (0.75s → 1.73s at `--rate 150ms`)
- byte-identical JSON across two runs
- exit codes 0 / 2

## What has not been verified

**It has never run against a real ServiceNow instance.** The mock is reconstructed
from the original's source, so it reproduces the request/response shapes the Go
code *expects* — not necessarily what a real Zurich or Yokohama instance returns.

### Validating against a real instance

Use a **Personal Developer Instance**: free from `developer.servicenow.com`,
provisioned on the current release, and yours — so authorisation is unambiguous
and you are not pointing an unproven scanner at a client during an engagement.

```bash
python3 snowpick.py --target devNNNNN.service-now.com     --rate 500ms --samples 3 --fingerprint --table-api     --output pdi-baseline.json
```

`--rate 500ms` on the first run: it is a shared instance and there is no reason
to be fast while you are establishing whether the tool behaves at all.

Two things to read from the result. Does the version tag report `Zurich`, which
confirms `stats.do` parsing and release inference against real output? And do the
findings look structurally sane — populated `evidence_fields`, working curl
reproductions, oracle hints where counts came back without rows?

A fresh PDI ships demo data under default ACLs, so it may legitimately show
exposure. That is a functional signal about the tool, **not** a finding about
ServiceNow's security, and it should not go in a report.

If anything looks wrong — empty evidence where records were returned, a version
that will not parse, a request the instance rejects — that is a divergence between
this port and real instance behaviour, and the fix belongs in the port rather
than in the interpretation of its output.
