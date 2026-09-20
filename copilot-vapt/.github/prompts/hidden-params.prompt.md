---
mode: agent
description: 'Recover parameter names from client code and flag the ones the interface never sends.'
tools: ['codebase', 'search', 'editFiles', 'runCommands']
---

# Find hidden parameters

Endpoint discovery answers *what can I call*. This answers *what can I send* —
which is where mass assignment, feature flags and forgotten debug switches live.

## Run it

```bash
python3 scripts/find_hidden_params.py ./js ./burp_js \
    --burp-index burp_index.json --out hidden_params.json --wordlist params.txt
```

`--burp-index` is what makes the output useful. Without captured traffic to
compare against, nothing can honestly be called hidden — every name is just a
name in the bundle. Say so rather than presenting the full list as findings.

If `scripts/` is not present, cover the same ground yourself and say the results
are unverified ad-hoc analysis rather than the tested pipeline.

## Present the classes differently, because they need different tests

**`hidden`** — in the bundle, never sent. Add each to a request the endpoint
already accepts and check whether the value persists or changes behaviour.

**`response_only`** — the client receives the field but never submits it. That
is the classic mass-assignment shape: submit it on an update to an object you
own and see whether the server binds it. Fields like `isSuperUser` or
`approvalStatus` in this class are worth naming explicitly to the tester.

**`commented`** — removed from the client, frequently still accepted by the
server, and invisible to traffic capture by definition.

**`observed`** — already exercised; no news.

## The habit that decides whether any of this is worth testing

Before spending payloads, confirm the parameter reaches server-side behaviour:
change it to something benign but different and look for any change in status,
body length, content or timing. Client bundles are full of dead parameters,
renamed fields and leftovers. A parameter that changes nothing is not worth a
payload, and saying so saves more time than any finding in the list.

## Framing

A name in the bundle is evidence the client knows a parameter, not that the
server reads it. Candidates until confirmed.
