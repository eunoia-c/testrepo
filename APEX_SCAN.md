# apex_scan.py

Static analysis for Salesforce Apex dumped by `aura-dump`. Stdlib-only, Python 3.11+.

```bash
python3 apex_scan.py --input ./apex_dump --out ./results --format json,csv,md
python3 apex_scan.py --self-test          # validate the engine, print nothing else
python3 apex_scan.py -i ./apex_dump -o ./results --min-confidence HIGH --rules APEX-SOQL
```

Outputs `results.json`, `results.csv` and `report.md` into `--out`.

## Design

**Precision over recall.** Three decisions follow from writing for a client report:

- **Source is preprocessed before any matching.** Comments and string-literal
  interiors are blanked while byte offsets are preserved, so line numbers still
  refer to the original file. A sink inside a comment cannot match; a keyword
  inside a literal cannot match. This is the single biggest false-positive
  reducer in the tool.
- **SOQL injection is a taint checker, not a grep.** `Database.query()` is
  reported only when attacker-controllable input actually reaches it, and the
  propagation chain is emitted so a reader can follow it in the source.
- **Confidence is separate from severity.** Severity says how bad it would be;
  confidence says how sure the tool is. Filter with `--min-confidence` before
  reporting.

**Redaction is a property of the output, not of one rule.** Every string that
leaves the tool — snippets, descriptions, chain steps, and the markdown context
windows — is scrubbed of values the secret detector recognises. This is
deliberate: the markdown report prints three lines of context either side of
each finding, so a credential sitting near an unrelated finding leaked into the
report when redaction was left to the secret rule alone. Output shows the first
four characters and a length, never the value.

## Rules

| ID | Severity | What it finds |
| --- | --- | --- |
| `APEX-SOQL-001` | CRITICAL / HIGH | Attacker-controllable input reaching a dynamic query |
| `APEX-SOQL-002` | LOW | Dynamic query built from locally derived input (review only) |
| `APEX-SECRET-001` | CRITICAL–MEDIUM | Hardcoded credentials, keys, high-entropy literals |
| `APEX-SHARE-001` | HIGH–LOW | `without sharing` / no sharing declaration, escalated with remote entry points and no CRUD/FLS |
| `APEX-CRYPTO-001` | HIGH / MEDIUM | MD5, SHA1, DES, 3DES, RC4, ECB |
| `APEX-CRYPTO-002` | HIGH | Hardcoded key or IV passed to `Crypto.encrypt`/`decrypt` |
| `APEX-CRYPTO-003` | HIGH | `Math.random()` used for a token-like value |
| `APEX-CALLOUT-002` | HIGH | Callout over cleartext `http://` |
| `APEX-CALLOUT-003` | LOW | Hardcoded external endpoint (inventory of non-Salesforce hosts) |
| `APEX-CALLOUT-004` | HIGH | Endpoint built from caller-controlled input (SSRF candidate) |
| `APEX-CALLOUT-005` | HIGH | `Authorization` header from a literal |
| `APEX-CALLOUT-006` | LOW | `setClientCertificate` in code |
| `APEX-MISC-001` | LOW | Read-modify-write without `FOR UPDATE` |
| `APEX-MISC-002` | MEDIUM | Sensitive variable written to the debug log |
| `APEX-MISC-003` | LOW | Hardcoded Salesforce record ID |
| `APEX-MISC-004` | INFO | DML inside a loop (not a vulnerability; noted only) |

### SOQL taint model

**Sources** — parameters of `@AuraEnabled`, `@RestResource`, `@HttpGet/Post/Put/Delete/Patch`,
`@InvocableMethod`, `@RemoteAction`, `webservice static` and `global` methods, public
constructors; and `ApexPages.currentPage().getParameters().get()` anywhere, including
in methods that are not themselves entry points.

**Sinks** — `Database.query`, `queryWithBinds`, `countQuery`, `countQueryWithBinds`,
`getQueryLocator`, `getQueryLocatorWithBinds`, `Search.query`, `Search.find`.

**Propagation** — local assignment, `+` and `+=` concatenation, `String.format`/`join`,
and one level of same-file helper calls (both directions: taint into a helper that
contains a sink, and a tainted value returned from a helper).

**Sanitizers that clear taint** — `String.escapeSingleQuotes()`, bind variables
(`:var` inside the query string is never seen as a code reference, so binding is
safe by construction), `Id/Integer/Decimal/Boolean.valueOf()`, explicit casts,
`.contains()` against an allowlist collection, and Schema describe lookups.

**Confidence** — HIGH when a source parameter reaches a sink directly; MEDIUM when
it arrives through a helper; LOW for `APEX-SOQL-002`.

Each finding carries the entry-point signature, the originating parameter names
(all of them when several contribute), the sink line, and a numbered propagation
chain intended to be usable as a proof-of-concept path.

## Coverage reporting

Bulk `ApexClass` dumps return managed-package bodies as `(hidden)`. These are
skipped silently during analysis and counted separately in every output format,
with the filenames listed in the report. A clean result on a dump that is 60%
withheld is not a clean result, and the report says so rather than implying
coverage it does not have.

Malformed files are analysed on a best-effort basis and never abort the run; a
rule that throws is recorded against that file and the other rules still run.

## Determinism

Findings are sorted by severity, confidence, rule, path, line, fingerprint, and
each carries a stable 16-character fingerprint. The fingerprint hashes the rule,
path, entry point, parameter and normalised snippet — **not** the line number, so
inserting lines elsewhere in a file does not churn every fingerprint and runs
stay diffable. Two runs over the same input produce byte-identical JSON and CSV.

## Validation

`--self-test` runs the engine over 15 built-in snippets — 8 vulnerable, 7
sanitised counterparts — and asserts each rule fires on the vulnerable case and
stays silent on the safe one. When run alongside a scan, the result is written
into `report.md` under **Checker validation** so the report can state the checker
was validated, with the assertion count.

`python3 -m unittest test_apex_scan` runs 80 unit tests covering preprocessing,
parsing, every rule, redaction across all three output formats, robustness
against malformed input, fingerprint stability, and the CLI.

## Limitations

State these rather than let them be assumed away:

- **Intraprocedural, one helper deep, single file.** Taint crossing files or
  passing through collections, maps or custom objects is not followed. Absence
  of a finding is not evidence of absence.
- **No type resolution.** The analyser works on text structure, not a symbol
  table, so an unusual formatting or a construct the regexes do not model can be
  missed.
- **Withheld bodies are invisible.** See Coverage.
- **Secret detection is pattern- and entropy-based.** A credential in an unusual
  format is missed; a high-entropy non-credential can appear at LOW confidence.
- **Findings are candidates.** Every one should be confirmed against the org
  before it is presented as exploitable.
