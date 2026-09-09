# Reporting

`report` produces a draft. It is structured and defensible, but it is generated from
*static leads* — it must be edited against what was actually confirmed before it goes to
a client.

## Before sending

1. **Delete what did not hold up.** A `none-observed` endpoint that returned 401 in
   Repeater is not a finding; drop it or move it to a tested-and-clean note.
2. **Fold in the confirmations.** Replace "candidate" language with the evidence:
   request, response, identity used, data that crossed a boundary.
3. **Re-rate severity by real impact**, not by the priority score. The score orders
   testing effort; it says nothing about consequence.
4. **Check the secrets section.** Publishable Stripe keys, Firebase web config and
   referrer-restricted Google Maps keys are public by design. Report them only where the
   key is unrestricted or grants server-side capability. Reporting a `pk_live_` key as a
   critical secret leak damages the report's credibility.
5. **Keep the limitations section.** It is what makes the rest defensible.

## Severity

Rate on demonstrated impact, with exploitability as a modifier:

- **Critical** — unauthenticated access to bulk sensitive data, RCE, authentication bypass.
- **High** — authenticated cross-user data access (BOLA), privilege escalation, stored
  XSS in an authenticated context, an exposed admin function.
- **Medium** — reflected/DOM XSS requiring interaction, CSRF on a meaningful action,
  information disclosure that materially aids further attack.
- **Low** — verbose version headers, non-sensitive information disclosure, missing
  defence-in-depth headers.
- **Informational** — client-side authorization logic, hardcoded public identifiers,
  observations with no direct impact.

Two modifiers that legitimately move a rating:

- A `location.hash` DOM XSS never reaches the server, so server-side filtering and the
  WAF do not apply. State this — it is why "the WAF blocks it" is not a valid rebuttal.
- An unauthenticated endpoint returning *bulk* records is materially worse than one
  returning a single record. Quantify it.

## Evidence per finding

- The exact request, as raw HTTP (`request ... -o`), with credentials redacted.
- The response, trimmed to what proves the point, with real data masked.
- The source location: `bundle.js:1420` and the code line the analysis flagged.
- Steps a reviewer can follow to reproduce independently.
- For authorization findings, both halves of the pair — the flow only makes sense as a
  contrast.

Redact real tokens, cookies, PII and customer records in the deliverable. Truncate to
enough characters to demonstrate the shape.

## Structure

The generated report follows: scope and method → what was recovered → endpoint inventory
→ authorization candidates → DOM XSS leads → hardcoded material → platform observations
→ next actions → limitations.

Keep the limitations section honest and specific:

- static analysis only; no request was issued by the tooling
- runtime-assembled URLs are not recoverable
- client-side auth inference can differ from server-side enforcement in both directions
- minification and obfuscation reduce recall
- the analysis covers only the bundles captured, at the privilege level captured

## Related tooling

For a single confirmed vulnerability needing CVSS vectors and a spreadsheet row, use the
`vuln-reporter` skill — it emits a tab-delimited row with base and threat/environmental
metrics. This report is the engagement-level view that gives those rows their context.
