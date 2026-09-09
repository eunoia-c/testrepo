---
mode: agent
description: 'Assemble the analysis artifacts into a Markdown findings report.'
tools: ['codebase', 'editFiles']
---

# Write the findings report

Merge whatever artifacts exist — `endpoints.json`, `secrets.json`,
`domxss.json`, `attacks.json`, `burp_index.json` — into one Markdown report.
Skip sections whose input is missing and renumber so there are no gaps.

## Structure

1. **Header** — target, date, method, and an explicit statement that no requests
   were issued to the target as part of the analysis
2. **Summary** — a counts table
3. **How to read this report** — the framing below
4. **Credentials and sensitive disclosures** — first, because a live key
   outranks everything else in the document
5. **Endpoints to test for missing authorization** — ranked, cross-referenced
   against observed Burp traffic where available
6. **Prioritised attack surface** — ranked endpoints with suggested tests
7. **Parameters worth attacking**
8. **DOM XSS candidates**
9. **Platform-specific surface** (ASP.NET `.axd`, postbacks, ASMX; or the
   equivalent for whatever stack the target runs)
10. **Full endpoint inventory**
11. **Method and limitations**

## Framing that has to be in there

Near the top, in substance:

> Static analysis shows what the *client* does, which is evidence about attack
> surface and no evidence at all about server-side enforcement. An endpoint
> listed as an authorization candidate may well be properly protected — the
> point is that nothing in the client proves it is, so it earns a manual test.
> Nothing here should be reported as a vulnerability until confirmed against the
> running application.

And in the limitations section, at minimum:

- Server-side enforcement is invisible to this method; every authorization row
  is a hypothesis
- Runtime-constructed URLs are missed — paths assembled from variables,
  configuration or server-injected values do not appear
- Minification loses names, weakening variable-level DOM XSS reasoning
- Bundles ship dead code: endpoints the deployed app no longer exposes, and
  unreachable sinks
- Secret detection is pattern-based — unusual formats are missed, and
  high-entropy non-credentials can appear as probable
- Attack suggestions come from names and shapes, not behaviour; they order a
  queue and none of them is a finding
- Coverage is bounded by the files supplied; bundles behind authentication,
  lazy-loaded chunks and per-role bundles must be captured separately

Add anything else specific to this engagement.

## Conventions

Every row carries a `file:line`. Use *candidate* and *worth testing* throughout.
If credential values appear unredacted, warn that the report should be
re-generated redacted before circulating.

Mention which account's bundle was analysed if known — a low-privilege bundle
naming endpoints that account's UI never exposes is the most valuable framing
available for the authorization section, and its absence is a coverage gap
worth stating.

Write to `report.md` and summarise the headline items in chat.
