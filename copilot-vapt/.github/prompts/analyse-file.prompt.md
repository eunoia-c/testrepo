---
mode: agent
description: 'Deep-dive a single JavaScript file — what it is, what libraries it ships, and what matters in it.'
tools: ['codebase', 'search', 'editFiles', 'runCommands']
---

# Analyse one JavaScript file

Answer the question "here is a file, what can you tell me about it". That is a
different question from "what is the whole attack surface", so give a briefing
someone can read, not a data dump.

## Run the analyser

```bash
python3 scripts/analyse_file.py <path-to-file>
```

It prints the whole briefing: what the file is, library versions with advisory
flags, feature flags and client config, endpoints, secrets annotated with the
scope the key actually grants, DOM XSS candidates, and cross-cutting
observations. Use `--json` if the tester wants structured output instead.

Two parts of that output are easy to misread, so read them the way they are
meant:

- **Feature flags** are split into *off in this build* and *on*. The off half is
  the interesting one — a false flag is a feature the UI will not show you, and
  the route behind it is frequently still mounted server-side. Minified `!0`/`!1`
  booleans are decoded for you. A flag that is off is a hint about where to look,
  never evidence the route is live.
- **Key scope** says whether a secret-shaped hit is actually a secret.
  `pk_live_…`, `AIzaSy…`, `G-…` and `phc_…` belong in client code by design;
  `sk_live_…` and `AKIA…` never do. A `depends` scope (Google API keys above all)
  means the risk is entirely about referrer/IP restrictions, so the real test is
  whether the restriction is set, not that the key exists.

If `scripts/` is not present, fall back to reading the file yourself (or writing
a script when it is minified) and cover the same ground in the same order — but
say the results are unverified ad-hoc analysis rather than the tested pipeline.

## Then add what a script cannot

The analyser handles the mechanical part. Your contribution is judgement on top:

**Say what the file is for**, in a sentence, in the application's terms. "The
authenticated dashboard bundle — it owns case listing, the approval workflow and
file download" is more useful than "a webpack bundle using React". Read enough
of the code to say this honestly; if it is minified beyond recognition, say that
instead of guessing.

**Pick the one thing to do next.** The briefing lists everything found. The
tester wants to know where to start. Name it and say why.

**Question the version findings.** Flagged libraries are the most concrete
findings available, and also the easiest to get wrong: bundles ship version
strings that shims replace, vendored copies get patched in place, and a banner
comment can outlive the code beneath it. Say what would confirm the version is
really the one running.

**Note what the file implies about the rest of the application.** One bundle
naming three API versions, or an admin route, or an auth interceptor, tells you
something about the architecture — and about what else to go looking for.

**Read the code the inventory points at.** This is the part that distinguishes a
useful file review from a regex dump, and it is the only part a script cannot
do. Open the file at the reported lines and answer:

- *What actually gates this endpoint?* `auth: none` means no token was visible in
  that call's own span. Read outward for a route guard, a login-gated module, or
  a global interceptor — one global `axios` interceptor makes every per-call
  verdict wrong in the same direction.
- *What does this flag turn on?* Follow it to its consumers. A flag that swaps a
  CSS class is noise; one that selects a different request path or mounts an
  admin component is the find.
- *What validation does this parameter get?* Client-side validation next to a
  parameter is a hint the server trusts it. Note the constraint, then test
  whether the server re-checks it.
- *What is this key for?* Confirm the scope annotation against the call the key
  is used in: which API, which host, which operation.

Cite `file:line` from the briefing for each. "Reachable without the admin role
because the only check is a client-side flag, at `app.js:1204`" is worth more
than any count of endpoints found.

## Keep the framing

Static analysis is evidence about attack surface, not about server-side
enforcement. Candidates until confirmed. If the file is minified, say plainly
that identifier names are gone and variable-level reasoning is weaker than the
confidence labels suggest.
