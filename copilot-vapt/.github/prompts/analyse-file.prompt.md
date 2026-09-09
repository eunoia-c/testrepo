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
flags, endpoints, secrets, DOM XSS candidates, and cross-cutting observations.
Use `--json` if the tester wants structured output instead.

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

## Keep the framing

Static analysis is evidence about attack surface, not about server-side
enforcement. Candidates until confirmed. If the file is minified, say plainly
that identifier names are gone and variable-level reasoning is weaker than the
confidence labels suggest.
