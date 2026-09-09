# VAPT recon copilot for GitHub Copilot (VS Code)

A web application security assessment assistant for Copilot Chat: static
analysis of JavaScript, `.axd` resources and Burp exports for endpoints,
secrets, interesting parameters and DOM XSS, plus Burp-ready requests,
wordlists, and a findings report.

This is the Copilot-native counterpart to the `js-recon` skill in
`.claude/skills/`. Same methodology, different delivery — see
[Differences from the Claude Code skill](#differences-from-the-claude-code-skill).

## Install

Copy the `.github` directory into the workspace you open in VS Code — typically
the folder holding the engagement's saved bundles and Burp exports:

```bash
cp -r copilot-vapt/.github /path/to/engagement-workspace/
```

Then in VS Code, open Copilot Chat in that workspace.

If prompt files are not picked up, check that they are enabled in settings
(`chat.promptFiles`) — availability and the exact setting key have moved between
VS Code releases, so verify against your version rather than assuming. The tool
lists in the frontmatter are likewise version-dependent; if a tool name is not
recognised, open the tools picker in Chat and match the names your build uses.

## What you get

**Always-on context** — `.github/copilot-instructions.md` applies to all Copilot
Chat in the workspace: the analysis-not-interaction posture, the reporting
discipline (candidates until confirmed, scores order a queue and are not
severities), and output conventions.

**A chat mode** — `.github/chatmodes/vapt-recon.chatmode.md`. Select "VAPT
Recon" in the Chat mode picker for the recon-focused persona.

**Scoped instructions** — `.github/instructions/js-analysis.instructions.md`
applies whenever Copilot touches a `.js`, `.axd`, `.map` or similar file, so it
treats them as captured evidence rather than source code to tidy up.

**Seven prompt files**, invoked with `/` in Chat:

| Command | What it does |
| --- | --- |
| `/js-endpoints` | Recover the endpoint inventory with authorization verdicts; ingests Burp XML exports |
| `/js-secrets` | Credentials, API keys, JWTs (decoded), source maps, internal hosts |
| `/js-domxss` | DOM XSS source-to-sink candidates, ranked by evidence |
| `/attack-surface` | Rank endpoints and parameters, suggest concrete tests |
| `/burp-request` | Raw HTTP for Repeater, with the credential-stripped pair |
| `/wordlist` | Fuzzing wordlists from the inventory |
| `/vapt-report` | Assemble everything into a Markdown findings report |

## Suggested flow

```
/js-endpoints      → endpoints.json
/js-secrets        → secrets.json
/js-domxss         → domxss.json
/attack-surface    → attacks.json     (reads the first two)
/vapt-report       → report.md        (reads everything present)
```

`/burp-request` and `/wordlist` are on-demand once the inventory exists.

## Differences from the Claude Code skill

The Claude version bundles six tested Python scripts. Copilot has no equivalent
mechanism — instructions, prompt files and chat modes are Markdown only — so the
analysis logic is expressed as instructions instead of pinned implementations.

What that changes:

**Copilot writes the analysis code each time.** In agent mode it can run
terminal commands, so the prompts tell it to generate and run a script when
files are too large to read directly. That preserves the ability to handle
multi-megabyte minified bundles, but the implementation varies run to run.

**No test suite.** The Claude version has 42 assertions pinning behaviour —
that a `credentials: 'omit'` is attributed to the right call, that placeholders
are rejected, that generated requests carry CRLF. Here, nothing enforces that.
Spot-check results early on a file you already understand.

**Results vary between runs.** Same inputs will not always produce identical
output. For an inventory you intend to work from over days, save the generated
script and re-run it rather than re-prompting.

**The knowledge is fully present.** Extraction patterns, the authorization
verdict table, the parameter classes, the DOM XSS sink catalog, the report
structure and the reporting discipline are all in the prompt files. Nothing was
dropped in translation; only the determinism was.

If you want reproducibility on a long engagement, the practical hybrid is to run
`/js-endpoints` once, keep the script Copilot writes, and drive subsequent
passes with that script directly.

## Scope

Written for authorized testing — penetration tests, bug bounty, security review
with permission. The instructions keep Copilot working from files in the
workspace and out of the target: requests are produced for the tester to run,
not issued.
