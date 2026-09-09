# VAPT recon copilot for GitHub Copilot (VS Code)

A web application security assessment assistant for Copilot Chat: static
analysis of JavaScript, `.axd` resources and Burp exports for endpoints,
secrets, interesting parameters and DOM XSS, plus Burp-ready requests,
wordlists, and a findings report.

This is the Copilot-native counterpart to the `js-recon` skill in
`.claude/skills/`. Same methodology, different delivery — see
[Differences from the Claude Code skill](#differences-from-the-claude-code-skill).

## Install

**Windows** (PowerShell or cmd — no WSL needed):

```
python copilot-vapt\install.py C:\engagements\acme-webapp --verify
```

**macOS / Linux:**

```bash
python3 copilot-vapt/install.py ~/engagements/acme-webapp --verify
```

There is also `install.sh` for shell users; `install.py` is the cross-platform
one and is the recommended path everywhere. It copies from this repository — it
does not download anything.

Python 3 is required either way, since the analysis scripts are Python. If
`python` is not recognised on Windows, install it from python.org or the
Microsoft Store and tick "Add to PATH".

Both installers place two directories in your workspace, which have to travel
together:

- `.github/` — the instructions, chat mode and prompt files
- `scripts/` — the tested `js-recon` analysis scripts the prompts call

Then open that folder in VS Code and pick the **VAPT Recon** chat mode.

`--verify` runs the full pipeline over test fixtures and reports 15 checks, so
you know the scripts work before you start — this matters more than it sounds,
because the failures that bite (a parser silently returning nothing, a filter
letting placeholders through) look fine to a syntax check. `--force` skips the
overwrite prompts.

The repository's `tests/smoke_test.sh` is bash and will not run on Windows;
`install.py --verify` is the cross-platform equivalent.

**Install both or neither.** If the prompts arrive without `scripts/`, Copilot
has nothing to call and rewrites each analysis from scratch — untested, and
differently every run. That is the single most likely way this package
underperforms, and it looks like it is working while it happens.

The installer copies the scripts from `.claude/skills/js-recon/scripts/` rather
than keeping a second copy in this directory, so there is one source of truth
and the two packages cannot drift apart.

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

## Verifying it is working

The tell that something is wrong is Copilot **writing** an analysis script
instead of running one. If you see it create `analyse_endpoints.py`,
`analyse_secrets.py` or similar, it could not see `scripts/`. Check that the
folder open in VS Code is the one you installed into — not a parent, and not a
subfolder.

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

**Installing with `install.sh` closes most of that gap.** The prompts check
`scripts/` first and run the tested implementations, so you get Copilot's chat
workflow driving deterministic code. Copilot only writes new analysis code when
nothing suitable exists, and is instructed to say so and flag it as unverified.

The residual difference is that Copilot decides *which* script to run and how to
interpret the output, where the Claude skill follows a fixed pipeline. That is
usually an advantage — it adapts to what you actually have — but it means two
runs can take different routes through the same data.

## Scope

Written for authorized testing — penetration tests, bug bounty, security review
with permission. The instructions keep Copilot working from files in the
workspace and out of the target: requests are produced for the tester to run,
not issued.
