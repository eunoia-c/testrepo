# Repository conventions

## Commit messages

Subject line only. One line, imperative, under ~72 characters, naming the
component it touches (`js-recon: …`, `apex_scan: …`, `dom-param-finder: …`).

**No body paragraphs.** Do not explain reasoning, alternatives considered,
bugs found along the way, or anything that reads as a record of how the change
came about. The reasoning belongs in the code and in the tool READMEs, where
someone picking up the tools will actually look for it. A commit log that
narrates a working session leaks context about assessments and targets to
anyone who later gains read access to this repository.

The only trailer is `Co-Authored-By:`. Do not add session links, conversation
URLs, or any other pointer back to the environment a change was authored in.

```
js-recon: add hidden parameter discovery          <- good
dom-param-finder: scope-gate content injection    <- good
```

## Documentation

READMEs document what a tool does and how to run it. They do not document
how this particular repository was set up, authenticated against, or
troubleshooted, and they do not name the owner, the branch, or an assessment
target.

## Layout

One top-level folder per target technology (`pega/`, `proiv/`, `salesforce/`,
`servicenow/`, `browser-extensions/`, `burp-extensions/`), plus `copilot-vapt/`
for the editor-assistant packaging and `.claude/skills/` for skills. The
top-level `README.md` is the index.
