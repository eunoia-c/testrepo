# Burp extensions

Jython extensions for Burp Suite, used alongside the analysis tooling in
`.claude/skills/js-recon/` and `copilot-vapt/`.

## copy_host_path_params.py

Right-click a request (or a multi-selection) in Burp and copy Host / Path /
Params to the clipboard, formatted for pasting straight into Excel.

Three menu entries:

| Entry | Output |
| --- | --- |
| Copy host/path/params (TSV) | One row per request; params joined into a single cell |
| Copy host/path/params (CSV) | Same, comma-delimited and quoted |
| Copy expanded — one row per param (TSV) | One row per parameter, with its type |

Handles GET, POST (urlencoded, multipart, JSON, XML) and anything else Burp's
parser understands. Where Burp parses no parameters but a body is present —
raw JSON blobs, GraphQL, custom content types — it falls back to emitting the
body as a single `<raw_body>` pseudo-parameter rather than silently producing
an empty row.

### Install

1. Burp needs Jython configured: **Extensions → Extensions settings → Python
   environment**, point it at a `jython-standalone-2.7.x.jar`.
2. **Extensions → Installed → Add**, type Python, select this file.

### Settings

Constants at the top of the file:

- `INCLUDE_COOKIES` — cookie parameters are excluded by default; they are
  usually session noise rather than testable input.
- `INCLUDE_HEADER_ROW` — emit a header line.
- `PARAM_SEPARATOR` — how parameters are joined inside one cell in the
  non-expanded modes.

### Where it fits

The expanded mode pairs well with the parameter triage in
`scripts/suggest_attacks.py`: paste the parameter column into a sheet, and the
attack classes there tell you which names justify which tests.

### One caveat worth knowing

Parameter values come from captured traffic, which means they can contain
attacker-influenced content. A value beginning with `=`, `+`, `-` or `@` is
interpreted as a **formula** by Excel when pasted or imported. That is CSV
injection pointed at your own analysis spreadsheet.

The extension does not neutralise this. If it matters for your workflow, prefix
such values with an apostrophe in `esc()`, or paste into a sheet with formula
evaluation disabled.
