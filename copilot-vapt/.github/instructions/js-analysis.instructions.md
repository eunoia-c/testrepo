---
applyTo: '**/*.{js,mjs,cjs,jsx,ts,tsx,axd,map,aspx,html}'
description: 'Context for reading client-side artifacts captured during a security assessment.'
---

# Reading captured client-side artifacts

Files matching these patterns in this workspace are **captured from a target
application**, not source code being developed here. Read them as evidence.

Do not offer to refactor, reformat, fix, lint or "improve" them, and do not
treat their bugs as work items — a sloppy pattern in captured code may be the
finding. Do not rewrite them in place; analysis output belongs in separate
files.

## Practical notes

**Minified files**: one enormous line, mangled identifiers. Do not attempt to
read these into context — write a script, run it, work from the output.

**`.map` files are the prize.** If a source map is present or referenced, it
reconstructs the original sources with comments and real names. Say so
immediately; recovering it and re-running any analysis over the result beats
every other coverage improvement available.

**`.axd` files** are ASP.NET resource handler responses — real application
JavaScript served from inside an assembly, often the only place a WebForms app's
service proxies appear.

**Bundles contain dead code.** An endpoint or sink present in a bundle may not
exist in the deployed application. Treat everything recovered as a candidate to
confirm, and say so rather than implying the inventory is a live map.

**Which account's bundle is this?** Applications commonly serve different
bundles per role. A low-privilege account's bundle naming endpoints its own UI
never exposes is the highest-value observation available — flag it whenever it
applies, and ask if it is not known.
