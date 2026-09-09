---
mode: agent
description: 'Generate fuzzing wordlists from the recovered endpoint inventory.'
tools: ['codebase', 'editFiles', 'runCommands']
---

# Generate a wordlist

Build wordlists from `endpoints.json`. Ask which shape is wanted if unclear —
different jobs need different ones:

- **paths** — full paths with `{param}` replaced by `FUZZ`, for replaying
  endpoints or Intruder positions
- **dirs** — every unique path prefix, for directory brute-forcing
- **params** — parameter names, for parameter mining
- **files** — last path segments, for extension fuzzing

## Conventions

Strip the leading slash by default, since `ffuf -u https://host/FUZZ` wants it
off; keep it only if asked. Drop query strings unless the query itself is the
target. Deduplicate and sort.

Do not leak internal placeholder tokens into the output — only real recovered
names belong in a params list.

Offer to filter by authorization verdict or method so the tester can fuzz just
the interesting subset rather than the whole inventory.

## Usage note to include

When you hand over the file, mention filtering on **response size and word
count** rather than status code, with ffuf's auto-calibration (`-ac`). Many
frameworks return `200 text/html` with an error document, so status-only
filtering drowns the results in false positives.

Write the file into the workspace and say how many entries it has.
