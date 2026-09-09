# Endpoint recovery

## What `scan` matches

Every string literal in the file is tested for endpoint shape, then classified by the
call site that surrounds it.

**Accepted:** absolute URLs, protocol-relative URLs, root-relative paths (`/api/...`),
template literals (`` `/api/users/${id}` `` → `/api/users/{id}`), and bare strings ending
in `.json .php .aspx .asmx .ashx .axd .svc .jsp .do .action .cgi .xml`.

**Rejected:** MIME types (`application/json`), dates (`12/25/2026`), regex fragments,
CSS selectors, static assets (`.css .png .woff .svg`), anything containing whitespace,
and known CDN/analytics hosts unless `--include-thirdparty`.

**Method inference**, in priority order:

| Construct | Method from |
|---|---|
| `xhr.open("DELETE", url)` | the literal first argument |
| `axios.put(url)`, `this.http.get<T>(url)` | the verb in the call |
| `$.post(url)`, `$.getJSON(url)` | the jQuery helper |
| `fetch(url, {method: "PATCH"})` | the options object, bounded to that statement |
| `{url: "...", type: "POST"}` | the enclosing options object |
| anything else | defaults to `GET` |

Lookups stop at the statement terminator, so one call never inherits the next call's
options. Same-URL different-method pairs are kept as separate endpoints.

## What it misses, and how to recover it

Literal extraction cannot follow computed values. These are the common blind spots.

**1. Concatenated bases.**

```js
var API_ROOT = "/api/v2";
fetch(API_ROOT + "/" + resource + "/" + id);
```

Only `/api/v2` is recovered. Grep the bundle for the base variable, then read the call
sites by hand:

```bash
grep -n "API_ROOT" bundle.js | head -40
```

**2. Route tables.** SPA routers hold the real page inventory. Search for them directly:

```bash
grep -oE '(path|route|url)\s*:\s*["'\''][^"'\'']+' bundle.js | sort -u
grep -oE 'component\s*:\s*[A-Za-z]+' bundle.js | sort -u
```

**3. Webpack lazy chunks.** The chunk map names bundles that are only fetched on
navigation — often the admin area.

```bash
grep -oE '[0-9]+:"[a-z0-9-]+"' bundle.js | head -50     # chunk id -> name map
grep -oE 'webpackChunkName:\s*"[^"]+"' bundle.js | sort -u
```

Fetch each chunk (`/static/js/<id>.<hash>.chunk.js`) and re-scan.

**4. GraphQL.** One transport endpoint hides every operation. Pull the documents out:

```bash
grep -oE '(query|mutation|subscription)\s+[A-Za-z]+' bundle.js | sort -u
grep -oE 'gql`[^`]+`' bundle.js
```

Each operation is a separate authorization test case even though the URL never changes.

**5. Config fetched at runtime.** Look for `/config`, `/settings`, `/env.json`,
`/.well-known/`, `appsettings`. Retrieve it and re-scan the response.

**6. Source maps.** The single highest-yield step. If `//# sourceMappingURL=` is present,
get the `.map` and re-scan it — `scan` unpacks `sourcesContent` automatically and gives
you original filenames, comments, and dead code paths.

## Triaging a large bundle

```bash
# distinct path prefixes - shows the API surface shape at a glance
python3 jsvapt.py endpoints results.json --format plain \
  | awk '{print $2}' | cut -d/ -f1-4 | sort | uniq -c | sort -rn | head -30

# only the state-changing calls
python3 jsvapt.py endpoints results.json --method POST,PUT,PATCH,DELETE

# highest-priority unauthenticated candidates
python3 jsvapt.py endpoints results.json --no-auth-only --min-score 40
```

## Re-scan triggers

Re-run `scan` and diff whenever the served code could differ:

- after authenticating (logged-in bundles carry more routes)
- after switching to a privileged role (admin bundles are the prize)
- after navigating to lazily-loaded areas (new chunks download)
- on a different tenant, locale or feature-flag cohort
- after any deploy during the engagement window
