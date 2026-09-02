# Pega Infinity path wordlist

`pega-paths.txt` — content-discovery wordlist for Pega Platform / Infinity web
deployments. For use in authorized security testing only.

No leading slashes, so it drops straight into a fuzzer:

    ffuf -w wordlists/pega-paths.txt -u https://TARGET/FUZZ -ac

## Coverage

- Servlet contexts: `prweb`, `prsysmgmt` (System Management Application), and
  lower-confidence siblings (`prgateway`, `prhelp`, `prdbutil`).
- Dispatch and auth entry points under `/prweb/`: `PRServlet`, `PRAuth`,
  `PRRestService`, `PRSOAPServlet`, `PRHTTPService`, `sso`.
- REST surfaces: `api/v1/*` (including the Swagger UI at `api/v1/docs`) and the
  DX API v2 tree at `api/application/v2/*`.
- Static content roots: `PRStaticContent/{global,webwb,mashup}`.
- Health probe paths taken from Pega's Helm chart liveness probes (both casings
  included; verify against the target's actual deployment).
- Tomcat leftovers and standard policy files.

## Notes

- Filter on response size/word count, not status — Pega commonly returns
  `200 text/html` with an error stream in the body.
- `PRStaticContent/webwb/` is better harvested than fuzzed: pull the JS the app
  references, then grep it for `pyActivity`, `pzInsKey`, `pyFlowAction`, and
  data page (`D_*`) names to build a target-specific corpus.
- Static content URLs usually carry a build string; capture it for version-to-CVE
  mapping before anything else.
