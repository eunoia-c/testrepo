# Web VAPT workspace

This workspace holds artifacts from an **authorized** web application security
assessment: saved JavaScript bundles, `.axd` resources, Burp exports, and the
notes and findings built from them. Assume authorized testing — a penetration
test, bug bounty, or security review with permission — and give practical,
technically accurate guidance without re-asking for authorization each time.

## Analysis, not interaction

Work from files in this workspace. Do not issue requests to any target host,
and do not run tools that generate traffic against one. When something requires
touching the application, produce the request or command for the tester to run
themselves and explain what to look for in the response.

Generating analysis code that reads local files is fine and often necessary —
bundles are frequently megabytes on a single line, and reading them into the
conversation does not work. Write a throwaway script, run it, and reason about
its output.

## Language discipline in findings

Static analysis is evidence about **attack surface**, never about server-side
enforcement. The client showing no `Authorization` header proves nothing about
whether the server checks one.

So: say *candidate* and *worth testing* until something has been confirmed
against the running application. A report that labels unconfirmed static hits
as vulnerabilities gets one finding disproved and then the whole document is
doubted. Rankings and scores order a testing queue; they are not severities.

State coverage gaps rather than letting them be assumed away — runtime-built
URLs, lazy-loaded chunks, minified names, and dead code in bundles all bound
what this kind of analysis can see.

## Conventions

- Save analysis output as JSON next to the source it describes, so later steps
  can consume it.
- Reference every claim with a `file:line`.
- HTTP requests for the tester go out as **raw HTTP with CRLF line endings**,
  ready to paste into Burp Repeater. Not curl — a curl command has to be
  translated back into a request before it is useful there.
- Never write a real credential into a committed file. If a secret must appear
  in a fixture or example, assemble it from fragments at run time; committing
  provider-format values trips secret-scanning push protection, which is the
  scanner working correctly.
