#!/usr/bin/env bash
# End-to-end smoke test: runs the whole pipeline over tests/fixtures/ and
# asserts the results the scripts are supposed to get right. Run this after
# changing any extraction pattern -- regex edits break neighbouring cases in
# ways that are easy to miss by eye.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SKILL="$(dirname "$HERE")"
REPO_ROOT="$(cd "$SKILL/../../.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# Assemble the fixture set in a temp dir. The secrets fixture is generated
# rather than committed: it must contain values in real provider formats to
# exercise find_secrets.py, and committing those trips GitHub push protection
# (rightly -- a scanner cannot distinguish a deliberately fake key from a live
# one). See fixtures/make_secrets_fixture.py.
FIX="$WORK/fixtures"
mkdir -p "$FIX"
cp "$HERE"/fixtures/app.js "$HERE"/fixtures/page.html "$HERE"/fixtures/burp_export.xml "$FIX"/
python3 "$HERE/fixtures/make_secrets_fixture.py" "$FIX/config.js"

fail=0
check() {  # check <description> <actual> <expected>
  if [ "$2" = "$3" ]; then
    printf '  ok   %s\n' "$1"
  else
    printf '  FAIL %s (got %s, want %s)\n' "$1" "$2" "$3"
    fail=1
  fi
}

echo "== copilot-vapt script sync =="
SYNC="$REPO_ROOT/copilot-vapt/sync_scripts.py"
if [ -f "$SYNC" ]; then
  if python3 "$SYNC" --check >/dev/null 2>&1; then
    printf '  ok   copilot-vapt/scripts matches the skill\n'
  else
    printf '  FAIL copilot-vapt/scripts has drifted from the skill\n'
    python3 "$SYNC" --check 2>&1 | sed 's/^/       /'
    fail=1
  fi
else
  printf '  --   copilot-vapt not present, skipping sync check\n'
fi

echo "== parse_burp =="
python3 "$SKILL/scripts/parse_burp.py" "$FIX/burp_export.xml" \
  --out-dir "$WORK/burp_js" --index "$WORK/burp_index.json" >/dev/null
check "js bodies written" "$(ls "$WORK/burp_js" | wc -l | tr -d ' ')" "3"

echo "== extract_endpoints =="
python3 "$SKILL/scripts/extract_endpoints.py" "$FIX" \
  --out "$WORK/endpoints.json" >/dev/null
q() { python3 -c "import json,sys; d=json.load(open('$WORK/endpoints.json')); print($1)"; }
check "endpoint count"        "$(q "len(d['endpoints'])")" "12"
check "auth_at_callsite"      "$(q "sum(1 for e in d['endpoints'] if e['auth']['verdict']=='auth_at_callsite')")" "1"
check "explicit_no_creds"     "$(q "sum(1 for e in d['endpoints'] if e['auth']['verdict']=='explicit_no_credentials')")" "1"
check "DELETE method parsed"  "$(q "sum(1 for e in d['endpoints'] if e['method']=='DELETE')")" "1"
check "asmx operation path"   "$(q "sum(1 for e in d['endpoints'] if e['normalized']=='/Services/AccountService.asmx/GetBalance')")" "1"
check "fragments absorbed"    "$(q "len(d['absorbed_fragments'])")" "3"
check "postback targets"      "$(q "len(d['postback_targets'])")" "2"
check "axd references"        "$(q "len(d['axd_references'])")" "2"

echo "== mining a bundle recovered from Burp =="
python3 "$SKILL/scripts/extract_endpoints.py" "$WORK/burp_js" --out "$WORK/ep_burp.json" >/dev/null
check "endpoint only in served bundle" \
  "$(python3 -c "import json; d=json.load(open('$WORK/ep_burp.json')); print(sum(1 for e in d['endpoints'] if e['normalized']=='/api/v3/secret/export'))")" "1"

echo "== dom_xss_scan =="
python3 "$SKILL/scripts/dom_xss_scan.py" "$FIX" --out "$WORK/domxss.json" >/dev/null
d() { python3 -c "import json,sys; d=json.load(open('$WORK/domxss.json')); print($1)"; }
check "high-confidence hits"  "$(d "d['by_confidence'].get('high',0)")" "3"
check "medium via tainted var" "$(d "d['by_confidence'].get('medium',0)")" "1"
check "textContent not a sink" "$(d "sum(1 for f in d['findings'] if 'textContent' in f['sink'])")" "0"

echo "== gen_wordlist =="
check "paths mode non-empty" \
  "$(python3 "$SKILL/scripts/gen_wordlist.py" "$WORK/endpoints.json" --mode paths | wc -l | tr -d ' ')" "12"
check "no internal placeholder leak" \
  "$(python3 "$SKILL/scripts/gen_wordlist.py" "$WORK/endpoints.json" --mode params | grep -c '^concat$' || true)" "0"

echo "== make_request =="
# Resolve by path: ids shift whenever a fixture is added, and a test that breaks
# for that reason teaches nothing. This endpoint is in the Burp export, so the
# generated request should carry its real captured headers.
NOTIF=$(python3 -c "import json; d=json.load(open('$WORK/endpoints.json')); \
  print([e['id'] for e in d['endpoints'] if e['normalized']=='/api/v2/notifications/unread'][0])")
python3 "$SKILL/scripts/make_request.py" "$WORK/endpoints.json" \
  --burp-index "$WORK/burp_index.json" --id "$NOTIF" --both --out-dir "$WORK/reqs" >/dev/null 2>&1
check "both variants written" "$(ls "$WORK/reqs" | wc -l | tr -d ' ')" "2"
check "CRLF line endings"     "$(grep -c $'\r' "$WORK/reqs/${NOTIF}_authed.txt")" "$(grep -c '' "$WORK/reqs/${NOTIF}_authed.txt")"
check "observed headers reused" \
  "$(grep -c 'Bearer eyJhb.FAKE' "$WORK/reqs/${NOTIF}_authed.txt" || true)" "1"
check "auth stripped in noauth" \
  "$(grep -ci '^authorization\|^cookie' "$WORK/reqs/${NOTIF}_noauth.txt" || true)" "0"
check "auth kept in authed" \
  "$(grep -ci '^authorization' "$WORK/reqs/${NOTIF}_authed.txt" || true)" "1"

echo "== find_secrets =="
python3 "$SKILL/scripts/find_secrets.py" "$FIX" --out "$WORK/secrets.json" \
  --min-tier info >/dev/null
sec() { python3 -c "import json; d=json.load(open('$WORK/secrets.json')); print($1)"; }
check "confirmed provider keys"  "$(sec "d['by_tier'].get('confirmed',0)")" "6"
check "placeholders rejected" \
  "$(sec "sum(1 for f in d['findings'] if 'YOUR_API_KEY' in str(f['value']) or 'changeme' in str(f['value']) or 'process.env' in str(f['value']))")" "0"
check "low-value noise rejected" \
  "$(sec "sum(1 for f in d['findings'] if str(f['value']) in ('en-US','application/json','true'))")" "0"
check "jwt decoded"              "$(sec "sum(1 for f in d['findings'] if f['kind']=='jwt' and 'jwt' in f)")" "1"
check "jwt alg=none flagged" \
  "$(sec "sum(1 for f in d['findings'] if any('alg=none' in n for n in f.get('jwt',{}).get('notes',[])))")" "1"
check "source map found"         "$(sec "sum(1 for f in d['findings'] if f['kind']=='source-map-ref')")" "1"
check "connection-string email FP suppressed" \
  "$(sec "sum(1 for f in d['findings'] if f['kind']=='email-address' and 'mongodb' in str(f['value']))")" "0"
python3 "$SKILL/scripts/find_secrets.py" "$FIX" --out "$WORK/secrets_r.json" --redact >/dev/null
check "redaction masks values" \
  "$(python3 -c "import json; d=json.load(open('$WORK/secrets_r.json')); print(sum(1 for f in d['findings'] if 'AKIAIOSFODNN7EXAMPLE' == f['value']))")" "0"

echo "== suggest_attacks =="
python3 "$SKILL/scripts/suggest_attacks.py" "$WORK/endpoints.json" \
  --secrets "$WORK/secrets.json" --out "$WORK/attacks.json" >/dev/null
atk() { python3 -c "import json; d=json.load(open('$WORK/attacks.json')); print($1)"; }
check "params classified"        "$(atk "len(d['interesting_parameters'])")" "3"
check "admin DELETE ranks first" \
  "$(atk "d['endpoints'][0]['path']")" "/api/v1/admin/users/{param}"
check "path-segment IDOR test" \
  "$(atk "sum(1 for e in d['endpoints'] if e['path']=='/api/v1/admin/users/{param}' and any(t.get('parameter')=='path segment' for t in e['suggested_tests']))")" "1"
check "admin-surface signal"     "$(atk "sum(1 for e in d['endpoints'] if 'admin-surface' in e['signals'])")" "2"
check "legacy-version contextual" \
  "$(atk "sum(1 for e in d['endpoints'] if 'legacy-version' in e['signals'] and '/v2/' in e['path'])")" "0"
check "secret notes surfaced"    "$(atk "1 if any('alg=none' in n for n in d['secret_notes']) else 0")" "1"

echo "== analyse_file (single-file briefing) =="
python3 "$SKILL/scripts/analyse_file.py" "$FIX/config.js" --json --out "$WORK/single.json" >/dev/null
af() { python3 -c "import json; d=json.load(open('$WORK/single.json')); print($1)"; }
check "single-file analysis runs"  "$([ -f "$WORK/single.json" ] && echo yes)" "yes"
check "endpoints found in file"    "$(af "1 if len(d['endpoints'])>0 else 0")" "1"
check "credentials found in file"  "$(af "1 if any(f['tier']=='confirmed' for f in d['secrets']) else 0")" "1"
check "cross-cutting observations" "$(af "1 if len(d['observations'])>0 else 0")" "1"
python3 "$SKILL/scripts/analyse_file.py" "$FIX/app.js" > "$WORK/brief.txt"
check "briefing has WHAT THIS FILE IS" "$(grep -c '^WHAT THIS FILE IS' "$WORK/brief.txt")" "1"
check "briefing has WHAT STANDS OUT"   "$(grep -c '^WHAT STANDS OUT' "$WORK/brief.txt")" "1"
check "briefing states the caveat"     "$(grep -c 'not about server-side' "$WORK/brief.txt")" "1"

echo "== gen_report =="
python3 "$SKILL/scripts/gen_report.py" --endpoints "$WORK/endpoints.json" \
  --domxss "$WORK/domxss.json" --secrets "$WORK/secrets.json" \
  --attacks "$WORK/attacks.json" --burp-index "$WORK/burp_index.json" \
  --target "Smoke test" --out "$WORK/report.md" >/dev/null
check "report has auth section" "$(grep -c 'missing authorization' "$WORK/report.md")" "1"
check "burp corroboration shown" "$(grep -c 'no-auth' "$WORK/report.md")" "2"
check "limitations section kept" "$(grep -c 'Method and limitations' "$WORK/report.md")" "1"
check "credentials section first" "$(grep -m1 '^## 1\.' "$WORK/report.md")" "## 1. Credentials and sensitive disclosures"
check "attack surface section"  "$(grep -c '^## .*Prioritised attack surface' "$WORK/report.md")" "1"
check "parameters section"      "$(grep -c '^## .*Parameters worth attacking' "$WORK/report.md")" "1"
# Sections must renumber, not leave gaps, when optional inputs are absent.
python3 "$SKILL/scripts/gen_report.py" --endpoints "$WORK/endpoints.json" \
  --target "Smoke test minimal" --out "$WORK/report_min.md" >/dev/null
check "renumbers without optional inputs" \
  "$(grep -o '^## [0-9]*\.' "$WORK/report_min.md" | tr -d '#. ' | tr '\n' ',')" "1,2,3,4,5,"

echo
if [ "$fail" -eq 0 ]; then echo "All checks passed."; else echo "FAILURES present."; fi
exit "$fail"
