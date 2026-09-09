#!/usr/bin/env bash
# End-to-end smoke test: runs the whole pipeline over tests/fixtures/ and
# asserts the results the scripts are supposed to get right. Run this after
# changing any extraction pattern -- regex edits break neighbouring cases in
# ways that are easy to miss by eye.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SKILL="$(dirname "$HERE")"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

fail=0
check() {  # check <description> <actual> <expected>
  if [ "$2" = "$3" ]; then
    printf '  ok   %s\n' "$1"
  else
    printf '  FAIL %s (got %s, want %s)\n' "$1" "$2" "$3"
    fail=1
  fi
}

echo "== parse_burp =="
python3 "$SKILL/scripts/parse_burp.py" "$HERE/fixtures/burp_export.xml" \
  --out-dir "$WORK/burp_js" --index "$WORK/burp_index.json" >/dev/null
check "js bodies written" "$(ls "$WORK/burp_js" | wc -l | tr -d ' ')" "3"

echo "== extract_endpoints =="
python3 "$SKILL/scripts/extract_endpoints.py" "$HERE/fixtures" \
  --out "$WORK/endpoints.json" >/dev/null
q() { python3 -c "import json,sys; d=json.load(open('$WORK/endpoints.json')); print($1)"; }
check "endpoint count"        "$(q "len(d['endpoints'])")" "9"
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
python3 "$SKILL/scripts/dom_xss_scan.py" "$HERE/fixtures" --out "$WORK/domxss.json" >/dev/null
d() { python3 -c "import json,sys; d=json.load(open('$WORK/domxss.json')); print($1)"; }
check "high-confidence hits"  "$(d "d['by_confidence'].get('high',0)")" "3"
check "medium via tainted var" "$(d "d['by_confidence'].get('medium',0)")" "1"
check "textContent not a sink" "$(d "sum(1 for f in d['findings'] if 'textContent' in f['sink'])")" "0"

echo "== gen_wordlist =="
check "paths mode non-empty" \
  "$(python3 "$SKILL/scripts/gen_wordlist.py" "$WORK/endpoints.json" --mode paths | wc -l | tr -d ' ')" "9"
check "no internal placeholder leak" \
  "$(python3 "$SKILL/scripts/gen_wordlist.py" "$WORK/endpoints.json" --mode params | grep -c '^concat$' || true)" "0"

echo "== make_request =="
python3 "$SKILL/scripts/make_request.py" "$WORK/endpoints.json" \
  --burp-index "$WORK/burp_index.json" --id e007 --both --out-dir "$WORK/reqs" >/dev/null 2>&1
check "both variants written" "$(ls "$WORK/reqs" | wc -l | tr -d ' ')" "2"
check "CRLF line endings"     "$(grep -c $'\r' "$WORK/reqs/e007_authed.txt")" "$(grep -c '' "$WORK/reqs/e007_authed.txt")"
check "auth stripped in noauth" \
  "$(grep -ci 'authorization\|^cookie' "$WORK/reqs/e007_noauth.txt" || true)" "0"
check "auth kept in authed" \
  "$(grep -ci 'authorization' "$WORK/reqs/e007_authed.txt" || true)" "1"

echo "== gen_report =="
python3 "$SKILL/scripts/gen_report.py" --endpoints "$WORK/endpoints.json" \
  --domxss "$WORK/domxss.json" --burp-index "$WORK/burp_index.json" \
  --target "Smoke test" --out "$WORK/report.md" >/dev/null
check "report has auth section" "$(grep -c 'missing authorization' "$WORK/report.md")" "1"
check "burp corroboration shown" "$(grep -c 'no-auth' "$WORK/report.md")" "2"
check "limitations section kept" "$(grep -c 'Method and limitations' "$WORK/report.md")" "1"

echo
if [ "$fail" -eq 0 ]; then echo "All checks passed."; else echo "FAILURES present."; fi
exit "$fail"
