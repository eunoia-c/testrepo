#!/usr/bin/env bash
# End-to-end check against the local mock: no real target is contacted.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$HERE")"
WORK="$(mktemp -d)"
PORT="${PORT:-8443}"
trap 'kill %1 2>/dev/null || true; rm -rf "$WORK"' EXIT

command -v openssl >/dev/null || { echo "openssl is required"; exit 1; }
openssl req -x509 -newkey rsa:2048 -keyout "$WORK/key.pem" -out "$WORK/cert.pem" \
    -days 1 -nodes -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost" 2>/dev/null

python3 "$HERE/mock_servicenow.py" "$WORK" "$PORT" &
sleep 1.5

set +e
python3 "$ROOT/snowpick.py" --target "localhost:$PORT" --insecure --fingerprint \
    --table-api --samples 3 --output "$WORK/a.json" >/dev/null 2>&1
rc=$?
python3 "$ROOT/snowpick.py" --target "localhost:$PORT" --insecure --fingerprint \
    --table-api --samples 3 --output "$WORK/b.json" >/dev/null 2>&1
set -e

fail=0
check() {
  if [ "$2" = "$3" ]; then printf '  ok   %s\n' "$1"
  else printf '  FAIL %s (got %s, want %s)\n' "$1" "$2" "$3"; fail=1; fi
}

check "exit code signals findings" "$rc" "2"
check "runs are byte-identical" "$(python3 - "$WORK/a.json" "$WORK/b.json" <<'PY'
import json, sys
a, b = (json.load(open(p)) for p in sys.argv[1:3])
for k in ("scan_time", "elapsed_ms"):
    a.pop(k, None); b.pop(k, None)
print("yes" if a == b else "no")
PY
)" "yes"

q() { python3 -c "import json,sys; d=json.load(open('$WORK/a.json'))['findings'][0]; print($1)"; }
check "session bootstrapped"      "$(q "d['token_obtained']")" "True"
check "stats.do detected"         "$(q "d['stats_do']")" "True"
check "release fingerprinted"     "$(q "d['fingerprint']['release']")" "Zurich"
check "widget exposure found"     "$(q "sum(1 for w in d['widgets'] if w['status']=='exposed')")" "1"
check "count oracle found"        "$(q "sum(1 for t in d['table_findings'] if t['status']=='count_oracle')")" "2"
check "oracle hint emitted"       "$(q "sum(1 for t in d['table_findings'] if 'oracle_hint' in (t.get('reproduction') or {}))")" "2"
check "table api X-Total-Count"   "$(q "d['table_api_findings'][0]['record_count']")" "8123"
check "json uses 'field' key"     "$(q "'field' in d['table_findings'][0]")" "True"
check "pii classified as observed" \
  "$(q "sum(1 for w in d['widgets'] for h in w.get('hints',[]) if h['category']=='pii' and h['basis']=='observed')")" "1"

echo
if [ "$fail" -eq 0 ]; then echo "All integration checks passed."; else echo "FAILURES present."; fi
exit "$fail"
