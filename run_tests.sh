#!/usr/bin/env bash
# Invokes the deployed function with five cases and prints one line each.
set -uo pipefail
FN=fli-proto-fn; END=2026-11-12T18:00:00Z
t() { # name employee account
  aws lambda invoke --function-name "$FN" --cli-binary-format raw-in-base64-out \
    --payload "{\"claims\":{\"employee_id\":\"$2\"},\"account\":\"$3\",\"window_hours\":24,\"end\":\"$END\"}" \
    "out_$1.json" >/dev/null
  python3 - "$1" "out_$1.json" <<'PY'
import json,sys
n,p=sys.argv[1:]; r=json.load(open(p)); rep=r.get("report") or {}
print("%-22s status=%-7s reason=%-14s class=%-24s esc=%-5s notes=%s" % (n, r.get("status"), r.get("reason","-"), rep.get("classification_id","-"), rep.get("escalate","-"), r.get("notes","-")))
PY
}
t owned_stale     E1001 svc-batch01
t owned_spray_inj E1001 svc-web02
t owned_no_data   E1001 svc-quiet03
t not_owned       E1001 svc-payroll
t tier0_owned     E1001 da-e1001-t0
t unknown_caller  E9999 svc-batch01
