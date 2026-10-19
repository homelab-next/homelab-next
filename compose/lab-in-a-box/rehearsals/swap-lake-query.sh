#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# P9.2 swap rehearsal (docs/build-order.md): replace the built-in fake lake with the lab's real
# query engine through the swap kit (shadow, parity, flip), then roll back, and prove the record
# validates and the incumbent is back.  smoke.sh runs every rehearsals/*.sh while the stack is up:
#
#   compose/lab-in-a-box/rehearsals/swap-lake-query.sh REPORT_DIR
#
# Needs HNX_ENDPOINT_LAKE_QUERY, HNX_ENDPOINT_LAKE_CATALOG and LAB_WAREHOUSE (smoke.sh exports
# them).  Writes REPORT_DIR/swap-lake-query/: the swap record, its evidence, the registry, the
# flip plan and rehearsal.json.  The driver is homelabnext/swap/rehearsal.py (unit-tested).
# hnx-script:
#   id: lab-rehearsal-swap-lake-query
#   kind: tool
#   purpose: Rehearse the lake-query swap on the lab-in-a-box (fake lake to Trino) and roll it back.
#   owner: lab-in-a-box
#   trigger: [manual]
#   inputs: REPORT_DIR; the lake endpoints and LAB_WAREHOUSE from the environment
#   outputs: REPORT_DIR/swap-lake-query/ (swap record, evidence, registry, plan, rehearsal.json)
#   exit:
#     "0": the swap ran to cutover, rolled back, and the record validates
#     "1": a step, the rollback or the record check failed
#     "2": usage, or the candidate lake could not be reached
set -uo pipefail

[ $# -eq 1 ] || { echo "usage: $0 REPORT_DIR" >&2; exit 2; }
out="$1/swap-lake-query"
py="${HNX_PYTHON:-python3}"
hnx_swap() {
  if [ -z "${HNX_PYTHON:-}" ] && command -v hnx >/dev/null 2>&1; then hnx swap "$@"
  else "$py" -m homelabnext.cli swap "$@"; fi
}
rm -rf "$out"
mkdir -p "$out"

echo "== the procedure"
hnx_swap plan || exit 2

echo "== rehearsal: shadow, parity, flip, rollback"
"$py" -m homelabnext.swap.rehearsal --report-dir "$out"
rc=$?
[ "$rc" -eq 2 ] && exit 2

record="$out/swap-lake-query-rehearsal.swap.json"
[ -f "$record" ] || { echo "no swap record was written" >&2; exit 1; }

echo "== the flip the cutover applied, and its inverse (rollback)"
hnx_swap plan --registry "$out/services.yml" --service lake-query \
  --to-host lab-lake-query --to-impl trino --to-version 470.0 | tee "$out/flip-plan.txt" | tail -n 8

echo "== the record"
hnx_swap status "$record" || rc=1
hnx_swap record "$record" --verify || rc=1
exit "$rc"
