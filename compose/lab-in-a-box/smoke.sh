#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Lab-in-a-box smoke test: bring the stack up, wait until every service reports healthy, check
# each service directly, run `hnx conform` where it exists, write a report, tear down.
#
#   compose/lab-in-a-box/smoke.sh [--keep] [--no-build] [--report-dir DIR]
#
# Exit codes: 0 all good; 1 a service or check failed; 2 usage; 3 docker or compose missing
# (nothing was run); 4 refused a non-loopback LAB_BIND (see bind_guard.sh; nothing was run).
# The conformance step degrades gracefully: with no `hnx conform` it is reported as "skipped"
# and does not fail the run.  Settings: .env.example, overridden by .env, overridden by the
# environment (the order docker compose itself uses).
# hnx-script:
#   id: lab-smoke
#   kind: tool
#   purpose: Bring the lab-in-a-box up, check every service, run conformance where present, tear down.
#   owner: lab-in-a-box
#   trigger: [ci:nightly/lab-in-a-box, make:lab-smoke]
#   inputs: compose/lab-in-a-box settings (.env.example, .env, environment)
#   outputs: build/lab-smoke/report.json (or --report-dir)
#   exit:
#     "0": all good
#     "1": a service or check failed
#     "2": usage
#     "3": docker or compose missing
#     "4": refused a non-loopback LAB_BIND
set -uo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
keep=0
build=1
report_dir="$repo/build/lab-smoke"
while [ $# -gt 0 ]; do
  case "$1" in
    --keep) keep=1 ;;
    --no-build) build=0 ;;
    --report-dir) shift; report_dir="${1:?--report-dir needs a path}" ;;
    -h|--help) sed -n '2,14p' "$0"; exit 0 ;;
    *) echo "smoke.sh: unknown option $1" >&2; exit 2 ;;
  esac
  shift
done

# before anything else: never publish the unauthenticated stack beyond loopback by accident
LAB_GUARD_DIR="$here"
# shellcheck source=bind_guard.sh
. "$here/bind_guard.sh"
lab_bind_guard || exit 4

if ! command -v docker >/dev/null 2>&1 || ! docker compose version >/dev/null 2>&1; then
  echo "smoke.sh: docker with the compose plugin is required; nothing was run" >&2
  exit 3
fi

mkdir -p "$report_dir"
env_args=(--env-file "$here/.env.example")
[ -f "$here/.env" ] && env_args+=(--env-file "$here/.env")
dc() { docker compose "${env_args[@]}" -f "$here/docker-compose.yml" "$@"; }

# the environment wins over both files, as it does for docker compose (and for the bind guard)
from_env=""
lab_vars="$(compgen -v LAB_ || true)"
# shellcheck disable=SC2086
[ -n "$lab_vars" ] && from_env="$(declare -p $lab_vars)"
set -a
# shellcheck disable=SC1091
. "$here/.env.example"
# shellcheck disable=SC1091
[ -f "$here/.env" ] && . "$here/.env"
set +a
eval "$from_env"

status=0
conform_state="skipped"
conform_note=""

collect_logs() {
  dc ps -a >"$report_dir/ps.txt" 2>&1
  dc logs --no-color --tail 200 >"$report_dir/compose.log" 2>&1
}

teardown() {
  if [ "$keep" -eq 1 ]; then
    echo "smoke.sh: --keep given, leaving the stack up (make lab-down to remove it)"
  else
    dc down --volumes --remove-orphans >/dev/null 2>&1
  fi
}

write_report() {
  python3 - "$report_dir" "$status" "$conform_state" "$conform_note" <<'PY'
import json, pathlib, sys
d = pathlib.Path(sys.argv[1])
checks = d / "checks.json"
doc = json.loads(checks.read_text()) if checks.exists() else {"checks": [], "ok": False}
report = {
    "ok": sys.argv[2] == "0",
    "checks": doc["checks"],
    "conformance": {"state": sys.argv[3], "note": sys.argv[4]},
}
(d / "report.json").write_text(json.dumps(report, indent=2) + "\n")
print(f"smoke.sh: report written to {d / 'report.json'}")
PY
}

trap 'collect_logs; teardown; write_report' EXIT

up_args=(up -d --wait --wait-timeout 420)
[ "$build" -eq 1 ] && up_args+=(--build)
echo "smoke.sh: bringing the stack up"
if ! dc "${up_args[@]}"; then
  echo "smoke.sh: the stack did not become healthy" >&2
  status=1
  exit "$status"
fi

echo "smoke.sh: every service reports healthy; checking each one directly"
python3 "$here/smoke_checks.py" --report "$report_dir/checks.json" || status=1

# --- conformance: only where the harness exists ---------------------------------------------
endpoints="$report_dir/endpoints.env"
{
  echo "HNX_ENDPOINT_LAKE_QUERY=http://${LAB_BIND}:${LAB_PORT_QUERY}"
  echo "HNX_ENDPOINT_LAKE_CATALOG=http://${LAB_BIND}:${LAB_PORT_CATALOG}"
  echo "HNX_ENDPOINT_OBJECT_STORE=http://${LAB_BIND}:${LAB_PORT_OBJECT_STORE}"
  echo "HNX_ENDPOINT_EVENTS=nats://${LAB_BIND}:${LAB_PORT_EVENTS}"
  echo "HNX_ENDPOINT_SECRETS=http://${LAB_BIND}:${LAB_PORT_SECRETS}"
  echo "HNX_ENDPOINT_NOTIFY=http://${LAB_BIND}:${LAB_PORT_NOTIFY}"
  echo "HNX_ENDPOINT_INFERENCE=http://${LAB_BIND}:${LAB_PORT_INFERENCE}"
  echo "HNX_ENDPOINT_CASES=http://${LAB_BIND}:${LAB_PORT_CASES}"
} >"$endpoints"

conform_caps="${HNX_CONFORM_CAPS:-lake-query lake-catalog object-store events secrets notify inference cases}"
conform_cmd="${HNX_CONFORM_CMD:-hnx conform run}"
if ${conform_cmd%% run*} --help >/dev/null 2>&1; then
  conform_state="pass"
  set -a; . "$endpoints"; set +a
  for cap in $conform_caps; do
    echo "smoke.sh: conformance: $cap"
    if $conform_cmd "$cap" >"$report_dir/conform-$cap.log" 2>&1; then
      :
    else
      rc=$?
      # a capability whose suite is not shipped yet is skipped; any other failure fails the run
      if grep -qiE "no (such )?(suite|capability)|not (implemented|found|available)|unknown capability" "$report_dir/conform-$cap.log"; then
        conform_note="$conform_note $cap:no-suite"
      else
        conform_note="$conform_note $cap:FAIL($rc)"
        conform_state="fail"
        status=1
      fi
    fi
  done
else
  conform_note="hnx conform is not available in this environment; direct checks only"
  echo "smoke.sh: $conform_note"
fi

exit "$status"
