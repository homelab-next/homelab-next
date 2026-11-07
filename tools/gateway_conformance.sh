#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# The run steps of CI's `gateway-conformance` job (ADR-0038 decision 7 as ADR-0039 amends it;
# docs/gateway.md, "Conformance in CI"): this repository's `inference` conformance suite against
# its own gateway, orchestrator/cmd/gateway, on loopback, with the fake inference server behind it.
# A workstation runs it the same way.
#
#   tools/gateway_conformance.sh deps   make the venv: pip by hash (constraints/bootstrap.txt), the
#                                       `core` extra under the hashed constraints/ci.txt, then this
#                                       checkout (editable, no deps, no build isolation), then a
#                                       check that every installed distribution is hash-pinned
#   tools/gateway_conformance.sh run    render the conformance spec, start the fake and the gateway,
#                                       run the suite, and fail on any check that did not pass
#
# Environment:
#   HNX_VENV     the venv to create (deps) or use (run); required
#   HNX_PYTHON   the interpreter that creates the venv (deps only; default python3; CI: 3.12)
#   GATEWAY_BIN  the built orchestrator/cmd/gateway binary (run only)
#   WORK_DIR     an absolute, empty or missing scratch directory: the render, the usage file, the
#                logs and the suite's JSON result (run only)
#
# The keys are generated here (32 random bytes, hex: 64 bytes each, distinct), exported only into
# this process's environment and never printed. Neither the gateway nor the fake logs a key value,
# so the logs printed on a failure carry none. Both processes are stopped on every exit.
# hnx-script:
#   id: gateway-conformance
#   kind: tool
#   purpose: Run the inference conformance suite against the repository's own gateway binary and the fake inference server on loopback, holding every check to a pass.
#   owner: maintainers
#   trigger: [ci:ci/gateway-conformance]
#   inputs: HNX_VENV, HNX_PYTHON, GATEWAY_BIN, WORK_DIR; the conformance gateway spec and the own-gateway target under compose/lab-in-a-box/
#   outputs: WORK_DIR (render, usage.jsonl, fake.log, gateway.log, conform-inference.json); a verdict line, also to $GITHUB_STEP_SUMMARY when set
#   exit:
#     "0": deps installed, or every check of the suite passed
#     "1": a setting is missing or wrong, a process did not come up, or a check did not pass
set -euo pipefail

repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
lo=127.0.0.1  # no-raw-endpoint: allow the conformance mode serves loopback only
fake_port=8000   # the conformance spec's svc:inference-small port and cloud_base_url
gw_port=4100
spec=compose/lab-in-a-box/config/llm-gateway-conformance/gateway.yml
target=compose/lab-in-a-box/targets/inference-own-gateway.yml
# the models the fake serves: the backend ids of fast-classifier, spare, embedder and
# cloud-reasoner in the conformance role table (docs/llm-gateway.md, "Running the suite against
# the lab's own gateway"). `spare` is served on purpose: a gateway that wrongly calls that refused
# fallback is then served by spare-1, which the fallback check reads back and fails on.
fake_models=(conformance-chat conformance-spare example-embed-8d example-cloud-chat)

die() { echo "gateway-conformance: $*" >&2; exit 1; }
need() { [[ -n "${!1:-}" ]] || die "$1 is not set"; }

cmd_deps() {
  need HNX_VENV
  local python=${HNX_PYTHON:-python3}
  [[ -f "$repo/constraints/ci.txt" && -f "$repo/constraints/bootstrap.txt" ]] ||
    die "$repo has no constraints/ci.txt and constraints/bootstrap.txt"
  "$python" -m venv "$HNX_VENV"
  local py="$HNX_VENV/bin/python" req="$HNX_VENV/hnx-requirements.txt"
  "$py" -m pip install --disable-pip-version-check --require-hashes --no-deps \
    -r "$repo/constraints/bootstrap.txt"
  # the core extra is what `hnx conform` needs to read the target (the gateway adapter and its
  # turn source are standard library only), as the lab-gateway job installs it
  "$py" -I - "$repo/pyproject.toml" core > "$req" <<'PY'
import sys
import tomllib

with open(sys.argv[1], "rb") as f:
    project = tomllib.load(f)["project"]
reqs = list(project.get("dependencies", []))
for extra in sys.argv[2:]:
    reqs += project["optional-dependencies"][extra]
reqs.append("setuptools")  # for the --no-build-isolation install below
print("\n".join(dict.fromkeys(reqs)))
PY
  "$py" -m pip install --disable-pip-version-check -c "$repo/constraints/ci.txt" -r "$req"
  "$py" -m pip install --disable-pip-version-check --no-deps --no-build-isolation -e "$repo"
  # pip checks hashes only for what the constraints list: a package outside them (a new
  # transitive dependency) would install unhashed. Refuse any installed distribution the two
  # hashed constraint files do not name.
  "$py" -I - "$repo/constraints/ci.txt" "$repo/constraints/bootstrap.txt" <<'PY'
import importlib.metadata as md, re, sys
norm = lambda n: re.sub(r"[-_.]+", "-", n).lower()
named = set()
for path in sys.argv[1:]:
    for line in open(path, encoding="utf-8"):
        m = re.match(r"\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*==", line)
        if m:
            named.add(norm(m.group(1)))
installed = {norm(d.metadata["Name"]) for d in md.distributions()} - {"homelab-next", "homelabnext"}
extra = sorted(installed - named)
if extra:
    sys.exit("installed but not hash-pinned by the constraints: " + ", ".join(extra))
print(f"every installed distribution ({len(installed)}) is hash-pinned")
PY
}

pids=()
cleanup() {
  local status=$?
  local pid
  for pid in "${pids[@]}"; do kill "$pid" 2>/dev/null || true; done
  for pid in "${pids[@]}"; do wait "$pid" 2>/dev/null || true; done
  if ((status != 0)); then
    local log
    for log in fake.log gateway.log; do
      echo "::group::$log"
      cat "$WORK_DIR/$log" 2>/dev/null || echo "(no $log)"
      echo "::endgroup::"
    done
  fi
  exit "$status"
}

# wait_for URL PID NAME: up to 30 s for URL to answer 2xx while PID lives
wait_for() {
  local i
  for ((i = 0; i < 60; i++)); do
    kill -0 "$2" 2>/dev/null || die "$3 exited before it was ready"
    if curl -fs --noproxy '*' --max-time 2 -o /dev/null "$1"; then return 0; fi
    sleep 0.5
  done
  die "$3 not ready at $1 after 30 s"
}

cmd_run() {
  need HNX_VENV; need GATEWAY_BIN; need WORK_DIR
  [[ "$WORK_DIR" == /* ]] || die "WORK_DIR must be an absolute path"
  if [[ -d "$WORK_DIR" ]] && [[ -n "$(ls -A "$WORK_DIR")" ]]; then
    die "WORK_DIR must be empty (a stale usage file would be read back)"
  fi
  local py="$HNX_VENV/bin/python"
  [[ -x "$py" ]] || die "HNX_VENV $HNX_VENV has no bin/python (run deps first)"
  [[ -x "$GATEWAY_BIN" ]] || die "GATEWAY_BIN $GATEWAY_BIN is not an executable"
  mkdir -p "$WORK_DIR"
  trap cleanup EXIT
  cd "$repo"
  # no proxy may stand between the suite and loopback (the gateway itself never reads one)
  export NO_PROXY="$lo,localhost${NO_PROXY:+,$NO_PROXY}" no_proxy="$lo,localhost${no_proxy:+,$no_proxy}"

  "$py" -m homelabnext.cli gen gateway render "$spec" "$WORK_DIR" --conformance --conformance-host "$lo"
  local config="$WORK_DIR/gateway/gateway.json"
  [[ -f "$config" ]] || die "the render wrote no $config"

  # every *_env name the rendered config holds gets a fresh dummy value
  local names name
  names=$("$py" -I - "$config" <<'PY'
import json
import re
import sys

def walk(node):
    if isinstance(node, dict):
        for key, value in node.items():
            if key.endswith("_env") and isinstance(value, str):
                yield value
            else:
                yield from walk(value)
    elif isinstance(node, list):
        for item in node:
            yield from walk(item)

names = sorted(set(walk(json.load(open(sys.argv[1])))))
bad = [n for n in names if not re.fullmatch(r"HNX_SECRET_[A-Z0-9_]+", n)]
if not names or bad:
    sys.exit(f"unexpected env names in {sys.argv[1]}: {bad or 'none at all'}")
print("\n".join(names))
PY
)
  declare -A seen=()
  local value
  for name in $names; do
    value=$("$py" -I -c 'import secrets; print(secrets.token_hex(32))')
    [[ -z "${seen[$value]:-}" ]] || die "generated a duplicate key value"
    seen[$value]=1
    export "$name=$value"
  done
  unset value seen
  echo "dummy values set for: $(echo "$names" | paste -sd' ' -)"

  local model_args=() m
  for m in "${fake_models[@]}"; do model_args+=(--model "$m"); done
  "$py" -I conformance/fakes/openai_server.py --host "$lo" --port "$fake_port" "${model_args[@]}" \
    > "$WORK_DIR/fake.log" 2>&1 &
  pids+=($!)
  wait_for "http://$lo:$fake_port/health" "${pids[-1]}" "the fake inference server"

  "$GATEWAY_BIN" -config "$config" -conformance -listen "$lo:$gw_port" -usage "$WORK_DIR/usage.jsonl" \
    > "$WORK_DIR/gateway.log" 2>&1 &
  pids+=($!)
  wait_for "http://$lo:$gw_port/healthz" "${pids[-1]}" "the gateway"

  export HNX_ENDPOINT_LLM_GATEWAY="http://$lo:$gw_port"
  local rc=0
  "$py" -m homelabnext.cli conform run inference --target "$target" --strict -v \
    --out "$WORK_DIR/conform-inference.json" || rc=$?
  ((rc == 0)) || die "hnx conform run exited $rc"

  # the exit code passes skipped and untested checks; this job holds every check to a pass
  "$py" -I - "$WORK_DIR/conform-inference.json" "${GITHUB_STEP_SUMMARY:-}" <<'PY'
import json
import sys

(run,) = json.load(open(sys.argv[1]))["runs"]
bad = {r["check"]: r["status"] for r in run["results"] if r["status"] != "pass"}
line = f"gateway-conformance: inference against orchestrator/cmd/gateway: {run['verdict']} {run['counts']}"
print(line)
if sys.argv[2]:
    with open(sys.argv[2], "a") as summary:
        print(line, file=summary)
if run["verdict"] != "pass" or bad or not run["results"]:
    sys.exit(f"not every check passed: {bad}")
PY
}

case "${1:-}" in
  deps) cmd_deps ;;
  run) cmd_run ;;
  *) die "usage: $0 deps|run" ;;
esac
