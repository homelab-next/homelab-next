#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# `make precheck`: every static gate in one parallel run, so a change fails in a minute or two on a
# workstation (and in CI's first job) instead of ten minutes into the test matrix. It runs the
# Makefile's precheck-run target (the static gates of `make check`, hygiene, the invariants' fast
# criteria, the ratchets against BASE and the `static` pytest rules) with `make -k -j`, each
# target's output kept together, and prints the failed targets and the time taken at the end.
#
#   tools/precheck.sh            run it (what `make precheck` does)
#
# Environment:
#   PY              the interpreter (default python3)
#   PRECHECK_JOBS   make's job count (default: the CPU count)
#   BASE            the commit the ratchets compare with; when unset, CI's event base
#                   (HNX_PR_BASE / HNX_PUSH_BEFORE through homelabnext.gitbase) in CI, otherwise
#                   the merge base with origin/main; with neither, the ratchets are skipped (said so)
#
# hnx-script:
#   id: precheck
#   kind: tool
#   purpose: Run every static gate (lint, schemas, docs facts, catalogs, ratchets, leak and hygiene scans, invariants' fast criteria, the static pytest rules) in one parallel make run and name what failed.
#   owner: maintainers
#   trigger: [make:precheck]
#   inputs: PY, PRECHECK_JOBS, BASE, HNX_PR_BASE, HNX_PUSH_BEFORE; the working tree
#   outputs: each gate's output, grouped per make target; the failed targets and the elapsed time
#   exit:
#     "0": every gate passed
#     "1": some gate failed (the targets are named)
#     "2": the base could not be decided in CI
set -uo pipefail

repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo" || exit 2
PY=${PY:-python3}
jobs=${PRECHECK_JOBS:-$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)}

base=${BASE:-}
if [ -z "$base" ]; then
  if [ -n "${HNX_PR_BASE:-}${HNX_PUSH_BEFORE:-}" ]; then
    # CI: the one base rule (homelabnext/gitbase.py); a root commit has none
    base=$("$PY" -m homelabnext.gitbase --allow-root) || { echo "precheck: no base"; exit 2; }
  elif git rev-parse -q --verify origin/main >/dev/null; then
    base=$(git merge-base origin/main HEAD 2>/dev/null || true)
  fi
fi
if [ -n "$base" ]; then
  echo "precheck: base $base, $jobs jobs"
else
  echo "precheck: no base (no origin/main): the ratchets are skipped; $jobs jobs"
fi

log=$(mktemp)
trap 'rm -f "$log"' EXIT
start=$(date +%s)
make -k -j"$jobs" --output-sync=target --no-print-directory precheck-run PY="$PY" \
  ${base:+BASE="$base"} 2>&1 | tee "$log"
rc=${PIPESTATUS[0]}
took=$(($(date +%s) - start))

if [ "$rc" -eq 0 ]; then
  echo "precheck: OK in ${took}s"
  exit 0
fi
failed=$(sed -nE 's/^make(\[[0-9]+\])?: \*\*\* \[[^]]*: ([A-Za-z0-9_.-]+)\] Error .*/\2/p' "$log" | grep -vx precheck-run | sort -u | tr '\n' ' ')
echo "precheck: FAILED in ${took}s: ${failed:-see the output above}"
exit 1
