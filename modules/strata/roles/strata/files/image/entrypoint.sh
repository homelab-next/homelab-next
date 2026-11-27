#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# hnx-script:
#   id: strata-entrypoint
#   kind: service
#   purpose: Start Strata for one model whose files are on disk, from named HNX_STRATA_* settings, and keep the container up while the server is.
#   owner: platform
#   trigger: [role:strata]
#   inputs: the HNX_STRATA_* environment variables the role renders (listed below) and PORT
#   outputs: the launcher's log on stdout and stderr
#   installs_to: /opt/strata/entrypoint.sh
#   exit:
#     "0": stopped on SIGTERM or SIGINT
#     "1": the server went away
#     "2": a setting or a file is missing
#     "3": the engine in the image does not match the card, or no card is visible
# The module's starter: `strata launch --no-tui` for ONE model whose files are already on disk, with the settings the role
# renders as HNX_STRATA_* environment variables (named settings only: no raw flag reaches the engine), then stay up and stop
# cleanly on SIGTERM. Nothing is downloaded: the guest has no egress, and the draft layer (MTP, a separate ~5 GB download)
# is never fetched (--drafting off unless the site sets another mode).
#   HNX_STRATA_MODEL_DIR     folder of the model's GGUF files (read-only mount), required
#   HNX_STRATA_MODEL_FILE    the first shard in it (the launcher finds the others beside it), required
#   HNX_STRATA_SERVED_NAME   the id the role expects /v1/models to list (informational here)
#   HNX_STRATA_CONTEXT       tokens of context, required
#   HNX_STRATA_KV            int8 | q4_0 | k8v4 | fp16
#   HNX_STRATA_PARALLEL      requests decoded together
#   HNX_STRATA_GPU           the card index(es) INSIDE the container, e.g. 0
#   HNX_STRATA_SPEC          draft depth (--spec N); 0 or empty: not set
#   HNX_STRATA_KV_STREAMING  on | off | auto
#   HNX_STRATA_MMAP_EXPERTS  1: --mmap-experts
#   HNX_STRATA_PCIE_FRAC     --pcie-frac F, empty: the engine's default
#   HNX_STRATA_POOL_WORKERS  --pool-workers N, empty: the engine's default
#   HNX_STRATA_VRAM_RESERVE_MIB  --vram-reserve-mib N, empty: the engine's default
#   HNX_STRATA_DRAFTING      off | auto | mtp
#   HNX_STRATA_DIRECTION     refusal-direction (control vector) GGUF file in the model directory, optional;
#                            _SCALE (default 1.0) and _LAYERS "A,B" (default 4,44)
set -u
APP=/opt/strata
STRATA="$APP/terminal/bin/strata"
PRESET=hnx
say() { printf '%s\n' "$*"; }
die() { printf '[X] %s\n' "$1" >&2; exit "${2:-1}"; }

[ -n "${HNX_STRATA_MODEL_DIR:-}" ] || die "HNX_STRATA_MODEL_DIR is not set" 2
[ -d "$HNX_STRATA_MODEL_DIR" ] || die "$HNX_STRATA_MODEL_DIR is not a directory: the model store entry is not mounted" 2
[ -n "${HNX_STRATA_MODEL_FILE:-}" ] || die "HNX_STRATA_MODEL_FILE is not set" 2
[ -f "$HNX_STRATA_MODEL_DIR/$HNX_STRATA_MODEL_FILE" ] || die "$HNX_STRATA_MODEL_DIR/$HNX_STRATA_MODEL_FILE is not there" 2
[ -n "${HNX_STRATA_CONTEXT:-}" ] || die "HNX_STRATA_CONTEXT is not set" 2
mkdir -p /data/state /data/home /data/install /data/Strata-data 2>/dev/null || die "/data is not writable" 2

# is there an engine for this card?
engine_json=$("$STRATA" components engine --output json 2>/dev/null || true)
printf '%s' "$engine_json" | grep -q '"usable": *true' \
  || { "$STRATA" components engine 2>&1 | sed 's/^/    /' >&2 || true; die "the engine in this image does not match the card, or the card is not visible to the container (CDI device, driver 580+)" 3; }

set -- launch --no-tui --yes --access lan --port "${PORT:-8080}" --data-dir /data/Strata-data \
       --model-path "$HNX_STRATA_MODEL_DIR/$HNX_STRATA_MODEL_FILE" --context "$HNX_STRATA_CONTEXT" --vision off \
       --no-api-key --drafting "${HNX_STRATA_DRAFTING:-off}" --tune skip
[ -n "${HNX_STRATA_KV:-}" ]       && set -- "$@" --kv "$HNX_STRATA_KV"
[ -n "${HNX_STRATA_PARALLEL:-}" ] && set -- "$@" --parallel "$HNX_STRATA_PARALLEL"
[ -n "${HNX_STRATA_GPU:-}" ]      && set -- "$@" --gpu "$HNX_STRATA_GPU"
spec="${HNX_STRATA_SPEC:-0}"
[ "$spec" != 0 ] && set -- "$@" --set "spec=$spec"
case "${HNX_STRATA_KV_STREAMING:-off}" in
  on|off|auto) set -- "$@" --set "kv-streaming=${HNX_STRATA_KV_STREAMING:-off}" ;;
  *) die "HNX_STRATA_KV_STREAMING must be on, off or auto" 2 ;;
esac
[ "${HNX_STRATA_MMAP_EXPERTS:-0}" = 1 ]   && set -- "$@" --set "mmap-experts=on"
[ -n "${HNX_STRATA_PCIE_FRAC:-}" ]        && set -- "$@" --set "pcie-frac=$HNX_STRATA_PCIE_FRAC"
[ -n "${HNX_STRATA_POOL_WORKERS:-}" ]     && set -- "$@" --set "pool-workers=$HNX_STRATA_POOL_WORKERS"
[ -n "${HNX_STRATA_VRAM_RESERVE_MIB:-}" ] && set -- "$@" --set "vram-reserve-mib=$HNX_STRATA_VRAM_RESERVE_MIB"
if [ -n "${HNX_STRATA_DIRECTION:-}" ]; then
  [ -f "$HNX_STRATA_MODEL_DIR/$HNX_STRATA_DIRECTION" ] || die "the refusal-direction file $HNX_STRATA_MODEL_DIR/$HNX_STRATA_DIRECTION is not there" 2
  set -- "$@" --set "control-vector-scaled=$HNX_STRATA_MODEL_DIR/$HNX_STRATA_DIRECTION:${HNX_STRATA_DIRECTION_SCALE:-1.0}" \
              --set "control-vector-layer-range=${HNX_STRATA_DIRECTION_LAYERS:-4,44}" \
              --set "cvec-mode=project" --set "cvec-dir=per-layer"
fi
set -- "$@" --save-preset "$PRESET"

stopping=""; launch_pid=""
on_term() {
  stopping=1
  say "Stop requested: shutting down."
  if [ -n "$launch_pid" ] && kill -0 "$launch_pid" 2>/dev/null; then
    kill -INT "$launch_pid" 2>/dev/null
    i=0; while kill -0 "$launch_pid" 2>/dev/null && [ "$i" -lt 30 ]; do sleep 1; i=$((i+1)); done
    kill -TERM "$launch_pid" 2>/dev/null || true
  fi
  "$STRATA" launch --stop --preset "$PRESET" || true
  exit 0
}
trap on_term TERM INT

# a command started with & by a non-interactive sh ignores SIGINT; the launch must see it (it is how it stops a load)
RESET_INT='import os, signal, sys; signal.signal(signal.SIGINT, signal.SIG_DFL); os.execv(sys.argv[1], sys.argv[1:])'
PYBIN="$APP/terminal/python/bin/python3"
say "Starting Strata: ${HNX_STRATA_SERVED_NAME:-strata} from $HNX_STRATA_MODEL_DIR/$HNX_STRATA_MODEL_FILE (preset '$PRESET')."
"$PYBIN" -c "$RESET_INT" "$STRATA" "$@" &
launch_pid=$!
wait "$launch_pid"; rc=$?
launch_pid=""
[ -n "$stopping" ] && exit 0
[ "$rc" -eq 0 ] || die "strata launch stopped with code $rc (the lines above say why)" "$rc"
say "Serving on port ${PORT:-8080}."

# stay up; leave (so the unit's restart policy can act) if the server is gone
bad=0
while [ -z "$stopping" ]; do
  sleep 10 &
  wait $!
  [ -n "$stopping" ] && break
  if "$STRATA" launch --status --output json 2>/dev/null | grep -q '"state": *"ready"'; then bad=0; else bad=$((bad+1)); fi
  [ "$bad" -lt 3 ] || die "the server is no longer running (its log is under /data/install)" 1
done
exit 0
