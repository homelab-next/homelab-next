#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# hnx-script:
#   id: lab-orchestrator-entrypoint
#   kind: tool
#   purpose: Start the lab controller with a tokens file written from the throwaway token's digest.
#   owner: lab-in-a-box
#   trigger: [compose:lab-in-a-box/orchestrator]
#   inputs: HNX_SECRET_ORCHESTRATOR_TOKEN; /etc/orchestrator/controller.yaml
#   outputs: /var/lib/orchestrator/api-tokens.yaml (owner-only); the controller's log
#   exit:
#     "0": the controller stopped cleanly
#     "1": no token, or the configuration's check failed
#
# The lab controller's start: write the job API's tokens file (the digest of
# HNX_SECRET_ORCHESTRATOR_TOKEN, never the token) owner-only into the state directory, then run
# the controller with the token unset in its own environment, so its sessions and facts commands
# cannot inherit it. The container's init (PID 1, the same uid) still holds it in its
# environment, which a session could read through /proc: the lab's token is a throwaway one
# (.env.example), which bind_guard.sh makes the operator change before any non-loopback bind.
set -eu
: "${HNX_SECRET_ORCHESTRATOR_TOKEN:?the job API token is required}"
umask 077
digest=$(printf '%s' "$HNX_SECRET_ORCHESTRATOR_TOKEN" | sha256sum | cut -d' ' -f1)
printf 'tokens:\n  - {caller: lab-smoke, sha256: %s, scopes: [jobs, admin]}\n' "$digest" \
  >/var/lib/orchestrator/api-tokens.yaml
/usr/local/bin/controller check --config /etc/orchestrator/controller.yaml
exec env -u HNX_SECRET_ORCHESTRATOR_TOKEN /usr/local/bin/controller serve --config /etc/orchestrator/controller.yaml
