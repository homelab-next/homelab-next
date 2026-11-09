#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# hnx-script:
#   id: lab-orchestrator-entrypoint
#   kind: tool
#   purpose: Start the lab controller with a tokens file written from the throwaway token's digest.
#   owner: lab-in-a-box
#   trigger: [compose:lab-in-a-box/orchestrator]
#   inputs: /run/secrets/orchestrator-token; /etc/orchestrator/controller.yaml
#   outputs: /var/lib/orchestrator/api-tokens.yaml (owner-only); the controller's log
#   exit:
#     "0": the controller stopped cleanly
#     "1": no token, or the configuration's check failed
#
# The lab controller's start: write the job API's tokens file (the digest of the token compose
# gives the container as the secret file /run/secrets/orchestrator-token, never the token)
# owner-only into the state directory, then run the controller. The token is in no environment,
# the container's init included; the lab's value is a throwaway one (.env.example), which
# bind_guard.sh makes the operator change, to at least 32 characters, before a non-loopback bind.
set -eu
token_file=/run/secrets/orchestrator-token
[ -s "$token_file" ] || { echo "orchestrator: $token_file is missing or empty (LAB_ORCHESTRATOR_TOKEN)" >&2; exit 1; }
umask 077
digest=$(tr -d '\n' <"$token_file" | sha256sum | cut -d' ' -f1)
printf 'tokens:\n  - {caller: lab-smoke, sha256: %s, scopes: [jobs, admin]}\n' "$digest" \
  >/var/lib/orchestrator/api-tokens.yaml
/usr/local/bin/controller check --config /etc/orchestrator/controller.yaml
exec /usr/local/bin/controller serve --config /etc/orchestrator/controller.yaml
