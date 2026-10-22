#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# hnx-script:
#   id: workflow-broker-agent-job-submit
#   kind: tool
#   purpose: Broker handler for agent.job.submit; puts one job on the orchestration controller's queue.
#   owner: broker
#   trigger: [manual]
#   inputs: the validated params as JSON on stdin; the ORCHESTRATOR_JOBS_URL secret (the controller's POST /jobs URL); the ORCHESTRATOR_JOBS_TOKEN secret (a bearer token with the controller's jobs scope)
#   outputs: the controller's answer as JSON on stdout, or a refused object (status, reason) for a final refusal
#   exit:
#     "0": queued, already queued (an idempotent replay), already retried, or refused for good (logged on stderr)
#     "1": no idempotency key or token, the controller could not be reached, refused the token (401, 403), or failed (400, 5xx)
#
# The workflow broker's handler for agent.job.submit (workflows/broker.manifest.json).  The broker
# validated the params against agent-job-submit.handler.json; they go to the controller as the
# request body, unchanged.  The controller's address is resolved by the broker like a secret, so no
# endpoint is in the tree; the controller admits the job against live load (docs/stackstorm.md).
# The params' idempotency_key also goes as the Idempotency-Key header (for a resubmit it is the
# failed run's id, so a retried POST is the same request).  The bearer token (ORCHESTRATOR_JOBS_TOKEN,
# resolved by the broker the same way, the controller's jobs scope) goes as the Authorization
# header through a 0600 header file in the run's private TMPDIR, so it is never in curl's argv
# (visible to every local user in ps) nor in a log line.
#
# What the controller answers, and what this handler makes of it:
#   2xx                    queued, or the idempotency key's original run (a replay): success
#   409 already_retried    this run was resubmitted already (by an earlier delivery): success
#   409 retry_chain_spent, 422 (agent_key_mismatch, not_failed, not_retryable, reason_mismatch,
#   payload_override, idempotency_key_mismatch), 404 unknown_run
#                          the controller refuses this resubmit for good: a refusal, logged, exit 0
#                          so nothing retries it
#   401, 403               the controller refused the token (missing, wrong, or without the jobs
#                          scope): failure, logged, exit 1
#   anything else (400 input_unsupported is a defect in the pack; 5xx; no answer): failure, exit 1
set -eu
url=${ORCHESTRATOR_JOBS_URL:?the broker did not hand over ORCHESTRATOR_JOBS_URL}
token=${ORCHESTRATOR_JOBS_TOKEN:-}
[ -n "$token" ] || { echo "agent.job.submit: the broker did not hand over ORCHESTRATOR_JOBS_TOKEN" >&2; exit 1; }
nl='
'
cr=$(printf '\r')
case $token in
  *"$nl"* | *"$cr"* | *' '*)
    echo "agent.job.submit: ORCHESTRATOR_JOBS_TOKEN is not a single token" >&2
    exit 1
    ;;
esac
params=$(cat)
# the schema restricts the key to [A-Za-z0-9._:-], so it is safe in a header as it stands
key=$(printf '%s' "$params" | sed -n 's/.*"idempotency_key"[[:space:]]*:[[:space:]]*"\([A-Za-z0-9._:-]*\)".*/\1/p')
[ -n "$key" ] || { echo "agent.job.submit: no idempotency_key in the params" >&2; exit 1; }
umask 077
hdrs=$(mktemp "${TMPDIR:-/tmp}/agent-job-submit.XXXXXX")
trap 'rm -f "$hdrs"' EXIT
printf 'Authorization: Bearer %s\n' "$token" >"$hdrs"
out=$(printf '%s' "$params" | curl --silent --show-error --max-time 20 --proto '=https' \
  --header 'Content-Type: application/json' --header "Idempotency-Key: $key" --header "@$hdrs" \
  --data-binary @- --write-out "${nl}%{http_code}" -- "$url") || {
  echo "agent.job.submit: the controller could not be reached" >&2
  exit 1
}
code=${out##*"$nl"}
body=${out%"$nl"*}
[ "$body" = "$out" ] && body=''
reason=$(printf '%s' "$body" | sed -n 's/.*"reason"[[:space:]]*:[[:space:]]*"\([a-z_-]*\)".*/\1/p' | head -n 1)
case $code in
  2??)
    printf '%s\n' "$body"
    ;;
  409)
    if [ "$reason" = already_retried ]; then
      printf '%s\n' "$body"
    else
      echo "agent.job.submit: refused by the controller: 409 ${reason:-unknown}" >&2
      printf '{"refused": true, "status": 409, "reason": "%s"}\n' "${reason:-unknown}"
    fi
    ;;
  401 | 403)
    echo "agent.job.submit: the controller refused the token: $code (ORCHESTRATOR_JOBS_TOKEN missing, wrong, or without the jobs scope)" >&2
    exit 1
    ;;
  404 | 422)
    echo "agent.job.submit: refused by the controller: $code ${reason:-unknown}" >&2
    printf '{"refused": true, "status": %s, "reason": "%s"}\n' "$code" "${reason:-unknown}"
    ;;
  *)
    echo "agent.job.submit: the controller answered $code ${reason:-}" >&2
    exit 1
    ;;
esac
