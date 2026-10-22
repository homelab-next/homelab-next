#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# hnx-script:
#   id: workflow-broker-agent-job-submit
#   kind: tool
#   purpose: Broker handler for agent.job.submit; puts one job on the orchestration controller's queue.
#   owner: broker
#   trigger: [manual]
#   inputs: the validated params as JSON on stdin; the ORCHESTRATOR_JOBS_URL secret (the controller's POST /jobs URL)
#   outputs: the controller's answer as JSON on stdout, or a refused object (status, reason) for a final refusal
#   exit:
#     "0": queued, already queued (an idempotent replay), already retried, or refused for good (logged on stderr)
#     "1": the controller could not be reached, or failed in a way a later attempt may not
#
# The workflow broker's handler for agent.job.submit (workflows/broker.manifest.json).  The broker
# validated the params against agent-job-submit.handler.json; they go to the controller as the
# request body, unchanged.  The controller's address is resolved by the broker like a secret, so no
# endpoint is in the tree; the controller admits the job against live load (docs/stackstorm.md).
#
# What the controller answers, and what this handler makes of it:
#   2xx                    queued, or the idempotency key's original run (a replay): success
#   409 already_retried    this run was resubmitted already (by an earlier delivery): success
#   409 retry_chain_spent, 422 (agent_key_mismatch, not_failed, not_retryable, reason_mismatch,
#   payload_override), 404 unknown_run
#                          the controller refuses this resubmit for good: a refusal, logged, exit 0
#                          so nothing retries it
#   anything else (400 input_unsupported is a defect in the pack; 5xx; no answer): failure, exit 1
set -eu
url=${ORCHESTRATOR_JOBS_URL:?the broker did not hand over ORCHESTRATOR_JOBS_URL}
nl='
'
out=$(curl --silent --show-error --max-time 20 --proto '=https' \
  --header 'Content-Type: application/json' --data-binary @- \
  --write-out "${nl}%{http_code}" -- "$url") || {
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
  404 | 422)
    echo "agent.job.submit: refused by the controller: $code ${reason:-unknown}" >&2
    printf '{"refused": true, "status": %s, "reason": "%s"}\n' "$code" "${reason:-unknown}"
    ;;
  *)
    echo "agent.job.submit: the controller answered $code ${reason:-}" >&2
    exit 1
    ;;
esac
