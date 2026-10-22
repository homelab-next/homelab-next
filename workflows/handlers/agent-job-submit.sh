#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# hnx-script:
#   id: workflow-broker-agent-job-submit
#   kind: tool
#   purpose: Broker handler for agent.job.submit; puts one job on the orchestration controller's queue.
#   owner: broker
#   trigger: [manual]
#   inputs: the validated params as JSON on stdin; the ORCHESTRATOR_JOBS_URL secret (the controller's POST /jobs URL)
#   outputs: the controller's answer (the run id) as JSON on stdout
#   exit:
#     "0": queued (or the idempotency key was already queued)
#     "1": the controller refused the job or could not be reached
#
# The workflow broker's handler for agent.job.submit (workflows/broker.manifest.json).  The broker
# validated the params against agent-job-submit.handler.json; they go to the controller as the
# request body, unchanged.  The controller's address is resolved by the broker like a secret, so no
# endpoint is in the tree; the controller admits the job against live load (docs/stackstorm.md).
set -eu
url=${ORCHESTRATOR_JOBS_URL:?the broker did not hand over ORCHESTRATOR_JOBS_URL}
exec curl --silent --show-error --fail-with-body --max-time 20 --proto '=https' \
  --header 'Content-Type: application/json' --data-binary @- -- "$url"
