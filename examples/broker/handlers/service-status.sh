#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# hnx-script:
#   id: broker-example-service-status
#   kind: tool
#   purpose: Example read-only broker handler for service.status; reports a stand-in state for the target.
#   owner: broker
#   trigger: [manual]
#   inputs: the validated params as JSON on stdin; HNX_BROKER_TARGET
#   outputs: the action's result as JSON on stdout
#   exit:
#     "0": reported
#
# Read-only example handler for service.status: reports a stand-in state for the target.
# The broker passes the validated params as JSON on stdin and the target in HNX_BROKER_TARGET;
# nothing reaches the command line.  Output on stdout is the action's result (JSON).
params=$(cat)
printf '{"service":"%s","state":"running","params":%s}\n' "${HNX_BROKER_TARGET:-none}" "$params"
