#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# hnx-script:
#   id: broker-example-service-restart
#   kind: tool
#   purpose: Example approval-gated broker handler for service.restart; a stand-in that reports what it would restart.
#   owner: broker
#   trigger: [manual]
#   inputs: the validated params as JSON on stdin; HNX_BROKER_TARGET; the DEMO_API_TOKEN secret
#   outputs: the action's result as JSON on stdout (the secret's presence, never its value)
#   exit:
#     "0": reported
#
# Example execute-tier handler for service.restart (needs an approval): a stand-in that reports
# what it would restart and whether the broker handed it its declared secret.  It prints the
# secret's presence, never its value.
params=$(cat)
if [ -n "${DEMO_API_TOKEN:-}" ]; then token=true; else token=false; fi
printf '{"would_restart":"%s","token_present":%s,"params":%s}\n' "${HNX_BROKER_TARGET:-none}" "$token" "$params"
