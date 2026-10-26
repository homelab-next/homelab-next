#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# hnx-script:
#   id: broker-example-hypervisor-guests
#   kind: tool
#   purpose: Example read-only broker handler for hypervisor.guests; reports one stand-in guest of the target node.
#   owner: broker
#   trigger: [manual]
#   inputs: the validated params as JSON on stdin; HNX_BROKER_TARGET
#   outputs: the action's result as JSON on stdout
#   exit:
#     "0": reported
#
# Read-only example handler for hypervisor.guests: the guests on one hypervisor node (the
# target) with their network MAC and state, here a single stand-in guest.
cat >/dev/null
printf '{"node":"%s","guests":[{"vmid":100,"name":"example","mac":"00:00:5e:00:53:10","state":"running"}]}\n' "${HNX_BROKER_TARGET:-none}"
