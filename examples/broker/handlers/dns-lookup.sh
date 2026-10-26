#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# hnx-script:
#   id: broker-example-dns-lookup
#   kind: tool
#   purpose: Example read-only broker handler for dns.lookup; reports a stand-in name and address for the target.
#   owner: broker
#   trigger: [manual]
#   inputs: the validated params as JSON on stdin; HNX_BROKER_TARGET
#   outputs: the action's result as JSON on stdout
#   exit:
#     "0": reported
#
# Read-only example handler for dns.lookup: resolves the target service's name to a stand-in
# address from the documentation range (RFC 5737).  The broker passes the validated params as
# JSON on stdin and the target in HNX_BROKER_TARGET; nothing reaches the command line.
cat >/dev/null
target=${HNX_BROKER_TARGET:-none}
printf '{"service":"%s","name":"%s.lab.example","addresses":["192.0.2.10"]}\n' "$target" "${target#svc:}"
