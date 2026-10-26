#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# hnx-script:
#   id: broker-example-dhcp-leases
#   kind: tool
#   purpose: Example read-only broker handler for dhcp.leases; reports one stand-in lease of the target DHCP server.
#   owner: broker
#   trigger: [manual]
#   inputs: the validated params as JSON on stdin; HNX_BROKER_TARGET
#   outputs: the action's result as JSON on stdout
#   exit:
#     "0": reported
#
# Read-only example handler for dhcp.leases: the leases one DHCP server (the target) holds, here a
# single stand-in lease with a documentation address (RFC 5737) and a documentation MAC (RFC 7042).
cat >/dev/null
printf '{"server":"%s","leases":[{"address":"192.0.2.10","mac":"00:00:5e:00:53:10","hostname":"example","expires":"2026-01-01T00:00:00Z"}]}\n' "${HNX_BROKER_TARGET:-none}"
