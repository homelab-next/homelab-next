#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Example execute-tier handler for service.restart (needs an approval): a stand-in that reports
# what it would restart and whether the broker handed it its declared secret.  It prints the
# secret's presence, never its value.
params=$(cat)
if [ -n "${DEMO_API_TOKEN:-}" ]; then token=true; else token=false; fi
printf '{"would_restart":"%s","token_present":%s,"params":%s}\n' "${HNX_BROKER_TARGET:-none}" "$token" "$params"
