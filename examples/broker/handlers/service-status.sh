#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Read-only example handler for service.status: reports a stand-in state for the target.
# The broker passes the validated params as JSON on stdin and the target in HNX_BROKER_TARGET;
# nothing reaches the command line.  Output on stdout is the action's result (JSON).
params=$(cat)
printf '{"service":"%s","state":"running","params":%s}\n' "${HNX_BROKER_TARGET:-none}" "$params"
