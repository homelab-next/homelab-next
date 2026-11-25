#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# hnx-script:
#   id: workflow-broker-notify-page
#   kind: tool
#   purpose: Broker handler for notify.page; publishes one page to the notify service's page topic.
#   owner: broker
#   trigger: [manual]
#   inputs: the validated params as JSON on stdin; the NOTIFY_PAGE_URL secret (the page topic's publish URL); the NOTIFY_PAGE_TOKEN secret (a publish-only token for that topic)
#   outputs: the notify service's answer on stdout
#   exit:
#     "0": the notify service accepted the page
#     "1": no alert_id or token, the service could not be reached, refused the token (401, 403), or failed (anything else)
#
# The workflow broker's handler for notify.page (workflows/broker.manifest.json).  The broker
# validated the params against notify-page.handler.json; they go to the notify service as the
# message, unchanged, with the alert id as its title.  The topic's publish URL is resolved by the
# broker like a secret (NOTIFY_PAGE_URL), so no endpoint is in the tree.  The publish token
# (NOTIFY_PAGE_TOKEN, resolved the same way) goes as the Authorization header through a 0600 header
# file in the run's private TMPDIR, so it is never in curl's argv (visible to every local user in
# ps) nor in a log line.  Only https is spoken (a token is never sent in clear).  A page is never dropped quietly: anything but a 2xx is a failure (exit 1),
# a 429 from the service included, so the run shows it.
set -eu
url=${NOTIFY_PAGE_URL:?the broker did not hand over NOTIFY_PAGE_URL}
token=${NOTIFY_PAGE_TOKEN:-}
[ -n "$token" ] || { echo "notify.page: the broker did not hand over NOTIFY_PAGE_TOKEN" >&2; exit 1; }
nl='
'
cr=$(printf '\r')
case $token in
  *"$nl"* | *"$cr"* | *' '*)
    echo "notify.page: NOTIFY_PAGE_TOKEN is not a single token" >&2
    exit 1
    ;;
esac
params=$(cat)
# the schema restricts the id to [A-Za-z0-9._:-], so it is safe in a header as it stands
alert=$(printf '%s' "$params" | sed -n 's/.*"alert_id"[[:space:]]*:[[:space:]]*"\([A-Za-z0-9._:-]*\)".*/\1/p')
[ -n "$alert" ] || { echo "notify.page: no alert_id in the params" >&2; exit 1; }
umask 077
hdrs=$(mktemp "${TMPDIR:-/tmp}/notify-page.XXXXXX")
trap 'rm -f "$hdrs"' EXIT
printf 'Authorization: Bearer %s\n' "$token" >"$hdrs"
out=$(printf '%s' "$params" | curl --silent --show-error --max-time 20 --proto '=https' \
  --header "Title: page $alert" --header 'Priority: 4' --header 'Tags: rotating_light' \
  --header "@$hdrs" --data-binary @- --write-out "${nl}%{http_code}" -- "$url") || {
  echo "notify.page: the notify service could not be reached" >&2
  exit 1
}
code=${out##*"$nl"}
body=${out%"$nl"*}
[ "$body" = "$out" ] && body=''
case $code in
  2??)
    [ -n "$body" ] || body='{}'
    printf '%s\n' "$body"
    ;;
  401 | 403)
    echo "notify.page: the notify service refused the token: $code (NOTIFY_PAGE_TOKEN missing, wrong, or not allowed to publish the topic)" >&2
    exit 1
    ;;
  *)
    echo "notify.page: the notify service answered $code" >&2
    exit 1
    ;;
esac
