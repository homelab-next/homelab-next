# SPDX-License-Identifier: Apache-2.0
"""Hypervisor notifications to ntfy (``_nodes.yml`` ``notify``).

Proxmox VE (8.1 and later) sends its own notifications (a failed backup job, fencing, replication,
the mail cron and ZFS send to root) through ``/etc/pve/notifications.cfg``.  Out of the box one
matcher sends all of them to ``mail-to-root``: the email address of ``root@pam``, through the
node's own MTA.  A node with no relay host delivers that mail nowhere (an external mailbox rejects
it from a residential address), so a failed backup reaches no one.

A node that declares ``notify: {url, topic, severities, priority, default_mail}`` gets, under
``notify/<node>/``:

* ``hnx-notify.sh``: run once on the node (as root), it creates or updates a webhook target
  ``hnx-notify`` that POSTs each notification as ntfy JSON (``topic``, ``title``, ``message``,
  ``priority``, ``tags``) to ``url``, and a matcher ``hnx-notify-route`` that routes the listed severities
  to it.  No MTA is involved.  Unless ``default_mail: true``, it also turns off the built-in
  ``default-matcher``, so nothing is sent to ``mail-to-root`` any more.  A re-run changes nothing
  that is already right.  ``--test`` asks Proxmox to send a test notification through the target;
  ``--remove`` deletes the matcher and the target and turns ``default-matcher`` back on.

The body is a fixed template rendered here and carried base64-encoded, the form ``pvesh`` takes,
so no value of the node's entry reaches the shell unquoted.  Proxmox fills ``{{ title }}``,
``{{ message }}`` and ``{{ severity }}`` when it sends (its ``escape`` helper makes them JSON
string content).  ntfy publishing with no credential is assumed: a server that needs a token for
publishing is not supported yet.
"""

from __future__ import annotations

import base64
import json
import re

from homelabnext.compute.model import ComputeError, Fleet
from homelabnext.generators.safe import checked

from ._text import HEADER

#: one hypervisor node applies this output: ``hnx guests render --node`` may narrow it to one
PER_NODE = True

#: made of the node's ``_nodes.yml`` entry, not its guests (an empty node is no hazard)
RENDERS_GUESTS = False

#: the webhook target and the matcher the script owns on the node.  Targets and matchers share
#: one namespace in notifications.cfg, so the two names must differ.
NAME = "hnx-notify"
MATCHER = "hnx-notify-route"
#: the Proxmox built-in matcher that sends everything to ``mail-to-root``
DEFAULT_MATCHER = "default-matcher"
#: the guest schema's placement.node pattern: the node name becomes a directory of the render
NODE_RE = re.compile(r"^[a-z][a-z0-9]*(?:-[a-z0-9]+)*\Z")


def body(node: str, topic: str, priority: int) -> str:
    """The ntfy JSON publish body, with Proxmox's template fields left for Proxmox to fill."""
    doc = {
        "topic": topic,
        "title": f"[{node}] {{{{ escape title }}}}",
        "message": "{{ escape message }}",
        "priority": priority,
        "tags": ["hypervisor", "{{ severity }}"],
    }
    return json.dumps(doc, separators=(",", ":"))


def _b64(text: str) -> str:
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


def script(node: str, spec: dict) -> str:
    node = checked(node, "node", "shell")
    url = checked(spec["url"], f"node {node}: notify.url", "shell")
    topic = checked(spec["topic"], f"node {node}: notify.topic", "shell")
    sev = ",".join(
        checked(s, f"node {node}: notify.severities", "shell") for s in spec["severities"]
    )
    payload = _b64(body(node, topic, spec["priority"]))
    ctype = _b64("application/json")
    keep_mail = spec["default_mail"]
    L = [
        "#!/bin/sh",
        f"# {HEADER}",
        f"# Node {node}: send hypervisor notifications of severity {sev} to topic {topic}",
        f"# at {url} (webhook target {NAME}, matcher {MATCHER}).",
        "# Idempotent.  --test sends a test notification; --remove takes the target and matcher off.",
        "set -eu",
        f'NAME="{NAME}"',
        f'MATCHER="{MATCHER}"',
        f'URL="{url}"',
        f'SEVERITIES="{sev}"',
        "# the JSON publish body, base64 as pvesh takes it: " + body(node, topic, spec["priority"]),
        f'BODY="{payload}"',
        f'CTYPE="{ctype}"',
        f'DEFAULT_MATCHER="{DEFAULT_MATCHER}"',
        f'COMMENT="hnx: {sev} to notify topic {topic}"',
        "WEBHOOKS=/cluster/notifications/endpoints/webhook",
        "MATCHERS=/cluster/notifications/matchers",
        "",
        "exists() {",
        '  pvesh get "$1" >/dev/null 2>&1',
        "}",
        "",
        'mode="apply"',
        'case "${1:-}" in',
        '  "") ;;',
        '  --test) mode="test" ;;',
        '  --remove) mode="remove" ;;',
        '  *) echo "usage: $0 [--test | --remove]" >&2; exit 2 ;;',
        "esac",
        'if [ "$#" -gt 1 ]; then',
        '  echo "usage: $0 [--test | --remove]" >&2',
        "  exit 2",
        "fi",
        "",
        'if [ "$mode" = test ]; then',
        '  pvesh create "/cluster/notifications/targets/$NAME/test"',
        "  exit 0",
        "fi",
        "",
        'if [ "$mode" = remove ]; then',
        "  # the matcher names the target, so it goes first",
        '  if exists "$MATCHERS/$MATCHER"; then pvesh delete "$MATCHERS/$MATCHER"; fi',
        '  if exists "$WEBHOOKS/$NAME"; then pvesh delete "$WEBHOOKS/$NAME"; fi',
    ]
    if not keep_mail:
        L.append('  pvesh set "$MATCHERS/$DEFAULT_MATCHER" --delete disable')
    L += [
        "  exit 0",
        "fi",
        "",
        "# the target first: the matcher must name a target that exists",
        'if exists "$WEBHOOKS/$NAME"; then',
        '  pvesh set "$WEBHOOKS/$NAME" --method post --url "$URL" --body "$BODY" \\',
        '    --header "name=Content-Type,value=$CTYPE" --comment "$COMMENT" \\',
        "    --delete disable --delete secret",
        "else",
        '  pvesh create "$WEBHOOKS" --name "$NAME" --method post --url "$URL" --body "$BODY" \\',
        '    --header "name=Content-Type,value=$CTYPE" --comment "$COMMENT"',
        "fi",
        "# a re-run also drops what a hand edit added: a disable, an inversion, other match rules",
        'if exists "$MATCHERS/$MATCHER"; then',
        '  pvesh set "$MATCHERS/$MATCHER" --mode all --match-severity "$SEVERITIES" --target "$NAME" \\',
        '    --comment "$COMMENT" --delete disable --delete invert-match \\',
        "    --delete match-field --delete match-calendar",
        "else",
        '  pvesh create "$MATCHERS" --name "$MATCHER" --mode all --match-severity "$SEVERITIES" \\',
        '    --target "$NAME" --comment "$COMMENT"',
        "fi",
    ]
    if not keep_mail:
        L += [
            "# root@pam's mail has no relay to leave by: stop sending everything to it",
            'pvesh set "$MATCHERS/$DEFAULT_MATCHER" --disable 1',
        ]
    return "\n".join(L) + "\n"


def readme(notifies: dict[str, dict]) -> str:
    L = [f"<!-- {HEADER} -->", "# Hypervisor notifications", ""]
    if not notifies:
        L.append("No node declares `notify` in `_nodes.yml`.")
    else:
        L += [
            "Each node below sends its hypervisor notifications of the listed severities to the notifier.",
            "Copy `<node>/hnx-notify.sh` to the node and run it as root; `hnx-notify.sh --test`",
            "then sends a test notification. A backup job sends through this only with",
            "`notification-mode notification-system` (or `auto` with no `mailto`).",
            "",
            "| Node | Notify server | Topic | Severities | Built-in mail matcher |",
            "|---|---|---|---|---|",
        ]
        for node, n in notifies.items():
            sev = ", ".join(f"`{checked(s, 'severity', 'markdown')}`" for s in n["severities"])
            mail = "kept" if n["default_mail"] else "turned off"
            L.append(
                f"| `{checked(node, 'node', 'markdown')}` "
                f"| `{checked(n['url'], 'notify.url', 'markdown')}` "
                f"| `{checked(n['topic'], 'notify.topic', 'markdown')}` | {sev} | {mail} |"
            )
    return "\n".join(L) + "\n"


def render(fleet: Fleet) -> dict[str, str]:
    notifies = {n: spec["notify"] for n, spec in sorted(fleet.nodes.items()) if "notify" in spec}
    for node in notifies:
        if not NODE_RE.match(node):
            raise ComputeError(
                f"node {node!r}: a notifying node's name must be one a guest can name"
            )
    out = {"notify/README.md": readme(notifies)}
    for node, spec in notifies.items():
        out[f"notify/{node}/hnx-notify.sh"] = script(node, spec)
    return out
