# SPDX-License-Identifier: Apache-2.0
"""Hypervisor notifications to ntfy (``_nodes.yml`` ``notify``).

Proxmox VE (the notification system arrived in 8.1; this target was proved on 9.2) sends its own
notifications (a failed backup job, fencing, replication, the mail cron and ZFS send to root)
through ``/etc/pve/notifications.cfg``.  Out of the box one matcher sends all of them to
``mail-to-root``: the email address of ``root@pam``, through the node's own MTA.  A node with no
relay host delivers that mail nowhere (an external mailbox rejects it from a residential address),
so a failed backup reaches no one.

A node that declares ``notify: {url, topic, severities, priority, default_mail}`` gets, under
``notify/<node>/``:

* ``hnx-notify.sh``: run on the node (as root), it creates or updates a webhook target
  ``hnx-notify-<node>`` that POSTs each notification as ntfy JSON (``topic``, ``title``,
  ``message``, ``priority``, ``tags``) to ``url``, and a matcher ``hnx-notify-<node>-route`` that
  routes the listed severities raised on this node (``hostname`` field) to it.  No MTA is involved.
  It then sends a test notification through the target and exits non-zero (pvesh's status) if that
  fails; only after a delivered test, and unless ``default_mail: true``, does it turn off the
  built-in ``default-matcher``, so mail is never turned off in favour of a target that does not
  deliver.  The test goes straight to the target, not through the matcher: it proves the server,
  not the severity and ``hostname`` match (a real failed vzdump on a live node proved that). A
  re-run changes nothing that is already right but sends one more test, so the script is for a
  manual run or a deploy, not for cron.  ``--test`` sends only the test; ``--remove`` first turns
  ``default-matcher`` back on (whatever ``default_mail`` says: the Proxmox default, harmless when
  it is already on), then deletes this node's matcher and target.  A node whose ``notify`` is
  deleted from ``_nodes.yml`` renders no script, so nothing rendered later can undo an apply: run
  the old script's ``--remove`` first.

``notifications.cfg`` is shared by every node of a cluster: the names and the ``hostname`` match
are per node so two nodes never overwrite or answer for each other, but ``default-matcher`` is
one entry for the whole cluster, so in a cluster give every node a ``notify`` before turning it
off.  The body is a fixed template rendered here and carried base64-encoded, the form ``pvesh``
takes, so no value of the node's entry reaches the shell outside double quotes.  Proxmox fills
``{{ title }}``, ``{{ message }}`` and ``{{ severity }}`` when it sends (its ``escape`` helper
makes the first two JSON string content; the severity is a fixed word).  ntfy publishing with no
credential is assumed: a re-run removes any header or secret added by hand, and a server that
needs a token for publishing is not supported yet.

This is deliberately not a client of the ``notify`` capability: a hypervisor must be able to
alert when no guest (the notify service included) is up, so the node talks to the server named in
its own entry, in that server's JSON publish shape, and ``hnx swap`` of the notify product does
not move it.
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

#: the prefix of the webhook target and the matcher the script owns.  Targets and matchers share
#: one namespace in notifications.cfg (and one file per cluster), so the names carry the node and
#: the two differ.
PREFIX = "hnx-notify"


def names(node: str) -> tuple[str, str]:
    """``(target, matcher)`` for ``node``."""
    return f"{PREFIX}-{node}", f"{PREFIX}-{node}-route"


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
    name, matcher = names(node)
    L = [
        "#!/bin/sh",
        f"# {HEADER}",
        f"# Node {node}: send hypervisor notifications of severity {sev} to topic {topic}",
        f"# at {url} (webhook target {name}, matcher {matcher}).",
        "# Idempotent, but each apply ends with a test notification: run it by hand or from a",
        "# deploy, not from cron.  --test sends only the test; --remove takes this node's target",
        "# and matcher off and turns the built-in mail matcher back on.",
        "set -eu",
        f'NODE="{node}"',
        f'NAME="{name}"',
        f'MATCHER="{matcher}"',
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
        "  # mail back on first, whatever default_mail says now (it may have been false at apply):",
        "  # a delete that fails below (set -e) then leaves two routes, not none",
        '  pvesh set "$MATCHERS/$DEFAULT_MATCHER" --delete disable',
        "  # the matcher names the target, so it goes before it",
        '  if exists "$MATCHERS/$MATCHER"; then pvesh delete "$MATCHERS/$MATCHER"; fi',
        '  if exists "$WEBHOOKS/$NAME"; then pvesh delete "$WEBHOOKS/$NAME"; fi',
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
        "# only what this node raises: notifications.cfg is one file for the whole cluster.",
        "# A re-run also drops what a hand edit added: a disable, an inversion, a calendar rule.",
        'if exists "$MATCHERS/$MATCHER"; then',
        '  pvesh set "$MATCHERS/$MATCHER" --mode all --match-severity "$SEVERITIES" \\',
        '    --match-field "exact:hostname=$NODE" --target "$NAME" --comment "$COMMENT" \\',
        "    --delete disable --delete invert-match --delete match-calendar",
        "else",
        '  pvesh create "$MATCHERS" --name "$MATCHER" --mode all --match-severity "$SEVERITIES" \\',
        '    --match-field "exact:hostname=$NODE" --target "$NAME" --comment "$COMMENT"',
        "fi",
        "# prove the path before anything else changes: a failed test exits here (set -e)",
        'pvesh create "/cluster/notifications/targets/$NAME/test"',
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
            "Each node below sends its hypervisor notifications of the listed severities to the",
            "server's topic. Copy `<node>/hnx-notify.sh` to the node and run it as root; each run",
            "ends with a test notification (so run it by hand or from a deploy, not from cron),",
            "and the built-in mail matcher is turned off only after it was delivered. The server",
            "must accept publishing with no credential. A backup job sends through this only with",
            "`notification-mode notification-system` (or `auto` with no `mailto`). The node keeps",
            "no other route: watch the topic for the test. `hnx-notify.sh --remove` turns the",
            "built-in mail matcher back on and deletes the node's target and matcher. Deleting a",
            "node's `notify` renders no script for it, so run the old script's `--remove` on the",
            "node before deleting the key.",
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
