# SPDX-License-Identifier: Apache-2.0
"""Hypervisor-side traffic mirror for a network sensor (``_nodes.yml`` ``mirror``).

A switch mirror (site 1.3) copies what crosses the switch.  Two guests on one hypervisor talk over
its bridge and never reach the switch, so a sensor on the switch's mirror port is blind to them.
A node that declares ``mirror: {to: <nic>, bridges: [...]}`` gets, under ``mirror/<node>/``:

* ``hnx-mirror.sh``: puts a ``tc`` matchall filter on the ingress of every guest port of each
  listed bridge, mirroring the frame to ``to``.  Every frame a guest sends enters the bridge
  through exactly one port, so each guest frame is copied once, whether it goes to another guest
  or out of the host.  Guest ports are the ones Proxmox names after the vmid: ``fwpr<vmid>p<n>``
  (NIC firewall on), ``tap<vmid>i<n>`` (a VM) and ``veth<vmid>i<n>`` (a container).  The node's
  own NICs are never mirrored; inbound traffic from the switch is the switch mirror's to see.
  ``--remove`` takes the filters off again.  The script refuses a ``to`` that is missing or is a
  port of a bridge, and a bridge that does not exist.
* ``hnx-mirror.service`` and ``hnx-mirror.timer``: guest ports appear when a guest starts, so the
  script runs every 15 seconds; a guest's first seconds after it starts can go unmirrored.

Install the three files (``/usr/local/sbin/hnx-mirror.sh``, ``/etc/systemd/system/``), then
``systemctl enable --now hnx-mirror.timer``.  ``mirror/README.md`` lists what each node mirrors.
"""

from __future__ import annotations

import re

from homelabnext.compute.model import ComputeError, Fleet
from homelabnext.generators.safe import checked

from ._text import HEADER

#: the filter's priority: fixed, so a re-run replaces it and ``--remove`` finds it
PREF = 49152
SCRIPT_PATH = "/usr/local/sbin/hnx-mirror.sh"
#: the guest schema's placement.node pattern: the node name becomes a directory of the render
NODE_RE = re.compile(r"^[a-z][a-z0-9]*(?:-[a-z0-9]+)*\Z")


def script(node: str, to: str, bridges: list[str]) -> str:
    to = checked(to, f"node {node}: mirror.to", "shell")
    words = " ".join(checked(b, f"node {node}: mirror.bridges", "shell") for b in bridges)
    L = [
        "#!/bin/sh",
        f"# {HEADER}",
        f"# Node {node}: copy every frame a guest sends into {words} to {to}.",
        "# Idempotent; hnx-mirror.timer runs it every 15 seconds.  --remove takes the filters off.",
        "set -eu",
        f'TO="{to}"',
        f'BRIDGES="{words}"',
        f"PREF={PREF}",
        'SYS="${HNX_MIRROR_SYSFS:-/sys/class/net}"',
        'remove=""',
        'if [ "${1:-}" = "--remove" ]; then',
        "  remove=1",
        'elif [ "$#" -gt 0 ]; then',
        '  echo "usage: $0 [--remove]" >&2',
        "  exit 2",
        "fi",
        'if [ -z "$remove" ]; then',
        '  if [ ! -d "$SYS/$TO" ]; then',
        '    echo "hnx-mirror: capture NIC $TO does not exist" >&2',
        "    exit 1",
        "  fi",
        '  if [ -e "$SYS/$TO/master" ]; then',
        '    echo "hnx-mirror: $TO is a port of a bridge; the capture NIC must carry nothing else" >&2',
        "    exit 1",
        "  fi",
        '  ip link set dev "$TO" up',
        "fi",
        "for br in $BRIDGES; do",
        '  if [ ! -d "$SYS/$br/brif" ]; then',
        '    echo "hnx-mirror: $br is not a bridge" >&2',
        "    exit 1",
        "  fi",
        '  for p in "$SYS/$br/brif"/*; do',
        '    [ -e "$p" ] || continue',
        '    port="${p##*/}"',
        '    case "$port" in',
        "      fwpr[0-9]*p[0-9]* | tap[0-9]*i[0-9]* | veth[0-9]*i[0-9]*) ;;",
        "      *) continue ;;",
        "    esac",
        '    if [ -n "$remove" ]; then',
        '      tc filter del dev "$port" ingress pref "$PREF" 2>/dev/null || true',
        "      continue",
        "    fi",
        '    tc qdisc add dev "$port" clsact 2>/dev/null || true',
        '    tc filter replace dev "$port" ingress pref "$PREF" handle 1 matchall \\',
        '      action mirred egress mirror dev "$TO"',
        "  done",
        "done",
    ]
    return "\n".join(L) + "\n"


def service(node: str) -> str:
    return "\n".join(
        [
            f"# {HEADER}",
            "[Unit]",
            f"Description=Mirror the guests of {checked(node, 'node', 'systemd')} to the network sensor",
            "After=network-online.target",
            "",
            "[Service]",
            "Type=oneshot",
            f"ExecStart={SCRIPT_PATH}",
            "",
        ]
    )


def timer(node: str) -> str:
    return "\n".join(
        [
            f"# {HEADER}",
            "[Unit]",
            f"Description=Keep the guests of {checked(node, 'node', 'systemd')} mirrored as they start",
            "",
            "[Timer]",
            "OnBootSec=30s",
            "OnCalendar=*:*:0/15",
            "AccuracySec=1s",
            "",
            "[Install]",
            "WantedBy=timers.target",
            "",
        ]
    )


def readme(mirrors: dict[str, dict]) -> str:
    L = [f"<!-- {HEADER} -->", "# Hypervisor mirrors", ""]
    if not mirrors:
        L.append("No node declares a mirror in `_nodes.yml`.")
    else:
        L += [
            "Each node below copies every frame its guests send into the listed bridges to its",
            "capture NIC. Install `hnx-mirror.sh` as `" + SCRIPT_PATH + "` and the two units",
            "under `/etc/systemd/system/`, then `systemctl enable --now hnx-mirror.timer`.",
            "",
            "| Node | Bridges | Capture NIC |",
            "|---|---|---|",
        ]
        for node, m in mirrors.items():
            br = ", ".join(f"`{checked(b, 'bridge', 'markdown')}`" for b in m["bridges"])
            L.append(
                f"| `{checked(node, 'node', 'markdown')}` | {br} "
                f"| `{checked(m['to'], 'mirror.to', 'markdown')}` |"
            )
    return "\n".join(L) + "\n"


def render(fleet: Fleet) -> dict[str, str]:
    mirrors = {n: spec["mirror"] for n, spec in sorted(fleet.nodes.items()) if "mirror" in spec}
    for node in mirrors:
        if not NODE_RE.match(node):
            raise ComputeError(
                f"node {node!r}: a mirroring node's name must be one a guest can name"
            )
    out = {"mirror/README.md": readme(mirrors)}
    for node, m in mirrors.items():
        out[f"mirror/{node}/hnx-mirror.sh"] = script(node, m["to"], m["bridges"])
        out[f"mirror/{node}/hnx-mirror.service"] = service(node)
        out[f"mirror/{node}/hnx-mirror.timer"] = timer(node)
    return out
