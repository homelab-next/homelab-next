# SPDX-License-Identifier: Apache-2.0
"""A Tailscale policy file (HuJSON) for the guests whose remote access is bound to Tailscale.

Access follows the site model, not hand-written policy (ADR-0016 decision 7).  A guest is on
the tailnet when one of its resolved baseline controls is bound to the ``tailscale_node`` role
(applied per guest); that role advertises ``tag:zone-<zone>`` for the guest's zone, so a zone is a tag here:

* ``tagOwners``: one entry per zone tag in use, owned by ``autogroup:admin`` (the tailnet's
  admins), so only an admin, or an auth key an admin made, can put a node in a zone;
* ``acls``, first the minimal default: admins reach every zone tag on SSH (port 22) only;
* then one rule per protocol of each flow the site model allows between two zones that both
  have tailnet nodes: the network IR's evaluated ``firewall.zone_to_zone`` rules, read through
  :func:`homelabnext.compute.zones.site_flows`, so the tailnet allows exactly what the IR allows
  between zones (tcp, udp, icmp; a flow with no protocols is any of them).  A zones-only site
  model has no flows, and the policy is the minimal default alone.

Not modelled: port-level denies, ``service_exceptions`` (they name a service, not a zone),
traffic inside one zone, exit nodes and subnet routes (the role advertises neither).  Everything
not listed is denied by Tailscale itself.  The file is JSON, so any HuJSON reader accepts it; the
``//`` header lines are HuJSON comments.
"""

from __future__ import annotations

import json
from typing import Any

from homelabnext.compute.baselines import APPLY_GUEST, resolve
from homelabnext.compute.model import Fleet, Guest

from ._text import HEADER

FILE = "tailscale-policy.hujson"
#: the role that puts a guest on the tailnet; it advertises ``ZONE_TAG_PREFIX + zone``
TAILSCALE_ROLE = "tailscale_node"
ZONE_TAG_PREFIX = "tag:zone-"
ADMINS = "autogroup:admin"
ADMIN_PORTS = (22,)


def zone_tag(zone: str) -> str:
    return ZONE_TAG_PREFIX + zone


def tailnet_guests(fleet: Fleet) -> list[Guest]:
    """Guests that need a control bound to :data:`TAILSCALE_ROLE`, applied per guest."""
    bs = fleet.baselines
    if bs is None:
        return []
    bound = {c for c in bs.controls if bs.role(c) == TAILSCALE_ROLE and bs.apply(c) == APPLY_GUEST}
    return [g for g in fleet.sorted() if bound & set(resolve(g, bs).controls)]


def _dst(tag: str, ports: tuple[int, ...], proto: str | None) -> str:
    if proto == "icmp" or not ports:
        return f"{tag}:*"
    return f"{tag}:" + ",".join(str(p) for p in ports)


def policy(fleet: Fleet) -> dict[str, Any]:
    """The policy document (``tagOwners``, ``acls``) for :func:`render`."""
    zones = sorted({g.zone for g in tailnet_guests(fleet)})
    tags = [zone_tag(z) for z in zones]
    acls: list[dict[str, Any]] = []
    if tags:
        acls.append(
            {
                "action": "accept",
                "src": [ADMINS],
                "proto": "tcp",
                "dst": [_dst(t, ADMIN_PORTS, "tcp") for t in tags],
            }
        )
    for f in fleet.flows:
        if f.src not in zones or f.dst not in zones or f.src == f.dst:
            continue
        for proto in f.protocols or (None,):
            rule: dict[str, Any] = {"action": "accept", "src": [zone_tag(f.src)]}
            if proto:
                rule["proto"] = proto
            rule["dst"] = [_dst(zone_tag(f.dst), f.ports, proto)]
            if rule not in acls:
                acls.append(rule)
    return {"tagOwners": {t: [ADMINS] for t in tags}, "acls": acls}


def render(fleet: Fleet) -> dict[str, str]:
    doc = policy(fleet)
    guests = tailnet_guests(fleet)
    L = [
        f"// {HEADER}",
        "// Tailscale policy from the site model (ADR-0016 decision 7): one tag per zone,",
        "// admins on SSH, and the site's zone-to-zone allows between zones with tailnet nodes.",
    ]
    if not guests:
        L.append(f"// no guest needs a control bound to {TAILSCALE_ROLE}: nothing is reachable")
    else:
        for z in sorted({g.zone for g in guests}):
            names = ", ".join(g.name for g in guests if g.zone == z)
            L.append(f"//   {zone_tag(z)}: {names}")
        if not fleet.flows:
            L.append("// the site model lists no zone-to-zone allows: admins on SSH only")
    L.append(json.dumps(doc, indent=2, ensure_ascii=True))
    return {FILE: "\n".join(L) + "\n"}
