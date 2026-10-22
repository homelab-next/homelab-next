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
* the deploy's access, when the site declares ``tailnet.deploy`` (:mod:`homelabnext.tailnet`):
  the deploy tag in ``tagOwners`` with its declared owners (and each zone it reaches, so the
  policy names no tag without an owner), one rule from the tag to those zones on TCP 22, one
  rule per listed exception, and a ``tests`` block Tailscale runs on every policy change: the
  tag reaches each declared zone on 22 (and on each exception port), is refused on other ports
  and on every other tag of the policy, and no zone tag reaches the deploy tag.

Not modelled: port-level denies, ``service_exceptions`` (they name a service, not a zone),
traffic inside one zone, exit nodes and subnet routes (the role advertises neither).  Everything
not listed is denied by Tailscale itself.  The file is JSON, so any HuJSON reader accepts it; the
``//`` header lines are HuJSON comments.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

from homelabnext.compute.baselines import APPLY_GUEST, resolve
from homelabnext.compute.model import Fleet, Guest
from homelabnext.tailnet import ANY_PORT, SSH, ZONE_TAG_PREFIX

from ._text import HEADER

FILE = "tailscale-policy.hujson"
#: the role that puts a guest on the tailnet; it advertises ``ZONE_TAG_PREFIX + zone``
TAILSCALE_ROLE = "tailscale_node"
ADMINS = "autogroup:admin"
ADMIN_PORTS = (22,)
#: ports the ``tests`` block checks the deploy tag is refused on (those an exception allows aside)
PROBE_PORTS = (23, 80, 443, 3389, 8080)


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
    owners: dict[str, list[str]] = {t: [ADMINS] for t in tags}
    doc: dict[str, Any] = {"tagOwners": owners, "acls": acls}
    dep = fleet.deploy
    if dep:
        for z in dep["zones"]:
            owners.setdefault(zone_tag(z), [ADMINS])
        owners[dep["tag"]] = list(dep["owners"])
        acls.extend(_deploy_rules(dep))
        doc["tests"] = _deploy_tests(dep, sorted(owners))
    return doc


def _deploy_rules(dep: Mapping[str, Any]) -> list[dict[str, Any]]:
    src = [dep["tag"]]
    rules = [
        {
            "action": "accept",
            "src": src,
            "proto": "tcp",
            "dst": [_dst(zone_tag(z), (SSH,), "tcp") for z in dep["zones"]],
        }
    ]
    for e in dep["exceptions"]:
        ports = () if e["ports"] == ANY_PORT else e["ports"]
        dst = [_dst(zone_tag(z), ports, "tcp") for z in e["zones"]]
        rules.append({"action": "accept", "src": src, "proto": "tcp", "dst": dst})
    return rules


def _deploy_tests(dep: Mapping[str, Any], all_tags: list[str]) -> list[dict[str, Any]]:
    """Tailscale policy tests: the deploy tag reaches exactly its zones on SSH (and listed
    exceptions), nothing else; no zone tag reaches it."""
    tag = dep["tag"]
    extra: dict[str, set[int] | None] = {}  # zone -> exception ports (None: every port)
    for e in dep["exceptions"]:
        for z in e["zones"]:
            if e["ports"] == ANY_PORT:
                extra[z] = None
            elif extra.get(z, ()) is not None:
                extra.setdefault(z, set()).update(e["ports"])  # type: ignore[union-attr]
    accept: list[str] = []
    deny: list[str] = []
    for z in dep["zones"]:
        t = zone_tag(z)
        more = extra.get(z, set())
        accept += [f"{t}:{p}" for p in (SSH, *sorted(more or ()))]
        if more is not None:
            deny += [f"{t}:{p}" for p in PROBE_PORTS if p not in more]
    reached = {zone_tag(z) for z in dep["zones"]}
    others = [t for t in all_tags if t not in reached and t != tag]
    deny += [f"{t}:{p}" for t in others for p in (SSH, *PROBE_PORTS)]
    tests: list[dict[str, Any]] = [{"src": tag, "proto": "tcp", "accept": accept, "deny": deny}]
    tests += [
        {"src": t, "proto": "tcp", "deny": [f"{tag}:{p}" for p in (SSH, *PROBE_PORTS)]}
        for t in all_tags
        if t.startswith(ZONE_TAG_PREFIX)
    ]
    return tests


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
    dep = fleet.deploy
    if dep:
        reach = ", ".join(zone_tag(z) for z in dep["zones"])
        L.append(f"// {dep['tag']} (the deploy, tailnet.deploy): SSH to {reach}")
        for e in dep["exceptions"]:
            where = ", ".join(zone_tag(z) for z in e["zones"])
            ports = "every port" if e["ports"] == ANY_PORT else ",".join(map(str, e["ports"]))
            L.append(f"//   and tcp {ports} to {where}: {e['reason']}")
        empty = [z for z in dep["zones"] if z not in {g.zone for g in guests}]
        if empty:
            L.append(f"//   no tailnet node yet in: {', '.join(empty)}")
    L.append(json.dumps(doc, indent=2, ensure_ascii=True))
    return {FILE: "\n".join(L) + "\n"}
