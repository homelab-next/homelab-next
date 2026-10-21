# SPDX-License-Identifier: Apache-2.0
"""What feeds each machine: the site's UPSes and every device's power declaration.

Pure functions over plain data, shared by the site model (:mod:`homelabnext.network.validate`),
the guest model (:mod:`homelabnext.compute.validate`) and the Topology map, so the one rule set
is written once and the compute model still never imports the site-model package.

The site declares ``power.ups`` (each with a logical ``id``) and optionally ``power.default``;
the router, every switch, every ``edge`` device but the internet, every hypervisor
(``_nodes.yml``) and every physical host (guest ``kind: host``) declares ``power: {ups: <id> |
[<id>, ...]}`` or ``{ups: none, reason: ...}``, or is covered by the default.  A VM or container
is never declared: it inherits its hypervisor's power (it is only as protected as that host).

A site without a ``power`` section asks nothing (labs modelled before 1.1 stay valid).  With
one, these are errors: an unknown UPS id; a UPS named ``none`` (reserved); ``none`` without a
reason; a device with no declaration and no default; a device declared twice (on its ``edge``
entry and on the router or switch it is); a VM or container with its own ``power``; a UPS that
feeds nothing (a UPS in the model is part of the lab, or it does not belong in the model).
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

NONE = "none"
#: the edge kind that is not a device of the lab and so has no power of its own
UPSTREAM = "internet"


def ups_ids(ref: Mapping[str, Any] | None) -> list[str]:
    """The UPS ids a power declaration names (``[]`` for ``none`` or no declaration)."""
    if not isinstance(ref, Mapping):
        return []
    ups = ref.get("ups")
    if ups == NONE or ups is None:
        return []
    return [str(u) for u in ([ups] if isinstance(ups, str) else ups)]


def ref_problems(ref: Any, where: str, known: Iterable[str]) -> list[str]:
    """Problems of one ``power`` declaration: unknown ids, ``none`` without a reason."""
    if not isinstance(ref, Mapping) or "ups" not in ref:
        return [f"{where}: power must be {{ups: <id> | [<id>, ...]}} or {{ups: none, reason}}"]
    ups = ref["ups"]
    if ups == NONE:
        reason = ref.get("reason")
        if not isinstance(reason, str) or len(reason.strip()) < 10:
            return [f"{where}: power.ups none needs a reason (why it runs without a UPS)"]
        return []
    names = [ups] if isinstance(ups, str) else ups
    if not isinstance(names, list) or not names or not all(isinstance(u, str) for u in names):
        return [f"{where}: power.ups must name one or more UPS ids, or none"]
    have = set(known)
    return [f"{where}: power.ups {u!r} is not a UPS of the site" for u in names if u not in have]


def site_power(doc: Mapping[str, Any]) -> dict[str, Any] | None:
    """The site's power facts as plain data, or None when it has no ``power`` section:
    ``ups`` (id -> UPS), ``default`` (a declaration or None) and ``devices`` (node id -> its
    declaration or None) for the router, the switches and the edge devices."""
    power = doc.get("power")
    if not isinstance(power, Mapping):
        return None
    ups = {
        str(u["id"]): dict(u)
        for u in power.get("ups") or []
        if isinstance(u, Mapping) and u.get("id")
    }
    devices: dict[str, Any] = {}
    router = doc.get("router") or {}
    if isinstance(router, Mapping) and router.get("id"):
        devices[f"router:{router['id']}"] = router.get("power")
    for s in doc.get("switches") or []:
        if isinstance(s, Mapping) and s.get("id"):
            devices[f"switch:{s['id']}"] = s.get("power")
    for e in doc.get("edge") or []:
        if not isinstance(e, Mapping) or not e.get("id") or e.get("kind") == UPSTREAM:
            continue
        node = edge_node(doc, e)
        if node not in devices:
            devices[node] = e.get("power")
    return {"ups": ups, "default": power.get("default"), "devices": devices}


def edge_node(doc: Mapping[str, Any], entry: Mapping[str, Any]) -> str:
    """The node id of an ``edge`` entry: the router or a switch when it names one, ``internet``
    for the upstream, else ``edge:<id>``."""
    eid = str(entry.get("id"))
    if entry.get("kind") == UPSTREAM:
        return "internet"
    router = doc.get("router") or {}
    if isinstance(router, Mapping) and router.get("id") == eid:
        return f"router:{eid}"
    if any(isinstance(s, Mapping) and s.get("id") == eid for s in doc.get("switches") or []):
        return f"switch:{eid}"
    return f"edge:{eid}"


def site_problems(doc: Mapping[str, Any]) -> list[str]:
    """The site-only power rules (the device rules for the router, switches and edge)."""
    out: list[str] = []
    power = doc.get("power")
    seen: set[str] = set()
    for i, e in enumerate(doc.get("edge") or []):
        if not isinstance(e, Mapping):
            continue
        eid = str(e.get("id"))
        if eid in seen:
            out.append(f"edge[{i}]: duplicate edge id {eid!r}")
        seen.add(eid)
        node = edge_node(doc, e)
        if e.get("power") is not None and node.split(":", 1)[0] in ("router", "switch"):
            out.append(f"edge {eid}: declare its power once, on the {node.split(':', 1)[0]} it is")
        if e.get("kind") == UPSTREAM and e.get("power") is not None:
            out.append(f"edge {eid}: the internet has no power of its own")
    if not isinstance(power, Mapping):
        return out
    ids: list[str] = [str(u.get("id")) for u in power.get("ups") or [] if isinstance(u, Mapping)]
    for u in sorted({x for x in ids if ids.count(x) > 1}):
        out.append(f"power.ups: duplicate UPS id {u!r}")
    if NONE in ids:
        out.append("power.ups: 'none' is reserved (it means no UPS)")
    known = set(ids) - {NONE}
    facts = site_power(doc) or {}
    default = facts.get("default")
    if default is not None:
        out += ref_problems(default, "power.default", known)
    for node, ref in (facts.get("devices") or {}).items():
        if ref is None:
            if default is None:
                out.append(f"{node}: no power declaration and no power.default")
        else:
            out += ref_problems(ref, node, known)
    return out


def resolve(
    site: Mapping[str, Any] | None,
    nodes: Mapping[str, Mapping[str, Any]],
    hosts: Mapping[str, Mapping[str, Any]],
) -> dict[str, dict[str, Any]]:
    """Every powered device's effective declaration: node id -> ``{"ups": [ids], "none":
    bool, "reason": str | None, "source": "own" | "default" | "missing"}``.  ``nodes``: the
    hypervisors (name -> their ``_nodes.yml`` spec); ``hosts``: the physical hosts (name -> the
    guest document).  A hypervisor that is also a host guest is one device (``guest:<name>``)."""
    if not site:
        return {}
    default = site.get("default")
    out: dict[str, dict[str, Any]] = {}

    def entry(ref: Any) -> dict[str, Any]:
        src = "own" if ref is not None else ("default" if default is not None else "missing")
        eff = ref if ref is not None else default
        none = isinstance(eff, Mapping) and eff.get("ups") == NONE
        reason = eff.get("reason") if isinstance(eff, Mapping) else None
        return {"ups": ups_ids(eff), "none": none, "reason": reason, "source": src}

    for node, ref in (site.get("devices") or {}).items():
        out[node] = entry(ref)
    for name in sorted(set(nodes) | set(hosts)):
        own = (hosts.get(name) or {}).get("power")
        if own is None:
            own = (nodes.get(name) or {}).get("power")
        out[f"guest:{name}" if name in hosts else f"node:{name}"] = entry(own)
    return out


def hypervisors(
    nodes: Mapping[str, Mapping[str, Any]], guests: Iterable[Mapping[str, Any]]
) -> dict[str, Mapping[str, Any]]:
    """``_nodes.yml`` plus every node another guest is placed on (with an empty spec): a
    hypervisor powers its guests whether or not ``_nodes.yml`` lists it."""
    out: dict[str, Mapping[str, Any]] = {}
    for g in guests:
        node = (g.get("placement") or {}).get("node")
        if node and node != str(g.get("id", "")).removeprefix("guest:"):
            out[str(node)] = {}
    return {**out, **nodes}


def feeds(resolved: Mapping[str, Mapping[str, Any]], ups: Iterable[str]) -> dict[str, list[str]]:
    """UPS id -> the node ids it feeds (sorted), every UPS listed."""
    out: dict[str, list[str]] = {u: [] for u in ups}
    for node, eff in sorted(resolved.items()):
        for u in eff["ups"]:
            if u in out:
                out[u].append(node)
    return out


def fleet_problems(
    site: Mapping[str, Any] | None,
    nodes: Mapping[str, Mapping[str, Any]],
    guests: Iterable[Mapping[str, Any]],
) -> list[str]:
    """The guest-side power rules (hypervisors, physical hosts, VMs and containers, and UPSes
    that feed nothing) for guest documents and ``_nodes.yml`` against :func:`site_power`."""
    guests = list(guests)
    nodes = hypervisors(nodes, guests)
    out: list[str] = []
    for g in guests:
        if g.get("kind") in ("vm", "lxc") and g.get("power") is not None:
            out.append(f"{g['id']}: a {g['kind']} has no power of its own; it inherits its node's")
    if not site:
        return out
    known = set(site.get("ups") or {})
    hosts = {str(g["id"]).removeprefix("guest:"): g for g in guests if g.get("kind") == "host"}
    for name, g in sorted(hosts.items()):
        spec = nodes.get(name) or {}
        own, listed = g.get("power"), spec.get("power")
        if own is not None and listed is not None and own != listed:
            out.append(f"{g['id']}: power differs from _nodes.yml {name}; declare it once")
    for name, spec in sorted(nodes.items()):
        if spec.get("power") is not None:
            out += ref_problems(spec["power"], f"_nodes.yml {name}", known)
    for _, g in sorted(hosts.items()):
        if g.get("power") is not None:
            out += ref_problems(g["power"], str(g["id"]), known)
    resolved = resolve(site, nodes, hosts)
    for node, eff in sorted(resolved.items()):
        if eff["source"] == "missing":
            out.append(f"{node}: no power declaration and no power.default")
    for u, fed in sorted(feeds(resolved, known).items()):
        if not fed:
            out.append(f"power.ups {u}: feeds nothing (wire it to a device, or remove it)")
    return out


def of_guest(
    raw: Mapping[str, Any], resolved: Mapping[str, Mapping[str, Any]]
) -> tuple[str, dict[str, Any]] | None:
    """(the device it draws from, that device's effective power) for a guest: a host is its
    own device, a VM or container inherits its node's; None when nothing is known."""
    name = str(raw["id"]).removeprefix("guest:")
    if raw.get("kind") == "host" and f"guest:{name}" in resolved:
        return f"guest:{name}", dict(resolved[f"guest:{name}"])
    node = str((raw.get("placement") or {}).get("node") or "")
    for key in (f"guest:{node}", f"node:{node}"):
        if key in resolved:
            return key, dict(resolved[key])
    return None
