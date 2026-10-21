# SPDX-License-Identifier: Apache-2.0
"""Hosts and the flows between them: what the Topology and Dataflow maps share (ADR-0018).

Everything here is a pure function of plain data:

* the **lab** (:func:`lab_of`): the registry's hosts and its services (which guest each runs on,
  its one-line description, what it calls);
* the **guests** (``raw`` guest documents) and the **site** document (zones, the router, the
  switches, the firewall's service exceptions).

:class:`Index` resolves anything a flow names -- a service, a guest, a zone, an address or CIDR
-- to a **node id**, the identity a map draws (``guest:<name>``, ``zone:<id>``,
``router:<id>``, ``switch:<id>``, ``node:<name>`` for a hypervisor with no guest file,
``internet``).  :func:`host_flows` lists every host-level flow the repository declares:

* the dataflow model's flows (:mod:`.dataflow`) split at their transport: a producer service's
  host to the transport service's host, and the transport's host to a consumer service's host
  (ends that are code, workflows or samples have no host and stay on the Dataflow page);
* the registry's ``upstreams`` (a service calls another);
* each guest's ``firewall_rules`` (``inbound_allow`` sources, ``outbound_allow`` destinations:
  ``zone:<id>``, a CIDR -- a /32 that is a guest's address is that guest, otherwise the zone
  that contains it -- or ``any``, drawn from the internet);
* the site firewall's ``service_exceptions`` (a zone to a service, so to its host).

A flow's **state** follows its ends: ``retired`` when an end is a retired guest, ``planned``
when an end is a planned guest (``status``, guest schema 1.4), else ``live``.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable, Mapping, Sequence
from typing import Any

INTERNET = "internet"
#: a guest's ``status`` values (guest schema 1.4), the default first
STATES = ("live", "planned", "retired")


def lab_of(registry: Any) -> dict[str, Any]:
    """The registry facts the maps use, as plain data: ``hosts`` (name -> address, zone, role)
    and ``services`` (sorted by name)."""
    if registry is None:
        return {"hosts": {}, "services": []}
    return {
        "hosts": {
            n: {"address": h.address, "zone": h.zone, "role": h.role}
            for n, h in sorted(registry.hosts.items())
        },
        "services": [
            {
                "name": s.name,
                "capability": s.capability,
                "impl": s.impl,
                "host": s.host,
                "protocol": s.protocol,
                "port": s.port,
                "description": s.description,
                "upstreams": list(s.upstreams),
            }
            for s in registry.sorted_services()
        ],
    }


def guest_name(raw: Mapping[str, Any]) -> str:
    return str(raw["id"]).removeprefix("guest:")


def status_of(raw: Mapping[str, Any]) -> str:
    s = raw.get("status") or "live"
    return s if s in STATES else "live"


def _net(value: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network | None:
    try:
        return ipaddress.ip_network(value, strict=False)
    except ValueError:
        return None


class Index:
    """Resolve the names a flow uses to node ids, and node ids to titles and states."""

    def __init__(
        self,
        site: Mapping[str, Any],
        guests: Sequence[Mapping[str, Any]],
        lab: Mapping[str, Any],
        hypervisors: Iterable[str] = (),
    ):
        self.guests = {guest_name(g): g for g in guests}
        self.by_ip = {
            str((g.get("network") or {}).get("ip")): n
            for n, g in self.guests.items()
            if (g.get("network") or {}).get("ip")
        }
        self.zones = {
            str(z["id"]): z
            for z in site.get("zones") or []
            if isinstance(z, Mapping) and z.get("id")
        }
        router = site.get("router") or {}
        self.router = (
            str(router["id"]) if isinstance(router, Mapping) and router.get("id") else None
        )
        self.switches = [
            str(s["id"])
            for s in site.get("switches") or []
            if isinstance(s, Mapping) and s.get("id")
        ]
        self.hypervisors = sorted(set(hypervisors))
        self.hosts = dict(lab.get("hosts") or {})
        self.services = {s["name"]: s for s in lab.get("services") or []}
        self.by_capability: dict[str, str] = {}
        for s in lab.get("services") or []:
            self.by_capability.setdefault(s["capability"], s["name"])

    # ---- names -> node ids
    def host_node(self, host: str | None) -> str | None:
        """A registry host (or guest) name as a node id: the guest of that name, the router when
        it is the site's router, a hypervisor, else None (a host the maps cannot place)."""
        if not host:
            return None
        if host in self.guests:
            return f"guest:{host}"
        if host == self.router:
            return f"router:{host}"
        if host in self.switches:
            return f"switch:{host}"
        if host in self.hypervisors:
            return f"node:{host}"
        addr = (self.hosts.get(host) or {}).get("address")
        if addr and str(addr) in self.by_ip:
            return f"guest:{self.by_ip[str(addr)]}"
        return None

    def service_node(self, service: str | None) -> str | None:
        s = self.services.get(service or "")
        return self.host_node(s["host"]) if s else None

    def service_title(self, service: str | None) -> str:
        """``name on host`` for a registry service (its host as the registry names it)."""
        s = self.services.get(service or "")
        return f"{service} on {s['host']}" if s else str(service or "")

    def zone_node(self, zone: str) -> str | None:
        return f"zone:{zone}" if zone in self.zones else None

    def address(self, value: str) -> tuple[str | None, str]:
        """A firewall source or destination (``any``, ``zone:<id>``, a CIDR) as (node id or
        None, title)."""
        if value == "any":
            return INTERNET, "any (the internet)"
        if value.startswith("zone:"):
            z = value[5:]
            return self.zone_node(z), f"zone {z}"
        net = _net(value)
        if net is None:
            return None, value
        if net.num_addresses == 1 and str(net.network_address) in self.by_ip:
            name = self.by_ip[str(net.network_address)]
            return f"guest:{name}", name
        for zid, z in self.zones.items():
            zn = _net(str(z.get("subnet") or ""))
            if zn is not None and zn.version == net.version and net.subnet_of(zn):  # type: ignore[arg-type]
                return f"zone:{zid}", f"{value} (zone {zid})"
        return None, value

    # ---- node ids -> facts
    def title(self, node: str | None) -> str:
        if node is None:
            return ""
        if node == INTERNET:
            return "internet"
        return node.split(":", 1)[1]

    def state(self, *nodes: str | None) -> str:
        """``retired`` if any node is a retired guest, ``planned`` if any is planned, else live."""
        states = {
            status_of(self.guests[n[6:]])
            for n in nodes
            if n and n.startswith("guest:") and n[6:] in self.guests
        }
        for s in ("retired", "planned"):
            if s in states:
                return s
        return "live"

    def services_on(self, node: str) -> list[dict[str, Any]]:
        """The registry services whose host is ``node`` (sorted by name)."""
        return [s for _, s in sorted(self.services.items()) if self.host_node(s["host"]) == node]


def _flow(group, src, src_title, dst, dst_title, label, detail, idx: Index) -> dict[str, Any]:
    return {
        "group": group,
        "from": {"node": src, "title": src_title},
        "to": {"node": dst, "title": dst_title},
        "label": label,
        "detail": detail,
        "state": idx.state(src, dst),
    }


def transport_hops(dataflow_vm: Mapping[str, Any] | None, idx: Index) -> list[dict[str, Any]]:
    """The dataflow model's flows as host-to-host hops through their transport's host."""
    if not dataflow_vm:
        return []
    tsvc = {t["id"]: (t["title"], t.get("service")) for t in dataflow_vm.get("transports") or []}
    out = []
    for f in dataflow_vm.get("flows") or []:
        title, svc = tsvc.get(f["transport"], (f["transport"], None))
        hub = idx.service_node(svc)
        ends = []
        for side in ("from", "to"):
            e = f[side]
            name = e["id"][4:] if e.get("kind") == "service" and e.get("id") else None
            ends.append((idx.service_node(name), name))
        (a, an), (b, bn) = ends
        label = f["label"]
        if hub is None:  # a transport with no host (the broker): service to service directly
            if a and b and a != b:
                out.append(
                    _flow(
                        title,
                        a,
                        idx.service_title(an),
                        b,
                        idx.service_title(bn),
                        label,
                        f["detail"],
                        idx,
                    )
                )
            continue
        if a and a != hub:
            via = f"{f['detail']} via {svc}"
            out.append(
                _flow(title, a, idx.service_title(an), hub, idx.service_title(svc), label, via, idx)
            )
        if b and b != hub:
            via = f"{f['detail']} via {svc}"
            out.append(
                _flow(title, hub, idx.service_title(svc), b, idx.service_title(bn), label, via, idx)
            )
    return out


def service_calls(idx: Index) -> list[dict[str, Any]]:
    """Registry ``upstreams``: the caller's host to the callee's host."""
    out = []
    for name, s in sorted(idx.services.items()):
        a = idx.host_node(s["host"])
        for cap in s.get("upstreams") or []:
            callee = idx.by_capability.get(cap)
            b = idx.service_node(callee)
            if a and b and a != b and callee:
                c = idx.services[callee]
                detail = f"{c['protocol']} {c['port']}"
                out.append(
                    _flow(
                        "Service calls",
                        a,
                        idx.service_title(name),
                        b,
                        idx.service_title(callee),
                        f"calls {callee}",
                        detail,
                        idx,
                    )
                )
    return out


def _ports(rule: Mapping[str, Any]) -> str:
    return f"{rule['proto']} {rule['ports']}" if rule.get("ports") else str(rule["proto"])


def firewall_flows(site: Mapping[str, Any], idx: Index) -> list[dict[str, Any]]:
    """Guest ``firewall_rules`` allows and the site's ``service_exceptions``."""
    out = []
    for name, g in sorted(idx.guests.items()):
        me = f"guest:{name}"
        rules = g.get("firewall_rules") or {}
        for r in rules.get("inbound_allow") or []:
            node, title = idx.address(str(r["source"]))
            label = f"allow {r['name']}"
            out.append(_flow("Firewall allows", node, title, me, name, label, _ports(r), idx))
        for r in rules.get("outbound_allow") or []:
            node, title = idx.address(str(r["dest"]))
            label = f"allow {r['name']}"
            out.append(_flow("Firewall allows", me, name, node, title, label, _ports(r), idx))
    for ex in (site.get("firewall") or {}).get("service_exceptions") or []:
        if not isinstance(ex, Mapping) or ex.get("action", "allow") != "allow":
            continue
        froms = ex.get("from") or []
        froms = [froms] if isinstance(froms, str) else froms
        to = str(ex.get("to") or "")
        svc = to[4:] if to.startswith("svc:") else None
        dst = idx.service_node(svc)
        ports = ", ".join(str(p) for p in ex.get("ports") or []) or "any port"
        for f in froms:
            node, title = idx.address(str(f))
            out.append(
                _flow(
                    "Firewall allows",
                    node,
                    title,
                    dst,
                    idx.service_title(svc) if svc else to,
                    f"exception to {to}",
                    f"site firewall, {ports}",
                    idx,
                )
            )
    return out


def host_flows(
    site: Mapping[str, Any], idx: Index, dataflow_vm: Mapping[str, Any] | None = None
) -> list[dict[str, Any]]:
    """Every host-level flow (see the module docstring), in a stable order."""
    flows = transport_hops(dataflow_vm, idx) + service_calls(idx) + firewall_flows(site, idx)
    unique = {repr(sorted(f.items())): f for f in flows}  # the same hop for many event types
    return sorted(
        unique.values(),
        key=lambda f: (
            f["group"],
            f["from"]["title"] or "",
            f["to"]["title"] or "",
            f["label"],
            f["detail"],
        ),
    )
