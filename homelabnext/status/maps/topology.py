# SPDX-License-Identifier: Apache-2.0
"""Topology: the lab as cards -- the edge and the hypervisors on top, one lane per zone below,
every guest a card -- with the data flows between them as an overlay.

Sources of truth (nothing else is read): the site model (``site.yml``: zones, VLANs, subnets,
gateways, internet egress, the router, the switches, the firewall), read by
:func:`homelabnext.network.loader.load_site`; the zone-to-zone flows the network IR allows
(:func:`homelabnext.compute.zones.flows_from_site`, first match wins); the guest model
(``guests/``: kind, provisioning, ``status``, placement, resources, image, zone and address,
capability and capability groups, firewall rules, baselines, owners) and ``_nodes.yml`` (the
hypervisors); the registry (which service runs on which guest, with its description); and the
host-level flows of :mod:`.lab` (the dataflow model's hops, registry upstreams, firewall allows).

Layout, after the lab's hand-kept topology page it replaces in spirit:

* **top cluster**: the uplink chain (the site's ``edge``, outermost first; without one the
  internet, the router and the switches), the switches not in it, the UPSes with what they feed
  (``power.ups``, :mod:`homelabnext.power`), then the hypervisors and every other physical host
  (``kind: host``);
* **one lane per zone** (site order; a zone a guest names that the site does not define gets a
  dashed lane), with its VLAN badge, purpose and subnet.  A lane with more than
  :data:`STACK_MIN` guests that use at least two capability groups is split into **stacks**, one
  per guest's first ``capability_groups`` entry: the same grouping the Ansible inventory deploys
  by (``docs/role-interface.md``), so a stack is what the deploy layer already treats as one
  functional unit, and no new field is needed;
* each card: name and address; type, resources, image, capability; badges for its service count,
  ``vmid``, ``not IaC`` (``manual`` or ``host-only``), ``planned`` / ``retired`` and, on a powered
  device, ``UPS: <id>`` or ``no UPS``; a VM's detail shows the power it inherits.

:func:`build` is pure; :func:`render` gives the page body: the toolbar, the canvas of
server-rendered cards (readable without script), the detail-panel data as an escaped JSON
element, and the same facts as tables.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

import yaml

from homelabnext import power as pw

from . import assets, svg
from .lab import INTERNET, Index, guest_name, host_flows, lab_of, status_of

CELL_W = 96  # the zone flow matrix
STACK_MIN = 4
#: the guest descriptor keys the detail panel shows, in this order
CORE_KEYS = (
    "id",
    "display_name",
    "kind",
    "provisioning",
    "status",
    "placement",
    "resources",
    "image",
    "network",
    "firewall_rules",
    "capability",
    "capability_groups",
    "tags",
    "baseline",
    "power",
    "backup",
    "owners",
)
KIND_TAG = {"ups": "UPS", "modem": "MDM", "ont": "ONT", "firewall": "FW", "edge": "DEV", "vm": "VM", "lxc": "LXC", "host": "HOST", "hypervisor": "HV", "node": "HV",
            "router": "GW", "switch": "SW", "internet": "NET"}  # fmt: skip


def _what(flow: Any) -> str:
    """``any``, ``tcp, udp`` or ``tcp 22, 443`` for one :class:`ZoneFlow`."""
    if not flow.protocols and not flow.ports:
        return "any"
    protos = ", ".join(flow.protocols) or "any"
    if not flow.ports:
        return protos
    return f"{protos} {', '.join(str(p) for p in flow.ports)}"


def _baselines(raw: Mapping[str, Any]) -> list[str]:
    b = raw.get("baseline") or {}
    if b.get("exemption"):
        return ["exempt"]
    return [str(n) for n in b.get("names") or []]


def _gb(mb: Any) -> str:
    v = round(int(mb) / 1024, 1)
    return f"{int(v)} GB" if v == int(v) else f"{v} GB"


def _resources(raw: Mapping[str, Any]) -> str | None:
    r = raw.get("resources") or {}
    parts = []
    if (r.get("cpu") or {}).get("cores"):
        parts.append(f"{r['cpu']['cores']} vCPU")
    if (r.get("memory") or {}).get("size_mb"):
        parts.append(_gb(r["memory"]["size_mb"]))
    disk = sum(int(d.get("size_gb") or 0) for d in r.get("disks") or [] if isinstance(d, Mapping))
    if disk:
        parts.append(f"{disk} GB disk")
    return " · ".join(parts) or None


def _image(raw: Mapping[str, Any]) -> str | None:
    img = raw.get("image") or {}
    if not img.get("logical"):
        return None
    return f"{img['logical']} ({img.get('os_type') or img.get('kind') or '?'})"


def _yaml(doc: Mapping[str, Any]) -> str:
    return yaml.safe_dump(dict(doc), sort_keys=False, default_flow_style=False, width=72).rstrip()


def _core(raw: Mapping[str, Any]) -> dict[str, Any]:
    doc = {k: raw[k] for k in CORE_KEYS if k in raw}
    doc["status"] = status_of(raw)
    return {k: doc[k] for k in CORE_KEYS if k in doc}


def _zone_row(z: Mapping[str, Any]) -> dict[str, Any]:
    egress = z.get("egress") or {}
    return {
        "id": str(z["id"]),
        "purpose": z.get("purpose"),
        "vlan": z.get("vlan_id"),
        "subnet": z.get("subnet"),
        "gateway": z.get("gateway"),
        "internet": egress.get("internet"),
        "known": True,
    }


def _guest_row(raw: Mapping[str, Any], services: list[str]) -> dict[str, Any]:
    net = raw.get("network") or {}
    return {
        "id": str(raw["id"]),
        "name": guest_name(raw),
        "kind": raw.get("kind"),
        "provisioning": raw.get("provisioning"),
        "status": status_of(raw),
        "node": str((raw.get("placement") or {}).get("node") or "unplaced"),
        "zone": str(net.get("zone") or "none"),
        "ip": net.get("ip"),
        "capability": raw.get("capability"),
        "baselines": _baselines(raw),
        "services": services,
    }


class _Cards:
    """Builds the cards and the detail-panel entries for one view-model."""

    def __init__(
        self,
        idx: Index,
        zones: Mapping[str, Mapping[str, Any]],
        flows: list[dict],
        power: Mapping[str, Mapping[str, Any]] | None = None,
    ):
        self.idx, self.zones, self.flows = idx, zones, flows
        self.power = power or {}
        self.details: dict[str, dict[str, Any]] = {}

    def _power(self, node: str) -> tuple[dict[str, str] | None, str | None, list[str]]:
        """(badge, tooltip text, detail lines) of a powered device; nothing for the rest."""
        eff = self.power.get(node)
        if eff is None:
            return None, None, []
        how = {"own": "declared", "default": "the site's power.default"}.get(eff["source"], "")
        if eff["none"]:
            reason = eff.get("reason") or ""
            return (
                {"cls": "nopower", "text": "no UPS"},
                f"no UPS: {reason}",
                [f"no UPS ({how}): {reason}"],
            )
        if not eff["ups"]:
            return {"cls": "nopower", "text": "power unknown"}, "not declared", ["not declared"]
        ups = ", ".join(eff["ups"])
        return {"cls": "power", "text": f"UPS: {ups}"}, ups, [f"UPS {ups} ({how})"]

    def _services(self, node: str) -> list[dict[str, Any]]:
        return [
            {
                "name": f"svc:{s['name']}",
                "description": s.get("description") or "",
                "sub": " · ".join(
                    x for x in (s.get("impl"), f"{s.get('protocol')} {s.get('port')}") if x
                ),
            }
            for s in self.idx.services_on(node)
        ]

    def _flow_lines(self, node: str) -> list[dict[str, Any]]:
        out = []
        for f in self.flows:
            mark = "" if f["state"] == "live" else f" ({f['state']})"
            what = f"{f['label']} [{f['detail']}]" if f["detail"] else f["label"]
            if f["from"]["node"] == node:
                out.append(
                    {
                        "dir": "out",
                        "state": f["state"],
                        "text": f"OUT -> {f['to']['title']}: {what}{mark}",
                    }
                )
            if f["to"]["node"] == node:
                out.append(
                    {
                        "dir": "in",
                        "state": f["state"],
                        "text": f"IN <- {f['from']['title']}: {what}{mark}",
                    }
                )
        return out

    def card(
        self,
        node: str,
        name: str,
        category: str,
        *,
        kind_type: str,
        ip: str | None = None,
        zone: str | None = None,
        meta: Sequence[str | None] = (),
        vmid: Any = None,
        status: str = "live",
        not_iac: bool = False,
        core: Mapping[str, Any] | None = None,
        does: str | None = None,
        subtitle: str | None = None,
        power: Sequence[str] | None = None,
        badge: Mapping[str, str] | None = None,
        badge2: Mapping[str, str] | None = None,
    ) -> dict[str, Any]:
        services = self._services(node)
        p_badge, p_tip, p_lines = self._power(node)
        if power is not None:  # given: an inherited power (a guest) or what a UPS feeds
            p_lines = list(power)
        z = self.zones.get(zone or "") or {}
        vlan = z.get("vlan_id")
        badges = []
        if services:
            n = len(services)
            badges.append({"cls": "count", "text": f"{n} service{'s' if n != 1 else ''}"})
        if not_iac:
            badges.append({"cls": "notiac", "text": "not IaC"})
        if status != "live":
            badges.append({"cls": status, "text": status})
        if p_badge:
            badges.append(p_badge)
        if badge:
            badges.append(dict(badge))
        if badge2:
            badges.append(dict(badge2))
        self.details[node] = {
            "name": name,
            "subtitle": subtitle,
            "yaml": _yaml(core) if core else "",
            "does": does,
            "services": services,
            "flows": self._flow_lines(node),
            "power": p_lines,
        }
        return {
            "node": node,
            "name": name,
            "category": category,
            "tag": KIND_TAG.get(category, category.upper()),
            "type": kind_type,
            "ip": ip,
            "zone": zone,
            "vlan": vlan if vlan is not None else (zone or None),
            "meta": [m for m in meta if m],
            "vmid": vmid,
            "status": status,
            "badges": badges,
            "services": [s["name"].removeprefix("svc:") for s in services],
            "power": p_tip,
        }

    def guest(self, raw: Mapping[str, Any], *, hypervisor: bool, children: int) -> dict[str, Any]:
        name = guest_name(raw)
        kind = str(raw.get("kind"))
        prov = str(raw.get("provisioning"))
        placement = raw.get("placement") or {}
        net = raw.get("network") or {}
        category = "hypervisor" if hypervisor else kind
        meta = [f"{kind} · {prov}", _resources(raw), _image(raw), raw.get("capability")]
        if hypervisor:
            meta.append(f"hypervisor · {children} guest{'s' if children != 1 else ''}")
        elif placement.get("node") and placement.get("node") != name:
            meta.append(f"on {placement['node']}")
        does = raw.get("description") or raw.get("display_name")
        if not does:
            does = f"Provides {raw.get('capability')}." if raw.get("capability") else None
        inherited = None
        if kind != "host" and self.power:
            got = pw.of_guest(raw, self.power)
            if got is None:
                inherited = ["unknown: its node declares no power"]
            else:
                src, eff = got
                what = (
                    f"no UPS ({eff.get('reason') or 'no reason'})"
                    if eff["none"]
                    else "UPS " + (", ".join(eff["ups"]) or "not declared")
                )
                inherited = [f"inherits {src.split(':', 1)[1]}: {what}"]
        return self.card(
            f"guest:{name}",
            name,
            category,
            kind_type=f"{kind} · {prov}",
            ip=net.get("ip"),
            zone=net.get("zone"),
            meta=meta,
            vmid=placement.get("vmid"),
            status=status_of(raw),
            not_iac=prov != "terraform",
            core=_core(raw),
            does=does,
            subtitle=raw.get("display_name"),
            power=inherited,
        )


#: a UPS's live power state (from its status summary) -> the badge text
_UPS_WORDS = {"on-battery": "on battery", "low-battery": "on battery, low"}


def _ups_live(live: Mapping[str, Any] | None) -> tuple[dict[str, str] | None, list[str]]:
    """(the state badge, the detail line) of a UPS with a NUT reading; nothing without one."""
    if not live:
        return None, []
    from homelabnext.status.power import power_state

    state = str(live.get("state") or "unknown")
    summary = str(live.get("summary") or "")
    word = _UPS_WORDS.get(power_state(summary) or "", "")
    if not word:
        word = "on line" if state == "ok" else state
    if state == "stale":
        word = "stale"
    at = f" at {live['observed_at']}" if live.get("observed_at") else ""
    return (
        {"cls": f"ups-{state}", "text": word},
        [f"live ({state}{at}, {live.get('source')}): {summary}"],
    )


def index_for(
    site: Mapping[str, Any],
    raws: Sequence[Mapping[str, Any]],
    lab: Mapping[str, Any],
    nodes: Sequence[str] = (),
) -> Index:
    """The :class:`.lab.Index` for these guest documents.  A hypervisor is a node in
    ``_nodes.yml`` or one some other guest is placed on."""
    hosting = {
        str((r.get("placement") or {}).get("node") or "")
        for r in raws
        if (r.get("placement") or {}).get("node") != guest_name(r)
    }
    return Index(site, raws, lab, sorted((set(nodes) | hosting) - {""}))


def _stacks(cards: list[dict[str, Any]], groups: Mapping[str, str]) -> list[dict[str, Any]]:
    """A lane's cards as stacks (see the module docstring); one untitled stack otherwise."""
    keys = {groups.get(c["node"], "") for c in cards}
    if len(cards) <= STACK_MIN or len(keys - {""}) < 2:
        return [{"title": None, "cards": cards}]
    by: dict[str, list[dict[str, Any]]] = {}
    for c in cards:
        by.setdefault(groups.get(c["node"], ""), []).append(c)
    order = sorted(by, key=lambda k: (k == "", -len(by[k]), k))
    return [
        {"title": k.removeprefix("cap_").replace("_", " ") if k else "other", "cards": by[k]}
        for k in order
    ]


def build(
    site: Mapping[str, Any],
    guests: Sequence[Any],
    flows: Sequence[Any],
    *,
    lab: Mapping[str, Any] | None = None,
    nodes: Sequence[str] | Mapping[str, Mapping[str, Any]] = (),
    dataflow: Mapping[str, Any] | None = None,
    ups_state: Mapping[str, Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    """The topology view-model.  ``site``: the site document; ``guests``: guest objects (``raw``
    is the guest document); ``flows``: zone flows (``src``, ``dst``, ``protocols``, ``ports``);
    ``lab``: :func:`.lab.lab_of` of the registry (services per host); ``nodes``: the hypervisors
    (``_nodes.yml``: names, or name -> spec with its ``power``); ``dataflow``: the dataflow view-model (its hops become flows);
    ``ups_state``: site UPS id -> its live NUT reading (:func:`homelabnext.status.power.states`),
    shown as a state badge on that UPS's card.
    Zones keep the site's order; a guest in a zone the site does not define gets its own lane
    (``known: false``), so a mismatch shows instead of vanishing."""
    lab = lab or {"hosts": {}, "services": []}
    raws = [g.raw for g in sorted(guests, key=lambda g: g.raw["id"])]
    specs = dict(nodes) if isinstance(nodes, Mapping) else {n: {} for n in nodes}
    idx = index_for(site, raws, lab, list(specs))
    hyper = idx.hypervisors
    facts = pw.site_power(site)
    hosts = {guest_name(r): r for r in raws if r.get("kind") == "host"}
    resolved = pw.resolve(facts, pw.hypervisors(specs, raws), hosts)
    hflows = host_flows(site, idx, dataflow)

    zones = [
        _zone_row(z) for z in site.get("zones") or [] if isinstance(z, Mapping) and z.get("id")
    ]
    known = {z["id"] for z in zones}
    for zid in sorted({str((r.get("network") or {}).get("zone") or "none") for r in raws} - known):
        zones.append({"id": zid, "known": False})
    site_zones = {z["id"]: z for z in site.get("zones") or [] if isinstance(z, Mapping)}

    cards = _Cards(idx, site_zones, hflows, resolved)
    children = {
        n: sum(
            1 for r in raws if (r.get("placement") or {}).get("node") == n and guest_name(r) != n
        )
        for n in hyper
    }
    # ---- the top cluster: the edge chain (site ``edge``, else internet, router, switches),
    # the switches not in it, the UPSes, then the hypervisors and other physical hosts
    internet_zones = [z["id"] for z in zones if z.get("internet") == "allow"]
    devices: dict[str, dict[str, Any]] = {}
    devices[INTERNET] = cards.card(
        INTERNET,
        "internet",
        "internet",
        kind_type="upstream",
        meta=["egress from " + ", ".join(internet_zones) if internet_zones else "no zone egresses"],
        core={"internet_egress": {z["id"]: z.get("internet") or "not set" for z in zones}},
        does="Everything outside the lab. Zones reach it only where the site allows egress.",
    )
    router = site.get("router") or {}
    if isinstance(router, Mapping) and router.get("id"):
        rid = str(router["id"])
        addr = (lab.get("hosts") or {}).get(rid, {}).get("address")
        devices[f"router:{rid}"] = cards.card(
            f"router:{rid}",
            rid,
            "router",
            kind_type=f"router \u00b7 {router.get('model') or '?'}",
            ip=addr,
            meta=[f"gateway of {len(known)} zone{'s' if len(known) != 1 else ''}"],
            core={k: router[k] for k in ("id", "model", "mgmt_endpoint", "power") if k in router},
            does="The edge: routes between the zones and enforces the site firewall.",
        )
    switches = []
    for sw in site.get("switches") or []:
        if not isinstance(sw, Mapping) or not sw.get("id"):
            continue
        ports = sw.get("port_assignments") or []
        node = f"switch:{sw['id']}"
        switches.append(node)
        devices[node] = cards.card(
            node,
            str(sw["id"]),
            "switch",
            kind_type=f"switch \u00b7 {sw.get('model') or '?'}",
            meta=[
                f"{len(ports)} port group{'s' if len(ports) != 1 else ''}",
                f"uplink port {sw['uplink_port']}" if sw.get("uplink_port") else None,
            ],
            core={
                k: sw[k]
                for k in ("id", "model", "uplink_port", "power", "port_assignments")
                if k in sw
            },
            does="Carries the zones' VLANs between the router and the hypervisors.",
        )
    chain = [e for e in site.get("edge") or [] if isinstance(e, Mapping) and e.get("id")]
    top: list[list[dict[str, Any]]] = []
    if chain:
        for e in chain:
            node = pw.edge_node(site, e)
            if node not in devices:
                kind = str(e.get("kind") or "other")
                category = kind if kind in ("modem", "ont", "firewall") else "edge"
                devices[node] = cards.card(
                    node,
                    str(e["id"]),
                    category,
                    kind_type=f"{kind} \u00b7 {e['model']}" if e.get("model") else kind,
                    meta=["in the uplink chain"],
                    core={k: e[k] for k in ("id", "kind", "model", "power") if k in e},
                    does=f"A {kind} in the uplink chain between the internet and the lab.",
                )
            top.append([devices[node]])
        shown = {c["node"] for row in top for c in row}
        rest = [devices[n] for n in switches if n not in shown]
        if rest:
            top.append(rest)
    else:
        top.append([devices[INTERNET]])
        if isinstance(router, Mapping) and router.get("id"):
            top.append([devices[f"router:{router['id']}"]])
        if switches:
            top.append([devices[n] for n in switches])
    power_lines: list[dict[str, str]] = []
    if facts is not None:
        fed = pw.feeds(resolved, facts["ups"])
        row = []
        for uid, ups in facts["ups"].items():
            how = ups.get("monitored_by") or "none"
            watch = f"monitored by {how}" + (f" ({ups['nut_name']})" if ups.get("nut_name") else "")
            n = len(fed[uid])
            live, live_lines = _ups_live((ups_state or {}).get(uid))
            row.append(
                cards.card(
                    f"ups:{uid}",
                    uid,
                    "ups",
                    kind_type=f"UPS \u00b7 {ups['model']}" if ups.get("model") else "UPS",
                    meta=[watch],
                    core=ups,
                    does="Keeps what it feeds running through a power cut, for as long as its "
                    "battery lasts.",
                    power=live_lines
                    + ([f"feeds {x.split(':', 1)[1]}" for x in fed[uid]] or ["feeds nothing"]),
                    badge={"cls": "count" if n else "nopower", "text": f"feeds {n}"},
                    badge2=live,
                )
            )
            power_lines += [{"source": f"ups:{uid}", "dest": x} for x in fed[uid]]
        if row:
            top.append(row)
    by_name = {guest_name(r): r for r in raws}
    physical = []
    for n in hyper:
        if n in by_name:
            physical.append(cards.guest(by_name[n], hypervisor=True, children=children[n]))
        else:
            physical.append(
                cards.card(
                    f"node:{n}",
                    n,
                    "node",
                    kind_type="hypervisor",
                    meta=[f"hypervisor · {children[n]} guests", "no guest file"],
                    core={"node": n},
                    does="A hypervisor named by the guests' placement; it has no guest file.",
                    not_iac=True,
                )
            )
    physical += [
        cards.guest(r, hypervisor=False, children=0)
        for r in raws
        if r.get("kind") == "host" and guest_name(r) not in hyper
    ]
    if physical:
        top.append(physical)

    # ---- the lanes
    groups = {f"guest:{guest_name(r)}": str((r.get("capability_groups") or [""])[0]) for r in raws}
    lanes = []
    for i, z in enumerate(zones):
        members = [
            cards.guest(r, hypervisor=False, children=0)
            for r in raws
            if r.get("kind") != "host"
            and guest_name(r) not in hyper
            and str((r.get("network") or {}).get("zone") or "none") == z["id"]
        ]
        if not members and not z.get("known"):
            continue
        stacks = _stacks(members, groups)
        for s in stacks:  # a column of cards per stack, two once it is long
            s["cols"] = 1 if len(s["cards"]) <= 5 else 2
        grid = min(3, len(stacks))  # stacks side by side, at most three to a row
        lanes.append({**z, "color": i % 7, "grid": grid, "stacks": stacks})

    # ---- the arrows: unique (source, dest) between nodes on the page, retired ends left out
    on_page = {c["node"] for row in top for c in row}
    on_page |= {c["node"] for ln in lanes for s in ln["stacks"] for c in s["cards"]}
    on_page |= {f"zone:{ln['id']}" for ln in lanes}
    pairs: dict[tuple[str, str], dict[str, Any]] = {}
    for f in hflows:
        a, b = f["from"]["node"], f["to"]["node"]
        if a not in on_page or b not in on_page or a == b or f["state"] == "retired":
            continue
        e = pairs.setdefault((a, b), {"source": a, "dest": b, "labels": [], "state": "planned"})
        if f["label"] not in e["labels"]:
            e["labels"].append(f["label"])
        if f["state"] == "live":
            e["state"] = "live"
    edges = [
        {
            "source": e["source"],
            "dest": e["dest"],
            "label": ", ".join(e["labels"]),
            "state": e["state"],
        }
        for _, e in sorted(pairs.items())
    ]

    zone_flows: dict[tuple[str, str], list[str]] = {}
    for f in flows:
        zone_flows.setdefault((str(f.src), str(f.dst)), []).append(_what(f))
    services_by_guest = {
        n: [s["name"] for s in idx.services_on(f"guest:{n}")] for n in sorted(by_name)
    }
    return {
        "site": (site.get("site") or {}).get("id"),
        "default": str((site.get("firewall") or {}).get("default_action") or "deny"),
        "zones": zones,
        "guests": [_guest_row(r, services_by_guest[guest_name(r)]) for r in raws],
        "flows": [
            {"from": a, "to": b, "allowed": "; ".join(sorted(w))}
            for (a, b), w in sorted(zone_flows.items())
        ],
        "top": top,
        "lanes": lanes,
        "edges": edges,
        "power": [p for p in power_lines if p["dest"] in on_page],
        "host_flows": hflows,
        "details": cards.details,
    }


def inputs(
    guests_dir: str | Path, site_path: str | Path
) -> tuple[Mapping[str, Any], list[Any], list[Any], dict[str, Any]]:
    """(site document, guests, zone flows, hypervisors: name -> ``_nodes.yml`` spec) read from a guest directory and the
    site model its zones come from (raises :class:`homelabnext.compute.model.ComputeError` on an
    unloadable tree or site)."""
    from homelabnext.compute.loader import NODES_FILE, load_fleet, load_nodes
    from homelabnext.compute.model import ComputeError
    from homelabnext.compute.zones import flows_from_site, open_site, site_power
    from homelabnext.network.loader import SiteError, load_site

    try:
        doc = load_site(site_path)
    except SiteError as exc:
        raise ComputeError(str(exc)) from exc
    if not isinstance(doc, Mapping):
        raise ComputeError(f"{site_path}: expected a mapping")
    zones, domain = open_site(site_path)
    fleet = load_fleet(
        guests_dir,
        zones,
        domain=domain or "example.internal",
        require_baselines=False,
        power=site_power(site_path),
    )
    nodes_file = Path(guests_dir) / NODES_FILE
    nodes = load_nodes(nodes_file) if nodes_file.is_file() else {}
    return doc, fleet.sorted(), list(flows_from_site(doc)), dict(sorted(nodes.items()))


def load(
    guests_dir: str | Path,
    site_path: str | Path,
    *,
    registry: Any = None,
    dataflow: Mapping[str, Any] | None = None,
    ups_state: Mapping[str, Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    """:func:`build` over :func:`inputs`, with the registry (services per guest), the
    dataflow view-model (its hops become flows) and the UPSes' live states when given."""
    doc, guests, flows, nodes = inputs(guests_dir, site_path)
    return build(
        doc,
        guests,
        flows,
        lab=lab_of(registry),
        nodes=nodes,
        dataflow=dataflow,
        ups_state=ups_state,
    )


# ------------------------------------------------------------------------------------ render
def _attr(name: str, value: Any) -> str:
    return f' {name}="{svg.e("" if value is None else value)}"'


def _card_html(c: Mapping[str, Any]) -> str:
    cls = f"net-card cat-{c['category']} status-{c['status']}"
    attrs = (
        _attr("class", cls)
        + _attr("data-node", c["node"])
        + _attr("data-hostname", c["name"])
        + _attr("data-ip", c["ip"] or "—")
        + _attr("data-vlan", c["vlan"] if c["vlan"] is not None else "—")
        + _attr("data-type", c["type"])
        + _attr("data-services", ", ".join(c["services"]))
        + (_attr("data-power", c["power"]) if c.get("power") else "")
        + ' tabindex="0" role="button"'
        + _attr("aria-label", f"{c['name']} ({c['type']}): details")
    )
    out = [f"<div{attrs}>", '<div class="card-header">']
    out.append(f'<span class="kind">{svg.e(c["tag"])}</span>')
    out.append(f'<span class="card-hostname">{svg.e(c["name"])}</span>')
    if c.get("vmid") is not None:
        out.append(f'<span class="badge vmid">vmid {svg.e(c["vmid"])}</span>')
    out.append("</div>")
    if c.get("ip"):
        out.append(f'<div class="card-ip">{svg.e(c["ip"])}</div>')
    for m in c["meta"]:
        cls = "card-meta card-parent" if str(m).startswith("on ") else "card-meta"
        out.append(f'<div class="{cls}">{svg.e(m)}</div>')
    if c["badges"]:
        out.append('<div class="card-badges">')
        out += [
            f'<span class="badge {svg.e(b["cls"])}">{svg.e(b["text"])}</span>' for b in c["badges"]
        ]
        out.append("</div>")
    out.append("</div>")
    return "".join(out)


def _lane_html(ln: Mapping[str, Any], i: int) -> str:
    known = ln.get("known")
    lid = f"lane-{i}-content"
    badge = (
        f"VLAN {ln['vlan']}" if known and ln.get("vlan") is not None
        else ("no VLAN" if known else "unknown zone")
    )  # fmt: skip
    sub = (
        " · ".join(
            x
            for x in (
                ln.get("subnet"),
                f"gw {ln['gateway']}" if ln.get("gateway") else None,
                f"internet {ln['internet']}" if ln.get("internet") else None,
            )
            if x
        )
        if known
        else "not in the site model"
    )
    title = ln.get("purpose") or ln["id"]
    out = [
        f'<section class="vlan-lane lane-{ln["color"]}{"" if known else " unknown"}"'
        f"{_attr('data-node', 'zone:' + ln['id'])}{_attr('aria-label', 'zone ' + ln['id'])}>",
        f'<button type="button" class="vlan-header" aria-expanded="true"{_attr("data-collapse", lid)}>'
        f'<span class="vlan-head"><span class="vlan-badge">{svg.e(badge)}</span>'
        f'<span class="vlan-title">{svg.e(ln["id"])} · {svg.e(title)}</span>'
        f'<span class="vlan-subnet">{svg.e(sub)}</span></span>'
        '<span class="vlan-chevron" aria-hidden="true">▾</span></button>',
        f'<div class="vlan-content" id="{lid}"><div class="stacks grid-{ln["grid"]}">',
    ]
    for j, s in enumerate(ln["stacks"]):
        out.append('<div class="stack">')
        if s["title"]:
            out.append(f'<div class="stack-label stack-{j % 6}">{svg.e(s["title"])}</div>')
        out.append(f'<div class="cards cols-{s["cols"]}">')
        out += [_card_html(c) for c in s["cards"]]
        out.append("</div></div>")
    out.append("</div>")
    if not any(s["cards"] for s in ln["stacks"]):
        out.append('<p class="muted">no guests</p>')
    out.append("</div></section>")
    return "".join(out)


def toolbar(
    count: str, *, flows: bool, placeholder: str, extra: str = "", power: bool = False
) -> str:
    """The shared toolbar (Topology and Dataflow): filter box, a count, buttons."""
    flow_btn = (
        '<button type="button" id="flow-toggle" class="tb-btn js-only" aria-pressed="false">'
        "↔ Show Data Flows</button>"
        + (
            '<button type="button" id="power-toggle" class="tb-btn js-only" aria-pressed="false">'
            "⚡ Show Power</button>"
            if power
            else ""
        )
        + '<button type="button" id="reset-btn" class="tb-btn js-only">⛶ Reset view</button>'
        if flows
        else ""
    )
    return (
        '<div class="hx-bar" role="toolbar" aria-label="Map controls">'
        '<label class="find js-only"><span class="muted" aria-hidden="true">⌕</span>'
        f'<input id="filter-input" type="search" placeholder="{svg.e(placeholder)}" '
        'aria-label="Filter (Ctrl+F; Esc clears)"></label>'
        f'<span class="count">{svg.e(count)}</span>{extra}{flow_btn}'
        '<button type="button" id="theme-toggle" class="tb-btn js-only">Light theme</button>'
        "</div>"
    )


def _flows_svg(vm: Mapping[str, Any]) -> str:
    zones = [z["id"] for z in vm["zones"] if z.get("known")]
    allowed = {(f["from"], f["to"]): f["allowed"] for f in vm["flows"]}
    left, top = 110, 40
    width, height = left + len(zones) * CELL_W + 8, top + len(zones) * 30 + 8
    body = [svg.text(8, 16, "from ↓  to →", width=left, cls="sub")]
    for i, z in enumerate(zones):
        body.append(svg.text(left + i * CELL_W + 6, top - 10, z, width=CELL_W - 8))
        body.append(svg.text(8, top + i * 30 + 20, z, width=left - 12))
    for i, a in enumerate(zones):
        for j, b in enumerate(zones):
            x, y = left + j * CELL_W, top + i * 30
            if a == b:
                cls, label, tip = "cell self", "—", f"{a} to itself"
            elif (a, b) in allowed:
                cls, label = "cell allow", allowed[(a, b)]
                tip = f"{a} to {b}: allowed {label}"
            elif vm["default"] == "deny":
                cls, label, tip = "cell deny", "deny", f"{a} to {b}: denied"
            else:
                cls, label = "cell other", vm["default"]
                tip = f"{a} to {b}: no rule, the default action ({vm['default']})"
            body.append(
                f'<g class="{cls}"><title>{svg.e(tip)}</title>'
                f'<rect class="bx" x="{x + 2}" y="{y + 2}" width="{CELL_W - 4}" height="26" rx="3"/>'
                + svg.text(x + 8, y + 20, label, width=CELL_W - 12)
                + "</g>"
            )
    desc = (
        f"A {len(zones)} by {len(zones)} matrix: a row is the source zone, a column the "
        "destination; a filled cell is an allowed flow with its protocols and ports, every other "
        "pair is denied. The table below lists the allowed flows."
    )
    return svg.svg("topology-flows", width, height, "Allowed zone-to-zone flows", desc, body)


def host_flow_rows(flows: Sequence[Mapping[str, Any]]) -> list[tuple[str, ...]]:
    def end(e: Mapping[str, Any]) -> str:
        if e["node"]:
            return svg.code(e["node"])
        return f'<span class="muted">{svg.e(e["title"] or "not placed")}</span>'

    return [
        (svg.e(f["group"]), end(f["from"]), end(f["to"]), svg.code(f["label"]), svg.e(f["detail"]),
         svg.e(f["state"]))
        for f in flows
    ]  # fmt: skip


def tables(vm: Mapping[str, Any]) -> str:
    """The table view: every fact the canvas shows (and the no-script page)."""
    g_rows = [
        (
            svg.code(g["id"]),
            svg.e(g["status"]),
            svg.e(g["kind"]),
            svg.e(g["provisioning"]),
            svg.code(g["node"]),
            svg.code(g["zone"]),
            svg.e(g["ip"] or ""),
            svg.code(g["capability"]) if g["capability"] else "",
            svg.codes(g["services"]),
            svg.codes(g["baselines"]),
        )
        for g in vm["guests"]
    ]
    z_rows = [
        (
            svg.code(z["id"]),
            svg.e(z.get("purpose") or ""),
            svg.e(z.get("vlan") if z.get("vlan") is not None else ""),
            svg.e(z.get("subnet") or ""),
            svg.e(z.get("gateway") or ""),
            svg.e(z.get("internet") or ("not in the site model" if not z.get("known") else "")),
        )
        for z in vm["zones"]
    ]
    f_rows = [(svg.code(f["from"]), svg.code(f["to"]), svg.e(f["allowed"])) for f in vm["flows"]]
    return (
        '<section class="maptables" aria-label="Table view"><h3>Table view</h3>'
        + svg.table(
            "Guests",
            (
                "Guest",
                "Status",
                "Kind",
                "Provisioning",
                "Node",
                "Zone",
                "Address",
                "Capability",
                "Services",
                "Baselines",
            ),
            g_rows,
        )
        + svg.table("Zones", ("Zone", "Purpose", "VLAN", "Subnet", "Gateway", "Internet"), z_rows)
        + svg.table(
            "Host flows",
            ("Group", "From", "To", "What", "Detail", "State"),
            host_flow_rows(vm["host_flows"]),
        )
        + "<h3>Zone-to-zone flows</h3>"
        + _flows_svg(vm)
        + svg.table(
            f"Allowed flows (every other pair: {vm['default']})", ("From", "To", "Allowed"), f_rows
        )
        + "</section>"
    )


def render(vm: Mapping[str, Any]) -> str:
    """The page body for a topology view-model: toolbar, legend, canvas, detail panel, data and
    the table view (escaped HTML; the script is added by the page, :mod:`.assets`)."""
    n_cards = sum(len(r) for r in vm["top"]) + sum(
        len(s["cards"]) for ln in vm["lanes"] for s in ln["stacks"]
    )
    out = [
        '<div class="hx hx-topology">',
        toolbar(
            f"{len(vm['guests'])} guests · {n_cards} cards · {len(vm['edges'])} flows",
            flows=True,
            power=bool(vm.get("power")),
            placeholder="Filter: host, IP, service, type",
        ),
        '<p class="legend"><span><i></i>live flow</span><span><i class="planned"></i>'
        "planned (an end is a planned guest)</span>"
        + (
            '<span><i class="power"></i>power (a UPS to what it feeds)</span>'
            if vm.get("power")
            else ""
        )
        + "<span>click a card for its descriptor, services and flows; drag to pan, wheel to zoom"
        "</span></p>",
        '<div class="topo-canvas" id="topo-canvas"><div class="topo-inner" id="topo-inner">',
        '<svg id="flow-svg" aria-hidden="true"><defs>'
        '<marker id="arrowhead" markerWidth="8" markerHeight="8" refX="7" refY="3" orient="auto">'
        '<path d="M0,0 L8,3 L0,6 Z"/></marker>'
        '<marker id="arrowhead-planned" markerWidth="8" markerHeight="8" refX="7" refY="3" '
        'orient="auto"><path d="M0,0 L8,3 L0,6 Z"/></marker></defs></svg>',
        '<div class="top-cluster">',
    ]
    for row in vm["top"]:
        out.append('<div class="top-row">' + "".join(_card_html(c) for c in row) + "</div>")
    out.append('</div><div class="lanes">')
    out += [_lane_html(ln, i) for i, ln in enumerate(vm["lanes"])]
    out.append("</div></div></div>")
    out.append(
        '<aside id="detail-panel" aria-label="Details"><button type="button" id="detail-close" '
        'aria-label="Close">✕</button><div id="detail-content"><p class="muted">'
        "Click a card to see its descriptor, services and data flow.</p></div></aside>"
        '<div id="tooltip-el" class="tooltip" role="tooltip"></div>'
    )
    out.append(
        assets.json_script(
            "topo-data",
            {"edges": vm["edges"], "power": vm.get("power", []), "details": vm["details"]},
        )
    )
    out.append(tables(vm))
    out.append("</div>")
    return "".join(out)
