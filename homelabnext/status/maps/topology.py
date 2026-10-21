# SPDX-License-Identifier: Apache-2.0
"""Topology: hypervisors and their guests grouped by zone, and the zone-to-zone flows allowed.

Sources of truth (nothing else is read): the site model (``site.yml``: zones, VLANs, subnets,
gateways, internet egress), read by :func:`homelabnext.network.loader.load_site`; the allowed
flows as the network IR evaluates them (:func:`homelabnext.compute.zones.flows_from_site`, first
match wins, so the map shows what the firewall would do, not what the YAML seems to say); and the
guest model (``guests/``, :func:`homelabnext.compute.loader.load_fleet`: node, zone, address,
capability, baselines).

:func:`build` is a pure function of those three; :func:`render` turns its view-model into the
page body (two SVGs and their tables).
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from . import svg

COL_W, GUEST_H, HEAD_H, ROW_PAD, LEFT_W, GAP = 200, 38, 80, 10, 150, 8
CELL_W = 96  # the flow matrix


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


def build(site: Mapping[str, Any], guests: Sequence[Any], flows: Sequence[Any]) -> dict[str, Any]:
    """The topology view-model.  ``site``: the site document; ``guests``: guest objects (``raw``
    is the guest document); ``flows``: zone flows (``src``, ``dst``, ``protocols``, ``ports``).
    Zones keep the site's order; a guest in a zone the site does not define gets its own column
    (marked ``known: false``), so a mismatch shows instead of vanishing."""
    zones: list[dict[str, Any]] = []
    for z in site.get("zones") or []:
        if not isinstance(z, Mapping) or not z.get("id"):
            continue
        egress = z.get("egress") or {}
        zones.append(
            {
                "id": str(z["id"]),
                "purpose": z.get("purpose"),
                "vlan": z.get("vlan_id"),
                "subnet": z.get("subnet"),
                "gateway": z.get("gateway"),
                "internet": egress.get("internet"),
                "known": True,
            }
        )
    known = {z["id"] for z in zones}
    rows = []
    for g in sorted(guests, key=lambda g: g.raw["id"]):
        raw = g.raw
        net = raw.get("network") or {}
        rows.append(
            {
                "id": str(raw["id"]),
                "name": str(raw["id"]).removeprefix("guest:"),
                "kind": raw.get("kind"),
                "node": str((raw.get("placement") or {}).get("node") or "unplaced"),
                "zone": str(net.get("zone") or "none"),
                "ip": net.get("ip"),
                "capability": raw.get("capability"),
                "baselines": _baselines(raw),
            }
        )
    for zid in sorted({r["zone"] for r in rows} - known):
        zones.append({"id": zid, "known": False})
    nodes = sorted({r["node"] for r in rows})
    flow_rows: dict[tuple[str, str], list[str]] = {}
    for f in flows:
        flow_rows.setdefault((str(f.src), str(f.dst)), []).append(_what(f))
    return {
        "site": (site.get("site") or {}).get("id"),
        "default": str((site.get("firewall") or {}).get("default_action") or "deny"),
        "zones": zones,
        "nodes": [
            {
                "id": n,
                "hypervisor": any(r["node"] == n and r["name"] == n for r in rows),
                "guests": [r for r in rows if r["node"] == n],
            }
            for n in nodes
        ],
        "flows": [
            {"from": a, "to": b, "allowed": "; ".join(sorted(w))}
            for (a, b), w in sorted(flow_rows.items())
        ],
    }


def load(guests_dir: str | Path, site_path: str | Path) -> dict[str, Any]:
    """:func:`build` over a guest directory and the site model its zones come from (raises
    :class:`homelabnext.compute.model.ComputeError` on an unloadable tree or site)."""
    from homelabnext.compute.loader import load_fleet
    from homelabnext.compute.model import ComputeError
    from homelabnext.compute.zones import flows_from_site, open_site
    from homelabnext.network.loader import SiteError, load_site

    try:
        doc = load_site(site_path)
    except SiteError as exc:
        raise ComputeError(str(exc)) from exc
    if not isinstance(doc, Mapping):
        raise ComputeError(f"{site_path}: expected a mapping")
    zones, domain = open_site(site_path)
    fleet = load_fleet(
        guests_dir, zones, domain=domain or "example.internal", require_baselines=False
    )
    return build(doc, fleet.sorted(), flows_from_site(doc))


# ------------------------------------------------------------------------------------ render
def _zone_lines(z: Mapping[str, Any]) -> list[str]:
    if not z.get("known"):
        return [z["id"], "not in the site model"]
    vlan = f"VLAN {z['vlan']}" if z.get("vlan") is not None else "no VLAN"
    lines = [z["id"], f"{vlan} \u00b7 {z.get('subnet') or '?'}"]
    lines.append(f"gateway {z['gateway']}" if z.get("gateway") else "no gateway")
    lines.append(f"internet {z.get('internet') or 'not set'}")
    return lines


def _hosts_svg(vm: Mapping[str, Any]) -> str:
    zones, nodes = vm["zones"], vm["nodes"]
    col = {z["id"]: i for i, z in enumerate(zones)}
    width = LEFT_W + len(zones) * (COL_W + GAP) + GAP
    body, y = [], HEAD_H + GAP
    for i, z in enumerate(zones):
        x = LEFT_W + GAP + i * (COL_W + GAP)
        cls = "zone" if z.get("known") else "zone unknown"
        body.append(svg.node(x, 4, COL_W, HEAD_H - 8, _zone_lines(z), cls=cls))
    for n in nodes:
        per = {z["id"]: [g for g in n["guests"] if g["zone"] == z["id"]] for z in zones}
        h = max(1, max((len(v) for v in per.values()), default=1)) * (GUEST_H + 4) + ROW_PAD
        body.append(svg.band(4, y, width - 8, h, "row"))
        what = "hypervisor" if n["hypervisor"] else "node"
        body.append(svg.text(12, y + 20, n["id"], width=LEFT_W - 16))
        body.append(svg.text(12, y + 35, what, width=LEFT_W - 16, cls="sub"))
        for zid, gs in per.items():
            x = LEFT_W + GAP + col[zid] * (COL_W + GAP)
            for j, g in enumerate(gs):
                tip = (
                    f"{g['id']} ({g['kind']}) on {n['id']}, zone {g['zone']}, {g['ip'] or 'no ip'}"
                    f", {g['capability'] or 'no capability'}, baselines: "
                    f"{', '.join(g['baselines']) or 'none'}"
                )
                sub = f"{g['ip'] or '-'} \u00b7 {g['kind']}"
                gy = y + ROW_PAD // 2 + j * (GUEST_H + 4)
                body.append(svg.node(x + 6, gy, COL_W - 12, GUEST_H, [g["name"], sub], tip=tip))
        y += h + GAP
    if not nodes:
        body.append(svg.text(12, y + 20, "no guests", width=200, cls="sub"))
        y += 30
    n_guests = sum(len(n["guests"]) for n in nodes)
    desc = (
        f"{len(nodes)} node(s) as rows, {len(zones)} zone(s) as columns, {n_guests} guest(s) "
        "placed in the cell of their node and zone. The table below lists the same guests."
    )
    return svg.svg("topology-hosts", width, y, "Guests by node and zone", desc, body)


def _flows_svg(vm: Mapping[str, Any]) -> str:
    zones = [z["id"] for z in vm["zones"] if z.get("known")]
    allowed = {(f["from"], f["to"]): f["allowed"] for f in vm["flows"]}
    left, top = 110, 40
    width, height = left + len(zones) * CELL_W + 8, top + len(zones) * 30 + 8
    body = [svg.text(8, 16, "from \u2193  to \u2192", width=left, cls="sub")]
    for i, z in enumerate(zones):
        body.append(svg.text(left + i * CELL_W + 6, top - 10, z, width=CELL_W - 8))
        body.append(svg.text(8, top + i * 30 + 20, z, width=left - 12))
    for i, a in enumerate(zones):
        for j, b in enumerate(zones):
            x, y = left + j * CELL_W, top + i * 30
            if a == b:
                cls, label, tip = "cell self", "\u2014", f"{a} to itself"
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


def render(vm: Mapping[str, Any]) -> str:
    """The page body for a topology view-model (escaped HTML: SVGs plus tables)."""
    guests = [g for n in vm["nodes"] for g in n["guests"]]
    g_rows = [
        (
            svg.code(g["id"]),
            svg.e(g["kind"]),
            svg.code(g["node"]),
            svg.code(g["zone"]),
            svg.e(g["ip"] or ""),
            svg.code(g["capability"]) if g["capability"] else "",
            svg.codes(g["baselines"]),
        )
        for g in sorted(guests, key=lambda g: g["id"])
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
        _hosts_svg(vm)
        + svg.table(
            "Guests",
            ("Guest", "Kind", "Node", "Zone", "Address", "Capability", "Baselines"),
            g_rows,
        )
        + svg.table("Zones", ("Zone", "Purpose", "VLAN", "Subnet", "Gateway", "Internet"), z_rows)
        + "<h3>Zone-to-zone flows</h3>"
        + _flows_svg(vm)
        + svg.table(
            f"Allowed flows (every other pair: {vm['default']})", ("From", "To", "Allowed"), f_rows
        )
    )
