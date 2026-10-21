# SPDX-License-Identifier: Apache-2.0
"""Architecture: capabilities -> implementations (fakes, adapters, products) -> services, and the
control plane.

Sources of truth: the knowledge graph's registry, compose and capability readers
(:mod:`homelabnext.graph.sources`, the same reading behind ``docs/capabilities/README.md``):
``svc -provides-> cap``, ``svc -runs-> product``, ``adapter -implements-> cap`` (``real`` or a
fake), ``cap -faked_by-> adapter``, ``adapter -for-> product``, and each capability's
``conformance`` (core or extended suite).  The control plane is read from the repository: the
broker manifest (actions, lanes), the decision specs (``workflows/decisions/`` and the safety
specs), the workflow packs and the status hub (registry service and status sources).

:func:`build` is a pure function of a :class:`homelabnext.graph.model.Graph` and the
control-plane facts; :func:`graph_for` builds just the part of the graph it reads.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from . import svg

CONTROL = ("agents", "bus", "workflows", "decision", "broker", "status-hub")


def graph_for(root: str | Path) -> Any:
    """The registry, compose and capability part of the knowledge graph of ``root``."""
    from homelabnext.graph.model import Graph
    from homelabnext.graph.sources import Builder, read_capabilities, read_compose, read_registry

    b = Builder(Path(root).resolve())
    for reader in (read_registry, read_compose, read_capabilities):
        reader(b)
    b.finish()
    return Graph(dict(b.nodes), list(b.edges))


def _name(nid: str) -> str:
    return nid.split(":", 1)[1] if ":" in nid else nid


def build(graph: Any, control: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """The architecture view-model: one row per capability that has a conformance suite, an
    implementation or a service (sorted by name), and the control-plane boxes."""
    rows: dict[str, dict[str, Any]] = {}

    def row(cap_id: str) -> dict[str, Any]:
        n = graph.nodes.get(cap_id)
        attrs = n.attrs if n is not None else {}
        return rows.setdefault(
            cap_id,
            {
                "id": _name(cap_id),
                "conformance": attrs.get("conformance"),
                "fakes": set(),
                "adapters": set(),
                "products": set(),
                "services": set(),
            },
        )

    adapter_products: dict[str, set[str]] = {}
    svc_products: dict[str, set[str]] = {}
    for e in graph.edges:
        if e.type == "for":
            adapter_products.setdefault(e.src, set()).add(_name(e.dst))
        elif e.type == "runs" and e.src.startswith("svc:"):
            svc_products.setdefault(e.src, set()).add(_name(e.dst))
    for e in graph.edges:
        if e.type == "implements":
            n = graph.nodes.get(e.src)
            real = bool(n.attrs.get("real")) if n is not None else False
            r = row(e.dst)
            r["adapters" if real else "fakes"].add(_name(e.src))
            r["products"] |= adapter_products.get(e.src, set())
        elif e.type == "faked_by":
            row(e.src)["fakes"].add(_name(e.dst))
        elif e.type == "provides" and e.src.startswith("svc:"):
            r = row(e.dst)
            r["services"].add(_name(e.src))
            r["products"] |= svc_products.get(e.src, set())
    for n in graph.nodes.values():
        if n.kind == "cap" and n.attrs.get("conformance"):
            row(n.id)
    caps = [
        {k: sorted(v) if isinstance(v, set) else v for k, v in r.items()}
        for _, r in sorted(rows.items())
    ]
    return {"capabilities": caps, "control": dict(control or {})}


def gather_control(root: str | Path, registry: Any) -> dict[str, Any]:
    """The control-plane facts: counts and names read from the repository at ``root``."""
    from .dataflow import BROKER_MANIFEST, _lanes, _packs, _yaml

    r = Path(root)
    manifest = r / BROKER_MANIFEST
    actions: list[str] = []
    if manifest.is_file():
        doc = _yaml(manifest) or {}
        actions = sorted(
            str(a.get("action")) for a in doc.get("actions") or [] if isinstance(a, Mapping)
        )
    specs = sorted(p.stem for p in (r / "workflows" / "decisions").glob("*.yml"))
    safety = sorted(
        p.stem
        for p in (r / "homelabnext" / "decide" / "safety_specs").glob("*.yml")
        if p.stem.count(".") == 0
    )
    packs = _packs(r)
    hub = registry.by_capability("status-hub") if registry is not None else None
    bus = registry.by_capability("events") if registry is not None else None
    every = (
        [src for s in registry.sorted_services() for src in s.status_sources] if registry else []
    )
    sources = sorted(str(src["id"]) for src in every)
    pushed = sorted(str(src["id"]) for src in every if src.get("kind") == "push-event")
    return {
        "broker": {
            "actions": actions,
            "lanes": [lane["name"] for lane in _lanes(manifest)],
            "source": BROKER_MANIFEST if manifest.is_file() else None,
        },
        "decision": {"specs": specs, "safety": safety},
        "workflows": {
            "packs": [p["name"] for p in packs],
            "triggers": sorted({p["event"] for p in packs if p["event"]}),
            "decides": any(p["decides"] for p in packs),
            "acts": any(p["actions"] for p in packs),
        },
        "status-hub": {"service": hub.name if hub else None, "sources": sources, "pushed": pushed},
        "bus": {"service": bus.name if bus else None, "impl": bus.impl if bus else None},
    }


# ------------------------------------------------------------------------------------ render
COLS = (
    ("Capability", 150),
    ("Fakes", 230),
    ("Adapters", 230),
    ("Products", 120),
    ("Services", 130),
)
CHIP_H, PAD = 24, 6


def _chips(x: int, y: int, w: int, values: Sequence[str], cls: str) -> list[str]:
    return [
        svg.node(x + 4, y + i * (CHIP_H + 4), w - 8, CHIP_H, [v.rsplit(".", 1)[-1]], cls=cls, tip=v)
        for i, v in enumerate(values)
    ]


def _matrix_svg(vm: Mapping[str, Any]) -> str:
    width = sum(w for _, w in COLS) + 16
    body, x = [], 8
    for title, w in COLS:
        body.append(svg.text(x + 4, 18, title, width=w - 8, cls="sub"))
        x += w
    y = 28
    for c in vm["capabilities"]:
        lists = [c["fakes"], c["adapters"], c["products"], c["services"]]
        n = max([1, *(len(v) for v in lists)])
        h = n * (CHIP_H + 4) + PAD
        body.append(svg.band(4, y, width - 8, h, "row"))
        conf = c["conformance"] or "no suite"
        body.append(svg.text(12, y + 17, c["id"], width=COLS[0][1] - 12))
        body.append(svg.text(12, y + 32, conf, width=COLS[0][1] - 12, cls="sub"))
        x = 8 + COLS[0][1]
        for (_, w), values, cls in zip(
            COLS[1:], lists, ("fake", "adapter", "product", "service"), strict=True
        ):
            body += _chips(x, y + PAD // 2, w, values, cls)
            x += w
        y += h + 4
    desc = (
        f"{len(vm['capabilities'])} capabilities as rows; for each, its fakes (conformance "
        "doubles), real-product adapters, the products those adapters and the registry services "
        "run, and the registry services that provide it. The table below lists the same matrix."
    )
    return svg.svg(
        "architecture", width, y + 4, "Capabilities and their implementations", desc, body
    )


def _control_lines(cid: str, c: Mapping[str, Any]) -> list[str]:
    if cid == "agents":
        return ["Agents", "act only through the broker"]
    if cid == "bus":
        b = c.get("bus") or {}
        return [
            "Event bus",
            f"svc:{b['service']} ({b.get('impl')})" if b.get("service") else "not registered",
        ]
    if cid == "workflows":
        w = c.get("workflows") or {}
        return [
            "Workflows",
            f"{len(w.get('packs', []))} pack(s), {len(w.get('triggers', []))} trigger(s)",
        ]
    if cid == "decision":
        d = c.get("decision") or {}
        return ["Decision", f"{len(d.get('specs', []))} spec(s), {len(d.get('safety', []))} safety"]
    if cid == "broker":
        b = c.get("broker") or {}
        return [
            "Broker",
            f"{len(b.get('actions', []))} action(s), {len(b.get('lanes', []))} lane(s)",
        ]
    h = c.get("status-hub") or {}
    return ["Status hub", f"{len(h.get('sources', []))} status source(s)"]


#: box positions (column, row) and the edges drawn between them, in the order data moves
_POS = {
    "agents": (0, 0),
    "bus": (0, 1),
    "workflows": (1, 1),
    "decision": (2, 2),
    "broker": (2, 0),
    "status-hub": (1, 2),
}


def control_edges(c: Mapping[str, Any]) -> list[tuple[str, str, str]]:
    """``(from, to, why)``: only the edges the control-plane facts support."""
    w = c.get("workflows") or {}
    out = []
    if (c.get("broker") or {}).get("actions"):
        out.append(("agents", "broker", "named actions"))
    if w.get("triggers"):
        out.append(("bus", "workflows", "trigger events"))
    if w.get("decides"):
        out.append(("workflows", "decision", "decide steps"))
    if w.get("acts"):
        out.append(("workflows", "broker", "action steps"))
    if (c.get("status-hub") or {}).get("pushed"):
        out.append(("bus", "status-hub", "status.observed"))
    return out


def _control_svg(vm: Mapping[str, Any]) -> str:
    c = vm["control"]
    bw, bh, gx, gy = 220, 44, 150, 40
    pos = {k: (16 + col * (bw + gx), 12 + r * (bh + gy)) for k, (col, r) in _POS.items()}
    body = []
    for a, b, why in control_edges(c):
        (x1, y1), (x2, y2) = pos[a], pos[b]
        if y1 == y2:
            pts = [(x1 + bw, y1 + bh // 2), (x2 if x2 > x1 else x2 + bw, y2 + bh // 2)]
        else:
            down = y2 > y1
            pts = [
                (x1 + bw // 2 + (20 if x2 > x1 else 0), y1 + (bh if down else 0)),
                (x2 + bw // 2 - (20 if x2 > x1 else 0), y2 + (0 if down else bh)),
            ]
        body.append(f"<g><title>{svg.e(f'{a} to {b}: {why}')}</title>")
        body.append(svg.arrow(pts, "control-arrow"))
        mx, my = (pts[0][0] + pts[1][0]) // 2, (pts[0][1] + pts[1][1]) // 2
        label = svg.text(mx, my - 5, why, width=gx - 10, cls="lbl", anchor="middle")
        body.append(label + "</g>")
    for cid in CONTROL:
        x, y = pos[cid]
        body.append(svg.node(x, y, bw, bh, _control_lines(cid, c), cls="transport"))
    width = 16 + 3 * bw + 2 * gx + 16
    height = 12 + 3 * (bh + gy)
    desc = (
        "The control plane: agents act only through the broker; the bus triggers workflows, "
        "which call the decision cascade and act through the broker; status observations reach "
        "the status hub. An arrow is drawn only where the repository declares it."
    )
    return svg.svg("control", width, height, "Control plane", desc, body)


def render(vm: Mapping[str, Any]) -> str:
    rows = [
        (
            svg.code(c["id"]),
            svg.e(c["conformance"] or "none"),
            svg.codes(c["fakes"]),
            svg.codes(c["adapters"]),
            svg.codes(c["products"]),
            svg.codes(f"svc:{s}" for s in c["services"]),
        )
        for c in vm["capabilities"]
    ]
    c = vm["control"]
    ctl = [
        (svg.e(_control_lines(k, c)[0]), svg.e(_control_lines(k, c)[1]), svg.codes(_names(k, c)))
        for k in CONTROL
    ]
    return (
        _matrix_svg(vm)
        + svg.table(
            "Capabilities",
            ("Capability", "Suite", "Fakes", "Adapters", "Products", "Services"),
            rows,
        )
        + "<h3>Control plane</h3>"
        + _control_svg(vm)
        + svg.table("Control plane", ("Part", "Holds", "Names"), ctl)
        + svg.table(
            "Control-plane edges",
            ("From", "To", "Why"),
            [(svg.e(a), svg.e(b), svg.e(w)) for a, b, w in control_edges(c)],
        )
    )


def _names(cid: str, c: Mapping[str, Any]) -> list[str]:
    part = c.get(cid) or {}
    if cid == "broker":
        return [*part.get("actions", []), *(f"lane:{x}" for x in part.get("lanes", []))]
    if cid == "decision":
        return [*part.get("specs", []), *part.get("safety", [])]
    if cid == "workflows":
        return [*part.get("packs", []), *part.get("triggers", [])]
    if cid == "status-hub":
        return part.get("sources", [])
    if cid == "bus":
        return [f"svc:{part['service']}"] if part.get("service") else []
    return []
