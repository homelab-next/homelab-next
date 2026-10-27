# SPDX-License-Identifier: Apache-2.0
"""Dataflow: how data moves, producer -> transport -> consumer, each flow labelled.

Sources of truth (:func:`gather` reads them; :func:`build` is a pure function of what it read):

* the event types: every ``schemas/events/<type>.schema.json`` (the same discovery the generated
  contract tests use, :mod:`homelabnext.events.contract`); each type's contract **samples**
  (``examples/``) name a publishing ``source``;
* the code: an AST scan of the ``homelabnext`` package finds every module that names an event
  type (a literal or a module constant, followed through ``from .x import NAME``).  A use inside
  a ``decode_event(...)`` or ``Consumer(...)`` call consumes the type; any other use builds one;
* the workflow packs (``workflows/packs/``): ``trigger.event`` consumes a type, an ``action`` step
  goes through the broker to its ``target``, a ``lookup`` step reads a table;
* the registry (``services.yml``): which service is the bus, the lake, the object store and the
  status hub (by capability), every status source (polled, pushed on the bus or spooled), and the
  services that store into the object store (``upstreams``);
* the lake tables: every ``schemas/ocsf/<table>.v<N>.json`` (:func:`contract.table_names`);
* the broker manifest (``examples/broker/manifest.yml``): its write lanes and the actions bound
  to them.

A producer or consumer the repository does not declare is drawn as such ("no writer declared"),
never guessed.
"""

from __future__ import annotations

import ast
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from typing import Any

from . import svg
from .lab import guest_addresses

#: transport id -> (title, the registry capability that implements it, or None)
TRANSPORTS: dict[str, tuple[str, str | None]] = {
    "bus": ("Event bus", "events"),
    "collect": ("Status collection", "status-hub"),
    "lake": ("Lake", "lake-catalog"),
    "object-store": ("Object store", "object-store"),
    "broker": ("Broker", None),
}
CONSUME_CALLS = frozenset({"decode_event", "Consumer"})
PREFIX = "homelabnext."
BROKER_MANIFEST = "examples/broker/manifest.yml"
PACKS_DIR = "workflows/packs"


# ------------------------------------------------------------------------------- the code scan
def _module_name(path: Path, base: Path) -> str:
    parts = path.relative_to(base).with_suffix("").parts
    if parts and parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)


def _resolve_from(mod: str, is_pkg: bool, node: ast.ImportFrom) -> str:
    if not node.level:
        return node.module or ""
    base = mod.split(".") if is_pkg else mod.split(".")[:-1]
    base = base[: len(base) - (node.level - 1)] if node.level > 1 else base
    return ".".join([*base, *([node.module] if node.module else [])])


def scan_code(package_dir: str | Path, types: Iterable[str]) -> dict[str, dict[str, list[str]]]:
    """``{event type: {"produces": [module, ...], "consumes": [module, ...]}}`` for the Python
    package at ``package_dir`` (deterministic: modules sorted).  Only exact type strings count,
    so a help text that mentions a type is not a use."""
    wanted = set(types)
    base = Path(package_dir).parent
    trees: dict[str, tuple[ast.Module, bool]] = {}
    for p in sorted(Path(package_dir).rglob("*.py")):
        if "__pycache__" in p.parts:
            continue
        try:
            trees[_module_name(p, base)] = (
                ast.parse(p.read_text(encoding="utf-8")),
                p.stem == "__init__",
            )
        except (OSError, SyntaxError, UnicodeDecodeError, ValueError):
            continue
    consts: dict[str, dict[str, str]] = {}
    defs: set[int] = set()
    imports: dict[str, dict[str, tuple[str, str]]] = {}
    for mod, (tree, is_pkg) in trees.items():
        for st in tree.body:
            target, value = None, None
            if isinstance(st, ast.Assign) and len(st.targets) == 1:
                target, value = st.targets[0], st.value
            elif isinstance(st, ast.AnnAssign):
                target, value = st.target, st.value
            if (
                isinstance(target, ast.Name)
                and isinstance(value, ast.Constant)
                and value.value in wanted
            ):
                consts.setdefault(mod, {})[target.id] = value.value
                defs.add(id(value))
        for st in ast.walk(tree):
            if isinstance(st, ast.ImportFrom):
                src = _resolve_from(mod, is_pkg, st)
                for a in st.names:
                    imports.setdefault(mod, {})[a.asname or a.name] = (src, a.name)

    def resolve(mod: str, name: str, depth: int = 0) -> str | None:
        if name in consts.get(mod, {}):
            return consts[mod][name]
        hop = imports.get(mod, {}).get(name)
        if hop is None or depth > 4:
            return None
        return resolve(hop[0], hop[1], depth + 1)

    out: dict[str, dict[str, set[str]]] = {}
    for mod, (tree, _) in trees.items():
        docstrings = {
            id(n.value)
            for n in ast.walk(tree)
            if isinstance(n, ast.Expr) and isinstance(n.value, ast.Constant)
        }
        for n, consuming in _uses(tree, consumers=CONSUME_CALLS):
            if isinstance(n, ast.Constant):
                if id(n) in defs or id(n) in docstrings or n.value not in wanted:
                    continue
                typ = n.value
            else:
                typ = resolve(mod, n.id)
                if typ is None:
                    continue
            role = "consumes" if consuming else "produces"
            out.setdefault(typ, {"produces": set(), "consumes": set()})[role].add(mod)
    return {t: {k: sorted(v) for k, v in r.items()} for t, r in sorted(out.items())}


def _call_name(call: ast.Call) -> str:
    f = call.func
    return f.id if isinstance(f, ast.Name) else f.attr if isinstance(f, ast.Attribute) else ""


def _uses(tree: ast.AST, *, consumers: frozenset[str]):
    """``(node, inside a consumer call)`` for every string constant and loaded name."""
    stack: list[tuple[ast.AST, bool]] = [(tree, False)]
    while stack:
        node, inside = stack.pop()
        if isinstance(node, ast.Call) and _call_name(node) in consumers:
            inside = True
        text = isinstance(node, ast.Constant) and isinstance(node.value, str)
        if text or (isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load)):
            yield node, inside
        stack.extend((c, inside) for c in ast.iter_child_nodes(node))


# --------------------------------------------------------------------------------- gathering
def _yaml(path: Path) -> Any:
    import yaml

    from homelabnext._yaml import UniqueKeyLoader

    return yaml.load(path.read_text(encoding="utf-8"), Loader=UniqueKeyLoader)


def _packs(root: Path) -> list[dict[str, Any]]:
    from homelabnext.workflows.pack import WorkflowError, expand, load_doc

    d = root / PACKS_DIR
    if not d.is_dir():
        return []
    out = []
    try:
        files = expand([d])
    except WorkflowError:
        return []
    for p in files:
        try:
            doc = load_doc(p)
        except WorkflowError:
            continue
        steps = [s for s in doc.get("steps") or [] if isinstance(s, Mapping)]
        out.append(
            {
                "name": str(doc.get("pack")),
                "event": (doc.get("trigger") or {}).get("event"),
                "actions": sorted(
                    {
                        (str(s.get("action")), str(s.get("target") or ""))
                        for s in steps
                        if s.get("kind") == "action"
                    }
                ),
                "tables": sorted({str(s["table"]) for s in steps if s.get("table")}),
                "decides": sorted({str(s["spec"]) for s in steps if s.get("kind") == "decide"}),
            }
        )
    return sorted(out, key=lambda p: p["name"])


def _lanes(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    doc = _yaml(path) or {}
    actions = [a for a in doc.get("actions") or [] if isinstance(a, Mapping)]
    return [
        {
            "name": str(lane.get("name")),
            "kind": lane.get("kind"),
            "actions": sorted(
                str(a.get("action")) for a in actions if a.get("lane") == lane.get("name")
            ),
        }
        for lane in doc.get("lanes") or []
        if isinstance(lane, Mapping)
    ]


def services_of(registry: Any) -> list[dict[str, Any]]:
    """The registry facts the maps use, as plain data (sorted by service name)."""
    return [
        {
            "name": s.name,
            "capability": s.capability,
            "impl": s.impl,
            "upstreams": list(s.upstreams),
            "status_sources": [
                {
                    "id": str(src.get("id")),
                    "kind": str(src.get("kind")),
                    "target_service": (src.get("target") or {}).get("service"),
                }
                for src in s.status_sources
            ],
        }
        for s in registry.sorted_services()
    ]


def gather(root: str | Path, registry: Any) -> dict[str, Any]:
    """Everything :func:`build` needs, read from the checkout at ``root`` and the registry."""
    from homelabnext.events import contract

    r = Path(root)
    events_dir = r / "schemas" / "events"
    stems = contract.event_type_stems(events_dir) if events_dir.is_dir() else []
    types = [contract.event_type(s) for s in stems]
    samples: dict[str, list[str]] = {}
    for s in stems:
        try:
            got = contract.samples(s, events_dir)
        except (OSError, ValueError):
            got = []
        samples[contract.event_type(s)] = sorted(
            {str(x.get("source")) for x in got if x.get("source")}
        )
    tables_dir = r / "schemas" / "ocsf"
    pkg = r / "homelabnext"
    return {
        "event_types": types,
        "samples": samples,
        "code": scan_code(pkg, types) if pkg.is_dir() else {},
        "packs": _packs(r),
        "services": services_of(registry),
        "tables": contract.table_names(tables_dir) if tables_dir.is_dir() else [],
        "lanes": _lanes(r / BROKER_MANIFEST),
        "broker_manifest": BROKER_MANIFEST if (r / BROKER_MANIFEST).is_file() else None,
    }


# ------------------------------------------------------------------------------------- build
def _end(nid: str | None, title: str, kind: str) -> dict[str, Any]:
    return {"id": nid, "title": title, "kind": kind}


def _svc(name: str) -> dict[str, Any]:
    return _end(f"svc:{name}", name, "service")


def _code(module: str) -> dict[str, Any]:
    return _end(f"pkg:{module}", module.removeprefix(PREFIX), "code")


NONE_DECLARED = "kind-none"


def build(inputs: Mapping[str, Any]) -> dict[str, Any]:
    """The dataflow view-model: the transports (with the registry service behind each) and one
    flow per (producer, label, consumer), sorted by transport, label, producer, consumer."""
    services = inputs.get("services") or []
    by_cap: dict[str, str] = {}
    for s in services:
        by_cap.setdefault(s["capability"], s["name"])
    impl = {s["name"]: s.get("impl") for s in services}
    hub = by_cap.get("status-hub")
    flows: list[dict[str, Any]] = []

    def flow(transport, label, src, dst, *, detail="", sample=False):
        flows.append(
            {
                "transport": transport,
                "label": label,
                "detail": detail,
                "from": src,
                "to": dst,
                "sample": sample,
            }
        )

    # events on the bus
    code = inputs.get("code") or {}
    packs = inputs.get("packs") or []
    for t in inputs.get("event_types") or []:
        made = [_code(m) for m in code.get(t, {}).get("produces", [])]
        made += [
            _end(s, s.split(":", 1)[-1], "sample") for s in (inputs.get("samples") or {}).get(t, [])
        ]
        used = [_code(m) for m in code.get(t, {}).get("consumes", [])]
        used += [
            _end(f"workflow:{p['name']}", p["name"], "workflow") for p in packs if p["event"] == t
        ]
        made = made or [_end(None, "no producer declared", NONE_DECLARED)]
        used = used or [_end(None, "no consumer declared", NONE_DECLARED)]
        for a in made:
            for b in used:
                flow("bus", t, a, b, detail="event type", sample=a["kind"] == "sample")
    # status sources
    hub_end = _svc(hub) if hub else _end(None, "status hub (not registered)", NONE_DECLARED)
    for s in services:
        for src in s["status_sources"]:
            origin = _svc(src["target_service"] or s["name"])
            if src["kind"] == "push-event":
                flow(
                    "bus",
                    f"homelabnext.status.observed ({src['id']})",
                    origin,
                    hub_end,
                    detail="push-event status source",
                )
            else:
                flow("collect", src["id"], origin, hub_end, detail=f"{src['kind']} status source")
    # the lake and the object store
    lake, store = by_cap.get("lake-catalog"), by_cap.get("lake-query")
    readers = [
        _svc(s["name"]) for s in services if lake and lake in s["upstreams"] and s["name"] != lake
    ] or ([_svc(store)] if store else [])
    for table in inputs.get("tables") or []:
        for r in readers or [_end(None, "no reader declared", NONE_DECLARED)]:
            flow(
                "lake",
                table,
                _end(None, "no writer declared", NONE_DECLARED),
                r,
                detail="OCSF lake table",
            )
    for p in packs:
        for table in p["tables"]:
            flow(
                "lake",
                table,
                _end(None, "no writer declared", NONE_DECLARED),
                _end(f"workflow:{p['name']}", p["name"], "workflow"),
                detail="workflow lookup",
            )
    obj = by_cap.get("object-store")
    if obj:
        for s in services:
            if obj in s["upstreams"]:
                flow(
                    "object-store",
                    "objects",
                    _svc(s["name"]),
                    _end(None, "no reader declared", NONE_DECLARED),
                    detail="registry upstream",
                )
    # the broker: workflow actions and the write lanes
    for p in packs:
        for action, target in p["actions"]:
            dst = (
                _svc(target.split(":", 1)[1])
                if target.startswith("svc:")
                else _end(
                    target or None,
                    target or "no target declared",
                    "target" if target else NONE_DECLARED,
                )
            )
            flow(
                "broker",
                action,
                _end(f"workflow:{p['name']}", p["name"], "workflow"),
                dst,
                detail="workflow action",
            )
    for lane in inputs.get("lanes") or []:
        for action in lane["actions"]:
            flow(
                "broker",
                action,
                _end("profile:*", "agent profiles", "agent"),
                _end(f"lane:{lane['name']}", f"lane {lane['name']}", "lane"),
                detail=f"{lane['kind']} lane",
            )
    order = list(TRANSPORTS)
    flows.sort(
        key=lambda f: (
            order.index(f["transport"]),
            f["label"],
            f["from"]["title"],
            f["to"]["title"],
        )
    )
    transports = []
    for tid, (title, cap) in TRANSPORTS.items():
        name = by_cap.get(cap) if cap else None
        transports.append(
            {
                "id": tid,
                "title": title,
                "service": name,
                "impl": impl.get(name) if name else None,
                "source": None if cap else inputs.get("broker_manifest"),
                "flows": sum(1 for f in flows if f["transport"] == tid),
            }
        )
    return {"transports": transports, "flows": flows}


# ------------------------------------------------------------------------------------ render
#: what each end kind is, on its row's second line when no host places it
END_KIND = {
    "code": "code",
    "workflow": "workflow pack",
    "sample": "contract sample",
    "lane": "broker lane",
    "agent": "agent profiles",
    "target": "broker target",
}
STATE_LABEL = {
    "live": "live",
    "planned": "planned",
    "retired": "retired",
    "gap": "gap",
    "sample": "sample",
}


def _sub(t: Mapping[str, Any]) -> str:
    if t["service"]:
        return f"svc:{t['service']}" + (f" ({t['impl']})" if t["impl"] else "")
    return t["source"] or "not registered"


def _place(e: Mapping[str, Any], idx: Any) -> tuple[dict[str, Any], str | None]:
    """A flow end as the page shows it (title, the line under it) and its node, if placed."""
    name = e["id"][4:] if e["kind"] == "service" and e.get("id") else None
    node = idx.service_node(name) if (idx is not None and name) else None
    if e["kind"] == NONE_DECLARED:
        on = "not declared"
    elif name and idx is not None and name in idx.services:
        host = idx.services[name]["host"]
        addr = (idx.hosts.get(host) or {}).get("address")
        on = f"on {host}" + (f" · {addr}" if addr else "")
    elif name:
        on = "service"
    else:
        on = END_KIND.get(e["kind"], e["kind"])
    return {
        "title": e["title"],
        "id": e.get("id"),
        "on": on,
        "none": e["kind"] == NONE_DECLARED,
    }, node


def page(
    vm: Mapping[str, Any], *, idx: Any = None, extra: Sequence[Mapping[str, Any]] = ()
) -> dict[str, Any]:
    """The Dataflow page model: one group per transport in use (producer -> label and transport
    -> consumer, each row with a state), then the host-level groups of :mod:`.lab` in ``extra``
    (service calls, firewall allows), and the counts on top.  ``idx``: a :class:`.lab.Index`
    that places services on hosts and knows which guests are planned or retired.

    A row's state: ``gap`` when an end is not declared, ``sample`` when the producer is a
    contract sample, else the state of the guests it touches (``retired``, ``planned``,
    ``live``; ``live`` when nothing places it)."""
    groups = []
    for t in vm["transports"]:
        rows = []
        hub = idx.service_node(t["service"]) if (idx is not None and t["service"]) else None
        for f in (f for f in vm["flows"] if f["transport"] == t["id"]):
            src, a = _place(f["from"], idx)
            dst, b = _place(f["to"], idx)
            if src["none"] or dst["none"]:
                state = "gap"
            elif f["sample"]:
                state = "sample"
            else:
                state = idx.state(a, b, hub) if idx is not None else "live"
            rows.append(
                {"from": src, "to": dst, "label": f["label"], "detail": f["detail"], "state": state}
            )
        if rows:
            host = ""
            if idx is not None and t["service"] in idx.services:
                host = f" on {idx.services[t['service']]['host']}"
            groups.append({"id": t["id"], "title": t["title"], "sub": _sub(t) + host, "rows": rows})
    by_group: dict[str, list[dict[str, Any]]] = {}
    for f in extra:
        on = {}
        for side in ("from", "to"):
            e = f[side]
            on[side] = {
                "title": e["title"] or "not placed",
                "id": e["node"],
                "on": _where(e["node"], idx),
                "none": not e["node"],
            }
        by_group.setdefault(f["group"], []).append(
            {
                "from": on["from"],
                "to": on["to"],
                "label": f["label"],
                "detail": f["detail"],
                "state": f["state"],
            }
        )
    for g in ("Service calls", "Firewall allows"):
        if by_group.get(g):
            sub = (
                "registry upstreams"
                if g == "Service calls"
                else "guest firewall_rules, site service_exceptions"
            )
            groups.append(
                {"id": g.lower().replace(" ", "-"), "title": g, "sub": sub, "rows": by_group[g]}
            )
    rows = [r for g in groups for r in g["rows"]]
    count = {s: sum(1 for r in rows if r["state"] == s) for s in STATE_LABEL}
    hosts = {
        r[side]["id"]
        for r in rows
        for side in ("from", "to")
        if r[side]["id"] and str(r[side]["id"]).startswith("guest:")
    }
    stats = [
        {"n": len(rows), "label": f"flows in {len(groups)} groups", "cls": "plain"},
        {"n": count["live"], "label": "live: every end declared, no planned guest", "cls": "live"},
        {"n": count["planned"], "label": "planned: an end is a planned guest", "cls": "planned"},
        {"n": count["gap"], "label": "gaps: an end the repository does not declare", "cls": "gap"},
        {
            "n": count["sample"],
            "label": "from contract samples, not deployed producers",
            "cls": "plain",
        },
        {"n": len(hosts), "label": "guests placed on a flow", "cls": "plain"},
    ]
    return {"groups": groups, "stats": stats, "counts": count}


def _where(node: str | None, idx: Any) -> str:
    """The line under a host-level flow's end: a guest's addresses (``network.ip``, then any
    ``network.extra_addresses``), else its node id."""
    if not node:
        return "not placed"
    if idx is not None and node.startswith("guest:") and node[6:] in idx.guests:
        addrs = ", ".join(a for a in guest_addresses(idx.guests[node[6:]]) if a)
        return f"{node} \u00b7 {addrs}" if addrs else node
    return node


def _end_html(e: Mapping[str, Any], cls: str) -> str:
    none = " none" if e["none"] else ""
    tip = f' title="{svg.e(e["id"])}"' if e.get("id") else ""
    return (
        f'<div class="end {cls}{none}"{tip}>{svg.e(e["title"])}'
        f'<span class="on">{svg.e(e["on"])}</span></div>'
    )


def _row_html(r: Mapping[str, Any]) -> str:
    search = " ".join(
        str(x)
        for x in (
            r["from"]["title"],
            r["from"]["on"],
            r["label"],
            r["detail"],
            r["to"]["title"],
            r["to"]["on"],
            r["state"],
        )
        if x
    )
    return (
        f'<div class="flow-row state-{svg.e(r["state"])}" data-state="{svg.e(r["state"])}" '
        f'data-search="{svg.e(search)}">' + _end_html(r["from"], "src") + '<div class="arrow-col">'
        f'<div class="via-text">{svg.e(r["label"])}</div>'
        f'<div class="via-detail">{svg.e(r["detail"])}</div>'
        '<div class="arrow-line" aria-hidden="true"></div>'
        f'<span class="status-tag">{svg.e(STATE_LABEL.get(r["state"], r["state"]))}</span></div>'
        + _end_html(r["to"], "dst")
        + "</div>"
    )


def tables(vm: Mapping[str, Any]) -> str:
    """The table view of the dataflow model (and the no-script reading of it)."""
    rows = [
        (
            svg.e(next(t["title"] for t in vm["transports"] if t["id"] == f["transport"])),
            svg.code(f["from"]["id"])
            if f["from"]["id"]
            else f'<span class="muted">{svg.e(f["from"]["title"])}</span>',
            svg.code(f["label"]) + (' <span class="muted">sample</span>' if f["sample"] else ""),
            svg.e(f["detail"]),
            svg.code(f["to"]["id"])
            if f["to"]["id"]
            else f'<span class="muted">{svg.e(f["to"]["title"])}</span>',
        )
        for f in vm["flows"]
    ]
    t_rows = [(svg.e(t["title"]), svg.e(_sub(t)), svg.e(t["flows"])) for t in vm["transports"]]
    return (
        '<section class="maptables" aria-label="Table view"><h3>Table view</h3>'
        + svg.table("Flows", ("Transport", "Producer", "Carries", "What", "Consumer"), rows)
        + svg.table("Transports", ("Transport", "Implemented by", "Flows"), t_rows)
        + "</section>"
    )


def render(
    vm: Mapping[str, Any], *, idx: Any = None, extra: Sequence[Mapping[str, Any]] = ()
) -> str:
    """The page body: toolbar, legend, the counts, one collapsible group of flow rows per
    transport (and the host-level groups in ``extra``), then the table view.  Every row is
    server-rendered and escaped; the shared script (:mod:`.assets`) only filters and collapses."""
    from .topology import toolbar

    pm = page(vm, idx=idx, extra=extra)
    n = sum(len(g["rows"]) for g in pm["groups"])
    states = "".join(
        f'<button type="button" class="tb-btn js-only{" active" if s == "all" else ""}" '
        f'data-state-filter="{s}">{svg.e(label)}</button>'
        for s, label in (("all", "All"), ("live", "Live"), ("planned", "Planned"), ("gap", "Gaps"))
    )
    out = [
        '<div class="hx hx-dataflow">',
        toolbar(
            f"{n} flows",
            flows=False,
            placeholder="Filter: service, host, event, table",
            extra=states,
        ),
        '<p class="legend"><span><i></i>live</span><span><i class="planned"></i>planned guest</span>'
        '<span><i class="gap"></i>gap: an end not declared</span><span><i class="sample"></i>'
        "contract sample or retired guest</span></p>",
        '<div class="df-stats">',
    ]
    out += [
        f'<div class="df-stat {svg.e(s["cls"])}"><div class="n">{svg.e(s["n"])}</div>'
        f'<div class="l">{svg.e(s["label"])}</div></div>'
        for s in pm["stats"]
    ]
    out.append('</div><div id="df-groups">')
    for i, g in enumerate(pm["groups"]):
        gid = f"df-group-{i}"
        out.append(
            f'<section class="df-group" aria-label="{svg.e(g["title"])}">'
            f'<button type="button" class="group-title" aria-expanded="true" data-collapse="{gid}">'
            f'<span>{svg.e(g["title"])}</span><span class="sub">{svg.e(g["sub"])}</span>'
            f'<span class="n">{len(g["rows"])} flows</span>'
            '<span class="vlan-chevron" aria-hidden="true">▾</span></button>'
            f'<div class="df-rows" id="{gid}">'
            + "".join(_row_html(r) for r in g["rows"])
            + "</div></section>"
        )
    if not pm["groups"]:
        out.append('<p class="muted">no flows</p>')
    out.append("</div>")
    out.append(tables(vm))
    out.append("</div>")
    return "".join(out)
