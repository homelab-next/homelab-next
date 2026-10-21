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
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

from . import svg

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
END_W, LABEL_W, T_W, ROW_H, HEAD_H = 230, 250, 150, 30, 26
X_FROM, X_T = 8, 8 + END_W + LABEL_W
X_TO = X_T + T_W + 60
WIDTH = X_TO + END_W + 8


def _end_box(x: int, y: int, end: Mapping[str, Any]) -> str:
    cls = "end muted" if end["kind"] in (NONE_DECLARED, "sample") else "end"
    kind = "not declared" if end["kind"] == NONE_DECLARED else end["kind"]
    tip = f"{end['id'] or end['title']} ({kind})"
    return svg.node(x, y, END_W, ROW_H - 6, [end["title"]], cls=cls, tip=tip)


def _sub(t: Mapping[str, Any]) -> str:
    if t["service"]:
        return f"svc:{t['service']}" + (f" ({t['impl']})" if t["impl"] else "")
    return t["source"] or "not registered"


def render(vm: Mapping[str, Any]) -> str:
    body, y = [], 4
    marker = "dataflow-arrow"
    shown = [t for t in vm["transports"] if t["flows"]]
    for t in shown:
        rows = [f for f in vm["flows"] if f["transport"] == t["id"]]
        top = y
        h = HEAD_H + len(rows) * ROW_H + 6
        body.append(svg.band(4, top, WIDTH - 8, h, "lane"))
        body.append(svg.text(12, top + 18, f"{t['title']} \u00b7 {_sub(t)}", width=WIDTH - 24))
        y = top + HEAD_H
        body.append(
            svg.node(X_T, y, T_W, len(rows) * ROW_H - 6, [t["title"], _sub(t)], cls="transport")
        )
        for f in rows:
            mid = y + (ROW_H - 6) // 2
            body.append(_end_box(X_FROM, y, f["from"]))
            cls = "dash" if f["sample"] or f["from"]["kind"] == NONE_DECLARED else ""
            body.append(svg.arrow([(X_FROM + END_W, mid), (X_T, mid)], marker, cls=cls))
            body.append(
                f"<g><title>{svg.e(f['label'] + ' - ' + f['detail'])}</title>"
                + svg.text(X_FROM + END_W + 8, mid - 4, f["label"], width=LABEL_W - 16, cls="lbl")
                + "</g>"
            )
            cls = "dash" if f["to"]["kind"] == NONE_DECLARED else ""
            body.append(svg.arrow([(X_T + T_W, mid), (X_TO, mid)], marker, cls=cls))
            body.append(_end_box(X_TO, y, f["to"]))
            y += ROW_H
        y = top + h + 8
    if not shown:
        body.append(svg.text(12, 24, "no flows", width=200, cls="sub"))
        y = 40
    n = len(vm["flows"])
    desc = (
        f"{n} flow(s) in {len(shown)} transport lane(s): each row is a producer on the left, the "
        "flow's event type, table, status source or action on its arrow, the transport in the "
        "middle and the consumer on the right. Dashed: a contract sample or an undeclared end. "
        "The table below lists the same flows."
    )
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
        svg.svg("dataflow", WIDTH, y, "Dataflow: producer, transport, consumer", desc, body)
        + svg.table("Flows", ("Transport", "Producer", "Carries", "What", "Consumer"), rows)
        + svg.table("Transports", ("Transport", "Implemented by", "Flows"), t_rows)
    )
