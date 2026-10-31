# SPDX-License-Identifier: Apache-2.0
"""``views.yml`` (the shell and its menu) and the ``status.json`` document built from it.

``status.json`` is **the contract** of the status hub (``docs/status.md`` documents it): the
static page, ``hnx status serve`` and any later UI all read this one shape, so the visual design
can change without touching collectors or consumers.  Top-level keys (``schema``
``homelabnext.status/1``; evolve additively)::

    schema, generated_at, title, main, act_via
    summary       {"total", "ok", "warn", "fail", "unknown", "stale"}   item counts by state
    menu          [{"id", "title", "kind": "panel"|"external"|"page", "panel"?, "href"?, "group"?,
                    "available"}]
    views         {<view id>: <panel payload>}                          one per panel view
    modules       [{"module", "state", "counts", "service", "capability", "links", "items"}]
    sources       [the menu of sources with "state", "last_attempt", "last_ok", "error"]
    observations  [every latest observation, "state" effective, "reported_state" as recorded]
    agents        null, or {"counts", "sessions"}: agent sessions, summary tier only (stage 1b)

Panel payloads:

* ``exceptions`` (checklist O-05) -- ``{"panel", "ok", "total", "live", "attention"}``: the green
  count, live work (items with ``work`` and a non-zero ``value``) and attention items (every item
  not ``ok``, plus every source not ``ok`` that has no items to show it).  Nothing else: with
  everything healthy the page is one green number and the live work.
* ``grid`` (O-02) -- ``{"panel", "modules": [...]}``: one tile per module, its worst state.
* ``sources`` -- ``{"panel", "sources": [...]}``: the source table.

Page panels (:data:`PAGE_PANELS`) are pages of their own, served live by ``hnx status serve``:
the agent pages (with ``--agents``), the strategy pages (with ``--strategy``; Strategy,
Requirements, Objectives, RFIs: :mod:`homelabnext.strategy.pages`) and the Baselines page (with
``--guests``: :mod:`homelabnext.compute.pages`), the Approvals page (when ``agents.yml``
configures ``approvals:``: :mod:`homelabnext.status.approvals`) and the generated maps
(:data:`MAP_PANELS`: topology with ``--guests``, dataflow, architecture and roadmap with ``--maps``;
:mod:`homelabnext.status.maps`, ADR-0018), the directory pages (:data:`DIRECTORY_PANELS`: Links,
Schedule, Agent roster and MCP servers with ``--maps``), the Projects page (with ``--projects``:
:mod:`homelabnext.projects.pages`) and the Orchestration page (with ``--orchestration``:
:mod:`homelabnext.orchestration.pages`).  Their menu entries are
``available`` only when that part is configured.  The private pages (:data:`PRIVATE_PANELS`, the
``private`` menu group) are never in the public ``status.json`` and render only for a request
through the trusted front door.  So do the withheld pages (:data:`WITHHELD_PANELS`): every page
that renders inputs of its own rather than a released document has no release transform yet
(ADR-0033 decision 8), so it may sit only in the private group, at ``red``.

A view's ``select`` (``sources``/``modules``) narrows its panel.  An external entry links to a
registry service by name; ``optional`` entries whose service is not registered are listed as
unavailable, so an optional tool (an agent dashboard) never makes the hub depend on it.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping, Sequence
from functools import cache
from pathlib import Path
from typing import Any

import yaml

from homelabnext import paths, tlp
from homelabnext._yaml import UniqueKeyLoader
from homelabnext.registry.model import Registry

from . import release
from .model import SEVERITY, STATES, SourceSpec, worst

STATUS_SCHEMA = "homelabnext.status/1"
#: panels that are pages of their own (stage 1b, agent activity), served live by ``hnx status
#: serve``: panel -> path.  The private ones render only for an authorized request.
PAGE_PANELS = {
    "agents": "/agents",
    "activity": "/activity",
    "agent-analytics": "/agent-analytics",
    "agent-detail": "/private/sessions",
    "agent-access-log": "/private/access-log",
    # the strategy pages (homelabnext.strategy.pages), served with ``--strategy DIR``
    "strategy": "/strategy",
    "requirements": "/requirements",
    "objectives": "/objectives",
    "rfis": "/rfis",
    # the guest baseline coverage page (homelabnext.compute.pages), served with ``--guests DIR``
    "baselines": "/baselines",
    # the broker Approvals page (homelabnext.status.approvals), with approvals: in agents.yml
    "approvals": "/approvals",
    # the generated maps (homelabnext.status.maps, ADR-0018): --guests for the topology,
    # --maps ROOT for the other three; also written as <panel>.html by render --private-out
    "topology": "/topology",
    "dataflow": "/dataflow",
    "architecture": "/architecture",
    "roadmap": "/roadmap",
    # the directory pages (homelabnext.status.maps): --maps ROOT; written as <panel>.html too
    "links": "/links",
    "schedule": "/schedule",
    "roster": "/roster",
    "mcp-servers": "/mcp-servers",
    # the Projects page (homelabnext.projects.pages), served with ``--projects DIR``
    "projects": "/projects",
    # the Orchestration page (homelabnext.orchestration.pages), with ``--orchestration DB``
    "orchestration": "/orchestration",
}
STRATEGY_PANELS = frozenset({"strategy", "requirements", "objectives", "rfis"})
MAP_PANELS = frozenset({"topology", "dataflow", "architecture", "roadmap"})
DIRECTORY_PANELS = frozenset({"links", "schedule", "roster", "mcp-servers"})
#: the pages :class:`homelabnext.status.maps.MapSite` serves and ``hnx status render`` writes
GENERATED_PANELS = MAP_PANELS | DIRECTORY_PANELS
PRIVATE_PANELS = frozenset({"agent-detail", "agent-access-log", "approvals"})
PRIVATE_GROUP = "private"
#: the TLP ceiling of each tier (ADR-0033 decision 8): anonymous readers of the public view and
#: its exports are granted ``clear``, the private tier behind the trusted front door ``red``.  A
#: view declares exactly its tier's ceiling: a public one above ``clear`` would show what no
#: grant allows, a private one below ``red`` would promise a filter the private pages do not run
PUBLIC_CEILING = tlp.Label.CLEAR
PRIVATE_CEILING = tlp.Label.RED
#: page panels withheld from the public view: they render inputs of their own (repository
#: files, a guest directory, the orchestration store, the full status document's observations
#: and sessions) and no release transform shapes them yet (ADR-0033 decision 8: a public field
#: with no transform is withdrawn).  Each may sit only in the private group, at ``red``, and is
#: served only through the trusted front door; a public panel outside
#: :data:`homelabnext.status.release.VIEWS` is refused (docs/status.md, "TLP ceilings and
#: release transforms").
WITHHELD_PANELS = (
    frozenset(
        {"strategy", "requirements", "objectives", "rfis", "baselines", "projects", "orchestration"}
    )
    | GENERATED_PANELS
)
#: the routes of the withheld pages, and the maps' shared script: a route that is one of them
#: or below one (``/orchestration/job``) is served only through the trusted front door
WITHHELD_ROUTES = (*sorted(PAGE_PANELS[p] for p in WITHHELD_PANELS), "/static/maps.js")


def withheld_route(route: str) -> bool:
    """Whether ``route`` belongs to a withheld page (:data:`WITHHELD_ROUTES`)."""
    return any(route == r or route.startswith(r + "/") for r in WITHHELD_ROUTES)


#: at most this many sessions go into status.json (worst state first)
MAX_SESSIONS = 200
_ATTENTION_ORDER = {s: -SEVERITY[s] for s in STATES}
_SILENT = {"unknown": "nothing read yet", "stale": "no reading within its staleness window"}


class ViewsError(ValueError):
    def __init__(self, message: str, problems: list[str] | None = None):
        self.problems = list(problems or [])
        super().__init__(message + "".join(f"\n  - {p}" for p in self.problems))


class ViewsUnreadable(ViewsError):
    """The views file cannot be read or parsed: bad input, not invalid views."""


@cache
def _validator():
    import jsonschema

    schema = json.loads(paths.schema_file("status", "views.schema.json").read_text("utf-8"))
    return jsonschema.Draft202012Validator(schema)


def views_problems(
    doc: Any,
    registry: Registry | None = None,
    specs: Sequence[SourceSpec] | None = None,
    releases: release.Releases | None = None,
) -> list[str]:
    """Schema problems, then the cross-references: unique ids, a main panel view, selections that
    name registered sources, external entries that name registered services (unless optional),
    and the TLP ceilings (:func:`ceiling_problems`) against ``releases`` (default: the hub's
    registry, :func:`homelabnext.status.release.registry`)."""
    errs = sorted(_validator().iter_errors(doc), key=lambda e: [str(p) for p in e.absolute_path])
    out = [f"schema: {'/'.join(map(str, e.absolute_path)) or '$'}: {e.message[:200]}" for e in errs]
    if out:
        return out
    ids = [v["id"] for v in doc["menu"]]
    out += [f"menu: duplicate view id {i!r}" for i in sorted({i for i in ids if ids.count(i) > 1})]
    by_id = {v["id"]: v for v in doc["menu"]}
    main = by_id.get(doc["shell"]["main"])
    if main is None or "panel" not in main or main["panel"] in PAGE_PANELS:
        out.append(f"shell.main {doc['shell']['main']!r} is not a panel view in the menu")
    for v in doc["menu"]:
        if v.get("panel") in PAGE_PANELS and v.get("select"):
            out.append(f"view {v['id']}: the {v['panel']} page takes no select")
        in_group = v.get("group") == PRIVATE_GROUP
        if v.get("panel") in PRIVATE_PANELS and not in_group:
            out.append(
                f"view {v['id']}: the {v['panel']} page is private: it sits in the "
                f"{PRIVATE_GROUP!r} group"
            )
        elif in_group and v.get("panel") not in PRIVATE_PANELS | WITHHELD_PANELS:
            out.append(
                f"view {v['id']}: the {PRIVATE_GROUP!r} group holds only the private and the "
                f"withheld pages ({', '.join(sorted(PRIVATE_PANELS | WITHHELD_PANELS))})"
            )
    known_sources = {s.id for s in specs} if specs is not None else None
    known_modules = {s.module for s in specs} if specs is not None else None
    for v in doc["menu"]:
        sel = v.get("select", {})
        if known_sources is not None:
            for s in sel.get("sources", []):
                if s not in known_sources:
                    out.append(f"view {v['id']}: unknown status source {s!r}")
            for m in sel.get("modules", []):
                if m not in (known_modules or set()):
                    out.append(f"view {v['id']}: no source reports module {m!r}")
        if v.get("external"):
            out += _unregistered(f"view {v['id']}: external", v["external"], registry)
    if doc["shell"].get("act_via"):
        out += _unregistered("shell.act_via", doc["shell"]["act_via"], registry)
    return out + ceiling_problems(doc, releases)


def ceiling_problems(doc: Mapping[str, Any], releases: release.Releases | None = None) -> list[str]:
    """ADR-0033 decision 6 for the hub: every menu entry and every export declares a TLP ceiling
    (``tlp``, a canonical label; the schema refuses any other spelling), a public one ``clear``
    and a private one ``red``, and every public export and every public view whose data the hub
    releases is served by a release transform whose output its ceiling allows.  Where the hub is
    reachable from never enters into it: a reachable name, address or front door raises no
    ceiling; only the private tier's grant does, and only for the private group."""
    if releases is None:
        try:
            releases = release.registry()
        except release.ReleaseError as exc:
            return [str(exc)]
    out: list[str] = []

    def served(where: str, name: str, ceiling: tlp.Label) -> None:
        ts = releases.serving(name)
        if not ts:
            out.append(f"{where}: no release transform serves {name!r}, so it is withdrawn")
        out.extend(
            f"{where}: release transform {t.id} outputs {t.output}, above the ceiling {ceiling}"
            for t in ts
            if not tlp.allows(ceiling, t.output)
        )

    for v in doc["menu"]:
        private = v.get("group") == PRIVATE_GROUP
        want = PRIVATE_CEILING if private else PUBLIC_CEILING
        if "tlp" not in v:
            out.append(f"view {v['id']}: declares no TLP ceiling (tlp: {want})")
            continue
        ceiling = tlp.parse(v["tlp"])
        if ceiling != want:
            tier = "a private view" if private else "a public view"
            out.append(f"view {v['id']}: {tier}'s TLP ceiling is {want}, not {ceiling}")
            continue
        panel = v.get("panel")
        if private or panel is None:
            continue  # an external entry is a menu link: its fields are the status document's
        if panel in release.VIEWS:
            served(f"view {v['id']}", panel, ceiling)
        else:  # a withheld page shown publicly would carry lab data with no transform
            out.append(
                f"view {v['id']}: the {panel} panel has no release transform, so it is "
                f"withdrawn from the public view: put it in the {PRIVATE_GROUP!r} group (tlp: red)"
            )
    exports = doc.get("exports") or {}
    for name in release.EXPORTS:
        if name not in exports:
            out.append(f"exports.{name}: declares no TLP ceiling (tlp: {PUBLIC_CEILING})")
            continue
        ceiling = tlp.parse(exports[name]["tlp"])
        if ceiling != PUBLIC_CEILING:
            out.append(f"exports.{name}: a public export's TLP ceiling is clear, not {ceiling}")
            continue
        served(f"exports.{name}", name, ceiling)
    return out


def _unregistered(where: str, ref: Mapping[str, Any], registry: Registry | None) -> list[str]:
    if registry is None or ref["service"] in registry.services or ref.get("optional"):
        return []
    return [f"{where} service {ref['service']!r} is not registered"]


def load_views(
    path: str | Path,
    registry: Registry | None = None,
    specs: Sequence[SourceSpec] | None = None,
    releases: release.Releases | None = None,
) -> dict[str, Any]:
    try:
        doc = yaml.load(Path(path).read_text(encoding="utf-8"), Loader=UniqueKeyLoader)
    except (OSError, yaml.YAMLError) as exc:
        raise ViewsUnreadable(f"cannot read views {path}: {exc}") from None
    problems = views_problems(doc, registry, specs, releases)
    if problems:
        raise ViewsError(f"invalid views {path}", problems)
    return doc


def service_href(registry: Registry, ref: Mapping[str, Any]) -> str | None:
    """The link for a registry service: its public hostname, else its capability alias.  Built
    from the registry, so the views never hold an address."""
    svc = registry.services.get(ref["service"])
    if svc is None:
        return None
    path = ref.get("path", "/")
    if svc.public_hostname:
        return f"https://{svc.public_hostname}{path}"
    return f"{svc.scheme}://{registry.alias(svc.capability)}:{svc.port}{path}"


def _counts(rows: Sequence[Mapping[str, Any]]) -> dict[str, int]:
    out = dict.fromkeys(STATES, 0)
    for r in rows:
        out[r["state"]] += 1
    return {"total": len(rows), **out}


def _attention_key(r: Mapping[str, Any]) -> tuple:
    return (
        _ATTENTION_ORDER[r["state"]],
        r.get("module", ""),
        r.get("source", ""),
        r.get("item", ""),
    )


def _modules(
    specs: Sequence[SourceSpec],
    obs: Sequence[Mapping[str, Any]],
    sources: Sequence[Mapping[str, Any]],
    capability_pages: set[str],
) -> list[dict[str, Any]]:
    src_state = {s["id"]: s["state"] for s in sources}
    owner: dict[str, SourceSpec] = {}
    for s in specs:
        owner.setdefault(s.module, s)
    names = sorted({s.module for s in specs} | {o["module"] for o in obs})
    out = []
    for m in names:
        items = sorted((o for o in obs if o["module"] == m), key=lambda o: (o["source"], o["item"]))
        mine = [s.id for s in specs if s.module == m]
        silent = [src_state[i] for i in mine if not any(o["source"] == i for o in items)]
        state = worst([o["state"] for o in items] + silent)
        spec = owner.get(m)
        links: dict[str, str] = {}
        if spec is not None:
            links = {
                "service": f"svc:{spec.service}",
                "capability": f"cap:{spec.capability}",
                "page": f"docs/systems/{spec.service}.md",
                "sources": "docs/status/sources.md",
            }
            if spec.capability in capability_pages:
                links["contract"] = f"docs/capabilities/{spec.capability}.md"
        out.append(
            {
                "module": m,
                "state": state,
                "counts": _counts(items),
                "service": spec.service if spec else None,
                "capability": spec.capability if spec else None,
                "sources": mine,
                "links": links,
                "items": items,
            }
        )
    return out


def _selected(view: Mapping[str, Any], row: Mapping[str, Any], *, source_key: str) -> bool:
    sel = view.get("select") or {}
    if "sources" in sel and row.get(source_key) not in sel["sources"]:
        return False
    return not ("modules" in sel and row.get("module") not in sel["modules"])


def _panel(
    view: Mapping[str, Any],
    obs: Sequence[Mapping[str, Any]],
    sources: Sequence[Mapping[str, Any]],
    modules: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    o = [r for r in obs if _selected(view, r, source_key="source")]
    s = [r for r in sources if _selected(view, r, source_key="id")]
    panel = view["panel"]
    if panel == "exceptions":
        reporting = {r["source"] for r in o}
        attention = [r for r in o if r["state"] != "ok"]
        attention += [
            {"source": r["id"], "module": r["module"], "item": "_source", "state": r["state"],
             "summary": r["error"] or _SILENT.get(r["state"], f"source {r['state']}"),
             "link": f"status:{r['id']}"}
            for r in s
            if r["state"] != "ok" and r["id"] not in reporting
        ]  # fmt: skip
        live = [r for r in o if r.get("work") and r.get("value")]
        return {
            "panel": panel,
            "ok": sum(1 for r in o if r["state"] == "ok"),
            "total": len(o),
            "live": sorted(live, key=lambda r: (r["module"], r["item"])),
            "attention": sorted(attention, key=_attention_key),
        }
    if panel == "grid":
        sel = view.get("select") or {}
        mods = []
        for m in modules:
            if "modules" in sel and m["module"] not in sel["modules"]:
                continue
            if "sources" in sel and not set(m["sources"]) & set(sel["sources"]):
                continue
            items = [i for i in m["items"] if _selected(view, i, source_key="source")]
            mods.append({**m, "items": items})
        return {"panel": panel, "modules": mods}
    return {"panel": panel, "sources": s}


def _page_available(
    panel: str,
    *,
    agents: Any,
    strategy: bool,
    baselines: bool,
    approvals: bool,
    maps: frozenset[str] = frozenset(),
    projects: bool = False,
    orchestration: bool = False,
) -> bool:
    if panel in GENERATED_PANELS:
        return panel in maps
    if panel in STRATEGY_PANELS:
        return strategy
    if panel == "baselines":
        return baselines
    if panel == "approvals":
        return approvals
    if panel == "projects":
        return projects
    if panel == "orchestration":
        return orchestration
    return agents is not None


def build_status(
    snapshot: Mapping[str, Any],
    views: Mapping[str, Any],
    registry: Registry,
    specs: Sequence[SourceSpec],
    *,
    capability_pages: set[str] | None = None,
    agents: Mapping[str, Any] | None = None,
    strategy: bool = False,
    baselines: bool = False,
    approvals: bool = False,
    maps: Iterable[str] = (),
    projects: bool = False,
    orchestration: bool = False,
) -> dict[str, Any]:
    """The ``status.json`` document (see the module docstring).  ``agents``: the summary tier's
    sessions (``{"sessions", "counts"}``) when an activity store is configured, else None.
    ``strategy``: the strategy pages are served (a strategy directory is configured);
    ``baselines``: the Baselines page is served (a guest directory is configured);
    ``approvals``: the Approvals page is served (``agents.yml`` configures it);
    ``maps``: the map and directory panels whose inputs are configured (:mod:`homelabnext.status.maps`);
    ``projects``: the Projects page is served (a projects directory is configured);
    ``orchestration``: the Orchestration page is served (a telemetry store is configured)."""
    if capability_pages is None:
        from homelabnext.conform.registry import CAPABILITIES

        capability_pages = set(CAPABILITIES)
    obs = [dict(o) for o in snapshot["observations"]]
    sources = [dict(s) for s in snapshot["sources"]]
    modules = _modules(specs, obs, sources, capability_pages)
    menu, panels = [], {}
    served_maps = frozenset(maps)
    for v in views["menu"]:
        if v.get("panel") in PAGE_PANELS:
            entry = {
                "id": v["id"],
                "title": v["title"],
                "kind": "page",
                "panel": v["panel"],
                "href": PAGE_PANELS[v["panel"]],
                "available": _page_available(
                    v["panel"],
                    agents=agents,
                    strategy=strategy,
                    baselines=baselines,
                    approvals=approvals,
                    maps=served_maps,
                    projects=projects,
                    orchestration=orchestration,
                ),
            }
            if v.get("group"):
                entry["group"] = v["group"]
            menu.append(entry)
        elif "panel" in v:
            menu.append(
                {
                    "id": v["id"],
                    "title": v["title"],
                    "kind": "panel",
                    "panel": v["panel"],
                    "available": True,
                }
            )
            panels[v["id"]] = _panel(v, obs, sources, modules)
        else:
            href = service_href(registry, v["external"])
            menu.append(
                {
                    "id": v["id"],
                    "title": v["title"],
                    "kind": "external",
                    "service": v["external"]["service"],
                    "href": href,
                    "available": href is not None,
                }
            )
    act = views["shell"].get("act_via")
    return {
        "schema": STATUS_SCHEMA,
        "generated_at": snapshot["now"],
        "title": views["shell"]["title"],
        "main": views["shell"]["main"],
        "act_via": service_href(registry, act) if act else None,
        "summary": _counts(obs),
        "menu": menu,
        "views": panels,
        "modules": modules,
        "sources": sources,
        "observations": obs,
        "agents": None
        if agents is None
        else {
            "counts": dict(agents["counts"]),
            "sessions": [dict(r) for r in agents["sessions"][:MAX_SESSIONS]],
        },
    }


def public_status(
    doc: Mapping[str, Any], releases: release.Releases | None = None, *, contract: bool = False
) -> dict[str, Any]:
    """The public view of a status document: the document through its release transform
    (ADR-0033 decision 7), so only the fields the transform keeps leave.  ``contract``: the
    ``status.json`` export, which also never lists the private menu group (the page lists it
    only for a request through the trusted front door).  ``ReleaseError`` when the transform is
    missing or its output carries an unlisted field (fail closed)."""
    releases = release.registry() if releases is None else releases
    out = releases.release(release.STATUS_PUBLIC, "status.json", doc)
    if contract:
        out["menu"] = [m for m in out.get("menu", []) if m.get("group") != PRIVATE_GROUP]
    return out


def dumps(doc: Mapping[str, Any]) -> str:
    """The canonical text of a status document (sorted keys: deterministic)."""
    return json.dumps(doc, indent=1, sort_keys=True, ensure_ascii=False) + "\n"
