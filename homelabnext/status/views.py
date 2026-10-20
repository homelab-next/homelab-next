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
the agent pages (with ``--agents``) and the strategy pages (with ``--strategy``; Strategy,
Requirements, Objectives, RFIs: :mod:`homelabnext.strategy.pages`).  Their menu entries are
``available`` only when that part is configured.

A view's ``select`` (``sources``/``modules``) narrows its panel.  An external entry links to a
registry service by name; ``optional`` entries whose service is not registered are listed as
unavailable, so an optional tool (an agent dashboard) never makes the hub depend on it.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from functools import cache
from pathlib import Path
from typing import Any

import yaml

from homelabnext import paths
from homelabnext._yaml import UniqueKeyLoader
from homelabnext.registry.model import Registry

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
}
STRATEGY_PANELS = frozenset({"strategy", "requirements", "objectives", "rfis"})
PRIVATE_PANELS = frozenset({"agent-detail", "agent-access-log"})
PRIVATE_GROUP = "private"
#: at most this many sessions go into status.json (worst state first)
MAX_SESSIONS = 200
_ATTENTION_ORDER = {s: -SEVERITY[s] for s in STATES}
_SILENT = {"unknown": "nothing read yet", "stale": "no reading within its staleness window"}


class ViewsError(ValueError):
    def __init__(self, message: str, problems: list[str] | None = None):
        self.problems = list(problems or [])
        super().__init__(message + "".join(f"\n  - {p}" for p in self.problems))


@cache
def _validator():
    import jsonschema

    schema = json.loads(paths.schema_file("status", "views.schema.json").read_text("utf-8"))
    return jsonschema.Draft202012Validator(schema)


def views_problems(
    doc: Any, registry: Registry | None = None, specs: Sequence[SourceSpec] | None = None
) -> list[str]:
    """Schema problems, then the cross-references: unique ids, a main panel view, selections that
    name registered sources, external entries that name registered services (unless optional)."""
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
        private = v.get("panel") in PRIVATE_PANELS
        if private != (v.get("group") == PRIVATE_GROUP):
            out.append(
                f"view {v['id']}: the {PRIVATE_GROUP!r} group holds exactly the private pages "
                f"({', '.join(sorted(PRIVATE_PANELS))})"
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
    return out


def _unregistered(where: str, ref: Mapping[str, Any], registry: Registry | None) -> list[str]:
    if registry is None or ref["service"] in registry.services or ref.get("optional"):
        return []
    return [f"{where} service {ref['service']!r} is not registered"]


def load_views(
    path: str | Path, registry: Registry | None = None, specs: Sequence[SourceSpec] | None = None
) -> dict[str, Any]:
    try:
        doc = yaml.load(Path(path).read_text(encoding="utf-8"), Loader=UniqueKeyLoader)
    except (OSError, yaml.YAMLError) as exc:
        raise ViewsError(f"cannot read views {path}: {exc}") from None
    problems = views_problems(doc, registry, specs)
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


def build_status(
    snapshot: Mapping[str, Any],
    views: Mapping[str, Any],
    registry: Registry,
    specs: Sequence[SourceSpec],
    *,
    capability_pages: set[str] | None = None,
    agents: Mapping[str, Any] | None = None,
    strategy: bool = False,
) -> dict[str, Any]:
    """The ``status.json`` document (see the module docstring).  ``agents``: the summary tier's
    sessions (``{"sessions", "counts"}``) when an activity store is configured, else None.
    ``strategy``: the strategy pages are served (a strategy directory is configured)."""
    if capability_pages is None:
        from homelabnext.conform.registry import CAPABILITIES

        capability_pages = set(CAPABILITIES)
    obs = [dict(o) for o in snapshot["observations"]]
    sources = [dict(s) for s in snapshot["sources"]]
    modules = _modules(specs, obs, sources, capability_pages)
    menu, panels = [], {}
    for v in views["menu"]:
        if v.get("panel") in PAGE_PANELS:
            entry = {
                "id": v["id"],
                "title": v["title"],
                "kind": "page",
                "panel": v["panel"],
                "href": PAGE_PANELS[v["panel"]],
                "available": strategy if v["panel"] in STRATEGY_PANELS else agents is not None,
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


def dumps(doc: Mapping[str, Any]) -> str:
    """The canonical text of a status document (sorted keys: deterministic)."""
    return json.dumps(doc, indent=1, sort_keys=True, ensure_ascii=False) + "\n"
