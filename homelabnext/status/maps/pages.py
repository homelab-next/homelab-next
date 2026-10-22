# SPDX-License-Identifier: Apache-2.0
"""The generated pages of the status hub: the maps ``/topology``, ``/dataflow``, ``/architecture``,
``/roadmap`` and the directory pages ``/links``, ``/schedule``, ``/roster``.

``hnx status serve`` routes them (``--guests DIR --guests-site SITE`` for the topology, ``--maps
ROOT`` for the rest, ``--invariants-results FILE`` for the roadmap's live state, ``--roster FILE``
for the roster, default ``ROOT/examples/status/roster.yml``) and
``hnx status render`` writes them beside ``index.html`` as ``<panel>.html``.  Each page is built
from the repository's own models on request (the dataflow and architecture, which only change
with the code, once per process); a source that cannot be read gives the page an error line,
escaped, instead of a half-drawn map.  Nothing here changes anything.

The Topology and Dataflow pages are interactive (:mod:`.assets`): served live they get their own
CSP (``script-src 'self'``) and the shared script at :data:`.assets.SCRIPT_ROUTE`; written, the
script is inline under a hash-pinned CSP meta.  ``lab_registry`` (``hnx status serve
--guests-registry FILE``) is the registry that places services on the guests; it defaults to the
hub's own.
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

import yaml

from homelabnext.status.render import _e, nav_html, shell_html

from . import assets

__all__ = ["MAP_ROUTES", "TITLES", "MapSite"]

Response = tuple[int, str, bytes] | tuple[int, str, bytes, dict[str, str]]
HTML = "text/html; charset=utf-8"
MAP_ROUTES = {
    "/topology": "topology",
    "/dataflow": "dataflow",
    "/architecture": "architecture",
    "/roadmap": "roadmap",
    "/links": "links",
    "/schedule": "schedule",
    "/roster": "roster",
}
#: the roster file read under ``--maps ROOT`` when ``--roster`` is not given
DEFAULT_ROSTER = "examples/status/roster.yml"
TITLES = {
    "topology": "Topology",
    "dataflow": "Dataflow",
    "architecture": "Architecture",
    "roadmap": "Roadmap",
    "links": "Links",
    "schedule": "Schedule",
    "roster": "Agent roster",
}
#: what each page is generated from (shown on the page; ADR-0018)
SOURCES = {
    "topology": "the site model (zones, VLANs, gateways, router, switches, firewall), the network "
    "IR's evaluated zone flows, the guest model (status, placement, resources, image, zone, "
    "capability groups, firewall rules) with _nodes.yml, the registry (services per guest) and "
    "the dataflow model's flows",
    "dataflow": "schemas/events and their samples, the code (an AST scan for event types), "
    "workflows/packs, the registry (transports, status sources, upstreams, hosts), schemas/ocsf, "
    "the broker manifest's lanes and, with the guests, their firewall rules and status",
    "architecture": "the knowledge graph's registry, compose and capability readers (the "
    "docs/capabilities/README.md matrix), the broker manifest, workflows/decisions, the safety "
    "specs and workflows/packs",
    "roadmap": "docs/build-order.md (phases, steps, each phase's Checklist cell), "
    "docs/checklist.md (criteria and tags) and the invariants results file",
    "links": "the service registry (zones, hosts, services: public hostname else capability "
    "alias, auth, front door, health and MCP endpoints)",
    "schedule": "the roles' and profiles' .timer units with their defaults, docs/scripts/"
    "catalog.json (timer: triggers), fleet_units specs, .github/workflows schedules, "
    "workflows/packs triggers, the registry's status sources and the hub's state (last runs)",
    "roster": "roster.yml: the compiled agent profiles, the broker manifests (grants, actions, "
    "lanes), workflows/packs actors, the model role table, and the agent-activity tier",
}
_ERRORS = (OSError, ValueError, LookupError, TypeError, yaml.YAMLError)


class MapSite:
    """The map routes over the configured inputs.  ``root``: a checkout (dataflow, architecture,
    roadmap); ``registry``: the hub's loaded registry; ``guests``/``guests_site``: the guest
    directory and its site model (topology); ``results``: an invariants results file."""

    def __init__(
        self,
        *,
        root: str | Path | None = None,
        registry: Any = None,
        guests: str | Path | None = None,
        guests_site: str | Path | None = None,
        results: str | Path | None = None,
        lab_registry: Any = None,
        roster: str | Path | None = None,
    ):
        self.root = Path(root) if root else None
        self.registry = registry
        self.lab = lab_registry if lab_registry is not None else registry
        self.guests, self.guests_site = guests, guests_site
        self.results = results
        self._static: dict[str, str] = {}
        self._dataflow: dict[str, Any] | None = None
        self._schedule: dict[str, Any] | None = None
        if roster:
            self.roster: Path | None = Path(roster)
        elif self.root is not None and (self.root / DEFAULT_ROSTER).is_file():
            self.roster = self.root / DEFAULT_ROSTER
        else:
            self.roster = None

    def available(self) -> frozenset[str]:
        """The map panels this site serves."""
        out = set()
        if self.guests and self.guests_site:
            out.add("topology")
        if self.root is not None:
            out |= {"roadmap", "schedule"}
            if self.registry is not None:
                out |= {"architecture", "links"}
            if self.roster is not None:
                out |= {"roster"}
            if self.lab is not None:
                out |= {"dataflow"}
        return frozenset(out)

    # ---- the pages
    def body(self, panel: str, doc: Mapping[str, Any] | None = None) -> str:
        """The main area of one page (escaped HTML); an unreadable source is an error line.
        ``doc``: the hub's ``status.json`` (the time, the sources' last runs, agent sessions)."""
        title = TITLES[panel]
        head = f'<h2>{_e(title)}</h2><p class="muted">Generated from {_e(SOURCES[panel])}.</p>'
        if panel not in self.available():
            return head + '<p class="s unknown">unavailable: its inputs are not configured</p>'
        try:
            return head + self._render(panel, doc or {})
        except _ERRORS as exc:
            return head + f'<p class="s fail">cannot build the map</p><pre>{_e(exc)}</pre>'

    def _dataflow_vm(self) -> dict[str, Any] | None:
        """The dataflow view-model of the lab registry (built from the code once per process);
        without a checkout, from the registry alone (status sources, upstreams)."""
        from . import dataflow

        if self.lab is None:
            return None
        if self._dataflow is None:
            if self.root is not None:
                self._dataflow = dataflow.build(dataflow.gather(self.root, self.lab))
            else:
                self._dataflow = dataflow.build({"services": dataflow.services_of(self.lab)})
        return self._dataflow

    def _guests(self) -> tuple[Any, list[dict[str, Any]]]:
        """The lab index and the host-level flows (service calls, firewall allows) the Dataflow
        page adds; with no guests configured, the registry's own."""
        from . import topology
        from .lab import Index, host_flows, lab_of

        lab = lab_of(self.lab)
        if not (self.guests and self.guests_site):
            return Index({}, [], lab), []
        from homelabnext.compute.model import ComputeError

        try:
            doc, guests, _, nodes = topology.inputs(self.guests, self.guests_site)
        except ComputeError as exc:
            raise ValueError(str(exc)) from None
        idx = topology.index_for(doc, [g.raw for g in guests], lab, nodes)
        return idx, host_flows(doc, idx)

    def _render(self, panel: str, doc: Mapping[str, Any]) -> str:
        from . import architecture, dataflow, links, roadmap, roster, schedule, topology

        if panel == "links":
            return links.render(links.build(self.registry))
        if panel == "schedule":
            if self._schedule is None:  # the checkout's timers and specs: once per process
                self._schedule = schedule.gather(self.root, self.registry)
            return schedule.render(
                schedule.build(
                    self._schedule,
                    now=doc.get("generated_at"),
                    sources=doc.get("sources") or (),
                    observations=doc.get("observations") or (),
                )
            )
        if panel == "roster":
            sessions = (doc.get("agents") or {}).get("sessions") if doc.get("agents") else None
            return roster.render(roster.build(roster.gather(self.roster), sessions))

        if panel == "topology":
            from homelabnext.compute.model import ComputeError

            try:
                vm = topology.load(
                    self.guests, self.guests_site, registry=self.lab, dataflow=self._dataflow_vm()
                )
            except ComputeError as exc:
                raise ValueError(str(exc)) from None
            return topology.render(vm)
        if panel == "dataflow":
            idx, extra = self._guests()
            return dataflow.render(self._dataflow_vm() or {}, idx=idx, extra=extra)
        if panel == "roadmap":
            return roadmap.render(roadmap.load(self.root, self.results))
        if panel not in self._static:  # built from the code: once per process
            graph = architecture.graph_for(self.root)
            control = architecture.gather_control(self.root, self.registry)
            self._static[panel] = architecture.render(architecture.build(graph, control))
        return self._static[panel]

    def page(self, panel: str, doc: Mapping[str, Any], *, live: bool) -> str:
        nav = nav_html(doc, live=live, home=None if live else "index.html")
        if panel not in assets.INTERACTIVE:
            return shell_html(doc, TITLES[panel], self.body(panel, doc), nav=nav)
        return shell_html(
            doc,
            TITLES[panel],
            self.body(panel, doc),
            nav=nav,
            head=assets.head(live=live),
            tail=assets.tail(live=live),
            theme="dark",
        )

    def handle(self, route: str, query: str, doc: Mapping[str, Any]) -> Response | None:
        """The response for a map route this site serves (or the maps' script), or None.  The
        interactive pages carry their own CSP header (:func:`.assets.live_csp`)."""
        if route == assets.SCRIPT_ROUTE and self.available() & assets.INTERACTIVE:
            return 200, assets.JS_TYPE, assets.js().encode("utf-8")
        panel = MAP_ROUTES.get(route)
        if panel is None or panel not in self.available():
            return None
        body = self.page(panel, doc, live=True).encode("utf-8")
        if panel in assets.INTERACTIVE:
            return 200, HTML, body, {"Content-Security-Policy": assets.live_csp()}
        return 200, HTML, body

    def write(self, out: str | Path, doc: Mapping[str, Any]) -> list[Path]:
        """Write every available map as ``<panel>.html`` into ``out``; returns the paths.  The
        interactive ones are self-contained (script and style inline, pinned by hash)."""
        d = Path(out)
        d.mkdir(parents=True, exist_ok=True)
        paths = []
        for panel in sorted(self.available()):
            p = d / f"{panel}.html"
            p.write_text(self.page(panel, doc, live=False), encoding="utf-8")
            paths.append(p)
        return paths
