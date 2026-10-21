# SPDX-License-Identifier: Apache-2.0
"""The map pages of the status hub: ``/topology``, ``/dataflow``, ``/architecture``, ``/roadmap``.

``hnx status serve`` routes them (``--guests DIR --guests-site SITE`` for the topology, ``--maps
ROOT`` for the other three, ``--invariants-results FILE`` for the roadmap's live state) and
``hnx status render`` writes them beside ``index.html`` as ``<panel>.html``.  Each page is built
from the repository's own models on request (the dataflow and architecture, which only change
with the code, once per process); a source that cannot be read gives the page an error line,
escaped, instead of a half-drawn map.  Nothing here changes anything.
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

import yaml

from homelabnext.status.render import _e, nav_html, shell_html

__all__ = ["MAP_ROUTES", "TITLES", "MapSite"]

Response = tuple[int, str, bytes]
HTML = "text/html; charset=utf-8"
MAP_ROUTES = {
    "/topology": "topology",
    "/dataflow": "dataflow",
    "/architecture": "architecture",
    "/roadmap": "roadmap",
}
TITLES = {
    "topology": "Topology",
    "dataflow": "Dataflow",
    "architecture": "Architecture",
    "roadmap": "Roadmap",
}
#: what each page is generated from (shown on the page; ADR-0018)
SOURCES = {
    "topology": "the site model (zones, VLANs, gateways), the network IR's evaluated zone flows "
    "and the guest model (node, zone, address, capability, baselines)",
    "dataflow": "schemas/events and their samples, the code (an AST scan for event types), "
    "workflows/packs, the registry (transports, status sources, upstreams), schemas/ocsf and "
    "the broker manifest's lanes",
    "architecture": "the knowledge graph's registry, compose and capability readers (the "
    "docs/capabilities/README.md matrix), the broker manifest, workflows/decisions, the safety "
    "specs and workflows/packs",
    "roadmap": "docs/build-order.md (phases, steps, each phase's Checklist cell), "
    "docs/checklist.md (criteria and tags) and the invariants results file",
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
    ):
        self.root = Path(root) if root else None
        self.registry = registry
        self.guests, self.guests_site = guests, guests_site
        self.results = results
        self._static: dict[str, str] = {}

    def available(self) -> frozenset[str]:
        """The map panels this site serves."""
        out = set()
        if self.guests and self.guests_site:
            out.add("topology")
        if self.root is not None:
            out |= {"roadmap"}
            if self.registry is not None:
                out |= {"dataflow", "architecture"}
        return frozenset(out)

    # ---- the pages
    def body(self, panel: str) -> str:
        """The main area of one map page (escaped HTML); an unreadable source is an error line."""
        title = TITLES[panel]
        head = f'<h2>{_e(title)}</h2><p class="muted">Generated from {_e(SOURCES[panel])}.</p>'
        if panel not in self.available():
            return head + '<p class="s unknown">unavailable: its inputs are not configured</p>'
        try:
            return head + self._render(panel)
        except _ERRORS as exc:
            return head + f'<p class="s fail">cannot build the map</p><pre>{_e(exc)}</pre>'

    def _render(self, panel: str) -> str:
        from . import architecture, dataflow, roadmap, topology

        if panel == "topology":
            from homelabnext.compute.model import ComputeError

            try:
                return topology.render(topology.load(self.guests, self.guests_site))
            except ComputeError as exc:
                raise ValueError(str(exc)) from None
        if panel == "roadmap":
            return roadmap.render(roadmap.load(self.root, self.results))
        if panel not in self._static:  # built from the code: once per process
            if panel == "dataflow":
                vm = dataflow.build(dataflow.gather(self.root, self.registry))
                self._static[panel] = dataflow.render(vm)
            else:
                graph = architecture.graph_for(self.root)
                control = architecture.gather_control(self.root, self.registry)
                self._static[panel] = architecture.render(architecture.build(graph, control))
        return self._static[panel]

    def page(self, panel: str, doc: Mapping[str, Any], *, live: bool) -> str:
        nav = nav_html(doc, live=live, home=None if live else "index.html")
        return shell_html(doc, TITLES[panel], self.body(panel), nav=nav)

    def handle(self, route: str, query: str, doc: Mapping[str, Any]) -> Response | None:
        """The response for a map route this site serves, or None."""
        panel = MAP_ROUTES.get(route)
        if panel is None or panel not in self.available():
            return None
        return 200, HTML, self.page(panel, doc, live=True).encode("utf-8")

    def write(self, out: str | Path, doc: Mapping[str, Any]) -> list[Path]:
        """Write every available map as ``<panel>.html`` into ``out``; returns the paths."""
        d = Path(out)
        d.mkdir(parents=True, exist_ok=True)
        paths = []
        for panel in sorted(self.available()):
            p = d / f"{panel}.html"
            p.write_text(self.page(panel, doc, live=False), encoding="utf-8")
            paths.append(p)
        return paths
