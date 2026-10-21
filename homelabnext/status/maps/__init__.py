# SPDX-License-Identifier: Apache-2.0
"""Generated maps of the lab for the status hub (ADR-0018, ``docs/status.md``).

Four pages, each GENERATED from models already in the repository, never drawn by hand:

* :mod:`.topology` -- hypervisors and guests by zone, and the allowed zone-to-zone flows
  (site model, network IR, guest model);
* :mod:`.dataflow` -- producer -> transport -> consumer, labelled with the event type, table,
  status source or action (event schemas and their samples, the code, workflow packs, the
  registry, the lake tables, the broker lanes);
* :mod:`.architecture` -- capabilities -> fakes, adapters, products -> services, and the control
  plane (knowledge graph readers, broker manifest, decision specs, workflow packs);
* :mod:`.roadmap` -- the build-order phases with their checklist criteria and live invariant
  state (``docs/build-order.md``, ``docs/checklist.md``, an invariants results file).

Each is ``build(inputs) -> view-model`` (pure, JSON-able) and ``render(view-model) -> HTML``
(inline SVG plus the same facts as tables; no script, no ``style`` attribute, every value
escaped).  :class:`.pages.MapSite` serves them (``hnx status serve``) and writes them as static
files (``hnx status render``).
"""

from .pages import MAP_ROUTES, MapSite

__all__ = ["MAP_ROUTES", "MapSite"]
