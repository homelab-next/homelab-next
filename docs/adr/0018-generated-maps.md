---
summary: Topology, dataflow, architecture and roadmap pages are generated from the repository models, never drawn by hand.
---
# ADR-0018: Generate the lab's maps from its models

- **Status:** proposed
- **Date:** 2026-10-21
- **Related:** ADR-0013 (status hub), ADR-0016 (guest baselines), `docs/status.md` ("Generated
  maps"), `homelabnext/status/maps/`, `schemas/status/views.schema.json` (1.5),
  `schemas/platform/guest.schema.json` (1.4), `schemas/platform/service.json` (2.4),
  `schemas/platform/site.schema.json` (1.1), `homelabnext/power.py`,
  `docs/build-order.md`, `docs/checklist.md`

## Context

A lab of this size needs four pictures: where things run (topology), how data moves (dataflow),
what implements what (architecture) and how far the build has come (roadmap). Kept by hand, as
diagrams or as pages someone regenerates when they remember, they drift: a guest moves zone, a
workflow starts consuming a new event type, a checklist row is added, and the picture keeps
showing the old lab with full confidence. A wrong map is worse than none, because people act on
it. Everything those pictures show is already declared in the repository: the site model and the
network IR, the guest model, the registry, the event schemas, the workflow packs, the broker
manifest, the knowledge graph's capability readers, the build order and the checklist.

## Decision

1. The four maps are **generated**, never drawn: each is a pure function `build(model) ->
   view-model` and `render(view-model) -> HTML` in `homelabnext/status/maps/`, deterministic
   (same input, same bytes) and pinned by goldens over small synthetic models.
2. **Sources of truth, and only these.** Topology: the site model (zones, VLANs, gateways,
   internet egress, router, switches, service exceptions), the zone-to-zone flows as the network
   IR evaluates them, the guest model with `_nodes.yml`, the registry (which service runs on
   which guest) and the dataflow model's flows.
   Dataflow: the event schemas and their contract samples, an AST scan of the code (a use inside
   `decode_event`/`Consumer` consumes a type, any other use builds one), the workflow packs, the
   registry (which service is the bus, lake, object store and status hub; the status sources;
   upstreams), the OCSF table schemas and the broker manifest's lanes. Architecture: the
   knowledge graph's registry, compose and capability readers (the same reading behind
   `docs/capabilities/README.md`) plus the control-plane files. Roadmap: `docs/build-order.md`
   and `docs/checklist.md`, read by a small tested Markdown table parser, and an invariants
   results file when one is given.
3. The phase-to-criteria mapping lives in `docs/build-order.md` itself, as each phase's
   `Checklist` cell (section letters, ids, ranges), not in code. A test fails when a cell names
   no checklist row or a row is named by no phase.
4. The hub serves them as pages (menu group `maps`, views schema 1.5) and `hnx status render`
   writes them as static files. Architecture and Roadmap are server-rendered inline SVG: no
   script, no `style` attribute (the CSP pins one stylesheet by hash, which themes the SVG for
   light and dark), a `title` and `desc` for assistive technology, and a table with the same
   facts under every picture. Every value is escaped.
5. A map whose inputs are not configured is listed as unavailable; a source that cannot be read
   puts an error line on the page, never a partial picture.
6. **Topology and Dataflow are interactive** (revised after review: the maintainer's own lab
   page is the bar, and a node-by-zone grid of boxes was not a topology). Topology is a canvas of
   cards -- internet, router, switches, hypervisors and physical hosts on top; one collapsible
   lane per zone, split into stacks by the guests' first capability group when it is big -- with
   a detail panel per card (descriptor, what it does, services, IN/OUT flows), a flow overlay of
   curved arrows (planned dashed, a selected card's flows highlighted), a filter, pan and zoom,
   tooltips, and a dark theme with the hub's light one on a toggle. Dataflow is one collapsible
   group of producer -> carries -> consumer rows per transport, each row graded live, planned,
   gap or sample, with the services placed on their guests, plus the registry's service calls
   and the guests' firewall allows. Both share one host-level flow model
   (`homelabnext/status/maps/lab.py`) and one script and stylesheet.
7. **The script is held to the CSP, not exempted from it.** One packaged file
   (`maps/static/maps.js`), served from `/static/maps.js` under a CSP sent on these two routes
   only (`script-src 'self'`, styles by hash), or inlined in the written page under a CSP meta
   that pins it and the styles by sha256. No inline handler, no `eval`, no font or CDN. Data
   travels as `<script type="application/json">` with `<`, `>` and `&` as JSON escapes and
   reaches the DOM through `textContent` only. The cards, rows and tables are server-rendered and
   escaped, so the page reads without script. A browser test drives both pages with hostile
   names and fails on a console error or a CSP violation.
8. **What the guest and registry models gained** (additive, frozen): guest 1.4 `status`
   (`planned | live | retired`, default `live`) and a one-line `description`; service 2.4 a
   one-line `description`. Informational only: no generator reads them.
9. **Power is part of the topology** (added after review). The site model (1.1) lists its UPSes
   and the uplink chain (`edge`: internet, modem, router, ...); every router, switch, edge device,
   hypervisor and physical host says which UPS feeds it, or `none` with a reason, or takes the
   site's default; a VM inherits its hypervisor's. The rules are one module
   (`homelabnext/power.py`) checked by `hnx site validate` and `hnx guests validate`; the map
   draws the chain from the data, UPS cards with what they feed, a power badge per device and
   the inherited power in a guest's detail. A live UPS reading (NUT) is a later status source;
   it is now `poll-nut` ([status hub](../status.md#8-ups-power-network-ups-tools)), and a UPS
   card shows the hub's reading as a state badge, read from `status.json` like any page.

## Consequences

- The maps are as current as the models: changing a guest, a pack or a checklist row changes the
  picture on the next request (dataflow and architecture: the next process), with no regeneration
  step to forget.
- **What is not shown, deliberately.** Anything the repository does not declare: who writes each
  OCSF lake table and who reads the object store (drawn as "no writer declared" / "no reader
  declared", never guessed); consumers of an event type outside the scanned code and packs;
  live state of any service (that is the hub's other pages); dynamic dispatch the AST scan cannot follow (an
  event type built from a variable). The contract samples' `source` values are drawn dashed as
  samples, not as deployed producers.
- The layout is simple on purpose (cards in lanes, rows and matrices rather than a
  force-directed graph) so it stays legible and deterministic without a layout engine; very large
  labs pan and zoom (Topology) or scroll.
- Topology and Dataflow need a script; the rest of the hub does not. The script is one reviewed
  file under a per-route CSP, and the pages stay readable without it, so the console's
  read-only, script-free default holds everywhere else.
- A flow is only as good as what the repository declares: an arrow means a declared upstream,
  event hop or firewall allow, not observed traffic. Code and workflow ends of a dataflow flow
  have no host, so they stay on the Dataflow page and never become arrows.
- `docs/build-order.md` gains a column to maintain, enforced by a test.

## Alternatives

- **Hand-drawn diagrams in the docs** (draw.io, Mermaid source): drift silently, which is the
  problem this ADR exists to solve.
- **Client-side rendering** (Mermaid, D3): a third-party library and data-driven markup; the two
  interactive maps instead render everything on the server and keep a small reviewed script for
  interaction only.
- **Keeping Topology script-free** (the first version: nodes as rows, zones as columns): rejected
  in review as not a topology -- no top cluster, no stacks, no detail, no flows between hosts.
- **Committed generated SVGs in `docs/`** with a staleness gate: possible later, but every
  change to a guest, pack or checklist row would then need a regeneration commit, and the roadmap
  depends on a results file that is not in git.
- **A full graph layout engine** (Graphviz): a new system dependency for pictures that read better
  as lanes and matrices.
