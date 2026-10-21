# ADR-0018: Generate the lab's maps from its models

- **Status:** proposed
- **Date:** 2026-10-21
- **Related:** ADR-0013 (status hub), ADR-0016 (guest baselines), `docs/status.md` ("Generated
  maps"), `homelabnext/status/maps/`, `schemas/status/views.schema.json` (1.5),
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
   internet egress), the zone-to-zone flows as the network IR evaluates them, and the guest model.
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
   writes them as static files. Diagrams are server-rendered inline SVG: no script, no `style`
   attribute (the CSP pins one stylesheet by hash, which themes the SVG for light and dark), a
   `title` and `desc` for assistive technology, and a table with the same facts under every
   picture. Every value is escaped.
5. A map whose inputs are not configured is listed as unavailable; a source that cannot be read
   puts an error line on the page, never a partial picture.

## Consequences

- The maps are as current as the models: changing a guest, a pack or a checklist row changes the
  picture on the next request (dataflow and architecture: the next process), with no regeneration
  step to forget.
- **What is not shown, deliberately.** Anything the repository does not declare: who writes each
  OCSF lake table and who reads the object store (drawn as "no writer declared" / "no reader
  declared", never guessed); consumers of an event type outside the scanned code and packs;
  `service_exceptions` (host-to-service firewall exceptions are not zone flows); live state of
  any service (that is the hub's other pages); dynamic dispatch the AST scan cannot follow (an
  event type built from a variable). The contract samples' `source` values are drawn dashed as
  samples, not as deployed producers.
- The layout is simple on purpose (rows, lanes and matrices rather than a force-directed graph)
  so it stays legible and deterministic without a layout engine; very large labs scroll.
- `docs/build-order.md` gains a column to maintain, enforced by a test.

## Alternatives

- **Hand-drawn diagrams in the docs** (draw.io, Mermaid source): drift silently, which is the
  problem this ADR exists to solve.
- **Client-side rendering** (Mermaid, D3): needs script, which the hub's CSP forbids and which a
  read-only console should not need.
- **Committed generated SVGs in `docs/`** with a staleness gate: possible later, but every
  change to a guest, pack or checklist row would then need a regeneration commit, and the roadmap
  depends on a results file that is not in git.
- **A full graph layout engine** (Graphviz): a new system dependency for pictures that read better
  as lanes and matrices.
