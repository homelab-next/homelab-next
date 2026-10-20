# ADR-0016: Guest baselines and defense layers

- **Status:** proposed
- **Date:** 2026-10-20
- **Related:** ADR-0001, ADR-0004, ADR-0012, ADR-0013, `docs/compute-model.md`,
  `schemas/platform/baseline_set.schema.json`, `schemas/platform/guest.schema.json` (1.3),
  `homelabnext/compute/baselines.py`

## Context

Every guest needs defenses (an endpoint agent for the SIEM, log forwarding, a vulnerability scan,
a host firewall, hardened SSH, backups that are restored in drills), and which ones it needs
depends on what it is: an edge-facing proxy needs more than a scratch lab VM. Kept as habit, the
list drifts: a guest created in a hurry gets none of them and nothing notices. At the same time
the products are not chosen yet (which SIEM agent, which network sensor, which scanner, which
remote-access gateway), and choosing them must not mean editing every guest file, or the guest
model would encode a product (against the swap discipline of ADR-0004 and ADR-0005).

## Decision

1. A **baseline set** (`_baselines.yml` beside the guest files, `baseline_set.schema.json` 1.0)
   holds a catalogue of generic **controls** and named **baselines** of controls. A baseline may
   `extends` others; resolution is a deterministic union (parents first, listed order, deduped).
2. Every control sits in exactly one **defense layer** from a closed set: identity, host, network,
   detection, data, recovery. Each carries a `verify` line, the observable that proves it is in
   place.
3. **Products are bound per control, in one place**: the control's `role`, the Ansible role that
   implements it, or `null` while no product is chosen. The inventory gains `baseline_<name>` and
   `control_<id>` groups; the `baseline-playbook` target applies each bound role to its
   `control_<id>` group and lists every unbound control as a commented block naming the guests
   that wait for it, never dropping one. Choosing a product is a one-line change to the set.
4. A guest declares `baseline.names` (guest schema 1.3, additive), optionally `add` and `remove`
   (each removal with a reason), or a `baseline.exemption` with a reason and review date, which
   mirrors `network.firewall_exemption`.
5. **When a baseline set exists, every guest (vm, lxc and physical host) must declare a baseline
   or an exemption**; `hnx guests validate` fails otherwise. Without a set nothing is required.
   The set is checked for unknown names, missing `extends` targets, cycles and baselines that
   resolve to nothing.
6. `hnx guests baselines` prints the guest x layer coverage matrix (`--json`, `--check`,
   `--require-bound`), and the status hub serves it as the Baselines page.

## Consequences

Creating a guest without deciding its defenses is no longer possible once a lab has a set, and
an opt-out is a reviewed line with a reason rather than an omission. The coverage matrix shows
which rings of defense each guest has before any product is installed, and `--require-bound`
turns "we have not picked a SIEM agent yet" into a visible, checkable gap. Binding a product
touches one file and re-renders the playbook; swapping it later is the same edit.

It obliges us to keep the control catalogue generic (a control names a function, never a
product) and to keep `verify` lines honest; the model does not run them. The requirement is
conditional on the set existing, so a lab that never writes one gets no baseline enforcement:
this is deliberate, because a pre-1.3 tree must stay valid (ADR-0001's additive evolution), and
a missing set is visible to `hnx guests baselines --check`, which fails without one.

## Alternatives

- **Products in the guest file** (for example `siem: product-x`): every product choice or swap
  would touch every guest, and the guest model would stop being vendor-neutral.
- **Baselines from tags or capability groups**: implicit; a guest with the wrong tag silently
  gets fewer defenses, and there is no place to record why a guest is exempt.
- **Making `baseline` required in the schema**: breaks every existing tree (not additive) and
  cannot express "required only when a set defines what baselines exist".
- **Open-ended layers**: a free-text layer drifts into synonyms, and the coverage matrix would
  stop being comparable between guests and labs.
