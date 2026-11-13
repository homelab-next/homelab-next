---
summary: 'Module manifest reference: the slot registry, requires and prefers, footprints, one-owner interfaces and the interchange formats of the SOC bundle.'
summary_of: outline:sha256:82768a5f78f2d5d3
---
<!-- SPDX-License-Identifier: Apache-2.0 -->
# Modules: slots, requirements and interfaces

> Part of [the module manifest](../modules.md) ([[modules]]), the draft for operator review
> ([ADR-0027](../adr/0027-feature-and-provider-modules.md), proposed).

## The slot registry (a draft schema; capability descriptor 1.1 when accepted)

Every slot has a descriptor; `examples/modules/slots.yml` is the draft data for the slots the
examples use, and the contract-test rules read it. The fields and their rules are a draft schema
of their own, `platform/slot` 1.0 (`schemas/platform/slot.schema.json`, `x-draft`): every
`slots.yml` entry validates against it (the loader checks every entry before a rule reads it and
reports one that does not, leaving it out of the registry), each contract names a real protocol
file, and the privileged set is pinned to the six trust roots named below, each with a
conformance suite.
`platform/capability` stays 1.0 until the ADR is accepted: 1.0 allows undeclared keys, so adding
these fields' rules to it would refuse a 1.0 descriptor that happened to carry one, which is not
an additive change. Capability descriptor 1.1 takes them then (a deliberate, documented break, or
2.0). A `stage` slot need not declare `formats` unless it is `pass_through`, which must pass
something (non-empty `in` and `out`). The fields:

| Field | Meaning | What it makes computable |
|---|---|---|
| `contract` | the protocol file, or null; `contracts` may be empty only then | provisional **by declaration**: an undeclared `cap:` is a typo, not a slot |
| `stage` | SOC pipeline stage 1-10, or null (replaces nothing: `layer` stays) | pass-through neighbours |
| `formats: {in, out}` | boundary formats | pass-through is legal only when the selected upstream's out meets the downstream's in |
| `stateful`, `export_formats` | whether providers carry a migration, and in which neutral formats | no fictional migrations for stateless slots (notify, static hosting, edge, inference) |
| `required_in_core` | a site must select a provider, or declare the slot an incumbent ([selection](selection.md#incumbents-slots-served-outside-modules)), or plan it, a warning until its review date ([planned](planned.md)) | a selection cannot silently omit dns or backup |
| `privileged` | secrets, idp, edge (the front door), broker, orchestration, records | never provisional; always a conformance run and the human review tier |
| `pass_through` | the stage may be skipped | |
| `authority` | broker, secrets, idp, edge, remote-admin, mcp-catalog (each that the registry holds) | never in an agent's `needs`; an authority for the site rules; must agree with `homelabnext.modules.authority`, the one list the schema generator and the rules read (the loader refuses a registry that disagrees, either way) |
| `granted_upstream` | broker, idp, remote-admin (each also `authority`) | a service row names it as an upstream only with `grants.upstreams`; agrees with the same list |

`implementations` is **derived** from provider manifests, never listed. `depends_on` (slot to slot)
is subsumed by the providers' and core modules' `requires`.

## `requires:` and `prefers:`

| Key | Entry | Notes |
|---|---|---|
| `capabilities` | `{cap, version, features, formats, instance, provisional, hosts, purpose}` | `version` is required unless `provisional` (then forbidden); provisional is refused where the slot has a contract; `hosts` (optional, the module's own host roles) scopes which roles the [egress policy](egress.md#egress-and-publishing) lets reach the slot, every role when absent |
| `model_roles` | `{role: mdl:<role>, purpose}` | a role alias; the model is bound once, in the site's role table |
| `interfaces` | `{interface, version, cardinality: one\|all, purpose}` | never names the offering module |
| `hosts` | `{role, kind, count, exposure, footprint, guest, roles, purpose}` | by role; `guest: {capability, baselines}` is what the guest under the role must provide, judged when the site's host references a guest record ([selection](selection.md#hosts-that-are-guests)), never on a `kind: external` role; `exposure: internal \| internet-facing \| isolated`; `internet-facing` only on a `kind: external` role or with `grants.internet_facing` |
| `scope` | `{part, purpose}` | a part of the selection's [network scope](network-scope.md#the-network-scope) (`trusted.wan`, `trusted.nets`, `trusted.tooling`, `target`, `exclude.unattended_mutation`, `exclude.offensive`); the module reads those addresses from the selection, never from its own config. `requires` only: a module that reads scope has no fallback for it |

A `prefers` entry names a `fallback`: `behaviour`, optionally a lighter slot `to`, and optionally
`data` overrides. **A dataset bound to a preferred slot moves with the fallback**: a dataset's `via`
names the requirement it lives in, and when the site resolves that slot to its fallback, the
dataset lives in the fallback slot with the override's retention and formats. In the single-box
profile the external data collector's `sessions` falls back from the lake to the hot index with
`retention: {days: 30}` and `jsonl` export: the manifest's retention, export path and topology are
right on exactly the profile the fallback exists for. The loader checks that `fallback.data` names
one of the module's datasets living in that preference, that it has a `to` (the schema), and that
its formats are a subset of the `to` slot's export formats; a service row's `upstreams` follow the
same fallback.

Semantic properties a dependant relies on are contract **features** (`alert-promotes-case`,
`subday-timestamps`), so a dependant can require them and a swap that loses one is blocked.

### Footprint and resources

Each host role carries a `footprint` (`cpu`, `memory_mb`, `disk_gb`, optional `gpu_memory_mb`, and
`resources: [{kind: gpu, exclusive: true}]`). A site sums every footprint placed on a host, times
the role's `count`, **core and provider modules included**, over all four dimensions against the
host's capacity less its headroom. Every resource claim names a kind the host has; an exclusive
claim takes one of the host's named resources (`gpu0`) to itself, so two exclusive users of one
card are refused, and so is a shared user of a card someone holds exclusively. Every selected
module needs a manifest; nothing is exempt.

**Footprints as limits** (follow-up 8, implemented for fleet units and data roots):
`homelabnext.modules.limits.render(site, modules, units)` turns every placement inside the lab into
limits, so an understated footprint starves its own module, not its neighbours. Per placed host it
writes one systemd slice per host role (`hnx-<id_>-<role_>.slice`; `-` is systemd's hierarchy
separator, so in the id and role it is replaced by `_`, the module's roles nest under
`hnx-<id_>.slice`, and no two pairs share a name; two instances of one provider on one host share
the slice, summed): `CPUQuota` is `cpu` times `count` (100 % per core), `MemoryMax` is `memory_mb`
times `count`, `MemoryHigh` is 90 % of it (throttled first, killed at the max) and
`MemorySwapMax=0` (cgroup v2), shared by every unit in the slice. Each of the module's fleet units
(`hnx-<name>.service`) gets a drop-in that runs it in its role's slice; a unit name is bound to its
module id, and a module with units needs exactly one placed role (the unit spec does not name one:
a known limit). A role's own services and containers join their slice with `Slice=`; nothing
confines one that does not. `hnx-module-quota.sh` caps **and reserves** each module's data root
(`/var/lib/hnx-modules/<id>/`) at its disk on that host: a ZFS dataset mounted exactly there gets
that `refquota` and `refreservation`; on any other filesystem an ext4 image of that size, allocated
in full, is mounted there by a generated `.mount` unit, keeping the root's owner and mode. It never
mounts over existing files or a mount it did not make, finishes what a failed run left, carries on
with the next module when one fails, and `--check` reports without changing anything (exit 3 while
a cap is owed). An image cap is not resized in place (move the data out and rerun); a ZFS cap is
set to the new size in place (ZFS refuses a `refquota` below what the dataset uses); `disk_gb: 0`
is no cap.
Roles on `kind: external` hosts are listed, not rendered: those hosts are outside the lab. GPU
memory has no systemd control and stays a placement sum. `hnx modules render` writes these limits
from the overlay's selection (`homelabnext/modules/cli.py`).

## Interfaces: one owner (`platform/interface` 1.0, a draft schema)

An interface is defined **once**, in the owning module's (or a core module's) `interfaces:`: `id`,
`version`, `kind` (`object-prefix | event | lake-table | service`), the item schema (`schema`, a
`.json` JSON Schema in the owner's directory with `$id .../modules/<owner>/<name>/<version>`, or a
shipped `schema_id`; event `$id`s with dots are accepted) and a description. A **provider** of the
interface references it in `provides.interfaces` with `via: {cap, instance, prefix|table|service}`;
the prefix is in the provider's own namespace and the instance is one it requires. Ownership is per
**id**, every version included: the loader refuses a second module defining any version of an id
another module defines, and a reference to a version the owner does not define. The inline
definition is what exists: [`schemas/platform/interface.schema.json`](../../schemas/platform/interface.schema.json)
is the shape of a manifest `interfaces:` entry, published as a draft schema with the examples' two
gate interfaces as its examples. It is generated from the manifest's definition, so it changes with
it until acceptance. No loader reads a standalone interface record yet, the shape names no owner,
and its `schema` path is relative to the owner's module directory: the ownership rules run on
manifests.

**Gate ownership.** A gate interface is owned by the consumer whose gate input the schema is
(`publishable-output` belongs to publishing, `sample-handoff` to the sandbox). The gate module
marks both sides: its consuming `requires` or `prefers` entry carries `gate: true`, and so does its
definition. The rules refuse, per id and every version:

- a module gating on an interface it does not define (another module owns it), and a gated
  interface whose definition lacks `gate: true`;
- a definition marked `gate: true` that its owner does not consume with `gate: true`;
- a gate interface its owner also provides;
- an id marked `gate: true` on some versions only (an id is a gate when any version says so, and
  every version must).

So a producer cannot take over the interface a gate checks: the gate's own entry names it, and the
gate must own it. What is not covered: an interface nobody marks as a gate, and a gate module that
consumes a different interface than it should (both are a change to the gate's own manifest, made
in review). Unselected modules'
manifests are still read for definitions; only selected ones run. The interface kinds
`agent-handoff` and `records-prefix` wait for a real module.

## Interchange formats

| Format | Where it lives today | Used at |
|---|---|---|
| `ocsf` 1.3.0 | [`schemas/ocsf/`](../../schemas/ocsf/README.md) (`x-lake`) | collect, move & shape, store; findings |
| `sigma` | [`detections/sigma/`](../../detections/README.md), `det:` ids | detect |
| `cloudevents` 1.0 | [`schemas/events/envelope.schema.json`](../../schemas/events/envelope.schema.json) | respond (the bus) |
| `action-request` | [`schemas/broker/`](../../schemas/broker/README.md) | act on hosts |
| `s3`, `sql`, `openai-compatible` | the object-store, lake-query and inference contracts | store, inference |
| `markdown-records` | the records lifecycle | understand, findings |
| `stix` 2.1, `sarif` 2.1.0, `ics` (RFC 5545) | **not in the repository yet** | triage, understand, assess; project feeds |

Neutral **export** formats (datasets and stateful slots, several per dataset): `parquet`, `jsonl`,
`csv`, `json`, `markdown-tree`, `object-tree`, `zone-file`, `sigma`, `stix`, `sarif`, `ics`. The list
is a draft enum; each slot descriptor names the subset it exports in.

### The SOC bundle, by pipeline stage

| # | Stage | Slots | Contract today | Boundary format |
|---|---|---|---|---|
| 1 | collect | `siem-source`, sensors | no (provisional) | OCSF events |
| 2 | move & shape | `log-pipeline`; may be **pass-through** | yes, the runtime label ([log pipeline](../log-pipeline.md)) | OCSF in and out |
| 3 | store | `object-store`, `lake-catalog`, `lake-query`; optional `hot-index` | yes; `hot-index` no | S3, SQL |
| 4 | detect | `detections` | yes | Sigma |
| 5 | triage | `fast-classifier`, `ioc-enrichment`, intel lookup | `fast-classifier` yes | STIX indicators |
| 6 | respond | `orchestration`, `cases`, `events`, `broker`; `soar` | yes for the first four | CloudEvents |
| 7 | act on hosts | `remote-admin`, behind the broker's approval | no | action-request |
| 8 | assess | `exposure-management` | no | SARIF or OCSF findings |
| 9 | understand | `threat-intel`, CTI pipeline, deep research; `records` | `records` yes | STIX + Markdown records |
| 10 | share | `static-hosting`, reachable only with the `publish` grant | no | a rendered static site |

A resource-constrained site selects fewer providers, not different modules: one provider fills
several stages (the SIEM suite in single-box), a stage is `pass-through` where the slot registry
allows it and the neighbours' formats meet, a slot is `none` when no selected module requires it,
and `prefers.fallback.to` binds a module to the lighter slot.
