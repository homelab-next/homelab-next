# schemas/platform

| Schema | What |
|---|---|
| `model_roles.json` (1.2) | alias table: `mdl:<alias>` -> tier + bindings (`svc:` backend, model id) + fallback. Consumers name only the alias. 1.2 adds a per-binding pin (`version`, `digest: sha256:<hex>`; `hnx golden pins check` requires both and a current evaluation report, G-11) and per-role `limits` (requests, tokens, cost per window; `homelabnext.registry.limits`, G-10) |
| `capability.schema.json` | descriptor for a `cap:` seam: layer 1..13, contract `$id`s, conformance path, readiness flags, implementations |
| `role_interface.schema.json` | what a deployable role provides/requires, its `svc:` id and the five hooks `deploy health readiness backup export` (tags + idempotency); UTC-only schedules |
| `agent_profile.schema.json` | compiled least-privilege agent profile; `mcp` must be a subset of `mcp_ceiling` (`check_profile_ceiling`); model is a role alias; hard budgets |
| `broker_action.schema.json` | one allowlisted broker action (default deny); `execute`/`privileged` tiers require approval; audit always on |
| `site.schema.json` | the site/network model: zones (VLAN, subnet, DHCP, egress), router and switches, firewall policy between zones, DNS; secrets and endpoints by reference only (`secret:`, `svc:`). Consumed by `homelabnext.network` |
| `guest.schema.json` | one guest (VM, container or host): `guest:` id, placement, resources, image, cloud-init, network zone and address, `cap:` capability, backup policy, lifecycle; 1.3 adds `baseline` (named defense baselines, per-guest `add`/`remove`, or a documented `exemption`). Consumed by `homelabnext.compute` |
| `baseline_set.schema.json` | the guest baseline set (`_baselines.yml` beside the guest files, ADR-0016): a catalogue of product-neutral defense `controls` (one layer each of identity, host, network, detection, data, recovery; a `verify` observable; the Ansible `role` that implements it, `null` until a product is chosen) and named `baselines` of controls that may `extends` others; 1.1 adds a control's `apply` (`guest`, or `central` on the product host's `group`, ADR-0016 decision 7). Consumed by `homelabnext.compute.baselines` |
| `customization.schema.json` | a lab or vendor customization: kind (profile, patch-overlay, role override, hook, registry patch), scope as logical ids, mandatory `reason`, `owner`, `review_by` and `upstream` status. Consumed by `homelabnext.customization` and invariant X-09 |
| `swap_record.schema.json` | the persisted state of one capability swap: nine procedure steps with gates and evidence, hash-chained transition log, route before/after the flip, rollback or closure. Written by `hnx swap`; semantic checks in `homelabnext.swap.record` |
| `script_header.schema.json` | the `# hnx-script:` header every script carries: id, kind (`check`, `tool`, `job`, `service`), purpose, owner, triggers, inputs, outputs, exit-code contract, and the invariants a check runs under. Consumed by `homelabnext.scripts` (`hnx scripts`, checklist M-01, M-02, M-04; docs/scripts.md) |

`service.json` (the service-registry row, 2.1 adds `status_sources`: what the status hub may poll or receive, by registry name, ADR-0013) is owned by the registry task and lives in this directory;
it is not part of this task's checks. Backends and services are always `svc:` ids, never URLs.
