---
summary: Service roles ship argument specs and six tagged task sets; inventory capability groups are what playbooks target, never host names.
summary_of: outline:sha256:b3d0e1b40715040f
---
# ADR-0004: Roles declare an interface and inventory groups are capabilities

- **Status:** proposed
- **Date:** 2026-10-15
- **Related:** ADR-0002, ADR-0005, ADR-0008, `docs/role-interface.md`
- **Amended:** 2026-11-07 by ADR-0040 (decision 1): the `backup` and `restore` hooks of decision 1
  take the declared method of the module's `recovery` entry, the backup manifest names every named
  volume and bind source the role mounts, and role interface 1.1 gains an `import` hook
- **Amended-by:** ADR-0040

## Context

Automation roles accumulate hard-coded addresses in their defaults, and inventory groups
describe placement (which box) rather than capability (which job). "Where does the query engine
live" is then a role name, not a group, and role drift is detected only by accident.

## Decision

1. Every service role ships `meta/argument_specs.yml` (inputs, types, defaults) and six tagged
   task sets: `health`, `readiness`, `backup`, `restore`, `upgrade`, `export`. A role without them
   does not deploy.
2. Inventory has capability groups (`cap_siem`, `cap_lake`, `cap_query`, `cap_inference`,
   `cap_edge`, `cap_idp`, `cap_secrets`, `cap_orchestration`, `cap_broker`, `cap_cases`,
   `cap_tip`, `cap_monitoring`, and more as capabilities are added: the list is open-ended);
   playbooks target groups, never host names.
3. Roles take endpoints from the registry (ADR-0002), never from their own defaults.
4. A shared `compose_app` role carries the common container pattern.
5. A scheduled check-mode run of every service role is an invariant; a non-empty diff is red.
6. `tools/role_lint.py` enforces points 1 and 3 in CI.

## Consequences

- Moving a capability between hosts is a group-membership change.
- Adopted as roles are touched, not as a separate rewrite.

## Alternatives

Keep roles as they are and rely on documentation: that is the status quo that produced embedded
addresses in the first place.
