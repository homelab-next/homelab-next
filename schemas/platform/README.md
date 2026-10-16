# schemas/platform

| Schema | What |
|---|---|
| `model_roles.json` | alias table: `mdl:<alias>` -> tier + bindings (`svc:` backend, model id) + fallback. Consumers name only the alias |
| `capability.schema.json` | descriptor for a `cap:` seam: layer 1..13, contract `$id`s, conformance path, readiness flags, implementations |
| `role_interface.schema.json` | what a deployable role provides/requires, its `svc:` id and the five hooks `deploy health readiness backup export` (tags + idempotency); UTC-only schedules |
| `agent_profile.schema.json` | compiled least-privilege agent profile; `mcp` must be a subset of `mcp_ceiling` (`check_profile_ceiling`); model is a role alias; hard budgets |
| `broker_action.schema.json` | one allowlisted broker action (default deny); `execute`/`privileged` tiers require approval; audit always on |

`service.json` (the service-registry row) is owned by the registry task and lives in this directory;
it is not part of this task's checks. Backends and services are always `svc:` ids, never URLs.
