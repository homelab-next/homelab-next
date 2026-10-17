# schemas/agent

Contracts for the agent layer (library: `homelabnext.agent`, guide: `docs/agent.md`).

| Schema | What it is |
|---|---|
| `profile` | a **compiled** profile: parts by logical id, grants, the permission ceiling they were checked against, hard budgets, digest, provenance |
| `context_manifest` | what goes into one agent's context pack and in which tier order (stable, session, volatile); pre-gates; memory scopes |
| `pregate_output` | the verdict of a mandatory pre-run check (`ok`, `degraded`, `stale`, `failed`) |
| `report_result` | what an agent hands back: `pack_id`, cites, unknowns, memory updates |
| `golden_task` | the existing `homelabnext.golden` suite file format, described unchanged (the loader and this schema reject the same negatives) |

`platform/agent_profile` is the lean runtime view of a profile; `agent/profile` is the compiler's
output and carries everything needed to audit it.

Rules JSON Schema cannot express are enforced in code and tested: grants subset of ceiling
(`homelabnext.agent.check_ceiling`), digest equals content (`verify_profile`), unique task ids
(the golden loader), `pack_id` equals the pack hash and must-cite coverage (`validate_report`).
