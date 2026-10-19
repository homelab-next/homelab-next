# schemas/agent

Contracts for the agent layer (library: `homelabnext.agent`, guide: `docs/agent.md`).

| Schema | What it is |
|---|---|
| `profile` | a **compiled** profile: parts by logical id, grants, the permission ceiling they were checked against, hard budgets, `reads_untrusted` (1.1), digest, provenance |
| `context_manifest` | what goes into one agent's context pack and in which tier order (stable, session, volatile); pre-gates; memory scopes; `screen` (1.1: redaction of untrusted sections, on by default) |
| `pregate_output` | the verdict of a mandatory pre-run check (`ok`, `degraded`, `stale`, `failed`) |
| `report_result` | what an agent hands back: `pack_id`, cites, unknowns, memory updates |
| `golden_task` | the existing `homelabnext.golden` suite file format, described unchanged (the loader and this schema reject the same negatives) |

`platform/agent_profile` is the lean runtime view of a profile; `agent/profile` is the compiler's
output and carries everything needed to audit it.

Rules JSON Schema cannot express are enforced in code and tested: grants subset of ceiling
(`homelabnext.agent.check_ceiling`; a reader, `reads_untrusted` true or absent, holds no
exec, file-write, egress or credential grant: `homelabnext.agent.readers`; the ceiling that counts is the separately owned
`CeilingPolicy`, not the `ceiling` copied into the profile), digest equals content and, with a
reviewed lock, the pinned digest (`verify_profile`), unique task ids
(the golden loader), `pack_id` equals the pack hash and must-cite coverage (`validate_report`).
