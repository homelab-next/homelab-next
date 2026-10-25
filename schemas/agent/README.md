# schemas/agent

Contracts for the agent layer (library: `homelabnext.agent`, guide: `docs/agent.md`).

| Schema | What it is |
|---|---|
| `profile` | a **compiled** profile: parts by logical id, grants, the permission ceiling they were checked against, hard budgets, `reads_untrusted` (1.1), `include` (1.2: rules for linked knowledge in the pack, seeded only from grants; 1.4: an optional `detail`, `summary` or `outline`, absent meaning the whole content), digest, provenance |
| `context_manifest` | what goes into one agent's context pack and in which tier order (stable, session, volatile); pre-gates; memory scopes; `screen` (1.1: redaction of untrusted sections, on by default) |
| `pregate_output` | the verdict of a mandatory pre-run check (`ok`, `degraded`, `stale`, `failed`) |
| `report_result` | what an agent hands back: `pack_id`, cites, unknowns, memory updates; `output` (1.1: the structured result an actor may act on) |
| `handoff` | a reader -> actor handoff: the reader, the actor, the schema the reader's `output` must satisfy, and the broker actions the actor may take with params bound to constrained output fields (G-04) |
| `golden_task` | the existing `homelabnext.golden` suite file format, described unchanged (the loader and this schema reject the same negatives) |
| `prompt_template` | a prompt: trusted `system`/`instructions` text plus slots, each declaring `trust: trusted\|untrusted`; untrusted slots render only fenced (G-01) |
| `injection_corpus` | the versioned prompt-injection corpus: per case a payload, a canary and/or forbidden tool, and the fake model's markers (G-02) |

`platform/agent_profile` is the lean runtime view of a profile; `agent/profile` is the compiler's
output and carries everything needed to audit it.

Rules JSON Schema cannot express are enforced in code and tested: grants subset of ceiling
(`homelabnext.agent.check_ceiling`; a reader, `reads_untrusted` true or absent, holds no
exec, file-write, egress or credential grant: `homelabnext.agent.readers`; the ceiling that counts is the separately owned
`CeilingPolicy`, not the `ceiling` copied into the profile), digest equals content and, with a
reviewed lock, the pinned digest (`verify_profile`), unique task ids
(the golden loader), `pack_id` equals the pack hash and must-cite coverage (`validate_report`), no untrusted
placeholder in trusted text and every trusted slot used (`lint_template`), and corpus cases whose
markers are present and whose canary is absent in the decoded payload (`parse_corpus`).
