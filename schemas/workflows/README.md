# schemas/workflows

Workflows as code (guide: `docs/workflows.md`; library and validator: `homelabnext.workflows`;
command: `hnx workflows`).

| Schema | What it is |
|---|---|
| `pack` | one workflow: the trigger (an event type from `schemas/events`, optional `where` conditions), ordered steps - `enrich` (deterministic `pick`, `lookup`, `extract-iocs`), `decide` (a decision spec id), `prompt` (a prompt template id), `action` (a broker action) - and fixtures (event, lookup rows, fake model outputs, approvals, the exact expected action calls) |
| `deploy` | the deploy manifest: the packs the orchestrator may run, each pinned to its `pack_digest` |
| `stackstorm` | when pinned packs run on StackStorm: the rendered pack, webhook, broker socket and actor, and one rule per pack (shadow or live with promotion evidence, coalesce window, cron schedule); `hnx workflows st2 render|check`, `docs/stackstorm.md` |

References inside a pack are strings: `$event.<path>` or `$steps.<step-id>.<path>` (`$$` escapes a
literal `$`). Rules JSON Schema cannot express - references resolve, deterministic steps run before
any model step, fixtures round-trip through the offline runner, risky actions are bound to an
approval of their payload digest, deploy pins match - are enforced by `hnx workflows validate`.
