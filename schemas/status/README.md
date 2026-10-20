# schemas/status

The status hub's contracts (ADR-0013, `docs/status.md`). The sources themselves are part of the
service registry (`status_sources:` in `schemas/platform/service.json` 2.1).

| Schema | What |
|---|---|
| `observation.schema.json` | one reading of one item of one module: `source` (a registered status-source id), `module`, `item`, `state` (`ok`, `warn`, `fail`, `unknown`, `stale`), `summary`, optional `link` (a logical id or a relative path, never a URL or an address), `observed_at`, `expires_at`, optional `value` and `work` (a live-work count). It is also the `data` of the `homelabnext.status.observed` event (`schemas/events/`) |
| `views.schema.json` | `views.yml`: the shell (`title`, `main`, optional `act_via` service) and the left menu; each entry is a built-in panel (`exceptions`, `grid`, `sources`) with an optional `select` of sources or modules, or an `external` link to a registry service (`optional` when the service may be absent). Consumed by `homelabnext.status.views` |
| `agent_activity.schema.json` | the summary tier of one agent activity event (stage 1b): ids, runtime, surface, host, project, model, agent, kind, tool name, outcome, tokens, cost. Never a prompt, command, tool input or output. Also the `data` of `homelabnext.agent.activity` |
| `agent_activity_detail.schema.json` | the private detail of one event: prompt, command, tool input and output, error, approval with its payload; redacted and capped by the hub, never on the bus |
| `agents.schema.json` | `agents.yml`: the activity store, retention, caps, stuck thresholds, the private tier's front door, the push ingest's senders (secret references only) |

The `status.json` document the hub renders is documented in `docs/status.md` (schema string
`homelabnext.status/1`). Evolution is additive within a major version (`tools/schema_check.py`).
