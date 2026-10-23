# schemas/broker

Contracts for a command broker: an allowlist of actions executed by reviewed handlers, with
approvals bound to the exact request. Reference evaluator: `homelabnext.broker`.

| Schema | What it is |
|---|---|
| `manifest` | the allowlist. `default` is the constant `deny`; `grants` say which profile may call which actions up to which tier; `approvers` (1.1) say whose approvals count |
| `handler` | one handler implementation: action, path, content digest, tier, timeout; execute and privileged handlers require approval |
| `request` | a call for one action; `digest` is the sha256 of `{action, actor, target, params}` |
| `decision` | `allow`, `deny` or `needs-approval` with a closed `reason` vocabulary (1.1 adds the approver, time and replay reasons; 1.2 adds `not-request-owner` with the optional `operation` and `caller`, for a read or cancel of someone else's request); shadow mode records but does not enforce |
| `approval` | an approver identity and the `request_digest` it approved; a changed request no longer matches. Single use: the broker consumes `approval_id` |
| `audit` | one record per outcome of the broker service (`homelabnext.broker.service`): operation, outcome (`ok`, `denied`, `invalid`, `error`, `shadow`), machine reason (empty only for `ok`), request id and digest, arguments with secret ones redacted |

Manifest 1.2 adds `lanes` (write lanes for the built-in lane handler), an action's `lane` and
`handler_docs`; handler 1.1 adds `argv`, `secrets` (names resolved at run time) and
`max_output_bytes`. Manifest 1.3 adds the socket transport's identities: `callers` (a peer, by
`uid` or `user`, and the one profile it acts as), `approval_relays` (a peer that files approvals
for the humans of one `issuer`) and `dev_identity` (whether the CLI's asserted `--as` is accepted;
absent means false). Audit 1.1 adds the operation `connect` (a transport refusal) and `via` (the
socket peer, `uid:<n>`); audit 1.2 adds the outcome `started` (the record an action writes before
it executes, with an empty reason). Manifest 1.4 adds `refusal_limit` (`max` refused requests per
`window_s` per transport peer before the socket answers it `rate-limited`; default 60 per 60 s).
Manifest 1.5 adds `quotas` (`pending_per_actor`, default 20, and `notify_window_s`, default
300 s: one approval page per actor and window) and a lane's `max_files` and `max_total_bytes`
(default 4096 files and 64 MiB per lane directory).
Manifest 1.6 adds a shared lane's per-actor share (`max_files_per_actor`, `max_bytes_per_actor`;
default an eighth of the lane's quotas) and a lane's `max_writes_per_hour` (default 120 on a shared
lane, none on a per-actor lane; refused `lane-rate-exceeded`).
Reference service and walkthrough: `docs/broker.md`, ADR-0017.

Table-driven fixtures: `tests/broker/fixtures/decision_table.yml` (manifest x tier x handler x
approval -> decision), including every default-deny case and the digest-mismatch negatives, and `access_cases` for
request ownership (only the actor may read or cancel its request).
