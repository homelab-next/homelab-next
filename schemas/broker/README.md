# schemas/broker

Contracts for a command broker: an allowlist of actions executed by reviewed handlers, with
approvals bound to the exact request. Reference evaluator: `homelabnext.broker`.

| Schema | What it is |
|---|---|
| `manifest` | the allowlist. `default` is the constant `deny`; `grants` say which profile may call which actions up to which tier; `approvers` (1.1) say whose approvals count |
| `handler` | one handler implementation: action, path, content digest, tier, timeout; execute and privileged handlers require approval |
| `request` | a call for one action; `digest` is the sha256 of `{action, actor, target, params}` |
| `decision` | `allow`, `deny` or `needs-approval` with a closed `reason` vocabulary (1.1 adds the approver, time and replay reasons); shadow mode records but does not enforce |
| `approval` | an approver identity and the `request_digest` it approved; a changed request no longer matches. Single use: the broker consumes `approval_id` |

Table-driven fixtures: `tests/broker/fixtures/decision_table.yml` (manifest x tier x handler x
approval -> decision), including every default-deny case and the digest-mismatch negatives.
