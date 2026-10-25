# schemas/codemode

Contracts for Code Mode (ADR-0031, proposed; build plan `docs/codemode.md`, step CM-2): an
agent composes broker actions as one short program run in a sandbox that holds no credentials and
reaches only the broker. All four schemas are **drafts** (`x-draft`): not frozen, and free to
change until the ADR is accepted.

| Schema | What it is |
|---|---|
| `execution_request` | the parameters of the broker action `codemode.execute`: the execution id, the actor, the language (`python` or `javascript`), the program and a `budget` (wall time, broker calls, output bytes, memory), each capped; `resume_of` continues a paused execution |
| `execution_result` | what the runner returns: `status` (`ok`, `paused`, `denied`, `error`, `limit`), the program's value (required for `ok`, marked `truncated` when cut off), every broker call in order with the broker's outcome (`denied` and `error` carry a reason, `replayed` marks a step served from the journal), `pending` requests (exactly when paused), the cap that ended a `limit` run and the error of an `error` run |
| `token` | the claims of the capability token the broker issues for one execution: issuer `svc:broker`, the actor, the actions it may reach (narrowing the actor's grants, never widening them), a call cap and an expiry; it carries no credential |
| `journal_step` | one completed step, keyed by execution id and step: its name, action, request id and digest, the broker's outcome and redacted result with its digest; a resume replays a step only when the name and request digest match |

Rules the schemas cannot express are the runner's and the broker's to enforce (and the
`codemode-runner` contract's to check, step CM-5): a token's `expires` is after `issued` and
short-lived, its `actor` is the request's, a result's calls are in step order with no gaps, and a
resumed execution's journal belongs to the same actor.
