# schemas/codemode

Contracts for Code Mode (ADR-0031, proposed; build plan `docs/codemode.md`, step CM-2): an
agent composes broker actions as one short program run in a sandbox that holds no credentials and
reaches only the broker. All four schemas are **drafts** (`x-draft`): not frozen, and free to
change until the ADR is accepted.

| Schema | What it is |
|---|---|
| `execution_request` | the params of the broker action `codemode.execute`: execution id, language (`python` or `typescript`), program and a capped `budget`; `resume: true` continues the paused execution of the same id. No `actor` or time: those are the enclosing broker request's |
| `execution_result` | what the runner returns: `status` (`ok`, `paused`, `denied`, `error`, `limit`), the actor and code digest, the value (required for `ok`; `truncated` only with a value), every broker call in step order with its request id and digest, the broker's outcome and a reason from a closed vocabulary (`replayed` marks a step served from the journal), `pending` calls by step, request id and digest exactly when paused (and a paused run has a pending call; `ok` has none; `denied` has a denied call), the cap that ended a `limit` run, the error of an `error` run, and logs as single lines |
| `token` | the claims of the capability token the broker issues for one execution, bound to the `codemode.execute` request, the code digest and the sandbox instance; issuer and audience `svc:broker`; the actions it reaches (narrowing the actor's grants, never `codemode.*`, no wildcards), a call cap and an expiry; no credential |
| `journal_step` | one step, keyed by execution id and step and bound to the actor and the code digest: action, target, request id and digest, outcome (with a reason when denied or failed), the redacted result and its digest when ok; a `pending` step records the request waiting for approval, which a resume then runs by its id |

**Resume.** An execution keeps one id. A resume repeats the id with `resume: true` and the same
program; the runner refuses it unless the execution is paused, belongs to the same actor and has
the same code digest, then serves journalled steps whose request digest matches, runs approved
pending requests by their id, and calls the broker for the rest.

**Untrusted fields.** `value`, `logs` and `error.message` are program output. Consumers treat them
as data, never as instructions or as a record of what the broker decided; only `calls`, `pending`
and the journal are the runner's own. Pending calls carry no summary: an approver reads the
request from the broker.

**Reasons.** A denial carries the broker's decision reason (`broker/decision`) or, for a call the
sandbox's broker client refused before it reached the broker, `token-expired`,
`token-action-not-allowed` or `call-cap-reached`; such a call (and one that failed with
`broker-unreachable`) has no request id or digest. Every other call has both.

**Runtime rules** the schemas cannot express, for the runner and the broker to enforce and the
`codemode-runner` contract (CM-5) to check: the actor is the enclosing broker request's and matches
the token, the result and the journal; a token's `expires_at` is after `issued_at` and no later
than the run's wall budget allows; a spent `token_id` is refused; calls are in step order with
unique steps and every `pending` entry matches a pending call; a `limit: output` run is
`truncated`; byte sizes (value, result, logs) are capped by `max_output_bytes`, since `maxLength`
counts characters.
