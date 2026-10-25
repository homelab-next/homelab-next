# schemas/codemode

Contracts for Code Mode (ADR-0031, proposed; build plan `docs/codemode.md`, step CM-2): an
agent composes broker actions as one short program run in a sandbox that holds no credentials and
reaches only the broker. All four schemas are **drafts** (`x-draft`): not frozen, and free to
change until the ADR is accepted.

| Schema | What it is |
|---|---|
| `execution_request` | the params of the broker action `codemode.execute`: execution id, language (`python` or `typescript`), program and a capped `budget`; `resume: true` continues the paused execution of the same id. No `actor` or time: those are the enclosing broker request's |
| `execution_result` | what the runner returns: `status` (`ok`, `paused`, `denied`, `error`, `limit`), the actor and code digest, the value (required for `ok`; `truncated` only with a value), every broker call in step order with its request id and digest, the broker's outcome and a reason as the broker gives it (`replayed` marks a step served from the journal), `pending` calls by step, request id and digest exactly when paused (and a paused run has a pending call; `ok` has none; `denied` has a denied call), the cap that ended a `limit` run (`output` is the printed output exceeding its budget; a value cut at the byte cap is `truncated` whatever the status), the error of an `error` run, and logs as single lines |
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

**Reasons.** A denied or failed call carries the broker's own reason exactly as the broker gives
it (any reason but the success ones `allowed`, `approved` and `approval-required`), or, for a call
refused before the broker built a request for it, a token refusal by the sandbox's client or the
broker's token check (`TOKEN_REFUSALS` of `conformance/protocols/broker.py`: `token-invalid`,
`token-sandbox-mismatch`, `token-expired`, `token-spent`, `token-paused`,
`token-action-not-allowed`, `call-cap-reached`, `token-request-not-paused`,
`request-not-approved`), `broker-unreachable` or `rate-limited` (the transport refused the peer
before reading a request). `token_run`'s refusals before it runs anything are token refusals too:
that call built no request. Such a call has no request id or digest and is never journalled, so a
resume calls again with its new token; every other call has both, from the broker's answer,
`request-denied` included (`token_run` of a paused request its approver denied: the request was
decided, so the refusal names it).

**Journal and tokens.** The journal is append-only and the latest record for a step counts: a
pending record is followed by the settled one once the approved request runs. Request digests are
the broker's (secret arguments enter them keyed with its digest key), so the runner takes them from
the broker's answers and never computes them. Every run of an execution, its start and each
resume, gets a fresh token bound to that run's `codemode.execute` request id. The call cap is the
execution's, in total across its runs: a resume's token carries what is left of it. Only a paused
execution resumes; a finished one never does (`docs/broker.md`, "Code Mode capability tokens").

**Runtime rules** the schemas cannot express, for the runner and the broker to enforce and the
`codemode-runner` contract (CM-5) to check:

- a request without `resume` whose execution id already exists is refused, so two runs never
  share a journal; a resume needs a paused execution of the same actor and code digest;
- the actor is the enclosing broker request's and matches the token, the result and the journal;
- every run (start or resume) gets a fresh token bound to its own request id; `expires_at` is
  after `issued_at` and within the run's wall budget; a spent `token_id` is refused;
- a call's outcome, reason, request id and digest are the broker's answer for that call, as its
  audit record holds it (the schema checks only that a reason is not a success reason, since the
  broker's vocabulary is not a closed list);
- calls are in step order with unique steps, and every `pending` entry matches a pending call;
- the journal is append-only and a step's only transition is pending to settled: nothing is
  appended after an `ok`, `denied` or `error` record;
- byte sizes (value, result, logs) are capped by `max_output_bytes`, since `maxLength` counts
  characters.
