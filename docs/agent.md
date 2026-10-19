# Agent profiles, context packs and the broker contracts

Vendor-neutral building blocks for running agents under least privilege. Everything here is
data plus pure functions: no model, network or hardware is involved, and the tests use in-memory
fakes. Contracts live in `schemas/agent/` and `schemas/broker/`; code in `homelabnext/agent/` and
`homelabnext/broker/`; command `hnx agent`.

## Why these exist

- A profile is **compiled**, not hand-assembled, so "this agent can never do more than its
  ceiling" is a property of the compiler rather than a review habit.
- A context pack is a **pure function** of a manifest and its inputs, so identical inputs give an
  identical pack and hash. A job log that records the hash can be replayed and audited.
- An agent never runs blind: a required pre-gate that is missing, stale or failed **defers** the
  job with a reason instead of letting the agent infer health from raw data.
- The broker is **default deny**, and an approval is bound to the digest of the exact request it
  approved, so a request changed after approval no longer matches.

## Schemas

| Schema | Purpose |
|---|---|
| `agent/profile` | compiled profile: `parts` by logical id, `grants`, `ceiling`, `budgets`, `digest`, `provenance` |
| `agent/context_manifest` | persona, skills, tools, pre-gates, memory scopes, tiered sections, character budget, must-cite sources |
| `agent/pregate_output` | `ok` / `degraded` / `stale` / `failed`, with per-source ages; a non-ok status needs a reason |
| `agent/report_result` | `pack_id`, cites, unknowns, memory updates; `ok` needs at least one cite, `deferred` is how a job reports it did nothing |
| `agent/golden_task` | the existing `homelabnext.golden` suite format, described unchanged |
| `broker/manifest` | the allowlist; `default` is the constant `deny`; `approvers` lists who may approve |
| `broker/handler` | one handler implementation; execute and privileged handlers require approval; always audited |
| `broker/request` | one call; `digest` binds `{action, actor, target, params}` |
| `broker/decision` | `allow` / `deny` / `needs-approval` with a closed reason vocabulary; shadow mode records but does not enforce |
| `broker/approval` | approver identity plus `request_digest` |

All are versioned 1.0 except `broker/manifest` and `broker/decision` (1.1, additive: approvers and
the new approval reasons), frozen under `schemas/_frozen/`, and registered with `tools/schema_check.py`
(each has an example and several negatives). `agent/profile` is the compiler's output;
`platform/agent_profile` stays as the lean runtime view.

Rules JSON Schema cannot express are code, with tests: grants subset of ceiling, digest equals
content, `pack_id` equals the pack hash, must-cite coverage, and that a manifest, its handler
documents and the broker table agree (`check_manifest_handlers`).

## Profile compiler

```python
from homelabnext.agent import PartsLibrary, compile_profile
from homelabnext.ids import MappingResolver

library = PartsLibrary(MappingResolver("parts", {"persona:analyst": "personas/analyst.md", ...}),
                       reader=read_text)          # reader(locator) -> str
profile = compile_profile(spec, library)
```

The spec names a persona, skills, capabilities, a model **role** (never a model id), the MCP
servers it wants, a tier, budgets and a `ceiling`. The compiler:

1. resolves every logical id through the library and reports **all** missing ids together
   (`MissingPartError`), never skipping one;
2. refuses a spec whose MCP servers, capabilities or tier exceed the ceiling (`CeilingViolation`,
   listing every excess);
3. requires all four budgets to be integers within the ceiling's budget caps (`BudgetError`);
4. sorts and de-duplicates lists, so source order never changes the result;
5. records `provenance`: each part's id, source and content digest, plus the digest of the
   normalised spec;
6. sets `digest` to the sha256 of the canonical JSON of everything else, and validates the result
   against its own schema. `verify_profile` re-checks schema, ceiling, budgets and digest on a
   profile you did not just compile.

Raising a ceiling is a reviewed change to the spec, never a compiler option.

## Context-pack assembler

```python
from homelabnext.agent import assemble_pack

pack, pack_hash = assemble_pack(manifest, {"sections": {...}, "pregates": {...}})
```

- **Order**: tier (`stable`, `session`, `volatile`), then section name. The stable prefix is
  identical across runs; `stable_prefix_digest` exposes it for caching.
- **Pure**: no I/O, no clock, arguments untouched. The hash is the digest of the pack, so any
  changed byte of any input changes it; dict, list and process (`PYTHONHASHSEED`) ordering do not.
- **No silent truncation**: a section over its `max_chars` is cut and listed; when the pack
  exceeds `budget_chars`, optional volatile then session sections are dropped and required ones
  trimmed, each cut recorded in `truncations` with its tier, and `budget.tiers_cut` says how deep
  the cut went. Stable content is never cut: if it alone does not fit, the pack is `deferred`.
- **Deferral**: a missing required section, or a required pre-gate that is missing, `stale` or
  `failed`, makes `status: deferred` with `deferred_reasons`. Pre-gate outputs are included in the
  pack as volatile sections so the agent sees the verdict itself.
- Section text is fenced with the manifest's delimiter and tier so untrusted input stays
  distinguishable from instructions. Stable sections (manifest text) open with
  `<delim> <name> [stable] <delim>`. Session and volatile sections are input, so their fences
  carry a per-pack nonce derived from the digest of that content
  (`<delim> <name> [<tier>] <nonce> <delim>` ... `<delim> end <name> <nonce> <delim>`), and any line
  of their text that starts with the delimiter is prefixed `[escaped] `. Input therefore cannot
  open a section of its own, least of all a stable one. This is a structural guarantee about the
  text, not about the model: a model can still be persuaded by data it reads, so the broker, not
  the pack, is what limits what an agent can do.

`validate_report(report, pack, pack_hash, manifest)` checks a `report_result` against the pack it
ran on: schema, `pack_id`, deferred-only-when-deferred, cites name real pack sources, and the
manifest's `must_cite` sources are cited by an `ok` report.

## Broker contracts and reference evaluator

`homelabnext.broker.decide(manifest, request, approval=None, now=..., store=...)` returns a
`decision`. Order of checks, first failure wins: action in manifest (else `default-deny`); actor
granted the action (`not-granted`); tier within the grant (`tier-exceeds-grant`); handler declared
(`handler-missing`); then approval for execute/privileged or flagged actions: none is
`needs-approval`, a digest that does not match the request is `approval-digest-mismatch`, then
`approval-denied`, `approval-self-approved`, `approval-approver-not-allowed`,
`approval-agent-approver`, `approval-time-invalid`, `approval-expired`, `approval-replayed`, else
`approved`. `request_digest` covers `action`, `actor`, `target` and `params` (not ids or
timestamps).

- **Time.** `now` defaults to the UTC clock. An approval is valid from `approved_at` (which may
  not precede the request's `created` or follow `now`) until the earlier of its `expires_at` and
  `approved_at + approval_ttl_s`. A manifest without `approval_ttl_s` gets 900 seconds
  (`DEFAULT_APPROVAL_TTL_S`).
- **Who may approve.** `manifest.approvers` lists `{issuer, subject, kind}`; an approval counts
  only when its approver matches an entry on both issuer and subject. A manifest without
  `approvers` accepts no approval. Identities are compared normalized (case-folded, `.`, `_` and
  whitespace folded to `-`, see `normalize_identity`), so `ops_bot` is the actor
  `profile:ops-bot` and is refused as a self-approval. An approver whose entry says
  `kind: agent`, or whose subject names any profile the manifest grants actions to, is an agent
  and is refused unless the manifest sets `allow_agent_approvers: true`.
- **Single use.** An `approved` decision in enforce mode consumes the `approval_id` in the
  `store` (an `ApprovalStore`: `consume(id)` must be atomic, `consumed(id)` reads). A second use
  is `approval-replayed`. `MemoryApprovalStore` is the in-process default; a broker that runs in
  more than one process, or restarts, needs a durable store. Shadow mode reports a replay but
  consumes nothing.

The table `tests/broker/fixtures/decision_table.yml` (manifest x tier x handler x approval ->
decision) is the conformance input for any broker implementation: run the same rows against it.

## Command line

```
hnx agent compile SPEC --library LIBRARY.yml [--out profile.json]
hnx agent pack MANIFEST --inputs INPUTS.json [--out pack.json]
```

`LIBRARY.yml` is `{parts: {<logical id>: <path relative to the file>}}`; paths may not escape its
directory. `compile` exits 1 on a missing part, ceiling or budget violation. `pack` prints the
hash and status on stderr and exits 0 when ready, **3 when deferred**, 1 on invalid input.
Install the extra with `pip install 'homelabnext[agent]'`.

## Tests

`pytest tests/agent tests/broker` covers: determinism (same input twice, shuffled inputs, three
hash seeds), ceiling and budget rejection, missing-id errors, truncation and tier reporting,
deferral, report validation, schema examples and negatives, the golden-suite compatibility check,
and the broker decision table.
