# The swap kit

Replacing a product behind a capability is a procedure, not an event ([ADR-0005](adr/0005-swap-procedure-and-conformance.md)).
The kit makes the procedure executable: a resumable state machine that refuses to advance on a
failed gate, parity tools that prove the candidate behaves like the incumbent, a dual-write helper,
a one-row cutover flip with its exact inverse, and a decommission check that proves nothing still
points at the old component.

| Piece | Where | Command |
|---|---|---|
| Swap runner and record | `homelabnext/swap/` | `hnx swap plan\|start\|status\|advance\|rollback\|record` |
| Record schema | `schemas/platform/swap_record.schema.json` | `python tools/schema_check.py` |
| Parity tools | `homelabnext/parity/` | library (see below) |
| Dual-write helper | `homelabnext/swap/dualwrite.py` | library |
| Registry flip | `homelabnext/swap/flip.py` | `hnx swap plan --registry ... --to-host ...` |
| Decommission check | `tools/decommission_check.py` | `python tools/decommission_check.py ROOT --host ...` |
| Per-guest teardown audit | `homelabnext/decommission/` | `hnx decommission check\|plan NAME` (`docs/decommission.md`) |

Everything here runs on a laptop with fakes. Starting and stopping real components, real traffic
mirroring and real DNS are **SERVER** work: the kit defines the interface (`Backend`) and ships a
fake-backed implementation (`LakeBackend`) plus an attestation-driven one (`ManualBackend`).

## The nine steps

Each step has pre-conditions, an action, post-conditions, a dry run and an evidence artefact.
`advance` works only on the current step; a failed gate records the failure and raises, and the
next `advance` retries the same step.

| # | Step | Pre-condition | Action | Post-condition (gate) |
|---|---|---|---|---|
| 1 | `declare` | adapters differ; the route changes | conformance of the incumbent | incumbent passes |
| 2 | `shadow-start` | 1 passed | conformance of the candidate; start in shadow, backfill | candidate passes; shadow running |
| 3 | `dual-write` | 2 passed | start the mirror | mirror running; unresolved divergences within budget |
| 4 | `parity-compare` | 3 passed | run the parity tools | parity holds on enough rows; divergences within budget |
| 5 | `soak` | 4 passed and `soak_hours` elapsed since it passed | re-run parity | parity still holds |
| 6 | `cutover` | 5 passed | flip the registry row, run the canary, stop the old component | route applied, canary green. On failure the old route is restored at once |
| 7 | `rollback-window` | 6 passed and `rollback_window_hours` elapsed | re-verify, stop the mirror | canary green; old component retained (stopped, not destroyed) |
| 8 | `decommission-check` | 7 passed | scan registry, inventory, tree | no references remain |
| 9 | `close` | 8 passed; an ADR reference is given | write the closure | swap closed |

**Rollback** is allowed from any step before `decommission-check` has passed. It restores the prior
route, restarts the old component, stops the mirror and records the reason (at least ten
characters). After decommission there is nothing to roll back to, so it is refused.

## The swap record

One JSON file per swap, validated against the schema before every write and written atomically.
It holds the plan (soak and window lengths, divergence budget, minimum rows), the route before and
after, the nine steps with their last gates and evidence references (file name plus SHA-256), the
rollback or closure, and an append-only transition log. Time comes from an injected clock; the
record never reads the wall clock itself.

What `hnx swap record FILE --verify` checks (it also re-hashes the evidence files):

* Each transition carries the hash of the previous one and a `state` digest of the steps, route,
  status, rollback and closure as they were when it was written; the hash covers both.
* The steps agree with the log: one `step-passed` transition per passed step, in order, at the
  step's `finished_at`, naming that step's evidence; a failed step has its `gate-failed`
  transition; `closed` and `rolled_back` have theirs; the last `state` matches the file. Marking a
  step passed, faking its evidence or flipping the route without the transitions is reported, and
  so is cutting transitions off the end.

What it does **not** guarantee. With the default unkeyed chain anyone who can write the file can
recompute every hash, so the chain detects damage and careless edits, not a determined writer.
Two optional measures close that gap:

* **Keyed chain.** Set `HNX_SWAP_CHAIN_KEY` when the swap starts (and for every later command):
  the record says `chain.alg: hmac-sha256` and the hashes are HMAC-SHA256, which cannot be
  recomputed without the key. With a key set, an unkeyed record is refused, so the chain cannot
  be downgraded.
* **Anchored head.** `hnx swap record FILE` prints `head: SEQ:HASH`. Store it where the record's
  writer cannot rewrite it (a ticket, a commit, the event bus) and later run
  `hnx swap record FILE --anchor SEQ:HASH`: a record that lost or rewrote that transition fails.
  This is the only check that catches a record replaced by a consistent older copy of itself.

Evidence artefacts live next to the record in `<swap_id>.evidence/`, one file per attempt, each
with the gate results and whatever the backend returned (for example the full parity report).

## Parity tools

`homelabnext.parity` works on any two implementations of `LakeQuery` / `LakeClient`:

* `diff_rows(left, right, RowRules(...))`: row-set equality after normalisation (timestamps to UTC
  text, decimals to floats, floats rounded). Rules: key columns, `ordered` / `order_by`, ignored
  columns, per-column tolerance (`Tolerance(abs=, rel=, seconds=)`), null equals missing, and a
  deterministic `Sample(fraction)` that keeps the same keys on both sides. A sampled report says so.
* `compare_queries(left, right, [ParityQuery(...)])`: run the same SQL or named query on both.
* `compare_tables(left, right, tables)`: schema drift (missing, extra, type, nullability, key,
  nested fields), row count and content, per table. `schema_drift()` is also usable alone.
* `compare_event_streams(old, new, EventRules())`: counts by type, missing/extra ids, duplicates
  that appear only on the new path, payload equality (volatile fields ignored), order inside a
  partition, optional delivery-lag budget.
* `compare_notifications(old, new, NotifyRules())`: the same set of pages (a lost page and an
  extra page both fail), priority, tags, routing, problem/recovery order, optional body text.

All return a `ParityReport` whose JSON is canonical, so it can be stored as swap evidence.
A parity pass on two empty results proves nothing, so `min_rows` is a gate.

## Dual-write

`DualWriter(primary, secondary)` writes to the primary first and returns its result. The secondary
gets the same idempotency key; a failure or a row-count mismatch becomes a recorded `Divergence`
(memory plus an optional JSON Lines file), the batch is parked, and `replay_pending()` retries it
safely. If the primary fails, the secondary is not touched, so the candidate can never hold data
the incumbent lacks. After cutover the direction reverses so a rollback loses nothing.

## The registry flip

Consumers resolve `<capability>.<svc_label>.<domain>`; the registry row says what answers. Cutover
is one reviewed change to that row.

```python
plan = plan_flip(doc, "lake-query", host="lake-core-2", impl="duckdb", version="1.5")
print(plan.diff())  # what changes, and the alias target before and after
new_doc = plan.apply(doc)  # validated with the registry's own rules
back = plan.inverse()  # the exact rollback
text = flip_text(yaml_text, plan)  # edits only the changed lines; comments survive
assert flip_text(text, back) == yaml_text
```

`plan_flip` is a pure function. `flip_text` re-parses its own output and refuses to write anything
that does not equal the plan. The goldens in `tests/swap/golden/` show the diff, the inverse and
the text change.

## Decommission check

```sh
python tools/decommission_check.py ROOT [ROOT ...] \
    --impl oldproduct --host old-host --alias old-query.svc.example.internal \
    --env-var OLD_ENDPOINT --unit old-sync \
    --registry services.yml --inventory hosts.yml --allow history-allow.txt
```

It reports stale aliases, registry rows, environment variables, systemd unit files and references,
inventory entries and mentions in docs, with word-bounded matching (`lake-core` does not match
`lake-core-2`). Exit code 0 is clean, 1 means references remain, 2 is a usage error.
`--from-record swap.json` derives the retired implementation from the record. Hosts are never
derived (a host usually carries other services); name them with `--host`. History that must keep
the old name goes in an allow file, never silently. Swap records and their evidence are excluded
by default.

## Worked example: swap a lake-query implementation between two fake lakes

This is the end-to-end test (`tests/swap/test_e2e.py`); the published schema examples are its
output.

```python
old, new = seeded_fake_lake(), FakeLake()
backend = LakeBackend(
    old,
    new,
    tables=["authentication", "dns_activity"],
    registry_path="services.yml",
    service="lake-query",
    new_host="lake-core-2",
    scan_roots=["tree"],
    retired=Retired("trino-lake", impls=("trino",)),
)
runner = SwapRunner.create(
    "swap-lake-query-0001.swap.json",
    backend,
    swap_id="swap-lake-query-0001",
    capability="cap:lake-query",
    from_adapter="trino-lake",
    to_adapter="duckdb-lake",
    service="lake-query",
    before={"host": "lake-core", "port": 8443, "impl": "trino"},
    after={"host": "lake-core-2", "port": 8443, "impl": "duckdb"},
    plan={
        "soak_hours": 48,
        "rollback_window_hours": 72,
        "max_divergences": 0,
        "min_parity_rows": 50,
    },
)

runner.advance()  # declare            incumbent conformance
runner.advance()  # shadow-start       candidate conformance, backfill
runner.advance()  # dual-write         production now writes through backend.writer
runner.advance()  # parity-compare     tables + queries; refuses on any drift
# ... 48 hours later ...
runner.advance()  # soak
runner.advance()  # cutover            registry row flipped, canary green, old stopped
runner.rollback("canary latency regression observed on the candidate")  # or keep going:
runner.advance()  # rollback-window    (after 72 h)
runner.advance()  # decommission-check refuses while a unit file or env var still names the old product
runner.advance(closure={"adr_ref": "docs/adr/0005-swap-procedure-and-conformance.md"})
```

Run 1 in the test stops at the rollback and checks the registry text is byte-identical to the
start and that a write made after the flip was replayed into the incumbent. Run 2 goes through to
decommission and close. A third test writes one row to the incumbent behind the mirror's back and
shows `parity-compare` refusing until the gap is reconciled.

## Rehearsal on the lab-in-a-box (P9.2)

`compose/lab-in-a-box/rehearsals/swap-lake-query.sh` runs while the smoke test has the stack up
(nightly). It drives `SwapRunner` with `LakeBackend` (driver: `homelabnext/swap/rehearsal.py`):
the incumbent is the built-in fake lake seeded with a deterministic dataset, the candidate is
the box's Trino over the Lakekeeper catalog (`homelabnext.conform.adapters.lake`, a scratch
namespace per run). It runs `declare` through `cutover` (zero-hour soak and window: this is a
rehearsal), checks that the flipped route answers from the candidate with the incumbent's
results, then rolls back and checks that the registry file is restored byte for byte, the route
answers from the incumbent again, and the record validates (`hnx swap record --verify`). The
record, its evidence, the registry, the flip plan and `rehearsal.json` land in
`<report-dir>/swap-lake-query/`. The unit tests run the same driver on two in-memory lakes and
the wrapper against a loopback stand-in for Trino and the catalog.

## Driving a real swap

`hnx swap advance` uses the `ManualBackend`. Gates that need a real system are satisfied by
attestation files, JSON containing `"ok": true`, whose hashes are written into the evidence:

```sh
hnx swap start --record swaps/s1.swap.json --capability cap:lake-query --from trino-lake \
    --to duckdb-lake --service lake-query --registry services.yml --to-host lake-core-2 --to-impl duckdb
hnx swap advance swaps/s1.swap.json --dry-run
hnx swap advance swaps/s1.swap.json --attest conformance-old=old.json
```

Attestation names: `conformance-old`, `conformance-new`, `shadow`, `mirror` (may carry
`unresolved`), `parity` (may carry `rows_compared`), `canary`, `old-stopped`. The registry flip and
the decommission scan are real, not attested. For a swap you run often, write a `Backend`
subclass instead; the interface is a dozen small methods returning `Outcome(ok, detail, data)`.

## Limits

* The record is a single file; two operators advancing the same swap at once is not guarded
  against. Use one driver per swap.
* The parity tools compare what you ask them to. A query set that misses a table is a gap in the
  swap test, not in the tool.
* Real traffic mirroring, component start/stop and DNS propagation are SERVER and not implemented.
