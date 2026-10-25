# schemas/registers

Generalised registers. Each is a record schema; a generator renders a collection and fails on a
schema violation.

| Schema | Core idea |
|---|---|
| `lesson.schema.json` (2.1) | `uid` (a UUIDv7) and `type: lesson` identify it (no stored number, ADR-0019); `contributing_factors` (what enabled it) vs `root_cause` (why the conditions existed), `preventive_control`, falsifiable `verification`; `control_installed_at` required once graded `controlled`/`partial`; `retired_by` required when `retired`; (2.1, additive) an optional `summary` |
| `runbook.schema.json` (2.2) | `uid` and `type: runbook`; ordered `steps`, each with its own `verify`; (2.1, additive) `lessons` names lesson uids (a 2.0 document's `LL-NNN` codes still validate, so 2.0 stays readable; the record validation refuses one); (2.2, additive) an optional `summary` |
| `invariant.schema.json` | `statement`, `observable`, `expected`, `evidence: auto|manual`; auto needs `check` (exit 0 pass, non-zero fail, >=100 could not measure) |
| `register_event.schema.json` | one append-only event in a record's `<id>.events/` sidecar: `review` (the review entry; role `check`, `audit` or `approve`, and since 1.2 `audit` replaces the deprecated `challenge`, still accepted), `recurrence`, `verified` (`outcome`, `result`), `transition` (`from`, `to`, `set`, the `intent` applied; decider only), and (1.1) `value` (one reading of a strategy measure: `value` or `finding`, `observed_at`, `sample`, `definition_digest`, `definition_version`, `evidence`); (1.3) `rekey` (`from` -> `to` digest, written only by `hnx:migrate`: the uid migration's identity rewrite carries the reviews of `from` to `to`); file name `<UTC stamp>-<event>-<actor>[-<n>].yml` checked by `homelabnext.registers.events` |
| `kanban_item.schema.json` | columns `rfi blocked todo progress partial done`; project card (`PRJ-NNN`, `steps[]`, column `partial`) vs step card (`PRJ-NNN.M`) |
| `decision_spec.json` (1.3) | `question_set`, `decision_table`, `tiers`, `error_direction`, `on_error: escalate`, `latency_budget_ms`, `sample_audit_pct`; optional `callers` (`inline`, `batch`); optional `noise_gate` (`deescalate` labels, named `corroborators`) |

`summary` (lesson 2.1, runbook 2.2; ADR-0032) is the record's level 0: one reviewed line of at most
160 characters with no control character, which the MCP `context_for` serves instead of the content.
It is part of the review digest. `hnx registers summaries` (run by `make registers`) fails a malformed
one and counts a record or docs page without one as a warning; the record validation refuses a
malformed one too. Baselines `_frozen/2.1/registers/lesson.schema.json` and
`_frozen/2.2/registers/runbook.schema.json`.

Lessons and runbooks are identified by uids (ADR-0019): nothing is allocated, so there is no
placeholder. The 1.0 baselines (numbered `LL-NNN` ids) stay in `schemas/_frozen/1.0/` (runbook 2.0 in
`schemas/_frozen/2.0/`); only the
migration (`hnx records assign-uids`) reads records of that form. Invariant ids are the checklist's
row ids. `PRJ-NEW` remains schema-legal for kanban cards, a work queue this repository does not
allocate.

Cross-record rules (unique ids, step cards must reference an open step, an all-done project cannot sit
in `partial`) are in `tools/schema_check.py::check_kanban_board`.
`decision_spec.json` 1.1 added, additively, `safety`, `default_min_confidence`, `impact` (keyword file and
floor tier) and per-tier `timeout_ms` and `acts`; the 1.0 baseline stays in `schemas/_frozen/1.0/`.
1.2 added, additively, question objects (`{text, labels, compare}` beside plain strings) and `callers`.
1.3 added, additively, `noise_gate`: an automatic answer with a `deescalate` label stands only when one of
the named `corroborators` returns a deterministic reference, which the decision carries (K-08).
`hnx decide lint` (run by `make check` and CI) checks every tracked spec for what the schema cannot
express: single-axis questions (one `?`, no `;`, no joining `and`/`or`), at most 5 labels per
question, every `compare` question asked in both orders, a non-zero audit sample, and inline specs
that stop at the fast tiers (`floor`, `small`) within a 1 s budget; rules in
`homelabnext/decide/lint.py`. Its
consumer is `homelabnext.decide`. The invariant register also accepts `evidence: plugin` rows (checks
loaded through the `homelabnext.invariants.checks` entry point or `--plugins-dir`), for example X-09.
