# schemas/registers

Generalised registers. Each is a record schema; a generator renders a collection and fails on a
schema violation.

| Schema | Core idea |
|---|---|
| `lesson.schema.json` | `contributing_factors` (what enabled it) vs `root_cause` (why the conditions existed), `preventive_control`, falsifiable `verification`; `control_installed_at` required once graded `controlled`/`partial`; `retired_by` required when `retired` |
| `runbook.schema.json` | ordered `steps`, each with its own `verify` |
| `invariant.schema.json` | `statement`, `observable`, `expected`, `evidence: auto|manual`; auto needs `check` (exit 0 pass, non-zero fail, >=100 could not measure) |
| `kanban_item.schema.json` | columns `rfi blocked todo progress partial done`; project card (`PRJ-NNN`, `steps[]`, column `partial`) vs step card (`PRJ-NNN.M`) |
| `decision_spec.json` (1.2) | `question_set`, `decision_table`, `tiers`, `error_direction`, `on_error: escalate`, `latency_budget_ms`, `sample_audit_pct`; optional `callers` (`inline`, `batch`) |

`LL-NEW`, `RB-NEW`, `A-NEW`, `PRJ-NEW` are schema-legal placeholders: a pre-commit hook allocates the
number under a lock, so nobody picks an id by reading "the next free one".

Cross-record rules (unique ids, step cards must reference an open step, an all-done project cannot sit
in `partial`) are in `tools/schema_check.py::check_kanban_board`.
`decision_spec.json` 1.1 added, additively, `safety`, `default_min_confidence`, `impact` (keyword file and
floor tier) and per-tier `timeout_ms` and `acts`; the 1.0 baseline stays in `schemas/_frozen/1.0/`.
1.2 added, additively, question objects (`{text, labels, compare}` beside plain strings) and `callers`.
`hnx decide lint` (run by `make check` and CI) checks every tracked spec for what the schema cannot
express: single-axis questions (one `?`, no `;`, no joining `and`/`or`), at most 5 labels per
question, every `compare` question asked in both orders, a non-zero audit sample, and inline specs
that stop at the fast tiers (`floor`, `small`) within a 1 s budget; rules in
`homelabnext/decide/lint.py`. Its
consumer is `homelabnext.decide`. The invariant register also accepts `evidence: plugin` rows (checks
loaded through the `homelabnext.invariants.checks` entry point or `--plugins-dir`), for example X-09.
