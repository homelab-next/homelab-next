# schemas/registers

Generalised registers. Each is a record schema; a generator renders a collection and fails on a
schema violation.

| Schema | Core idea |
|---|---|
| `lesson.schema.json` | `contributing_factors` (what enabled it) vs `root_cause` (why the conditions existed), `preventive_control`, falsifiable `verification`; `control_installed_at` required once graded `controlled`/`partial`; `retired_by` required when `retired` |
| `runbook.schema.json` | ordered `steps`, each with its own `verify` |
| `invariant.schema.json` | `statement`, `observable`, `expected`, `evidence: auto|manual`; auto needs `check` (exit 0 pass, non-zero fail, >=100 could not measure) |
| `kanban_item.schema.json` | columns `rfi blocked todo progress partial done`; project card (`PRJ-NNN`, `steps[]`, column `partial`) vs step card (`PRJ-NNN.M`) |
| `decision_spec.json` | `question_set`, `decision_table`, `tiers`, `error_direction`, `on_error: escalate`, `latency_budget_ms`, `sample_audit_pct` |

`LL-NEW`, `RB-NEW`, `A-NEW`, `PRJ-NEW` are schema-legal placeholders: a pre-commit hook allocates the
number under a lock, so nobody picks an id by reading "the next free one".

Cross-record rules (unique ids, step cards must reference an open step, an all-done project cannot sit
in `partial`) are in `tools/schema_check.py::check_kanban_board`.
`decision_spec.json` is extended additively by the decision task.
