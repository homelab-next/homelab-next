---
summary: 'Every dated example and the day it falls due: CI judges some against the real date, so move the date or work the record in a reviewed change first.'
summary_of: outline:sha256:377ef954a32e767a
---
<!-- SPDX-License-Identifier: Apache-2.0 -->
# Dated examples

Some examples carry a date that a check compares with the real date, not with a fixed one. CI's
invariants job and the register review run on the day they run, so an example past its date turns
a job red with no code change. This page lists those dates, soonest first. When one comes close,
move the date (or work the record it guards) in a reviewed change, and update this page in the
same change.

| Falls due | What | Where | Read by |
|---|---|---|---|
| 2027-01-17 | lesson `review_by` | `examples/registers/lessons/` (two lessons); the same date in the orchestrator's lessons test data | the register review (`hnx registers review`) |
| 2027-01-31 | module licence `expires` | `examples/modules/example-static-host/module.yml`; `schemas/platform/examples/module.provisional-provider.yml` | specified, not yet read: the licence probe of the module manifest (warns 30 days ahead) |
| 2027-03-31 | module licence `expires` | `examples/modules/example-detonation/module.yml` | as above |
| 2027-04-19 | lesson and runbook `review_by` | `examples/registers/lessons/`, `examples/registers/runbooks/` | the register review |
| 2027-04-20 | strategy `review_by` | `examples/strategy/` (the strategy, its objectives and measures) | the strategy pages |
| 2027-06-30 | module licence `expires`; runbook `review_by` | `examples/modules/other-object-store/module.yml`; `examples/registers/runbooks/` | the licence probe (when it exists); the register review |
| 2027-11-30 | registry `standing.until` (`hub-candidate`, eval) | `examples/four-box-lab/services.yml` | checklist X-12 (`hnx registry standing --overdue`), in the invariants job |

Not listed: dates that are only shapes (schema examples validated by their schema, fixtures
under `tests/` that pin `HNX_TODAY`), and the shipped customization profiles, which are
`maintained_upstream` and exempt from `review_by` expiry (X-09).

A test that needs a date to stay valid sets `HNX_TODAY`; an example in the published tree cannot,
which is why this list exists.
