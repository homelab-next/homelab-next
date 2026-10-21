---
type: register-transition
title: Retire the expired-certificate lesson, M-17 holds
requesting_agent: profile:example-checker
created: '2026-10-19T09:30:00Z'
record: LL-001
from: controlled
to: retired
retired_by: [M-17]
retired_on: '2026-10-19'
reason: M-17 has held in every run since the control shipped
---

Filed before the uid migration: the legacy code LL-001 still validates (note 1.4 widens record
to a uid without narrowing the numbered form), and the decider resolves it through the tree's
aliases.yml with a deprecation warning.
