---
group: Fixed
---
the endpoint agent role names its unit and the unit's drop-in directory in two steps: one set_fact cannot use a value it defines itself, so the start-retry drop-in failed on every guest; a new test refuses any set_fact whose values name another key of the same task.
