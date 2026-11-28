---
group: Fixed
---
the endpoint agent role names its unit and the unit's drop-in directory in two steps: one set_fact cannot use a value it defines itself, so the start-retry drop-in failed on every guest; a new test refuses any set_fact whose values name another key of the same task. The drop-in also clears the vendor start script's lock left by a hard reset mid-start (only when no agent daemon runs), which otherwise made every retry time out.
