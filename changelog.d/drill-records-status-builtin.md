---
group: Added
---
status hub: a `drill-records` built-in mapper for restore-drill records files (`drills.json`, role `restore_drill`; ADR-0042 decision 4). A `poll-file` source on the backup host surfaces one hub item per guest and per exported application, the age of the last verified drill against overdue and stale limits (30 d / 90 d by default); a drill that failed or has never verified fails; the shared state-diffed notifier pages once on each transition.
