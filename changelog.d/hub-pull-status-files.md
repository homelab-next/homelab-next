---
group: Added
---
The status hub pulls per-host status files (ADR-0049 decision 7, "The results transport"; `docs/status.md` "Pulled status files"): role `status_hub` takes `status_hub_pulls` (`{name, host, user, host_key, dest}`) and `status_hub_pull_key_ref`, and a root-run timer dials each registry host with a pinned host key and no command, files the JSON object the producer's forced command prints at the hub-chosen `dest` under the status root (0640, by rename) and leaves the previous file on any failure. Module `lab-checks` gains `lab_checks_results_readers`: a locked account whose restricted key prints only a copy of the last results document the unit publishes after each run, so the hub's `invariants` source has something to read.
