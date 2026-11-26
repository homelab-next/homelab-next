---
group: Added
---
`hnx guests backup-members --policy <name> --node <node>`: the sorted vmid list for a (policy, node) pair, derived from the guest records so the real backup job (`pvesh set /cluster/backup/<id> --vmid`) is reconciled off the lab's declaration rather than a hand list that drifts (B5). Exit 1 and `""` when the pair holds no member (a reconciler must not read empty as "truncate the job"); `--allow-empty` lets a deliberately-empty job through. `--json` prints an array. `--policy none` is refused: "none" is the opt-out marker, never a job. New helpers `homelabnext.compute.gen.backup_jobs.members_on_node` and `vmids_on_node` back it.
