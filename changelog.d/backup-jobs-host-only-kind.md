---
group: Changed
---
`hnx guests render backup-jobs`: a `kind: host` member (`provisioning: host-only`: a physical sensor, a DNS Pi, the hypervisor's own config) is now emitted with `kind: host-only` in place of `vmid` so a job dispatcher can tell a file-level backup (a `proxmox-backup-client backup` or a role export hook) from a vzdump of a VM or container, instead of having to infer it from a missing field. VM and container members keep the existing `vmid` field unchanged; existing goldens are unchanged. docs/compute-model.md's `backup-jobs` row and `homelabnext/compute/gen/backup_jobs.py` note the convention. ADR-0042.
