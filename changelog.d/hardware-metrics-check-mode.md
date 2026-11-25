---
group: Changed
---
role `hardware_metrics`: the timer is enabled and started through the systemctl command in `config`, and never under `--check`, so the dry run of a first install no longer fails asking systemd about a unit the run has not installed yet.
