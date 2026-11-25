---
group: Changed
---
role `restore_drill`: the drill finds an application's scheduled export in a module's data root (`var/lib/hnx-modules/<app>/export/db`) as well as under `var/backups`; the modules keep it there, so a guest that "should carry an export" failed its drill although the export was present and fresh.
