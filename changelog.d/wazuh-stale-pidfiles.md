---
group: Fixed
---
SIEM module: the manager's pid directory is a tmpfs, so a hard reset no longer leaves stale pid files that make the product's start skip every daemon (a manager that came back up with nothing running, and nothing alerted); health now also fails on a stale alert stream; a liveness timer writes `siem_*` textfile metrics and the monitoring module gains `SiemManagerDaemonsDown`, `SiemAlertStreamStale` and `SiemLivenessCheckStale` rules.
