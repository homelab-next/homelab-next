---
group: Fixed
---
Health hooks judge ages with `now().timestamp()`: `now(utc=true).timestamp()` read a naive UTC time as local, so on a controller not on UTC every age was off by the zone offset (vector, honeypot, aide, clamav, lynis, needrestart, nut_ups, rkhunter, trivy, unattended_upgrades). A test refuses the pattern.
