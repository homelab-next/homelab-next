---
group: Added
---
Module `vector`: the OCSF remap maps the edge's access log (Caddy JSON from the SIEM agent) to `http_activity` rows (client, site as destination host, method, URI, status, bytes, user agent; a 4xx/5xx is a failure; the default logger's error lines are not accesses), and a NAS connection-log login forwarded by syslog (`Users`, `Source IP`, `Connection type`, `Action: Login OK|Fail`) to an `authentication` row. Goldens: `agent-stream.in.json` (three edge lines) and `syslog-nas.in.json`.
