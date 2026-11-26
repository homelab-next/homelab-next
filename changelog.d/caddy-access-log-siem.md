---
group: Added
---
Module `caddy` and generator `caddy`: the edge now writes an access log, one redacted JSON line per request (every site and the 404 catch-all name the logger `hnx_access`; file `<data root>/logs/access.log`, rotated by Caddy), and the host's SIEM agent reads it (one marked localfile block, only when the agent is installed). Credentials are redacted as in the default logger, plus the sign-in redirect's `code`, `state`, `id_token` and `session_state`. Pinned by `tests/roles/test_caddy_role.py` and the three `sites.caddy` goldens.
