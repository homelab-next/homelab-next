---
group: Changed
---
Module `caddy`: the edge's default logger now redacts credentials before anything is written: query values (`api_key`, `ApiKey`, `token`, `access_token`, `X-Emby-Token`, `X-MediaBrowser-Token` and variants) and the `Authorization`, `X-Emby-Authorization`, `X-Emby-Token`, `X-Mediabrowser-Token`, `Cookie` and `Proxy-Authorization` request headers and `Set-Cookie` response header. Reverse-proxy warnings (such as an aborted upstream response) carry the full request and went through the unfiltered default logger. Pinned by `tests/roles/test_caddy_role.py`.
