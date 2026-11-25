---
group: Fixed
---
Module `caddy`: stripping the auth proxy's session cookie from a request no longer leaves a leading `; ` in the `Cookie` header when it was the first cookie. OpenSearch Dashboards (Wazuh) rejects such a header, so after the login the next request was unauthenticated and the user bounced back to the login page. The generated `hnx_forward_auth` snippet now deletes the cookie together with the separator before it and trims a leading `;`. Pinned by `tests/generators/test_session_cookie_strip.py`.
