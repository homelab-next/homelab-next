<!-- SPDX-License-Identifier: Apache-2.0 -->
# Changelog: module `caddy`

## 0.1.0 (draft)

- The `edge` provider: stock Caddy 2.11.7 (image pinned by tag and digest) serving only one
  deployment's sites, rendered by the role itself with the edge generator and `--edge-host`
  (refused without one), and exactly the names the overlay declares; a catch-all answers 404.
- A public-trust certificate obtained and renewed on the host by lego 5.6.0 (sha256 per
  architecture) with a DNS-01 challenge, a root-only token file, a daily timer and a reload
  (`caddy reload --force`), never a restart.
- Upstream TLS from the generated `caddy/edge_tls.json`: the edge's client certificate and the
  lab's CA written from the secret store, mounted read-only.
- Role `caddy_auth_proxy`: oauth2-proxy 7.15.5 as the forward-auth check and the OIDC sign-in
  (PKCE S256, scope `openid`, `--set-xauthrequest`, a `__Host-` cookie).
- Health: TLS by name, the sign-in redirect, the catch-all 404, the identity strip in the running
  configuration, the hub's mTLS refusal without the client certificate; export, backup and
  restore of the ACME account and the configuration.
- The `edge` suite through the shared Caddy adapter (`homelabnext.conform.adapters.caddy`): the
  forgery is every identity header (and other proxies') in every spelling.
- Review fixes: the generated forward-auth snippet deletes the auth proxy's session cookie
  before any upstream; the session lasts 4h by default (at most 12h); a client key must come from
  the module's own store area; the controller command must be an hnx entry point; the renewal unit and the
  validate container join the role's slice; the export replaces its snapshot atomically; restore
  refuses a non-canonical source; remove can purge the account (`caddy_remove_purge`).
