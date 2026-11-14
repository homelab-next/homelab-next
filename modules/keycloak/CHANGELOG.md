<!-- SPDX-License-Identifier: Apache-2.0 -->
# Changelog: module `keycloak`

## 0.1.0 (unreleased)

- First version (Stage 5, H4): the `idp` provider on Keycloak 26.8.1 with PostgreSQL 17.10, both
  pinned by tag and digest, as `compose_app` containers in the module's slice. HTTPS only on the
  guest's address with a certificate from the lab's internal CA; the database unpublished.
- The `idp_realm` generator's realm imported, then converged through the admin API on every run
  (flows created when missing, never edited in place; users never touched): a password and a
  passkey (WebAuthn, user verification required) on every browser sign-in, every direct grant
  refused, no one-time code, the reserved usernames refused by the user profile.
- Health: OIDC discovery and its issuer, WebAuthn required in the approvers' flow, no OTP, no
  user holding a reserved username, the database reachable, clients and groups as rendered.
- Export (pg_dump plus the realm's partial export, sha256 listing), backup, a checked restore
  (pg_restore in one transaction, the IdP stopped), a documented restore drill.
- The conformance adapter `homelabnext.conform.adapters.keycloak` (a scratch realm,
  client-credentials tokens, RS256 against the JWKS, introspection for revocation).
