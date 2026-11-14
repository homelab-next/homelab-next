---
summary: The platform depends only on OIDC, one identity-header set and one group-to-role table; Keycloak is the default IdP, oauth2-proxy the edge's forward auth.
summary_of: outline:sha256:881053abbe9b00d9
---
# ADR-0034: Single sign-on: an OIDC IdP behind a neutral contract; Keycloak is the default

- **Status:** accepted (2026-10-31, by the operator)
- **Date:** 2026-10-31
- **Amended:** 2026-11-06 (decision 4, the username claim; decision 3, the note on public
  routes); 2026-11-13 (decision 2, the second factor: a passkey or a client certificate, never a
  one-time code, by the operator; reserved usernames)
- **Related:** ADR-0017 (the broker's approval gate, approvers by SSO issuer and subject);
  ADR-0027 (modules, the product-name lint); ADR-0030 (agents act only through the broker);
  [architecture](../architecture.md) (layer 4); [idp](../systems/idp.md);
  [status](../status.md) (the private tier and the Approvals page); checklist F-03 and F-23

## Context

Every human-facing app of the lab needs a login, and people should sign in once, with a second
factor, and be the same person everywhere. The platform had been written against one IdP
product: the Caddy generator called that product's proxy outpost, the edge lint and the status
hub hard-coded its header names (and its `|` group separator), the realm content was that
product's blueprint format, and the SSH login path relied on its LDAP outpost. Swapping the IdP
would have meant editing the generator, the lint, the hub and the docs at once, and the group
names the hub trusted lived in a second file (`agents.yml`) beside the registry.

The operator chose Keycloak as the lab's IdP (2026-10-31) and does not want the platform tied to
one IdP product.

## Decision

1. **The platform depends on OIDC only**: discovery, the JWKS, and token verification (the
   `idp` contract, `conformance.protocols.idp`, stays product-neutral). No platform code calls an
   IdP's admin API or reads an IdP-specific header.
2. **Keycloak is the default `idp` implementation** (registry `impl: keycloak`). Its realm is
   generated from the registry (`idp_realm`, `idp/realm.json`, importable by Keycloak's realm
   import or keycloak-config-cli): one confidential OIDC client per `auth: idp` service (the
   authorization code flow with PKCE, redirects under the service's public hostname, default
   client scopes trimmed to `basic` so a token carries only what the client asks for), one for
   the auth proxy (its callback on every site it guards), the groups and client roles of the
   group-to-role table, a groups claim and a roles claim, and a browser flow that requires a
   second factor. The realm never holds a secret: each client secret is a secret-store
   reference, one per service (for example `secret:idp/clients/metrics`), substituted at import.
   **The second factor is a passkey (WebAuthn) or a browser client certificate, required, with
   nothing beside it, in every flow that signs a user in; no one-time code (TOTP or HOTP) is
   offered** (amended 2026-11-13: the operator declined code-based MFA fleet-wide, and recorded
   on that date that approvers authenticate with a password plus a passkey or a client
   certificate; the earlier text required OTP). The realm binds two user sign-in flows and
   covers both:
   - **browser** (`browserFlow`): the session cookie, or the username/password form and then
     the WebAuthn form (`webauthn-authenticator`), both `REQUIRED` in one subflow. A `REQUIRED`
     authenticator a user has not configured adds its setup action, so a user with no key yet
     goes through `webauthn-register` (enabled in the realm's `requiredActions` as a default
     action, so every new user has it) before the sign-in completes; with the action disabled
     the sign-in fails, never passes on the password alone. The realm's WebAuthn policy requires
     user verification on the key (a PIN or biometric: a passkey, not bare possession);
   - **direct grant** (`directGrantFlow`, `grant_type=password`, which the IdP's own built-in
     `admin-cli` client allows): **refused for every user** (`deny-access-authenticator`,
     `REQUIRED`, alone). A passkey cannot be presented on a direct grant and a direct grant
     cannot run a required action, so no direct grant can carry the second factor. Without this
     binding the IdP's built-in direct grant flow would run, whose OTP step is conditional on
     the user having one: password alone.
   `CONFIGURE_TOTP` and the passwordless key's `webauthn-register-passwordless` are rendered
   **disabled** (so the account console offers neither), and no OTP step is in any flow.
   Every client the realm renders has `directAccessGrantsEnabled: false` and no flow-binding
   override. The other user-facing flows are unreachable: `registrationAllowed` and
   `resetPasswordAllowed` are false, and no identity provider is rendered, so no broker login
   flow runs (the client-authentication flow authenticates clients, not people). Adding any of
   these, or a new binding, is a change to this rule.
   **A client certificate** is a permitted second factor under this rule but is not rendered
   yet: it takes the IdP's X.509 authenticator and the edge forwarding the browser's verified
   certificate (the edge terminates TLS), a change of its own. It must keep the property this
   rule states: a password and a possession factor on every path, never an `ALTERNATIVE` an
   un-enrolled user can skip. A subflow of alternatives none of which the user has configured
   is the ambiguous case this rule closes; offering both factors needs, for example, a
   conditional subflow on the user's configured credentials. A test reads every path through
   each bound flow and fails on one without a password and a passkey step, on any OTP step, on
   an enabled `CONFIGURE_TOTP`, and on any of the conditions above
   (`tests/generators/test_gen_golden.py`).
   **First-sign-in enrolment is trust on first use**: whoever first signs in with an
   un-enrolled user's password registers the key, so an attacker holding that password before
   the user signs in registers their own. Create users with a temporary password
   (`UPDATE_PASSWORD`) and have them register their key in person, at a session the operator
   watches, and do not leave an account un-enrolled.
   **Reserved usernames** (amended 2026-11-13): the realm refuses, as a username, every name on
   the generator's built-in list (the Stage 4 proof manifest's approver, `operator-one`) and
   every name the site adds (`hnx registry generate --reserved-username`), through a `pattern`
   validator on the username in the realm's user profile, so no admin, console or form can
   create or rename a user into one. A realm import of users bypasses validators, so the IdP
   module's health hook also fails while a user with a reserved name exists. A name an
   approver allowlist or a proof scenario has used is never handed to a person.
3. **Forward auth goes through an auth proxy** (registry capability `auth-proxy`; the default is
   oauth2-proxy) next to the edge, for every app with no OIDC login of its own. The generated
   `hnx_forward_auth` Caddy snippet proxies the auth proxy's `/oauth2/*` paths under each site,
   asks its `/oauth2/auth` check about every other request, copies the identity headers on a
   2xx and redirects a 401 to `/oauth2/sign_in` (the return target `rd` query-escaped, so a
   query with `&` comes back whole). A public `auth: idp` service with no auth proxy in the
   registry fails generation rather than being published without a login.
   *Note (2026-11-06):* the registry refuses any row with a `public_hostname` whose `auth` is
   missing, `none` or `mtls` (`a public route needs auth`, as for a module's rows): a public
   site is `auth: idp` (forward auth) or `auth: own` (the app's own login), since the edge
   terminates TLS and checks no client certificate; the edge's own row has no public site.
   `auth: own` is the row's own claim that the app has a login: the registry cannot check it,
   so a reviewer checks it against the app before accepting a public `own` row.
   **The edge lets in only the service's own groups, not every realm user.** Each site imports
   the snippet with one argument, the sorted union of the groups of its `roles` (rule 5),
   URL-encoded and joined by `,`, and the check is `/oauth2/auth?allowed_groups=<them>`. The
   auth proxy (oauth2-proxy's `AuthOnly` handler, `checkAllowedGroups`) answers 202 for a
   signed-in user in at least one of them, 401 for no session, and **403** for a signed-in user
   in none; an *empty* `allowed_groups` imposes no restriction. So the Caddy generator
   **refuses a public `auth: idp` service without `roles`** (it would admit the whole realm)
   and a group name outside lower case and `-`; every such service in the examples and
   fixtures has a table. A 403 is passed to the browser unchanged, never redirected to sign-in
   (the user is signed in; signing in again would answer 403 again, a loop). A config that
   imports the generated snippet without its argument is refused by the edge lint (an
   argument past those given), since Caddy itself would leave the placeholder to run time.
   Who may reach a multi-tier app (the status hub's non-private pages) is therefore its role
   table too: a group that should only see those pages gets a role of its own that the app
   does not read.
4. **One identity-header set** (`homelabnext.edge_identity.IDENTITY_HEADERS`): by default the
   auth proxy's `X-Auth-Request-User`, `-Groups`, `-Email` and `-Preferred-Username`, groups
   joined by `,`, and the mark `auth-request` that every identity header carries.
   **One claim names a person: the IdP's `preferred_username`**
   (`homelabnext.edge_identity.USERNAME_CLAIM`, amended 2026-11-06). The reference auth proxy
   (oauth2-proxy with `--set-xauthrequest`) sends it as `X-Auth-Request-Preferred-Username`, which
   the edge copies (`IdentityHeaders.username`); `X-Auth-Request-User` carries the proxy's
   user-id claim (`email` by default, or `sub`), which names nobody an allowlist lists. The status
   hub's private tier and its approver subject read the username header, and the SSH CA signs
   from the same claim (`hnx ssh-ca` refuses any other `oidc.user_claim`), so an approver
   allowlist entry and an SSH certificate name the same person the same way. The realm
   generator maps the username into the claim on every client (a `username` protocol mapper),
   so it does not depend on the optional `profile` scope a proxy may narrow away, and renders
   `editUsernameAllowed: false` (with `registrationAllowed: false` and no identity providers): a
   user who could choose or change their own username could take a name an allowlist lists. An
   overlay that enables self-registration, or adds an identity-brokering provider whose first
   login lets a user pick or review their username, re-opens that path and must not. A token
   without the claim gives no identity (the hub answers `403`), never a fallback to the user-id
   claim. The Caddy generator, the edge lint (F-23)
   and the status hub read this declaration and nothing else. Every public site strips, at site
   level and before `forward_auth`, every client-sent header carrying the mark in every spelling
   (`request_header -*auth-request*` and `-*auth_request*`); the lint fails closed on anything
   less, for whatever set is declared.
5. **One group-to-role table**: each `auth: idp` service's `roles` in the registry (platform
   service schema 2.7), mapping each of the app's roles to the IdP groups that hold it. The realm
   generator renders exactly those grants (a test compares the rendered realm with the table),
   and the status hub reads its viewer and approver groups from its own row; `agents.yml` no
   longer names them (status agents schema 1.4).
6. **Apps with native OIDC get their own client** in the realm (rule 2); forward auth may still
   front them at the edge. Every app keeps a **break-glass local admin** whose secret lives in
   the secret store, never in the IdP.
7. **SSH does not go through the IdP's directory**: people get short-lived SSH certificates
   signed by the secret store after an OIDC login ([private overlay](../private-overlay.md),
   "SSH certificates"). No LDAP outpost is needed; the `sssd_ldap` role is superseded for SSH
   sign-on and kept for a lab whose IdP has an LDAP outpost.
8. **Agents never use a human SSO session.** They keep their broker and secret-store scoped
   credentials (ADR-0030); a human's IdP session is never handed to an agent.
9. **Active Directory, if built, is an attack-range target only**, never the lab's identity.

## Consequences

- Swapping the IdP is a registry change plus a realm format for the new product; swapping the
  auth proxy is a registry change plus, if its header names differ, the one declaration in
  `homelabnext.edge_identity`. Nothing else changes.
- The edge lint and its tests are parameterised by the declared set; most of its tests run
  against a non-default set on purpose, so a hard-coded name would fail them.
- The groups separator is now `,`. Group names are restricted (lower case and `-`) in the
  registry so that no group name can hold one; a group created in the IdP by hand with a `,` in
  its name could be read as two groups by the hub, so groups are created from the table only.
- The status hub's private tier and Approvals page need `roles.viewer` and `roles.approver` on
  the hub's registry row (or, for a row without `roles`, the deprecated `agents.yml` keys).
- New obligations: the realm import, the auth proxy's deployment (its cookie secret and client
  secret from the secret store, `--set-xauthrequest`, `--reverse-proxy`) and the break-glass
  admins are lab-side steps; Keycloak and oauth2-proxy are not yet in the product-name
  vocabulary, which takes a provider module for each. A non-default IdP must put the username
  in `preferred_username` for every client, as the generated realm's mapper does.

## Alternatives

- **Authentik** (the previous reference): built-in proxy and LDAP outposts and lighter to run,
  but one company's product with an MIT core and an enterprise tier, and its outpost headers and
  blueprint format had leaked into the platform. Not chosen by the operator.
- **FreeIPA**: Kerberos, HBAC and a directory for hosts, but heavy, and no OIDC provider of its
  own; the web apps would still need another IdP.
- **Active Directory / plain LDAP**: a directory only, no OIDC, no MFA flows; kept as an attack
  range target (rule 9).
