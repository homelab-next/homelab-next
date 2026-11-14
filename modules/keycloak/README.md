<!-- SPDX-License-Identifier: Apache-2.0 -->
# Module `keycloak`: the idp provider

A provider module ([module manifest](../../docs/modules.md), draft, ADR-0027 proposed) that fills
the `idp` slot with [Keycloak](https://www.keycloak.org) and its own PostgreSQL. It is a
**service, not a machine**: the guest it runs on is the site's guest file, and the site's
selection places the module's one host role (`server`) on it. Nothing in this directory names a
real host, address, public name, VM id or secret value; those live only in the private overlay.

`idp` is a **privileged authority slot** (`examples/modules/slots.yml`): never provisional, always
a conformance run and the human review tier, and reached by another module only through an
overlay grant (`grants.upstreams.<module>: [cap:idp]`).

| | |
|---|---|
| Slot | `idp` (contract `conformance/protocols/idp.py`), stateful, migration format `json` |
| Adapter | `homelabnext.conform.adapters.keycloak:make` (a scratch realm of its own) |
| Product | Keycloak 26.8.1 (`quay.io/keycloak/keycloak`), PostgreSQL 17.10 (`docker.io/library/postgres`), both pinned by tag and digest |
| Host role | `server`: kind `vm`, baseline `base`, footprint 2 vCPU, 2560 MB, 8 GB |
| Role | `keycloak` (role interface v1), a wrapper of the core `compose_app` |
| Requires | `cap:secrets` (the credentials and the client secrets, read by name at deploy time) |
| Egress | none |
| Public route | only through the edge: `public_hostname` (the site's sign-in name) with `auth: own`, `tls: internal` and `edge_tls` |

## The realm: what a sign-in takes (ADR-0034, amended 2026-11-13)

The realm is not written here: it is the `idp_realm` generator's `idp/realm.json`, rendered from
the lab's registry (`hnx registry generate --only idp_realm`), and the role refuses any other.

- **A password and a passkey** on every browser sign-in. The browser flow is the session cookie,
  or the username/password form and the WebAuthn form (`webauthn-authenticator`), both
  `REQUIRED`, nothing beside them. The WebAuthn policy requires **user verification** on the key
  (a PIN or biometric: a passkey, not bare possession). A user with no key registers one at their
  first sign-in (`webauthn-register`, a default action) before the sign-in completes.
- **No one-time code.** The operator declined code-based MFA fleet-wide: no OTP step is in any
  flow, and `CONFIGURE_TOTP` (and the passwordless key's action) are rendered **disabled**, so the
  account console offers neither.
- **Every direct grant is refused** (`deny-access-authenticator`): no passkey can be presented on
  one. The lab's apps sign people in through the browser (oauth2-proxy at the edge, or their own
  OIDC login).
- **A client certificate** is a second factor ADR-0034 permits but this realm does not render yet
  (it takes the IdP's X.509 authenticator and the edge forwarding the browser's verified
  certificate: a change of its own).
- **Reserved usernames are refused.** The realm's user profile carries a `pattern` validator on
  the username that refuses the generator's built-in list (the Stage 4 proof manifest's approver,
  `operator-one`) and every name the site adds with `--reserved-username`, case-insensitively, so
  no admin, console or form can create or rename a user into one. The rendered realm lists them
  (`hnx.reserved_usernames`); a realm import of users bypasses validators, so the **health hook
  fails while any user holds a reserved username**.
- **Groups** are the registry's group-to-role table: for the new lab, `lab-approvers` (approve on
  the hub) and `lab-admins` (view), from the hub row's `roles`. **Clients**: one confidential
  client per `auth: idp` service and one for the auth proxy (oauth2-proxy), its callback on every
  site it guards. Each client's secret is `idp/clients/<client>` in the secret store (the generator's name;
  the auth proxy's is `idp/clients/<auth-proxy row name>`, which H3's `modules/caddy`
  reads too). The issuer the auth proxy is configured with is `https://<public name>/realms/<lab
  name>`, and every token carries the `groups` claim with those group names.
- Registration, credential reset, identity brokering and username edits are off.

## What the role does

`roles/keycloak` renders two `compose_app` services in the module's slice:

- **`postgres`** (PostgreSQL 17.10): runs as `keycloak_db_uid:keycloak_db_gid` (61021, no account
  on the host has it), its cluster in `<data root>/pgdata` (0700). **No published port**: the IdP
  reaches it by its compose service name on the project's own network. Its password is set at the
  cluster's first start (`POSTGRES_PASSWORD`, env_file only).
- **`keycloak`** (Keycloak 26.8.1, `start`): runs as `keycloak_uid:0` (61020; the image is built
  for an arbitrary uid in the root group), **HTTPS only** on `keycloak_bind:keycloak_port` (the
  guest's own address; all interfaces is refused), with the server certificate and key the lab's
  internal CA issued (`tls/server.crt`, `tls/server.key`, read-only, root's group). Fixed, not
  settings (`vars/main.yml`): no plain HTTP listener; the hostname strict (`KC_HOSTNAME` is
  `https://<keycloak_hostname>`: every issuer and redirect names the public name); the admin
  console's URL is the internal name (`KC_HOSTNAME_ADMIN`); `X-Forwarded-*` read only from
  `keycloak_edge_addresses` (`KC_PROXY_TRUSTED_ADDRESSES`); health on the management port inside
  the container (never published); no metrics; impersonation and Kerberos disabled.
- Both containers: every capability dropped, `no-new-privileges`, a memory limit, bounded logs, a
  healthcheck (`pg_isready`; `/health/ready` on the management port).

Then it **imports or converges the realm** through the admin API (`files/keycloak_api.py`, run on
the guest, its settings and secrets on stdin, never in argv; the connection verifies the server
by its certificate name against the lab CA, never by address and never unverified):

- an absent realm is created from the whole rendered document, each client's secret substituted
  from `idp/clients/<client>` in the secret store;
- an existing realm is converged on what is safe to change live: the realm's settings and flow
  bindings, the required actions, the user profile (the reserved usernames), missing clients,
  roles and groups, each rendered client's settings, mappers and secret, and each rendered
  group's client roles (exactly the rendered ones). **A bound authentication flow is never edited
  in place**: one that differs from the rendered document is drift the role refuses (see "Flow
  drift"). Users are never touched.

The break-glass admin (`keycloak_admin_user`, default `hnx-admin`) is the **master** realm's,
created at the first start from `secret:keycloak/admin-password` (ADR-0034 decision 6); the
master realm keeps Keycloak's built-in flows (password only), which is why the admin console and
the master realm must never be public (see "The edge").

## Hooks

| Hook | What it checks or does |
|---|---|
| `readiness` (also the module's preflight) | `docker_engine` readiness; the rendered realm is this lab's (`keycloak_realm`), binds rendered flows, requires `webauthn-authenticator`, refuses the direct grant, has no OTP step, registration and reset off, no literal client secret, and lists every reserved username the role's floor names; every credential resolves in its form (the passwords 24 to 256 safe characters and different, the certificate and CA PEM certificates, the key an unencrypted PEM key, every client secret 32 characters or more) |
| `health` | the master realm brute-force protected; no identity provider (broker) configured; no client overriding a flow binding; the username's validators exactly the rendered ones; **every enabled member of a rendered group has a registered passkey** (until then whoever first signs in with their password registers one); and: both containers running and healthy; **the database answers** (`pg_isready` in its container); **OIDC discovery** for the realm answers over verified TLS with the issuer `https://<keycloak_hostname>/realms/<realm>` and a key set; the bound flows are the rendered ones, **WebAuthn is `REQUIRED` in the approvers' browser flow**, no flow offers a one-time code, the direct grant is refused; `webauthn-register` is an enabled default action and `CONFIGURE_TOTP` is not enabled; the WebAuthn policy requires user verification; the user profile's reserved-username pattern is the rendered one; **no user holds a reserved username**; every rendered client and group exists and each group holds exactly its rendered client roles. Read-only |
| `export` | `export/db/keycloak.dump` (`pg_dump -Fc` in the database's container, as its own user), `export/realm.json` (the realm's partial export through the admin API: clients, groups, roles, flows, settings; client secrets masked, no users) and `export/listing.jsonl` (key, size, sha256) |
| `backup` | the export, then `compose_app`'s backup manifest (the data root, export included) |
| `restore` | checks the source first and writes nothing until it passes (`files/keycloak_backup.py check`: no links, root or the database's user owning each file, writable by no one else, the listing's two files with their sizes and sha256); then, with the IdP stopped, stages the dump as the database's user through the very descriptor it checked, hashing what it writes (`keycloak_backup.py stage`), and runs `pg_restore --clean --if-exists --no-owner --single-transaction --exit-on-error`; the staged copy is removed and the IdP started again whatever happened; then the realm is converged onto the rendered document and `health` runs (an older dump may hold an older flow or a reserved user) |
| `upgrade` | one target: the IdP's image, or PostgreSQL's within its major version; refuses a target not pinned by tag and digest or from another repository, then records the bump (`compose_app` upgrade) |

Two deviations from the role interface table, on purpose: `export` (so `backup`) writes a new
snapshot on every run and reports `changed`, and `main` reports `changed` when the realm sync
changed anything (it says what).

## Data

| Dataset | Kind | What | Export |
|---|---|---|---|
| `realm` | `state` | the realm's configuration as the IdP's partial export (no users, secrets masked) | `json`, by the role's export hook |
| `database` | `database` | the PostgreSQL database: the realm with its users, password hashes and passkeys | object-tree (`db/keycloak.dump` + listing), by the role's export hook |

`idp` is a stateful slot: the provider entry carries a migration in `json` (the realm export).
The **database dump is the restore's source**: it alone holds the users and their registered
passkeys. A VM-level backup (the guest's `backup:` policy) captures the data root; the export gives
it a consistent dump.

## Export and import (migration to another instance)

1. **Export** on the old instance: the role's `export` hook (`include_role: {name: keycloak,
   tasks_from: export}` on `mod_keycloak_server`, as `playbooks/remove.yml` does). It writes
   `<data root>/export/`.
2. **Same product, new instance** (a rebuilt guest, a new VM): copy the export directory to the
   new guest (root-owned, 0700), install the module there (`main`: an empty database, the realm
   created from the rendered document), then run the `restore` hook with
   `keycloak_restore_source=<copied export>`. The dump replaces the empty database whole (the
   realm, the users, their passkeys); run `main` again (it converges the realm onto the rendered
   document) and then `health`.
3. **Another product** (the slot's `json` migration): `realm.json` is the realm's configuration in
   Keycloak's representation (clients, groups and their roles, flows, settings), the input a
   migration tool maps to the other product; the clients' secrets are re-read from the secret
   store by name, and **users are not exported**: people re-enrol (a password and a new key) on
   the new IdP. Passkeys are bound to the relying party (the public name) and cannot move to
   another product.

## Restore drill (ADR-0042)

Prove a restore before you need one, on a scratch guest or after a backup on the live one:

1. **Mark** the realm: create a user `drill-<date>` in a group (the admin console on the internal
   name, or `kcadm.sh` in the container), and note the realm's `hnx.generated` attribute.
2. **Export**: run the `export` hook; check `listing.jsonl` names `db/keycloak.dump` and
   `realm.json` with their sha256 (`sha256sum` agrees).
3. **Damage**: delete the drill user (and, on a scratch guest, the whole realm).
4. **Restore**: the `restore` hook with `keycloak_restore_source=<data root>/export` (or a copy of
   it): the check passes, the IdP stops, `pg_restore` runs in one transaction, the IdP starts.
5. **Verify**: `health` passes (discovery, the passkey required, no reserved user, groups and
   roles); the drill user is back with its group; a sign-in by an enrolled person still asks for
   their existing passkey (it is in the database). Then delete the drill user.
6. **Tamper test**: change one byte of a copy's `db/keycloak.dump` and run `restore` on it: it is
   refused before anything stops (`sha256 differs from the listing`).

Record the date, the export's sha256 and the result in the overlay's evidence (lab README).

## Using it in a site

The overlay carries every real value ([selection](../../docs/modules/selection.md),
[registry rows](../../docs/modules/registry-rows.md), [apply path](../../docs/modules/apply.md)):

1. **A guest file** (`lab/guests/<name>.yml`): a VM, `status: planned` or `live`, baseline `base`,
   resources covering the footprint and the docker engine (the plan's 2 vCPU, 4 GiB, 32 GiB fits),
   `capability: cap:idp`, a `backup:` policy, and `firewall_rules` (below).
2. **The selection** (`lab/modules.yml`): `hosts.<name>: {guest: guest:<name>}`;
   `slots.idp: [{provider: keycloak, instance: idp, placement: {server: <name>}}]` (moved out of
   `planned`); `grants.public_routes.keycloak: [idp]` (the row is public); and, for the auth
   proxy's module, `grants.upstreams.<its module>: [cap:idp]`.
3. **The registry row** (`lab/services.yml`): `registry/services.yml`'s `idp` row renamed to the
   instance, `host` the guest's name, `version: "26.8.1"`, **its own `public_hostname`**
   (the site's sign-in name, e.g. `sso.<domain>`) and **its own `edge_tls`** (`ca:` the secret
   name of the lab CA the edge verifies this certificate with, and `server_name:` when the
   certificate is not issued for the capability alias), plus at most `standing`, `backup_job`
   and `scope`. `hnx modules check` compares the rest field by field and requires both of these
   (their values are the site's).
4. **The secrets**, by name: `keycloak/admin-password`, `keycloak/db-password` (24 to 256 of
   `A-Z a-z 0-9 . _ ~ + / = @ % ^ * -`, different), `keycloak/tls-cert` and `keycloak/tls-key`
   (the lab CA's server certificate for `keycloak_tls_server_name`, e.g. `idp.svc.<domain>`),
   `keycloak/ca` (the lab CA's certificate), and one `idp/clients/<client>` per client the
   rendered realm names (32 characters or more), including the auth proxy's.
5. **The realm**: `hnx registry generate lab/services.yml <out> --only idp_realm
   --reserved-username <name> ...` with the site's reserved names (at least the Stage 4 proof
   approver, which is built in, and any other proof or test caller the site has used).
6. **The role's variables** (`group_vars/mod_keycloak_server.yml`): `keycloak_logical_id: idp`,
   `keycloak_hostname: <public name>`, `keycloak_realm: <lab name>`, `keycloak_realm_file: <out>/idp/realm.json`,
   `keycloak_tls_server_name: <the certificate's name>`, `keycloak_edge_addresses: [<edge guest
   address>]`, and `keycloak_reserved_usernames` if the floor should name more than the built-in.
7. **Apply**: `docker_engine` on `mod_keycloak_server`, then the rendered `modules.yml` twice
   (the second `changed=0`), then `checks/keycloak.yml`.

### The edge and the firewall

- **No public route except through the edge.** The guest file's `firewall_rules` (the
  hypervisor's per-VM firewall, which filters before the guest and is the control for a Docker
  published port) admit **8443/tcp from the edge guest only** and 22/tcp from the deploy host;
  nothing else. A guest-side nftables rule does not see Docker's published port (its NAT and
  FORWARD chains), so it is not the control.
- The edge reaches the IdP over TLS verified against the lab CA (`edge_tls`, H2's `tls:
  internal`, `ca` only: no client certificate on this hop), by the certificate's name.
- **The edge publishes only the realm's paths.** The generated edge (`hnx registry generate`,
  the `caddy` generator) renders the realm's IdP row (`realm_idp`: the `idp` row whose `impl` is
  the realm format's product) as `@hnx_published path /realms/<lab name>/* /resources/*`, proxied,
  and **404 for every other path**: the master realm (password only, the break-glass admin's)
  and `/admin/` are never reachable under the public name; the admin console's URL is the
  internal name (`KC_HOSTNAME_ADMIN`), reached from the deploy host or the edge guest only. An
  edge that does not render from that generator must do the same before the row is granted a
  public route. Prove it once the edge is up, from outside the lab: `/admin/` and
  `/realms/master/` under the public name answer 404. The master realm also gets brute-force
  protection (`main` turns it on; `health` checks it).

## Conformance

`conformance/target.yml` binds the `idp` suite to the Keycloak adapter. The adapter signs in as
the break-glass admin and works only in a **scratch realm** of its own (`hnxconf-<hex>`, deleted
when the target closes): per subject a confidential service-account client with no default
scopes, the requested scopes as optional client scopes, a hard-coded `hnx_sub` claim and the
ttl as the client's token lifespan; it verifies RS256 against the realm's JWKS and then asks the
IdP's introspection (a revoked token is inactive). CI runs the suite through this target against
the HTTPS stand-in (`tests/modules/keycloak_stand_in.py`). Against the lab's instance, from the
deploy host or the edge guest:

```sh
HNX_ENDPOINT_IDP=https://<internal name>:8443 HNX_IDP_CA_FILE=<lab CA PEM> \
HNX_IDP_ADMIN_USER=hnx-admin HNX_IDP_ADMIN_PASSWORD=<from the secret store> \
  hnx conform --root <homelab-next checkout> run idp \
    --target <checkout>/modules/keycloak/conformance/target.yml
```

## Known limits

- **Upgrading from an OTP-era realm.** A realm imported from a render before 2026-11-13 binds
  the same browser-flow alias with an OTP step: `main` refuses it as flow drift. Follow "Flow
  drift" (export, recreate on a realm with no users to keep, or ship the flow under a new alias).
- **The public name is the passkeys' relying party.** Renaming `keycloak_hostname` (the site's
  sign-in name) orphans every registered passkey: each person registers again.

- **Flow drift is refused, not fixed.** A realm whose bound flow differs from the rendered one
  (a hand edit, or a generator change to a flow) fails `main` with `flow ... differs`. Fix it by
  rendering a flow under a **new alias** (the change ships a new alias, the role creates it, then
  rebinds), or, on a realm with no users to keep, by exporting, deleting the realm and running
  `main`. Never edit the bound flow by hand.
- **The adapter needs the lab CA** (`HNX_IDP_CA_FILE`): the admin's password goes only to the
  internal name the lab CA vouches for; point `HNX_ENDPOINT_IDP` at the internal name, never the
  public one.
- **What `sync` does not converge**: session and token lifespans, the password policy,
  `loginWithEmailAllowed` and other realm settings the generator does not render keep the IdP's
  values; `sync` overwrites only what the rendered document names (the user profile, the rendered
  clients' settings and secrets, the rendered groups' roles).
- **Passwords are set once.** `POSTGRES_PASSWORD` and `KC_BOOTSTRAP_ADMIN_PASSWORD` act only on
  the first start. To rotate: change the role's password in the database (`ALTER ROLE` in the
  database's container) or the admin's (the admin console), then the secret; `health` fails while
  the stored admin password does not sign in.
- **Client secrets are outside the module's namespace** (`idp/clients/<client>` in the secret store, the
  generator's names, ADR-0034), so `credentials` cannot list them; the role reads them by name.
- **The containers are on a bridge network**, so `egress: none` is what the IdP is configured to
  do (no identity brokering, no SMTP, no remote JWKS), not a network rule (`hnx modules check`
  warns).
- **Trust on first use**: a user's first sign-in registers their passkey; create users with a
  temporary password and have them register in person (ADR-0034 decision 2).
- **Removal** exports first, takes both containers down and deletes the env_files and the
  server's key; the data root (with the export) stays for the operator. Every passkey is in the
  database: removing the data root ends every sign-in.
