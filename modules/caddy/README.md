<!-- SPDX-License-Identifier: Apache-2.0 -->
# Module `caddy`: the edge provider

A provider module ([module manifest](../../docs/modules.md), draft, ADR-0027 proposed) that fills
the `edge` slot, the front door of **one deployment**, with stock [Caddy](https://caddyserver.com)
and a forward-auth proxy ([oauth2-proxy](https://oauth2-proxy.github.io/oauth2-proxy/)) in front
of the IdP. It is a **service, not a machine**: the guest is the site's guest file, and the
site's selection places the module's one host role (`edge`) on it. Nothing here names a real
host, address, VM id or secret value; those live only in the private overlay.

| | |
|---|---|
| Slot | `edge` (contract `conformance/protocols/edge.py`, extended suite), stateless, **privileged** (a trust root: always a conformance run and the human review tier) |
| Adapter | the shared `homelabnext.conform.adapters.caddy:make` (a Caddy of its own on loopback, never the lab's) |
| Product | Caddy 2.11.7, `docker.io/library/caddy:2.11.7-alpine` pinned by tag and digest |
| Also runs | oauth2-proxy 7.15.5 (its `-alpine` image from quay.io, pinned by tag and digest); lego 5.6.0 (sha256 per architecture), the ACME client |
| Host role | `edge`: kind `vm`, guest capability `cap:edge`, baseline `base`, footprint 1 vCPU, 768 MB, 4 GB |
| Roles | `caddy` and `caddy_auth_proxy` (role interface v1), each a wrapper of the core `compose_app` |
| Requires | `cap:secrets` (every credential by name), `cap:idp` (the auth proxy signs users in there) |
| Egress | `internet` from the host: the ACME directory and the DNS provider's API (DNS-01) |
| Public route | none of its own: the sites are the deployment's public rows, rendered by the edge generator |

## Why it is built this way

- **One deployment, by construction.** The sites are the edge generator's
  (`homelabnext.generators.builtin.caddy`), which the `caddy` role runs **itself, on the
  controller**: `hnx registry generate <registry> <scratch> --only caddy --edge-host <host> ...`
  for every host in `caddy_edge_hosts`. Validation refuses an empty `caddy_edge_hosts`, so the
  role never renders without `--edge-host`; with it the generator renders only the public rows on
  those hosts and refuses any dial (a site's upstream, the forward-auth proxy) outside them. A
  registry that still holds another deployment's rows (the old lab's) can therefore never reach
  this edge. The role then holds what was rendered to what the overlay declared: the sites are
  **exactly** `caddy_acme_domains` (each on the certificate), the front doors' environment
  placeholders exactly `caddy_front_door_refs`, the forward-auth proxy the auth proxy role's port,
  every upstream TLS file a `.pem` under `/etc/hnx/edge-tls/` named by a `secret:` reference. Any
  difference fails before anything is written: no name gets a route the overlay did not declare.
- **A public-trust certificate obtained on the host (lego, DNS-01), not by Caddy.** Stock Caddy
  obtains certificates over HTTP-01 or TLS-ALPN-01, which need the names to resolve publicly to the
  edge (they never do), or over DNS-01 only with a DNS provider module compiled in: a custom build
  (`xcaddy`) that no upstream publishes, so nothing could pin it by digest. lego is a pinned release
  verified by sha256 per architecture, the same client, pin and pattern as role `openbao`'s ACME
  mode (#367): a `secret:` token reference, a root-only environment file the renewal script reads
  itself, a daily renewal timer, a fixed propagation wait (split-horizon DNS and blocked outbound
  DNS defeat lego's own check), exactly the configured names (`--force-cert-domains`), and a
  **reload, never a restart** (`caddy reload --force` through the admin API inside the container).
  Caddy runs with `auto_https disable_certs disable_redirects` and loads the installed pair.
- **One module, two roles.** The forward-auth proxy exists only for this edge: the generated sites
  dial it, it must be inside the `--edge-host` scope, and its callbacks are the edge's own names.
  It is one module (one placement, one guest, one review), but its own role, so its credentials
  (the IdP client's secret, the cookie key) never reach Caddy's env_file, its hooks are its own and
  its image bumps separately. A provider contributes only rows keyed by the slots it fills, and
  `auth-proxy` is not a slot, so the module contributes the `edge` row and the overlay keeps the
  `auth-proxy` row (below).

## What `caddy` does

- **Sites**: renders them as above and installs them as `config/sites.caddy` beside the role's
  `Caddyfile` (`templates/Caddyfile.j2`), which adds only the global options (admin API on the
  container's loopback, `auto_https disable_certs disable_redirects`, HTTP/1.1 and HTTP/2), a
  health site on the container's loopback, and a **catch-all** (`https://`) that loads the
  certificate and answers **404** for every name no site has. The generator's identity strip
  (every client-sent `X-Auth-Request-*` in every `-`/`_` spelling, and other proxies' identity
  headers) is at the top of every site; the module adds nothing that proxies.
- **Upstream TLS** (registry 2.10 `edge_tls`, H2): every file the generated `caddy/edge_tls.json`
  lists is written from the secret store (`hnx_secret`, `no_log`) to `edge-tls/` under the data
  root, owned by the container's user with the generator's mode (a key 0600), and mounted
  read-only at `/etc/hnx/edge-tls`, where the sites name it. A file no site names any more is
  removed. So the hub is reached over mTLS with the edge's client certificate, verified against
  the lab's CA by its server name.
- **The container** runs `caddy run` as `caddy_uid:caddy_gid` (61010) with a read-only root
  filesystem, every capability dropped but `NET_BIND_SERVICE` (the stock binary carries it as a
  file capability, and the kernel refuses to exec it when the bounding set lacks it; it binds no
  privileged port and `no-new-privileges` keeps the capability from being granted), a memory
  limit, bounded logs and a healthcheck on the loopback health site. It listens on 8443 inside;
  the host publishes it on the guest's own address (`caddy_bind`) at `caddy_port` (443). Its
  containers join the module role's slice (`compose_app_cgroup_parent`), and so do the
  throwaway `caddy validate` container (`--cgroup-parent`) and the renewal unit (`Slice=`).
- **Secrets** reach only their files: the DNS token the root-only `acme-env/dns.env`; a front
  door's shared secret Caddy's env_file (`{env.HNX_SECRET_...}` in the sites); the client key
  `edge-tls/`. `caddy validate` (in a throwaway container, no network) checks the configuration
  before it is started; a changed configuration or TLS file reloads a running Caddy.

Data root `caddy_data_root` (`/var/lib/hnx-modules/caddy`, `root:<caddy_gid>` 0750): `config/`,
`certs/`, `edge-tls/` (read-only in the container), `data/` and `state/` (Caddy's own), `acme/`
(lego's account, key and certificates; root, 0700), `acme-env/` (the DNS token; root, 0700),
`export/`.

## What `caddy_auth_proxy` does

oauth2-proxy as the forward-auth check and the sign-in only: no upstream (`static://202`),
`--set-xauthrequest` (the identity headers the edge copies: `X-Auth-Request-User`, `-Groups`,
`-Email`, `-Preferred-Username`), `--reverse-proxy`, the OIDC authorization code flow with **PKCE
S256** (the realm requires it) at `caddy_auth_proxy_issuer_url`, scope `openid` only (the realm's
client mappers add `preferred_username` and `groups` to every token; the username is the user id
and the e-mail claim, so no address is needed), a host-only `__Host-` cookie (Secure, HttpOnly,
SameSite=Lax, `caddy_auth_proxy_cookie_expire`: 4h by default, at most 12h), no access token or Authorization header passed
on, no provider button, no debug page, sign-in return targets only on the edge's names. The
site's allowed groups come from the generated snippet (`/oauth2/auth?allowed_groups=...`): a
signed-in user outside them gets **403**, never a sign-in loop. The generated snippet deletes
the session cookie (`__Host-hnx_auth`, `homelabnext.edge_identity.AUTH_PROXY_COOKIE`) from the
request once `forward_auth` has read it, so no upstream ever receives a session it could replay
against another site. The client is the realm
generator's client for the auth-proxy row: client id = the row's name, secret
`secret:idp/clients/auth-proxy` for a row named `auth-proxy`. The container runs as 61011, read-only, every capability dropped,
published on the guest's address at 4180 (the row's port), where the edge dials it.

## Hooks

| Role | Hook | What it checks or does |
|---|---|---|
| `caddy` | `readiness` (also the preflight) | `docker_engine` readiness; the generator renders this deployment's sites, exactly the declared names; every credential in its form (the DNS token one word, a front door's secret 16+ characters, a client key a PEM key, a certificate or CA PEM certificates) |
| `caddy` | `health` | the container healthy; the installed certificate outlives `caddy_acme_health_min_days` and no reload is owed; probed on the edge's own address: **TLS served** for every name, verified against the public trust bundle by that name; an unauthenticated request to a gated site is **redirected to the sign-in page**; a name no site has gets **404**; the **running** configuration (read from Caddy's admin API in the container) deletes every spelling of the identity headers first on every site (the **strip that removes a forged identity header** is in force; the forgery itself is proved end to end by the conformance run, below); every **mTLS upstream** (the hub) refuses a TLS peer without the edge's client certificate and answers with it; every other TLS upstream (the IdP) verifies against the lab's CA by name |
| `caddy` | `export` | `export/snapshot/{acme/...,config/...,listing.jsonl}` (key, size, sha256), root only |
| `caddy` | `backup` | the export, then `compose_app`'s backup manifest (the data root, which holds private keys and the DNS token: see Data) |
| `caddy` | `restore` | one script, two passes: **check** (nothing written: the source and every file opened without following a link, root's and writable by no one else, the listing naming only `acme/` and `config/`, each a single-link regular file of the listed size and sha256), then **apply** (each copied through the descriptor that was checked into a staging file and renamed in, 0600); run `main` afterwards |
| `caddy` | `upgrade` | refuses a target not pinned by tag and digest or from another repository, then records the bump |
| `caddy_auth_proxy` | `readiness` | `docker_engine` readiness; the client secret and the cookie key in their form (the IdP is not asked: its public name is served by this edge, not up before the first install) |
| `caddy_auth_proxy` | `health` | the container healthy; `/ping`; `/oauth2/auth` with no session is 401; signing in for each site is a 302 to the issuer's authorization endpoint for this client, with `code_challenge_method=S256` and the site's own callback (the proxy read the IdP's discovery document) |
| `caddy_auth_proxy` | `backup`, `export`, `restore` | nothing: it keeps no state (sessions are the users' cookies) |

`export` (so `backup`) writes a new snapshot on every run and reports `changed`.

## Data

| Dataset | Kind | What | Export |
|---|---|---|---|
| `acme` | `state` | lego's account (its key and registration) and its certificates, and the rendered configuration | object-tree, by `caddy`'s export hook |

`edge` is a stateless slot, so the provider entry carries no migration. A lost account is
replaced by a new registration on the next renewal; the backup keeps it because a CAA record
(`accounturi`) names it. **The backup (the guest's, of the whole data root) also holds private
keys and a credential in clear**: the certificate's key, the upstream client key, the ACME
account key and the DNS token. Its target must be encrypted and access-controlled like the
secret store. A restore needs only the export; everything else comes back from the account and
the secret store on the next `main`.

## Using it in a site

The overlay carries every real value ([selection](../../docs/modules/selection.md),
[registry rows](../../docs/modules/registry-rows.md), [apply path](../../docs/modules/apply.md)).
Fictional names below (`example.internal`, documentation addresses).

1. **A guest file** (`lab/guests/edge-01.yml`): a VM, `capability: cap:edge`, baseline `base`,
   resources covering the footprint and the docker engine, `firewall_rules` admitting the
   operator's sources on 443 and SSH from the deploy host only, and a `backup:` policy. **The
   hypervisor's per-VM firewall (the guest file's `firewall_rules`) is a MUST, not a nicety**:
   Docker publishes ports past any INPUT chain inside the guest, so it is the only thing keeping
   the auth proxy's plain-HTTP port 4180 (published on the guest's own address, where the edge
   dials it; the role refuses all interfaces) closed to everyone else. Never open 4180. Outbound: the upstreams' ports (the hub's, the
   IdP's), and 443 to the ACME directory and the DNS provider's API.
2. **The selection** (`lab/modules.yml`): `hosts.edge-01: {guest: guest:edge-01}`,
   `slots.edge: [{provider: caddy, instance: edge, placement: {edge: edge-01}}]` (and `edge` out of
   `planned` and `incumbents`), the `idp` slot served (a provider or an incumbent: the module
   requires it), and `grants.egress.caddy.edge: [internet]`.
3. **The registry rows** (`lab/services.yml`):
   - the module's `edge` row as bound (`registry/services.yml`, `host: edge-01`,
     `version: "2.11.7"`, plus at most `standing`, `backup_job`, `scope`); `hnx modules check`
     compares it field by field;
   - the lab's own `auth-proxy` row, on the same guest, dialled by the generated sites:

     ```yaml
     auth-proxy:
       capability: auth-proxy
       impl: oauth2-proxy
       host: edge-01
       protocol: http
       port: 4180
       health: {kind: http, path: /ping, expect_status: 200}
       upstreams: [idp]
       owner: operator
       version: "7.15.5"
       tls: none
       auth: own
     ```

   - each public row this edge serves, on a host in `caddy_edge_hosts`, with its
     `public_hostname`, `auth: idp` (with `roles`) or `own`, and `edge_tls` when the edge reaches
     it over TLS: the hub as `protocol: https`, `tls: mtls`,
     `edge_tls: {client_cert: secret:caddy/hub-client-cert, client_key: secret:caddy/hub-client-key, ca: secret:<the lab CA>, server_name: <the hub's svc name>}`;
     the IdP as `tls: internal`, `edge_tls: {ca: secret:<the lab CA>}`. A client key must come from
     the module's own store area (`caddy_edge_tls_key_area`, `caddy`): the role refuses a
     row whose `edge_tls.client_key` names another holder's secret.
4. **The secrets**, by name: `caddy/acme-dns-token` (a DNS API token with Zone DNS edit on the
   edge's zone only; delegating `_acme-challenge.<name>` to a zone that holds nothing else narrows
   it further), `caddy/auth-proxy-cookie-secret` (`openssl rand -base64 32 | tr -- '+/' '-_'`),
   `caddy/hub-client-cert` and `caddy/hub-client-key` (the edge's client certificate from the
   lab's CA, its SAN the name the hub pins), and, shared with their other holders: the lab CA's
   certificate, `idp/clients/auth-proxy` (the auth-proxy row's name) (the IdP client's secret, which the realm import
   reads too) and each front door's secret (`status/front-door-secret`, which the hub reads too).
5. **The role variables** (`group_vars/mod_caddy_edge.yml`, carried by `--group-vars`):

   ```yaml
   caddy_logical_id: edge
   caddy_registry: /abs/path/on/the/controller/lab/services.yml
   caddy_edge_hosts: [edge-01, core-01, idp-01]   # every host of THIS deployment's public rows and the auth proxy
   caddy_hnx_cli: [/abs/path/to/the/overlay/venv/bin/hnx]
   caddy_acme_domains: [hub.example.internal, sso.example.internal]
   caddy_front_door_refs: ["secret:status/front-door-secret"]
   caddy_auth_proxy_logical_id: auth-proxy
   caddy_auth_proxy_issuer_url: https://sso.example.internal/realms/<lab name>
   ```

   The rendered inventory's `ansible_host` is the guest's IPv4 address, which both binds default
   to. The hub trusts the edge by its client certificate's name and its address: set the hub's
   `status_hub_client_names` to the certificate's SAN and `status_hub_trusted_proxies` to the
   edge guest (H1).
6. **Apply**: `docker_engine` on `mod_caddy_edge`, then the rendered `modules.yml` twice (the
   second `changed=0`), then `checks/caddy.yml`. The first run obtains the certificate before
   Caddy starts (the renewal unit, so it is in its journal); test against Let's Encrypt's staging
   directory first (`caddy_acme_server`), whose chain the health hook will refuse.
7. **Prove it once on the lab**: the conformance run below with the binary from the pinned image,
   and the health hook (TLS, the sign-in redirect, the strip in the running configuration, the
   hub's mTLS refusal).

## Conformance

`conformance/target.yml` binds the `edge` suite to the shared Caddy adapter. The adapter runs a
Caddy of its own (`$HNX_CADDY`, else `caddy` on `PATH`) on loopback, configured with the
production pieces: the generator's `hnx_forward_auth` snippet and both strips, and this role's
catch-all; only the routing table is the suite's. It translates at the boundary (the module
docstring says how): the contract's `x-auth-user` is forged as every identity header in every
spelling, and read back from what the upstream receives as `X-Auth-Request-Preferred-Username`; the
sign-in redirect is the contract's 401. CI runs it in the `schemas` job against the pinned release
(`tests/modules/test_edge_module.py`, `HNX_REQUIRE_TOOLS=caddy`). Against the lab's pin:

```sh
docker create --name caddy-bin <caddy_image> && docker cp caddy-bin:/usr/bin/caddy ./caddy && docker rm caddy-bin
HNX_CADDY=$PWD/caddy hnx conform --root <homelab-next checkout> run edge \
  --target modules/caddy/conformance/target.yml
```

Findings: `forwarded-for-appended` (SHOULD) fails by design. Caddy trusts a client's
`X-Forwarded-For` only from a configured `trusted_proxies` (the edge has none, it is the first
proxy), so it replaces the header with the connection's address rather than appending to it.
Every MUST passes, and a strip removed from the configuration fails `spoofed-identity-header-stripped`
(the module's test holds that).

## Known limits

- **The forged-header check in `health` is structural**: it reads the running configuration and
  checks the strip is first on every site; the end-to-end proof (a forged header never reaches an
  upstream) is the conformance run against the same binary and snippet. An upstream that echoes
  headers would make it end to end; none is deployed.
- **The containers' network is Docker's default bridge**, so `egress` is not enforced for them
  (`hnx modules check` warns). The ACME client runs on the host, not in a container.
- **The front door's secret and the IdP client's secret** are read by reference from names
  outside the module's own secret namespace (the hub's and the realm's), so the manifest's `credentials` does not
  list them (a module lists only its own namespace).
- **Newer releases exist but are younger than 14 days** at this pin: Caddy 2.11.8 and 2.11.9
  (security fixes, mostly FastCGI and `client_auth` merging, neither used here) and oauth2-proxy
  7.15.6 (dependency CVEs). `tools/pin_freshness.py` reports them once they pass the cooldown.
- **Removal** exports first, takes both containers down, disables the renewal timer and deletes
  the credentials the secret store holds the source of (both env_files, the upstream TLS files,
  the DNS token). The certificate and its key, the ACME account and the export stay unless
  `-e caddy_remove_purge=true` (archive them first if the account is to be kept); the compose
  projects stay.
- **A session outlives a removal at the IdP**: oauth2-proxy has no refresh here (scope `openid`
  only), so a disabled or removed user keeps a session for up to `caddy_auth_proxy_cookie_expire`
  (4h; at most 12h). Rotating the cookie key signs everyone out at once. A short lifetime with
  `offline_access` and cookie refresh is a follow-up with the realm.
- **The auth proxy on the guest's address** rather than on a private network shared with Caddy:
  `compose_app` has no networks key yet, so the two compose projects meet on the guest's address;
  the hypervisor's firewall is the control (above), and Caddy overwrites `X-Forwarded-*` and
  `X-Real-IP` on its own requests. A shared internal network is a follow-up.
- **The renewal unit holds the docker socket** (root on the host) for its reload, in the same unit
  that runs lego, so its sandbox (`ProtectSystem=strict`, only `CAP_CHOWN`) does not confine
  what the socket allows. A reload through a Caddy admin socket on a shared directory, or a
  separate reload unit, is a follow-up.
- **Renewal failures surface late unless paged**: `caddy_acme_on_failure` is empty by default
  (this repository ships no paging unit); without it a failing renewal shows in the unit's
  last-run record and fails `health` only 14 days before expiry. Set it in the overlay.
- **A new public name** needs its registry row (on a host in `caddy_edge_hosts`), the name in
  `caddy_acme_domains` (the role refuses either without the other), and a certificate reissue,
  which the next `main` starts by itself (the installed certificate no longer names exactly the
  configured names).
- **No access log**: the generated sites carry no `log` directive, so Caddy logs no requests;
  the hub's own log names the user. An edge access log is a follow-up in the generator.
- **The suite does not prove** the auth proxy's 403 for a signed-in user outside a site's allowed
  groups (the contract has no such check); the generator's tests pin the `allowed_groups`
  argument and `caddy_auth_proxy`'s health proves the sign-in path.
