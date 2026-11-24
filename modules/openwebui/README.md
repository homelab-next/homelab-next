<!-- SPDX-License-Identifier: Apache-2.0 -->
# Module `openwebui`: the chat provider

A provider module ([module manifest](../../docs/modules.md), draft, ADR-0027 proposed) that fills
the `chat` slot with [Open WebUI](https://openwebui.com), the lab's chat front end. It is a
**service, not a machine**: the guest is the site's guest file, and the site's selection places the
module's one host role (`server`) on it. Nothing here names a real host, address, VM id, model or
secret value; those live only in the private overlay.

| | |
|---|---|
| Slot | `chat` (provisional: no contract or suite yet), stateful, object-tree export |
| Adapter | `homelabnext.conform.adapters.chat:make`, a read-only probe (`/health`, the anonymous `/api/config`) |
| Product | Open WebUI 0.12.5, `ghcr.io/open-webui/open-webui` pinned by tag and digest |
| Host role | `server`: kind `vm`, baseline `base`, footprint 2 vCPU, 3 GB, 10 GB |
| Role | `openwebui` (role interface v1), a wrapper of the core [`open_webui`](../../docs/model-serving.md) role, itself a wrapper of `compose_app` |
| Requires | `cap:secrets`, `cap:inference` (the gateway), `cap:idp` (the sign-in) |
| Egress | none requested: the app calls the gateway and the identity provider, both on the lab network |
| Public route | the row declares `public_hostname` (the site's value), `auth: idp` and `roles`; the edge serves it |

Old-lab context (configuration intent only): concierge-core, two users, "the answers that matter
live in Paperless". The module starts **fresh**: no chat history comes over.

## Why a wrapper of the core `open_webui` role

The core role already holds what must not be re-derived: the fixed settings that make Open WebUI a
gateway client and nothing else (Ollama, direct connections, sign-up, community sharing, the update
check, telemetry, external apps, plugins, Tools, Functions, tool servers and pip installs all off;
`ENABLE_PERSISTENT_CONFIG=false`, so the environment is the configuration on every start), the
allowlist of extra settings and the reserved-name pattern that refuses everything that calls out,
the keys-only-in-the-0600-env_file rendering, and the health/backup/export/restore/upgrade hooks.
It was **not** usable as it was, for four reasons, and this change extends it additively (every new
option defaults to the old behaviour, its tests still pass):

1. it accepted only a registry service of capability `llm-gateway`; the new lab's gateway is
   capability `inference`, **as is every engine behind it**, so a capability check cannot tell them
   apart. New `open_webui_gateway_capabilities` and `open_webui_gateway_impls` (the registry's
   `impl`, new `hnx_registry` field `impl`): the module requires the gateway's product, and the
   backend-name pattern (which would refuse an id named `inference`) applies only when no product is
   named;
2. it could send no header: the gateway needs `X-HNX-TLP` and `X-HNX-Tag` (below);
3. it had no sign-in but local accounts (`OAUTH_*`/`OPENID_*` are reserved names for extra settings,
   on purpose) and no break-glass administrator;
4. web search was only "not set"; it is now fixed `false` unless the site names the lab's
   metasearch service (below).

The module role (`roles/openwebui`) maps `openwebui_*` onto `open_webui_*` in one place
(`tasks/map.yml`), adds the module's policy (`tasks/validate.yml`: the sign-in and the administrator
are required, never `red`, the row is the `chat` row and its `public_hostname` is the address sign-in
returns to) and a stricter `health`.

## Models: the gateway only, with this app's own key

- `OPENAI_API_BASE_URLS` is the gateway's registry URL plus `/v1` (the registry resolves the id the
  overlay gives, `openwebui_gateway_id`); **there is no provider key** and no second connection:
  Ollama and direct (user-added) connections are off. **The environment is authoritative only at
  start** (`ENABLE_PERSISTENT_CONFIG=false` makes each start re-read it and forget what the UI
  saved); an administrator's edit of the connection in the admin UI can take effect in the
  *running* process until the next restart. The module does not pretend otherwise: `health` signs
  in as the break-glass administrator and reads the running connection back, and fails (red) when
  its base URL or its two headers differ from the rendered ones; a restart restores them. The
  real bounds are the gateway key's `tlp_ceiling`, roles and limits (an edit cannot give the app
  a better key than the one it holds) and the guest's firewall (no other destination is
  reachable). The check needs the break-glass password unchanged; if the administrator changes it
  in the UI, `health` fails on the sign-in until the secret is updated.
- The key is the store's **`gateway/key-openwebui`** (reference `secret:gateway/key-openwebui`), the gateway spec's `keys:` entry for this caller
  (roles, `data_tier`, `tlp_ceiling`, limits; see [modules/gateway/README.md](../gateway/README.md),
  "Using it in a site", steps 4 and 5). It is outside this module's secret namespace because the
  gateway's spec names it; the role reads it by name (`openwebui_gateway_key_ref`), and it reaches
  the container only through the env_file.
- **Headers.** The gateway judges a request by `X-HNX-TLP` (no field reads as **red**, and a role
  that leaves the lab refuses it) and records `X-HNX-Tag`. Open WebUI cannot add arbitrary headers
  through a plain environment variable, but each connection has a `headers` setting
  (`OPENAI_API_CONFIGS`, a JSON object by connection index, read in the pinned release,
  `utils/headers.py`), applied to **every** call of that connection (chat, the model list, title and
  tag generation) and substituting placeholders per request. The role renders
  `{"0": {"headers": {"X-HNX-TLP": "<label>", "X-HNX-Tag": "<prefix>:{{USER_ID}}"}}}`:
  - `X-HNX-TLP` is **static for the whole app** (`openwebui_gateway_tlp`, default `amber`; never
    `red`). Open WebUI has no notion of the sensitivity of one chat, so a label per message is not
    possible here: the app is one classification, and the gateway key's `tlp_ceiling` and the
    role's own ceiling are what actually bound it. Raise or lower it for the whole app by the
    variable. A role that leaves the lab needs the label at or below the role's ceiling.
  - `X-HNX-Tag` is `<prefix>:<signed-in user's id>` (`openwebui_gateway_tag_prefix`), so the
    gateway's `usage.jsonl` says whose calls they are. Both values match the gateway's tag pattern
    (checked by a test) and the tag survives an empty id (`openwebui:`).
  - The user-info headers (`X-OpenWebUI-User-*`) are **not** forwarded.

## Sign-in: the identity provider, plus a break-glass administrator

- The row is `auth: idp` with `roles: {user: [...], admin: [...]}`: the realm generator
  (ADR-0034) renders **a confidential client named after the row** (authorization code with PKCE
  S256, redirects `https://<public_hostname>/*`, the client's `roles` and `groups` claims and
  `preferred_username`), its secret is the store's `idp/clients/<row>` (the generator's name; the role
  reads it by that name, `openwebui_oidc_client_secret_ref`, which the overlay sets), and the edge's forward-auth
  lets in the `roles` groups only. A person therefore passes the edge's check, then Open WebUI's own
  OpenID Connect login through the same client (the identity provider's session makes the second
  step silent). It cannot be an `auth: own` row: the generator renders clients for `auth: idp` rows
  only.
- Open WebUI is configured with `OPENID_PROVIDER_URL` (the issuer's discovery document),
  `OPENID_REDIRECT_URI=<public_url>/oauth/oidc/callback`, scopes `openid email profile` (the realm's
  client has `email` and `profile` as optional scopes), `S256`, `OAUTH_USERNAME_CLAIM=
  preferred_username`, **role management on**: `OAUTH_ROLES_CLAIM=roles`, allowed roles
  `user,admin`, admin roles `admin`; a person with neither client role is refused. Accounts are not
  merged by email.
- **Break-glass administrator.** `openwebui_admin_email` and `secret:openwebui/admin-password`
  create a local administrator **at start, only while the database has no user** (`WEBUI_ADMIN_*`),
  and turn sign-up off. This also closes a trap: Open WebUI makes the first account that signs in an
  administrator, so without it the first OpenID Connect sign-in would be one. The password form
  stays on (`ENABLE_LOGIN_FORM`) so the administrator can sign in when the identity provider is
  down. `health` fails while `/api/config` still reports `onboarding` (no administrator yet).
- The container reaches the identity provider by its public name over verified TLS from the system
  trust store; with an issuer certificate from the lab's own CA the image would need that CA added
  (not done: the edge serves a public-trust certificate for the sign-in name).

## What it cannot do within these rules (honest list)

- **Server-side execution and fetching** is fixed off by environment: web search, code execution
  and the code interpreter (both default **on** upstream), image generation and editing,
  automations, local web fetch (and web loader TLS verification fixed on), external apps, plugins,
  Tools, Functions and tool servers. One path has no switch in 0.12.5: attaching a URL to a chat
  makes the server fetch it with the web loader; the guest's firewall is what bounds where.
- **A different TLP per chat or per user.** One label for the whole app (above).
- **Show only some of the gateway's roles to some users.** Which models appear is the gateway key's
  `roles`; Open WebUI's per-user model access (workspace) is the admin UI's and is overridden by
  the environment only where the role sets it. One key, one set of roles for both people.
- **Paperless as a knowledge source is a later step.** Not built. It needs an API token for
  Paperless's REST API (`secret:openwebui/paperless-token`, to be added to the manifest with that
  step), a call out of the container to the Paperless service (a firewall rule and a registry
  upstream), and a way to feed it in that keeps the rules: Open WebUI's built-in retrieval (RAG)
  loaders and embeddings call an embedding engine of their own and are **reserved** here (an
  embedding backend behind the gateway does not exist yet: the gateway module's "No `embeddings`
  feature" limit), so the likely route is a Tool or an agent outside the container. Tools and
  Functions run admin-supplied Python in the container and are off by environment. Decide that
  with the Paperless module's author, not here.
- **Web search** is off unless the site names the lab's own metasearch service
  (`openwebui_web_search_id`, a registry row of capability `web-search`, e.g. the `searxng`
  module). It cannot be enabled by an extra setting (a reserved name), nor pointed at any other
  engine. When on, Open WebUI asks that service for JSON results (`/search`) and answers from the
  results' **snippets only**: `BYPASS_WEB_SEARCH_WEB_LOADER` and
  `BYPASS_WEB_SEARCH_EMBEDDING_AND_RETRIEVAL` are set, so the container fetches no result page and
  embeds nothing, and needs no internet egress (the metasearch guest holds that grant). The chat
  guest's firewall must admit the service's port. In native function-calling mode the model also
  gets the built-in `search_web` and `fetch_url` tools; `fetch_url` is bounded by the guest's
  firewall (it can reach nothing outside the lab).
- **Enforce the no-egress rule in the network.** The container is on a bridge network, so
  `egress: none` is what the app is configured to do, not a network rule (`hnx modules check`
  warns). The control is the per-VM firewall in the overlay: the guest may reach the gateway, the
  identity provider and the resolver, nothing else. `OFFLINE_MODE=true` stops the model-hub
  downloads (the embedding model, the update check) the container would otherwise try.
- **A migration.** Fresh by the operator's decision; `export`/`restore` handle this instance's own
  data directory only.

## Hooks

| Hook | What it checks or does |
|---|---|
| `readiness` (also the module's preflight) | `docker_engine` readiness; the inputs are valid; the row is the `chat` row and public at the address sign-in returns to; the gateway id resolves to the gateway's product (not an engine) and accepts connections; every secret resolves and is long enough |
| `health` | the core role's (the container running and healthy, `/health` 200), then the anonymous `/api/config`: **an administrator exists** (no `onboarding`), sign-up off, the password form on, and the one provider `oidc`; then, signed in as the break-glass administrator, **the running connection**: its base URL is the gateway's registry URL plus `/v1`, it is the only one, and its `X-HNX-TLP` and `X-HNX-Tag` headers equal the rendered ones (an admin-UI edit turns this red). Read-only (the keys in the answer are never printed) |
| `export` / `backup` | the core role's: the data directory (the SQLite database, uploads, the vector store) as the open-format exit copy / the backup manifest. The export is a file copy: take it with the app stopped for a guaranteed-consistent database |
| `restore` | the core role's, from `openwebui_restore_source` |
| `upgrade` | refuses a target not pinned by tag and digest or of another repository, then records the bump; the playbook exports first (the database is migrated forward on the new image's first start) |

## Using it in a site

The overlay carries every real value ([selection](../../docs/modules/selection.md),
[registry rows](../../docs/modules/registry-rows.md), [apply path](../../docs/modules/apply.md)):

1. **A guest file** (`lab/guests/<name>.yml`): the module's `server` role on a guest with
   `docker_engine`; its `firewall_rules`: inbound 8080 from the edge guest only; outbound the
   gateway's port and the identity provider's name (443) and the resolver, nothing else.
2. **The selection** (`lab/modules.yml`): `hosts.<name>: {guest: guest:<name>}`,
   `slots.chat: [{provider: openwebui, instance: <row name>, placement: {server: <name>}}]`, and the
   grant `grants.public_routes.openwebui: [<row name>]`. Remove `chat` from `planned`, if listed.
3. **The registry row**: `registry/services.yml`'s `chat` row renamed to the instance, `host` the
   guest, `version: "0.12.5"`, `public_hostname` the site's name, `roles` the site's groups (the
   module's example groups are placeholders), plus at most `standing`, `backup_job`, `scope`.
   `upstreams: [inference]` names the gateway's row (rename it if the gateway instance is named
   otherwise). The edge needs the site on its list (`caddy_acme_domains`) and the generated realm
   must be re-rendered and applied so the client exists **before** the module's first start.
4. **The gateway side**: a `keys:` entry for this caller in the gateway spec (roles, `data_tier`,
   `tlp_ceiling` at least the label chosen here, limits) and the secret `gateway/key-openwebui`
   (32 to 512 characters), then the gateway re-rendered and restarted.
5. **The secrets**, by name: `gateway/key-openwebui`, `idp/clients/<row name>` (the realm
   generator's name for the client's secret), `openwebui/session-key` (32 characters or more),
   `openwebui/admin-password` (12 or more).
6. **The role's variables** (`group_vars/mod_openwebui_server.yml`): `openwebui_logical_id` (the row
   name), `openwebui_gateway_id` (the gateway's row), `openwebui_gateway_impls` (`[hnx-llmgate]`: the product the
   gateway's row names, which tells it from an engine behind it), `openwebui_public_url`
   (`https://<public_hostname>`), `openwebui_oidc_issuer_url` (`https://<sso name>/realms/<realm>`),
   `openwebui_oidc_client_secret_ref` (the generator's reference for the row's client secret),
   `openwebui_admin_email`; optionally `openwebui_gateway_tlp`, `openwebui_gateway_tag_prefix`,
   `openwebui_extra_env`, `openwebui_web_search_id` (the metasearch row; add it to the chat row's
   `upstreams`) and `openwebui_web_search_result_count`.
7. **Apply**: the firewall rules (three applies, see the cutover notes), `docker_engine`, the realm,
   the edge, then the rendered `modules.yml` twice (the second `changed=0`), then `checks/openwebui.yml`.
8. **First sign-in**: the break-glass administrator signs in with the form once to prove it works
   (and then keeps the password in the store); the two people sign in through the identity provider.

## Known limits

- The two-step sign-in (edge forward-auth, then Open WebUI's own) is a consequence of the realm
  generator rendering clients for `auth: idp` rows; it is silent while the identity provider's
  session lasts.
- The public configuration check reads Open WebUI 0.12.5's `/api/config` shape; a release that
  changes it fails `health` loudly (a missing key), which is the signal to re-read it.
- Open WebUI's licence is not an OSI one: its branding clause (keep the "Open WebUI" name and logo)
  applies above 50 users; the lab has two. The manifest's `spdx` is a `LicenseRef`.
