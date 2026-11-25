<!-- SPDX-License-Identifier: Apache-2.0 -->
# Module `searxng`: web search

A provider module ([module manifest](../../docs/modules.md), draft) that fills the `web-search` slot
with [SearXNG](https://docs.searxng.org), a metasearch engine: one query goes to many public search
engines and comes back as one result list, as a web page or as JSON. The lab's programs (research and
enrichment jobs) call it as an API. It is a **service, not a machine**: the guest is the site's guest
file and the site's selection places the module's one host role (`server`) on it. Nothing here names a
real host, address, VM id or domain; those live in the private overlay.

| | |
|---|---|
| Slot | `web-search` (provisional: no contract or suite yet), stateless |
| Product | SearXNG `2026.11.9-57ff753ad`, `docker.io/searxng/searxng` pinned by tag and digest (the multi-arch index digest) |
| Host role | `server`: kind `vm`, baseline `base`, footprint 1 vCPU, 1 GB, 5 GB |
| Role | `searxng` (role interface v1), a wrapper of the core `compose_app` |
| Secret | `secret:searxng/secret-key`: the instance key, 32 or more characters of letters, digits and `. _ ~ + = -` |
| Egress | the internet: the search engines' own sites, for every search |
| Public route | **none**. The row declares no `public_hostname`; a site that wants an edge route later adds one (the row's `public_hostname` and the grant) |

## Settings ported from the old lab

The old instance's configuration intent, rendered by the role into `settings.yml` (the template
`roles/searxng/templates/settings.yml.j2`); nothing else is set, so the product's defaults apply:

| Setting | Value | Why |
|---|---|---|
| `use_default_settings` | `true` | the product's whole default engine set; the file names only what differs |
| `search.formats` | `[html, json]` | **json is required**: the consumers call `/search?q=...&format=json`; without it the product answers 403 |
| `server.image_proxy` | `true` | result images are fetched through the service, so a caller's browser never contacts an engine's image host |
| `server.limiter` | `false` | see below |
| `server.public_instance` | `false` | this is a private service, not one offered to the internet |
| `search.safe_search` | `0` (variable `searxng_safe_search`: 0 off, 1 moderate, 2 strict) | the old instance's default |
| `general.instance_name` | variable `searxng_instance_name` (default `SearXNG`) | |
| `outgoing.request_timeout` | variable `searxng_request_timeout` (default `3.0` seconds) | an engine that is slower than this is dropped from that search |
| `server.secret_key` | read from `secret:searxng/secret-key` | see below |

**Why the limiter is off.** The product's bot limiter needs a key-value store (Valkey or Redis) beside
it and works from the client's browser fingerprint; an API caller (a script sending no browser
headers) is exactly what it blocks. This service is internal only and its callers are programs, so the
control is who can reach the port (the guest's firewall, below), not a limiter. Turning the limiter on
would also add a second container and break the JSON callers; the role does not offer it.

**The secret key** is read by name at deploy time and rendered only into
`<searxng_data_root>/config/settings.yml`, a file of mode 0600 owned by the container's user in a 0700
directory. It is never put in the compose file, the container's environment or any log: the tasks that
touch it run under `no_log`, and the health hook fails if the file is not 0600.

**Disabling engines.** `searxng_engines_disabled` (default `[]`) is a list of engine names; each is
rendered as `engines: [{name: <name>, disabled: true}]`. Because the file uses
`use_default_settings: true` (not the `keep_only` or `remove` forms), an `engines` entry is **merged
by name into the default engine of that name**: only the engines named change and every other engine
keeps its default. The names are the product's own, as the preferences page lists them; a misspelled
name does not fail, it adds a stray engine entry that the product ignores, so check the result on
the preferences page. To run only a chosen few engines instead, the `keep_only` form is needed, which
this role does not render.

## Hooks

- **readiness**: the container engine is ready, the inputs are valid, the secret resolves (the
  refusal names the reference, never a value) and is 32 or more characters of the allowed alphabet.
- **health** (read-only): the container is running and healthy; the settings file is 0600; `/healthz`
  answers 200; **and a real JSON search** (`/search?q=<searxng_health_query>&format=json`, default
  query `debian`) answers 200 with a `results` list. **Zero results fail health**: a metasearch whose
  engines are all blocked (or whose guest has no route out) still answers 200 with an empty list, so a
  health check that stopped at `/healthz` would pass on a service that finds nothing. A site that
  accepts an empty answer sets `searxng_health_require_results: false`; a body that is not a
  result list fails either way.
- **upgrade**: refuses a target that is not pinned by tag **and** digest or is another repository,
  records the bump, then the playbook converges on it. Nothing is exported first.
- **backup, export, restore**: the service is stateless (the settings are rendered from the site's
  variables and the key is in the secret store), so there is nothing to back up, export or restore;
  the hooks say so and write nothing. A rebuilt guest is a re-run of the install.
- **remove**: takes the container down and deletes the settings file (it holds the key). The compose
  project directory stays for the operator.

A change to the rendered settings restarts a container that was already running (the product reads
its settings at start); a first run and an unchanged re-run do not.

## Using it in a site

The overlay carries every real value ([selection](../../docs/modules/selection.md),
[registry rows](../../docs/modules/registry-rows.md), [apply path](../../docs/modules/apply.md)):

1. **A guest file** (`lab/guests/<name>.yml`): a VM, baseline `base`, resources covering the
   footprint (and the docker engine). Its `firewall_rules` admit the registry port (8095) **only from
   the named consumers' addresses**, and SSH from the deploy host. The guest file's rules render to the
   hypervisor's per-VM firewall, which filters before the guest; that is the control, because this
   service has no accounts and no limiter. An nftables rule inside the guest does not see the port
   (Docker publishes it through its own chains). Nothing else may reach it: anyone who can reach the
   port can spend the guest's egress on searches.
2. **The selection** (`lab/modules.yml`): `hosts.<name>: {guest: guest:<name>}`,
   `slots.web-search: [{provider: searxng, instance: <instance>, placement: {server: <name>}}]`, and
   the egress grant `grants.egress.searxng: {server: [internet]}`. Every other required core slot is a
   provider or an incumbent.
3. **The registry row** (`lab/services.yml`): `registry/services.yml`'s `web-search` row renamed to
   the instance, `host` the guest's name, `version: "2026.11.9-57ff753ad"`, plus at most the lab's own
   `standing`, `backup_job` and `scope`. `hnx modules check` compares them field by field. Add a
   `public_hostname` (and its grant) only if an edge route is wanted later; the module's own row has
   none.
4. **The secret**, by name, in the secret store: `searxng/secret-key` (32 or more characters; for
   example the output of `openssl rand -hex 32`).
5. **The role's variables** (the overlay's `group_vars/mod_searxng_server.yml`):
   `searxng_logical_id: <instance>` (required). Optional, with their defaults: `searxng_port: 8095`,
   `searxng_safe_search: 0`, `searxng_instance_name: SearXNG`, `searxng_request_timeout: 3.0`,
   `searxng_engines_disabled: []`, `searxng_health_query: debian`,
   `searxng_health_require_results: true`. `searxng_bind` defaults to the inventory's `ansible_host`
   (the guest's IPv4 address); a hostname is refused.
6. **Apply**: `docker_engine` on the module group (`mod_searxng_server`), then the rendered
   `modules.yml` twice (the second `changed=0`), then the `health` hook.
7. **Prove it once against the real service**: `curl -s 'http://<guest>:8095/search?q=debian&format=json'`
   from an admitted consumer returns a JSON document with a non-empty `results` list (CI runs the
   hooks against a stand-in; only the lab proves the engines are reachable).

## Known limits

- **Plain HTTP inside the lab.** No TLS and no accounts: the per-VM firewall is the only access
  control. Do not admit a network, only addresses.
- **Search engines rate-limit and block.** A metasearch from one address is throttled or captcha'd by
  some engines from time to time; the service then returns fewer results, and the health hook's
  non-empty check is what notices when it returns none.
- **The container's network is Docker's default bridge**, so `egress: internet` is a declaration the
  site grants, not a rule the module enforces; an outbound rule on Docker's FORWARD path is a
  follow-up.
- **No image-version freshness feed**: the project publishes dated container builds, not releases,
  so `tools/pin_freshness.py` lists the pin as checked by hand; a bump is a tag and its digest
  together (at least 14 days old).
- **The settings are the role's, not the preferences page's.** Changes made in the web UI apply to
  one browser only; the instance's behaviour is what the variables render.
