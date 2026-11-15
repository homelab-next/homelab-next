<!-- SPDX-License-Identifier: Apache-2.0 -->
# Module `tunnel`: a connector for a remotely managed tunnel

A provider module ([module manifest](../../docs/modules.md), draft, ADR-0027 proposed) that fills
the `tunnel` slot with [cloudflared](https://github.com/cloudflare/cloudflared), the connector of
a Cloudflare Tunnel that is **remotely managed**: its public hostnames, ingress rules and Access
policies live in the Cloudflare dashboard, and the connector needs one credential, the tunnel
token. It is a **service, not a machine**: the guest it runs on is the site's guest file, and the
site's selection places the module's one host role (`server`) on it (in the first lab, the edge
guest, next to the front door). Nothing in this directory names a real host, address, VM id or
secret value; those live only in the private overlay.

| | |
|---|---|
| Slot | `tunnel` (provisional: no contract yet), stateless |
| Product | cloudflared 2026.10.7, `docker.io/cloudflare/cloudflared` pinned by tag and digest |
| Host role | `server`: kind `vm`, baseline `base`, footprint 1 vCPU, 256 MB, 2 GB |
| Role | `tunnel` (role interface v1), a wrapper of the core `compose_app` |
| Requires | `cap:secrets` (the token, read by name at deploy time) |
| Egress | `internet` from `server`, outbound only (Cloudflare's edge, port 7844) |
| Inbound | none, except the metrics and readiness listener on the guest's address (registry port 20241) |
| Public route | none here: the public names are the tunnel's, in the dashboard |

## What the role does

`roles/tunnel` renders one `compose_app` service:

- **The image** is `repository:tag@sha256:digest` (the multi-arch index digest of 2026.10.7, 16
  days old when pinned); `tools/pin_freshness.py` watches it.
- **Remotely managed, so no ingress configuration.** The container is started as
  `tunnel --no-autoupdate --metrics :20241 run` with `TUNNEL_TOKEN` in its environment. There is
  no config file, no volume and no `--config`; the role never renders an ingress rule, so the
  dashboard stays the single place a hostname or origin is decided. Auto-update is off: the pin
  moves by the upgrade hook only.
- **The token is the only secret**: `secret:tunnel/token`, written to the compose
  env_file (`secrets/tunnel.env`, 0600) through `hnx_secret` in `no_log` tasks. The role
  **refuses an empty token** (and one that is not base64 of the `{a, s, t}` object cloudflared
  reads) before anything is rendered or started, naming the secret and never printing it. The
  token is the tunnel's, shared by every connector of that tunnel.
- **Outbound only.** The only port the container publishes is the metrics and readiness listener,
  on the guest's own address (`tunnel_bind`, default the inventory's `ansible_host`; all
  interfaces is refused) at `tunnel_port` (20241, the registry row's port, the old lab's too).
- **The container** runs as the image's non-root user (65532), every capability dropped,
  `no-new-privileges`, a read-only root filesystem, a memory limit, bounded logs, and a
  healthcheck (`cloudflared tunnel ready`).
- **UDP buffers (LL-173).** QUIC wants a large receive buffer; the old lab's tunnel thrashed on
  an undersized `net.core.rmem_max` (208 KiB against ~7 MiB) while every container and LAN check
  stayed green. The role keeps `net.core.rmem_max` and `wmem_max` at least
  `tunnel_udp_buffer_bytes` (8 MiB) in a sysctl.d file and applies them (`tunnel_sysctl_manage`
  false leaves it to the baseline).

## Hooks

| Hook | What it checks or does |
|---|---|
| `readiness` (also the module's preflight) | `docker_engine` readiness, and the token resolves, is not empty, is base64 and decodes to a JSON object with the keys `a`, `s`, `t` |
| `health` | every container running and healthy; the port published on the guest's address only; `GET /ready` on the metrics port is **200** and its `readyConnections` is at least `tunnel_min_connections` (1). The daemon's own view, read-only |
| `backup`, `export`, `restore` | nothing to do: the connector keeps no data (the tunnel, names and policies are the provider's) |
| `upgrade` | refuses a target not pinned by tag and digest or from another repository, then records the bump (`compose_app` upgrade) |

## Handing the tunnel over from another connector (design section 7)

The same tunnel can have several connectors at once, so a move never has a gap:

1. **Add a second connector to the same tunnel.** Deploy this module with the existing tunnel's
   token (`secret:tunnel/token`); no hostname, origin or Access policy changes. The
   health hook passes and the dashboard lists two connectors on the tunnel.
2. **Prove it.** Check the new connector from the Cloudflare edge, never from the LAN: a public
   name resolves through the LAN's split DNS to the internal front door, so a LAN test never
   touches the tunnel (LL-107, LL-173). Resolve the name with DoH or `dig` against a public resolver,
   then `curl --resolve` to the address it returns.
3. **Repoint the origin** of the public hostname in the dashboard (and the internal DNS name) to
   the new lab's front door. This is the only step that changes what users reach; the old
   connector can still serve if it is put back.
4. **Remove the old connector** only after the new one has run clean for a day: stop its
   container. The tunnel, its names and its Access policy are untouched.

Rollback at any point before step 4 is repointing the origin back; after it, start the old
connector again (it is the same token).

Public names are verified **via the Cloudflare edge only** (LL-107), never by a LAN resolver. The
health hook proves only that this connector holds connections; it cannot tell that a name works
end to end.

## Using it in a site

The overlay carries every real value ([selection](../../docs/modules/selection.md),
[registry rows](../../docs/modules/registry-rows.md), [apply path](../../docs/modules/apply.md)):

1. **A guest file**: the edge guest (it hosts the front door the dashboard's ingress points at),
   `firewall_rules` admitting the lab's monitoring to the registry port; outbound to Cloudflare
   (7844, tcp and udp) must be allowed. No inbound public port is opened.
2. **The selection** (`lab/modules.yml`): `slots.tunnel: [{provider: tunnel, instance: edge-tunnel,
   placement: {server: <host>}}]` (the instance name must not be `tunnel`: a module id may not equal a registry service name), and a `grants.egress.tunnel.server: [internet]` grant.
3. **The registry row** (`lab/services.yml`): `registry/services.yml`'s `tunnel` row renamed to
   the instance (`edge-tunnel`), `host` the guest's name, `version: "2026.10.7"`, plus at most the lab's own
   `standing`, `backup_job` and `scope`.
4. **The secret**, by name, in the secret store: `tunnel/token`.
5. **The role's variables** (`group_vars/mod_tunnel_server.yml`): `tunnel_logical_id: <instance>`.
6. **Apply**: `docker_engine` on the module group (`mod_tunnel_server`), then the rendered
   `modules.yml` twice (the second `changed=0`), then `checks/tunnel.yml`.

## Conformance

The `tunnel` slot has no contract yet (provisional), so there is no conformance suite; the proof
is the health hook against the real connector. Alerting on the connection count (a sustained drop
below the expected number of connections, a dead metrics endpoint) belongs to the `metrics`
module's scrape of the registry row.
