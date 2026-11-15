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
  `tunnel --no-autoupdate --metrics :20241 run --token-file /run/tunnel-join`. There is no config
  file and no `--config`; the role never renders an ingress rule, so the dashboard stays the single
  place a hostname or origin is decided. Auto-update is off: the pin moves by the upgrade hook only.
- **The token is the only secret**: `secret:tunnel/token`, written by the role to
  `<tunnel_data_root>/join/token` (0400, owned by the container's user, in a 0700 directory) and mounted
  read-only into the container. It is **not** in the container's environment, so not in
  `docker inspect` or `/proc/<pid>/environ`. Only the two tasks that handle it are `no_log`; docker
  and compose failures stay readable. The role **refuses an empty token** (and one that is not base64
  of the `{a, s, t}` object cloudflared reads, standard or URL-safe, padded or not) before anything
  is rendered or started, naming the secret and never printing it. The token is the tunnel's, shared
  by every connector of that tunnel.
- **Outbound only.** The only port the container publishes is the metrics and readiness listener,
  on the guest's own address (`tunnel_bind`, default the inventory's `ansible_host`; all
  interfaces is refused) at `tunnel_port` (20241, the registry row's port, the old lab's too).
- **The container** runs as the image's non-root user (65532), every capability dropped,
  `no-new-privileges`, a read-only root filesystem, a memory limit, bounded logs, and a
  healthcheck (`cloudflared tunnel ready`).
- **UDP buffers (LL-173).** QUIC wants a large receive buffer; the old lab's tunnel thrashed on
  an undersized `net.core.rmem_max` (208 KiB against ~7 MiB) while every container and LAN check
  stayed green. The role only **raises** `net.core.rmem_max` and `wmem_max` to
  `tunnel_udp_buffer_bytes` (8 MiB): it reads the live values, and when both are already at least
  that it writes nothing, so it never lowers a higher value another file set. `tunnel_sysctl_manage:
  false` leaves it to the baseline. The drop-in is kept on removal.

## Hooks

| Hook | What it checks or does |
|---|---|
| `readiness` (also the module's preflight) | `docker_engine` readiness, and the token resolves, is not empty, is base64 (URL-safe or unpadded accepted) and decodes to a JSON object with the keys `a`, `s`, `t` |
| `health` | every container running and healthy; the port published on the guest's address only; `GET /ready` on the metrics port is **200** and its `readyConnections` is at least `tunnel_min_connections` (1). The daemon's own view, read-only |
| `backup`, `export`, `restore` | nothing to do: the connector keeps no data (the tunnel, names and policies are the provider's) |
| `upgrade` | refuses a target not pinned by tag and digest or from another repository, then records the bump (`compose_app` upgrade) |

## Handing the tunnel over from another connector (design section 7)

**A tunnel has one ingress configuration shared by every connector, and the provider spreads
requests across all connected connectors.** So the moment a second connector is connected, a share
of real traffic reaches the origins in the CURRENT ingress through it; if its guest cannot reach
them, those requests fail while the module's health stays green. Joining a connector early is
therefore not traffic-neutral. The procedure keeps the new connector **stopped** until its origin is
the one in the ingress, and accepts a brief, announced outage window (a few seconds to a minute,
between stopping the old connector and the new one reporting ready connections).

1. **Deploy the new connector stopped.** Set `tunnel_start: false` for the first apply, so the
   container is rendered and the token file written but nothing connects. The health hook is
   expected to fail until it is started.
2. **Check the new origin is reachable** from the new guest (the edge service the ingress will
   point at, on the same guest or the LAN), and announce the window.
3. **Cutover window**, in this order: (a) in the dashboard change the public hostname's origin to
   the new edge service; (b) stop the old connector (`docker compose stop` on its host); (c) set
   `tunnel_start: true` and re-apply the module (or `docker compose up -d` in `<tunnel_dir>`).
   From (a) to (c) requests fail or go to the old connector's now-changed origin: that is the
   outage window.
4. **Verify** (see below): the new connector holds connections, serves requests, and the public
   name answers from the provider's edge.
5. **Rollback** is the reverse: stop the new connector, start the old one, set the origin back.
   The old connector stays stopped, not removed, until the new one has run clean for a day; then
   run `playbooks/remove.yml` on the old host's equivalent.

### Verifying

A request through the edge cannot show which connector served it, so attribute it by the new
connector's own request counter, then check the public name from the provider's edge, never a LAN
resolver (LL-107; the split DNS answers a public name with the internal front door, so a LAN test
never touches the tunnel). Placeholders: `<guest>` is the connector's guest address, `<name>` the
public hostname.

```sh
# 1. ready connections, and the request counter before
curl -fsS http://<guest>:20241/ready                       # {"status":200,"readyConnections":N,...}
curl -fsS http://<guest>:20241/metrics | grep '^cloudflared_tunnel_total_requests'
# 2. the edge's own answer for the name (DoH to a public resolver, not the LAN's)
curl -fsS -H 'accept: application/dns-json' 'https://cloudflare-dns.com/dns-query?name=<name>&type=A'
# 3. a request pinned to one of those edge addresses (<edge-ip> from step 2)
curl -sS -o /dev/null -w '%{http_code}\n' --resolve <name>:443:<edge-ip> https://<name>/
# 4. the counter after: it must have increased by at least the requests sent
curl -fsS http://<guest>:20241/metrics | grep '^cloudflared_tunnel_total_requests'
```

If the counter does not move while the old connector is still running, the old one served the
request: stop it and repeat. `cloudflared_tunnel_ha_connections` on the same endpoint is the
number of connections to the edge.

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
