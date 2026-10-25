---
summary: 'The vendor-neutral site model (site.yml): zones, router, switches, firewall intent and DNS policy, validation, rule order and adapters, with the UniFi dry run.'
summary_of: outline:sha256:3674cb724285c094
---
# Site / network model

One document, `site.yml`, describes the network of a site in vendor-neutral terms: zones (VLANs and
subnets), the router and switches, the zone-to-zone and service-level firewall intent, DNS policy
and which adapters realise it. Adapters turn that intent into the files a particular platform
needs. Swapping the router product means selecting another adapter, not rewriting policy.

The model is testable with no hardware. Everything below runs on a laptop; applying a result to a
live device is **SERVER-only** and is not implemented in this repository.

```
site.yml + services.yml --validate--> IR --adapter--> files --plan--> diff against current
```

## Files

| Path | Role |
|---|---|
| `schemas/platform/site.schema.json` | the contract (shape). Examples and negatives sit next to it |
| `schemas/platform/examples/site.valid.yml` | the synthetic example site used by every test |
| `tests/network/fixtures/services.yml` | the service registry that example resolves against |
| `homelabnext/network/` | loader, validation, intermediate representation, adapters, plan, CLI |
| `tests/network/golden/<adapter>/` | the rendered output of the example, per adapter |

The registry is the one defined by `schemas/platform/service.json`. The site document references it
by id and never repeats it: a service is `svc:<id>`, a zone is `zone:<id>`, and a registry host
supplies the address. There is no endpoint literal and no secret value anywhere in a site document;
authentication is a `secret:<name>` reference to an entry in the secret store.

## The document

| Block | What it says |
|---|---|
| `site` | `id`, `domain`, `timezone` (UTC unless there is a reason) |
| `zones[]` | `id`, `purpose`, `vlan_id`, `subnet`, `gateway`, optional `dhcp.range`, `dns.resolvers`, `egress`, `tags` |
| `router` | `id`, `model` (the adapter), `mgmt_endpoint` (a `svc:` reference), optional `tls_pin`, `auth.reads` / `auth.writes` as `{mode, secret_ref}`, `power` (1.1) |
| `switches[]` | `id`, `model`, `device_mac`, `uplink_port`, `port_assignments` (access or trunk, ports and ranges), `power` (1.1) |
| `edge[]` (1.1) | the uplink chain, outermost first: `{id, kind: internet \| modem \| ont \| router \| firewall \| switch \| other, model, power}`; an entry whose `id` is the router's or a switch's is that device |
| `power` (1.1) | `ups[]` (`id`, the logical id everything names; `model`, `monitored_by: nut \| snmp \| usb \| none`, `nut_name` (what the power monitor queries), `serial`, `mac` only for a UPS with a network card) and `default` (the power of a device that declares none) |
| `tailnet` (1.2) | `deploy`: the CI deploy tag's tailnet access, `{tag, owners, zones, exceptions}` (see [Deploy access](#deploy-access-12)) |
| `dhcp_reservations[]` | pin a registry host to a hardware address |
| `firewall` | `default_action` (always `deny`), `zone_to_zone[]`, `service_exceptions[]` |
| `dns` | `resolvers[]`, `records.static[]`, `policy` (`split_horizon`, `ttl_default`) |
| `adapters` | site-wide choices: `network`, `dns`, and per-adapter `options` |

`firewall.default_action` has a single legal value. Anything not listed is denied; there is no way
to write a permissive default.

## Validation

`hnx site validate` runs the JSON Schema and then the semantic rules, which only report and never
repair. Errors block `plan` and `render`; warnings do not.

Before the schema, any key or value holding a control character (a newline included) is an error.
Adapters write line-oriented configs, and Python's `re`, which the schema validator uses, lets a
pattern's `$` match before a trailing newline, so a pattern alone does not keep `"lan\n"` out.

* VLAN ids are unique; subnets are valid, large enough and do not overlap.
* The gateway is a usable address inside its subnet; a DHCP range is ordered, inside the subnet and
  excludes the gateway and every statically addressed registry host.
* Every `zone:` and `svc:` reference resolves, against the site and the registry respectively.
  Registry zones must exist in the site with the same CIDR.
* Switch ports are not assigned twice; VLANs named on ports are zones; the uplink is a trunk.
* No two `zone_to_zone` rules cover the same pair; deny rules apply to the whole pair; ports need
  tcp or udp.
* A URL, or an IP literal outside the fields that define addressing, is rejected: use a reference.
* DNS names stay inside the site domain and do not shadow a name generated from the registry.
* The router and switch `model`, and `adapters.*`, must name a known adapter.

### Power (1.1)

What feeds each machine is data, so a power cut can be reasoned about before it happens. The site
lists its UPSes under `power.ups`; every device names what it draws from with
`power: {ups: <id> | [<id>, ...]}` (two power supplies on two UPSes is a list) or
`{ups: none, reason: "..."}`, and `power.default` covers the common case. The devices are the
router, every switch, every `edge` entry but the internet, every hypervisor (`_nodes.yml`:
`nodes: {hv-1: {power: {ups: ups-a}}}`, or any node a guest is placed on) and every physical host
(a guest with `kind: host`, guest schema 1.4). A VM or container never declares power: it is only
as protected as its hypervisor and inherits that.

The rules live in one place, `homelabnext/power.py`. `hnx site validate` checks the site's half:
an unknown UPS id; a UPS named `none` (reserved); duplicate UPS or edge ids; `none` without a
reason; a router, switch or edge device with no declaration and no default; a device declared
both on its `edge` entry and on the router or switch it is; power on the internet. `hnx guests
validate DIR --site SITE` checks the rest against the site: the hypervisors and physical hosts
(declared or defaulted, known ids, a reason with `none`, `_nodes.yml` and a host guest file not
disagreeing), a VM or container with its own `power`, and **a UPS that feeds nothing, which is an
error**: a UPS in the model is part of the lab, so it is wired to something or it does not belong
in the model (a spare on a shelf is inventory, not topology). A site without a `power` section
asks none of this, so sites written before 1.1 stay valid.

The Topology map draws the edge chain at the top, the UPSes with what they feed (dotted lines on
"Show Power"), a `UPS: <id>` or `no UPS` badge on every powered card (the reason in its tooltip
and detail panel), and each guest's inherited power in its detail panel
([status hub](status.md#generated-maps-topology-dataflow-architecture-roadmap)). A UPS with
`monitored_by: nut` and a `nut_name` becomes a live status source of the hub (`poll-nut`, generated
from this section; [status hub](status.md#8-ups-power-network-ups-tools)): its state shows on its
Topology card, and going on battery sends one message listing the guests on it.

### Deploy access (1.2)

The private overlay's deploy joins the tailnet with an ephemeral key tagged `tag:ci-deploy`
([private overlay](private-overlay.md#tailscale-the-deploy-tag-least-access)). What that tag may
reach is site data, so the tailnet policy is generated rather than hand-edited:

```yaml
tailnet:
  deploy:
    tag: tag:ci-deploy           # the default
    owners: [autogroup:admin]    # who may mint keys for the tag (tagOwners); never a tag
    zones: [mgmt, data]          # TCP 22 on these zones' tailnet nodes, nothing else
    exceptions:                  # optional: another port, on some deploy zones, with its reason
      - {zones: [mgmt], ports: [9443], reason: "the identity provider's admin API"}
```

The rules live in `homelabnext/tailnet.py` and run in `hnx site validate` and when `hnx guests`
reads the site: zones by id only (`*`, `any` or a tag is refused, so there is no wildcard
destination); a zone of the site, listed once; an exception names deploy zones, ports other than
22 (or `"*"`, every port) and a reason of at least ten characters; the tag is not a zone tag; the
owners are people, never a tag (a user login, a `group:`, or `autogroup:admin`, `owner`,
`it-admin` or `network-admin`): a tag owner lets every node carrying that tag apply the deploy tag
to itself, so a zone tag owner would make any node of the zone the deploy. `hnx guests render ... --target tailscale-acl` renders it
([compute model](compute-model.md#bound-products)), with policy `tests` Tailscale runs on every
change.

### One-way zones

A zone with `egress.one_way: true` (for example a malware-analysis zone) may not be reached and may
only send out through listed `service_exceptions`. The document must prove it:

* `egress.internet` is `deny`;
* exactly one `zone_to_zone` rule `{from: <zone>, to: any, action: deny, one_way_contract: true}`;
* no `allow` into the zone, whether a zone rule or an exception to a service that lives in it;
* no `allow` rule out of it except through `service_exceptions`.

## Intermediate representation and rule order

`homelabnext.network.ir.build_ir` produces a frozen, JSON-serialisable `NetworkIR`: the VLAN
interface plan, DHCP pools and reservations, DNS records, resolvers, switch port plan, router
plan and the firewall policy. Adapters render the IR and nothing else, so they cannot disagree
about meaning. `hnx site ir` prints it.

Firewall rules are evaluated first match wins, in this order:

1. `service_exceptions`, in document order (host-specific beats everything general);
2. `zone_to_zone` rules whose `to` is a zone, in document order;
3. `zone_to_zone` rules whose `to` is `any` (the one-way contracts);
4. internet egress, one rule per zone from `egress.internet`;
5. the default: deny.

Return traffic is allowed by connection state, not by rules. A registry service of protocol `dns`
expands to both udp and tcp.

## Adapters

`hnx site adapters` lists them.

| Adapter | Status | Output |
|---|---|---|
| `linux` | ready | systemd-networkd VLAN files (or `/etc/network` with `flavor: ifupdown`), a forwarding sysctl, one nftables file with a set per zone, a default-drop forward chain and masquerade for zones with internet egress |
| `dnsmasq` | ready | DHCP pools, DHCP reservations and local DNS records as `dnsmasq.d` drop-ins, including split-horizon answers |
| `zonefile` | ready | RFC 1035 master files per authoritative domain, plus one per split-horizon override domain. The SOA serial is `adapters.options.zonefile.serial`, else derived from that zone's records |
| `unifi` | ready, DRY-RUN | JSON payloads for networks and VLANs, firewall rules, port profiles and switch port overrides |
| `opnsense` | **deferred** | none: see below |

All adapters are pure and deterministic: the same IR yields the same bytes, file order is sorted,
and nothing opens a socket (a test patches the socket module to prove it).

### The UniFi adapter is a dry run

It builds the documents a UniFi-class controller would be sent. It makes no network call, holds no
credential (`controller.json` carries `secret:` reference names only), and has no apply. Objects
refer to one another with `${network:<name>}` placeholders that are resolved to controller ids at
apply time. The golden files pin *our rendering* of the documented object shapes; whether a given
controller version accepts every field is checked on the server. **SERVER-only:** reading the
controller state, resolving ids, and writing the objects.

### OPNsense is deferred

This release registers the name (a site document may select it) and the interface, and the CLI
answers with a clear "deferred" message and exit status 2. No config-XML is rendered, because XML
that cannot be loaded into a real instance in CI would prove only that we can print XML. A test
proves the registry rejects an unknown adapter cleanly and treats `opnsense` as deferred, not
unknown. The adapter returns when a run against a real or containerised instance can back it.

## Plan, render, idempotency

```
hnx site validate site.yml --registry services.yml
hnx site plan     site.yml --registry services.yml --adapter linux --current ./deployed/ [--exit-code]
hnx site render   site.yml --registry services.yml --adapter linux --out ./deployed/ [--prune]
```

Without `--registry` the file `services.yml` next to the site file is used. Without `--adapter`,
`adapters.network` is used, else `router.model`.

`plan` compares the rendered files with a directory of current state (the last applied render, or a
snapshot taken from a device) and prints a summary followed by unified diffs. JSON payloads that are
shaped `{"objects": [{"name": ...}]}` also get an object-level summary (`+ hnx-edge`, `~ hnx-mgmt`,
`- hnx-old`). Files in the current tree that carry the generated-file marker but are no longer
rendered show as deletions; hand-written files are never touched. `render` writes only the files
that differ, so a second run writes nothing, and `plan` against its own output is empty. This is
the review step of the swap kit: render the old and new adapter into two directories and read the
diff.

Exit status: 0 success, 1 invalid site or registry, 2 usage error or an unknown or deferred
adapter, 3 `plan --exit-code` found changes.

## Out of scope here (SERVER)

Applying files to a router, switch or controller; reading live controller state; certificate
pinning against a real console; IPv6 zones; reverse DNS zones. The adapter interface has an
`apply` that raises `ServerOnly` for every adapter, so the seam exists and cannot be used by
accident.
