---
summary: 'The vendor-neutral site model (site.yml): zones, router, switches, firewall intent and DNS policy, validation, rule order and adapters, with the UniFi dry run.'
summary_of: outline:sha256:4f4bead7bc3a3c24
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
| `router` | `id`, `model` (the adapter), `mgmt_endpoint` (a `svc:` reference), optional `tls_pin`, `auth.reads` / `auth.writes` as `{mode, secret_ref}`, `power` (1.1), `wan6` (1.6: the router's own IPv6 on the WAN, see [The WAN's IPv6](#the-wans-ipv6-16)) |
| `switches[]` | `id`, `model`, `device_mac`, `uplink_port`, `port_assignments` (access, trunk or mirror (1.3), ports and ranges), `power` (1.1) |
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
* A zone's `subnet6` (1.4) is one canonical IPv6 prefix, a /48 to a /64, with no zone id
  (`%scope`), that names that zone only ([IPv6 prefixes](#ipv6-prefixes-14)); no two overlap.
* The gateway is a usable address inside its subnet; a DHCP range is ordered, inside the subnet and
  excludes the gateway and every statically addressed registry host.
* Every `zone:` and `svc:` reference resolves, against the site and the registry respectively.
  Registry zones must exist in the site with the same CIDR.
* Switch ports are not assigned twice; VLANs named on ports are zones; the uplink is a trunk.
* A mirror port has `mirror_from` and no VLAN of its own; its sources are assigned on the same
  switch, listed once, are not mirror ports, and each is copied to one mirror port only. On a `unifi` switch a
  mirror port has exactly one source ([mirror ports](#mirror-ports-13)).
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

### Mirror ports (1.3)

A network sensor (Suricata, Zeek) on its own machine listens on a switch port that receives a copy
of other ports' traffic: a SPAN or mirror port. It is declared on the switch like any other port:

```yaml
port_assignments:
  - {ports: [1], kind: trunk, vlans: [10, 20, 30, 40, 50]}   # the uplink to the router
  - {ports: [9], kind: mirror, mirror_from: [1]}             # the sensor's capture NIC
```

Mirroring the uplink shows the sensor every packet that crosses the router, between zones and to
the internet; traffic between two hosts of one zone on one switch never reaches it. The mirror port
carries no VLAN, so the sensor's capture interface has no address; give the sensor a second NIC on
an access port for its management and its event output.

A mirror whose sources carry a management zone or a one-way zone is a warning: the copy takes that
traffic out of the isolation the firewall gives it, so whatever is on the mirror port sees it. That
is usually the point (a sensor on the uplink), but keep the sensor's capture NIC out of every zone
and the machine physically secure. The UniFi dry run renders the mirror as a port override with
`op_mode: mirror` and `mirror_port_idx` (the source) and no port profile. The field names are the
controller's; that the destination's override names the source is checked on the server.

### IPv6 prefixes (1.4)

A zone may give its IPv6 prefix:

```yaml
zones:
  - id: compute
    subnet6: 2001:db8:0:82::/64   # beside its subnet (IPv4), which it does not replace
```

It is what a guest's IPv6 `network.extra_addresses` is held against
([compute model](compute-model.md)): an IPv6 address a guest in the zone sends from (its SLAAC
address, say) must sit inside its own zone's prefix and in no other zone's, so the log pipeline's
runtime table labels it as that guest's and no other's ([log pipeline](log-pipeline.md)). Without
a `subnet6` a global IPv6 address names no zone and is refused there.

`hnx site validate` requires the prefix in its canonical form (lower case, compressed, no host
bits), a /48 to a /64, and none of: link-local, multicast, loopback or unspecified, and a range
that writes an IPv4 address inside IPv6 (mapped, compatible, translated, NAT64, 6to4, Teredo),
where the address a collector sees is the IPv4 one. It must come from the space zones are
numbered from: unique-local (`fc00::/7`), global unicast (`2000::/3`, less the IETF protocol
assignments `2001::/23`: benchmarking, ORCHID, AMT, Teredo and the rest; the retired 6bone
`3ffe::/16`; and the reserved `2000::/16`) or documentation space; discard-only, deprecated
site-local and any other special-purpose range is refused. Two zones'
prefixes may not overlap.

A guest firewall rule that names the zone (`zone:<id>`) reaches its IPv6 hosts by it: the
`.fw` file and the inventory's `hnx_firewall` carry the rule once per address family (the IPv6
one as `ip6` in the guest's own nftables ruleset, an ICMP allow as ICMPv6), and egress validation
judges the prefix as it judges an IPv4 subnet: a unique-local or documentation prefix is the
lab's, a global-unicast one reaches the internet unless it lies inside a prefix the site
declares its own (below), so without one a model runtime (whose egress is lab-only) may not
allow it ([compute model](compute-model.md#firewall-on-by-default)). Other guests' rules render
either kind. A rule that names a zone whose `subnet6` does not read is refused. The router
adapters configure it too ([IPv6 in the adapters](#ipv6-in-the-adapters)): the router's address
is the prefix's `::1`, which no guest may name as an extra address.

### Delegated IPv6 prefixes (1.5)

`delegated_prefixes6` is the site's statement that a global-unicast prefix is its own (an ISP
delegation): a list of `{prefix, why}`, the reason required. In the lab-only rule, a destination
network inside a declared prefix is the lab's, so a model runtime (a VM, a container or a physical
host) may allow it. The rule judges every destination network, but a guest's `outbound_allow` names
an IPv6 network only through a zone (the guest schema takes a literal CIDR in IPv4 alone), so today
that means a zone's global `subnet6` inside a declared prefix.

`hnx site validate` requires each prefix canonical, a /48 to a /64 (what an ISP delegates to one
site; a /32 is an ISP's own allocation, and a site that holds more than a /48 declares the /48s it
numbers zones from), global unicast (`2000::/3`) outside the IETF protocol assignments
(`2001::/23`), the retired 6bone (`3ffe::/16`), the reserved `2000::/16` and documentation space,
with no zone id and nothing IPv4-embedding, and no two overlapping. A unique-local or documentation
prefix needs no declaration (it is the lab's already). The compute path reads the site file without
`hnx site validate`, so it judges the list again: a declaration that does not read is a problem,
and then no prefix is held as the lab's.

The declaration is the site's word, not a proof: nothing checks the prefix against the ISP, so a
wrong one opens a model runtime's egress to that space, and the `why` it carries is a note, not a
control. The only control is review: the private overlay's `CODEOWNERS` template names
`lab/site.yml` ([private overlay](private-overlay.md)), which gates the edit **only** where the
overlay's branch rules require an approving Code Owners review. Without that rule the declaration
is unreviewed site configuration. `hnx site review-tier`, which the overlay's `checks.yml` runs on
every pull request, rates a declared prefix added or changed as human-approve against the base
commit and fails when no code owner as of the base would approve it ([private
overlay](private-overlay.md#what-a-change-to-the-lab-claims)); that makes the change visible and
gives the Code Owners rule an owner to bind, and it is no more than that. The declaration changes
only the lab-only judgement: which prefixes a zone may use, which IPv6 extra
addresses a guest may name (its zone's `subnet6`, as before) and what the roles render are
unchanged.

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

The order holds for IPv6 too. A zone with a `subnet6` carries it, and its router address (the
prefix's `::1`), in the IR (`Interface.subnet6`, `Interface.address6`, `Policy.zones6`), and every
adapter renders each rule's IPv6 form (`homelabnext.network.ir.ipv6_form`) right after the rule,
so first match is the same in each family:

* a rule between zones has an IPv6 form when every zone it names has a prefix;
* an allow that names a host has none: the registry's hosts have IPv4 addresses only, so IPv6 to
  the host stays closed by the default deny;
* a deny that names a host denies, in IPv6, the same traffic to the host's whole zone. Without
  it a later, wider allow would let through in IPv6 what the deny refuses in IPv4;
* an internet rule has an IPv6 form only from a routed (global) prefix. Nothing translates IPv6,
  and a unique-local or documentation source has no business on the internet.

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

### IPv6 in the adapters

A zone with a `subnet6` gets, from the adapter that routes it:

| Adapter | Addressing | Policy |
|---|---|---|
| `linux` | the router's `::1` on the zone's VLAN interface and router advertisements for the prefix (SLAAC): networkd's own sender, or `radvd` (`etc/radvd.conf`) with `flavor: ifupdown`. The router takes no advertisement on a zone (`accept_ra = 0`; on the WAN only with `router.wan6` `ra`), and IPv6 forwarding is on | an `ipv6_addr` set per zone and every rule's IPv6 form in the same default-drop forward chain; to the router itself only the ICMPv6 RFC 4890 says a router must take (errors, neighbour discovery and MLD, a router advertisement only on the WAN with `router.wan6` `ra`; echo at 10 a second), and SSH from the management zone in IPv6 too; and a strict reverse-path check: IPv6 has no `rp_filter`, so a packet whose source does not route back out the interface it came in on is dropped. Only on-link control traffic skips the check: neighbour discovery (hop limit 255) and MLD reports (hop limit 1) from the unspecified or a link-local source, which duplicate-address detection needs and which is never forwarded. Without the check a host could claim another zone's source and match that zone's rules. No IPv6 translation. The WAN's own IPv6 is `router.wan6` (1.6) |
| `unifi` | the network's static IPv6 settings (`ipv6_interface_type`, `ipv6_subnet`) and router advertisements | every rule's IPv6 form in the controller's IPv6 rule sets (`LANv6_IN`, `WANv6_OUT`, `NETv6`), inside the same allow-established, drop-invalid and default-deny frame as IPv4, so IPv6 between zones is closed by default and never left to the controller's own default. IPv6 rules number from the same base as IPv4 (2000 to 2999; they are separate rule sets) and name their protocol in `protocol_v6`. Traffic to the gateway itself (`LANv6_LOCAL`) and the controller's anti-spoofing for IPv6 sources are left to the controller's defaults, as `LAN_LOCAL` is for IPv4. The index range, `protocol_v6` and these defaults are unverified offline and checked on the server |
| `dnsmasq`, `zonefile` | unchanged: no DHCPv6 (addressing is SLAAC from the router) and no AAAA records (the registry's hosts have IPv4 addresses only) | none |
| `opnsense` | deferred | deferred |

Two consequences of the IPv6 forms, both closing rather than opening:

- **IPv6 can be stricter than IPv4.** A deny naming a host has no host address to name in IPv6, so
  it denies the same traffic to the host's whole zone. Where it is followed by a wider allow to that
  zone, IPv4 closes only the host and IPv6 closes the zone: the later allow is shadowed in IPv6.
  Give the host's zone its own rules, or accept the narrower IPv6 reach.
- **The WAN's IPv6 needs `router.wan6`.** Without it the router takes no advertisement
  (`accept_ra = 0`), so it has no IPv6 default route, the reverse-path check drops every
  WAN-sourced IPv6 packet, and IPv6 to the internet does not work: it fails closed. See
  [The WAN's IPv6](#the-wans-ipv6-16).

### The WAN's IPv6 (1.6)

`router.wan6` gives the router its own IPv6 on the WAN, which the zones' routed prefixes reach the
internet by. It is exactly one of:

- `static: {address, gateway}`: the router's WAN address with its /64 and the default gateway.
  `hnx site validate` requires the address canonical, with no zone id, global unicast (never
  unique-local, documentation, link-local, special-purpose or IPv4-embedding: the rules of a
  delegated prefix), neither the /64's subnet-router anycast address nor one of its top 128
  (RFC 2526), and outside every zone's `subnet6` and every `delegated_prefixes6` prefix (which
  numbers zones); the gateway canonical, with no zone id (it is the
  WAN's), and either link-local or another usable address in the WAN /64.
- `ra: true`: router advertisements are accepted on the WAN, and only there: the address by SLAAC
  and the default route from the advertisement. No DHCPv6: an upstream that numbers its customers
  by DHCPv6 only needs `static`.

Prefix delegation (DHCPv6-PD) is not expressed. networkd could ask for one, but ifupdown has no
clean way to, and a delegated prefix would number zones whose `subnet6` the site already states;
declare an ISP delegation in `delegated_prefixes6` and number the zones from it.

| Flavor | `ra` | `static` |
|---|---|---|
| networkd | `IPv6AcceptRA=yes` (`[IPv6AcceptRA]` `DHCPv6Client=no`, `UseDNS=no`, `UseOnLinkPrefix=no`) | `Address=`, `IPv6AcceptRA=no` and a `[Route]` with `Gateway=` |
| ifupdown | `iface <wan> inet6 auto` with `accept_ra 2`, `dhcp 0` | `iface <wan> inet6 static` with `address`, `gateway`, `accept_ra 0` |

- networkd gets a drop-in for the WAN's own `.network` file,
  `etc/systemd/network/<wan_network>.d/50-hnx-wan6.conf` (`adapters.options.linux.wan_network`,
  default `10-<wan_interface>.network`), never a second file for the WAN: networkd applies only
  the first `.network` file that matches an interface, so a second one would replace the WAN's
  IPv4 or be ignored. **A drop-in whose file does not exist is ignored**: name the WAN's file, or
  the WAN has no IPv6 and IPv6 fails closed. ifupdown gets `etc/network/interfaces.d/hnx-wan6`,
  an `inet6` stanza; the WAN's `auto` line and IPv4 stanza stay the operator's.
- The sysctl file sets `default.accept_ra` and `default.accept_redirects` to 0 (an interface made
  later takes neither: without a zone prefix forwarding is off, and then it would), then
  `all.accept_ra = 0`, then for the WAN `accept_redirects = 0`, `accept_ra_rt_info_max_plen = 0`
  (no route-information option) and last its `accept_ra`: 2 for `ra` (so forwarding does not
  switch advertisements off) and 0 for `static`. A WAN name with a dot (a VLAN) is written with
  slashes (`net/ipv6/conf/<wan>/accept_ra`). Every zone takes no advertisement: `accept_ra 0`
  with ifupdown, and with networkd `IPv6AcceptRA=no` on every zone's file, a zone without a
  `subnet6` included (networkd takes advertisements by default while forwarding is off).
- nftables: once the router has any IPv6 it takes the ICMPv6 a router must (above). With `ra`,
  the input chain also takes a router advertisement from a link-local source at hop limit 255 on
  the WAN, and nowhere else, and the reverse-path check exempts that same packet. Legitimate WAN
  traffic passes the check by the default route. The forward chain gains one rule, before
  `established,related`: IPv6 to a zone's `subnet6` never leaves by the WAN. A neighbour on the
  WAN that can send advertisements can still take the router's default route (an `ra` WAN trusts
  its link, as every SLAAC host does), but a prefix it advertises inside a zone's, which would
  route that zone's traffic, return traffic included, out the WAN, only drops it
  (`UseOnLinkPrefix=no` keeps networkd from installing such a route at all; the kernel, with
  ifupdown, installs it). NAT is unchanged.
- Other adapters do not render `wan6`. `hnx site validate` warns when the site's network adapter
  is not `linux`, and `hnx site render|plan --adapter` does when another adapter renders a site
  whose own adapter is. Configure the WAN's IPv6 on that router itself.
- A site without `wan6` renders byte for byte as before, and its IR digest is unchanged. A change
  to `router` is human-approve in `hnx site review-tier`.

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
pinning against a real console; DHCPv6 and IPv6 DNS servers (RDNSS); IPv6 host addresses in the registry; reverse DNS zones. The adapter interface has an
`apply` that raises `ServerOnly` for every adapter, so the seam exists and cannot be used by
accident.
