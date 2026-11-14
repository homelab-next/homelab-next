---
summary: 'Module egress reference: declared egress as network policy, the publishing gate, ADR-0033 egress points and follow-ups for labelled requests.'
summary_of: outline:sha256:49ac3dda76b6b1ef
---
<!-- SPDX-License-Identifier: Apache-2.0 -->
# Modules: egress and publishing

> Part of [the module manifest](../modules.md) ([[modules]]), the draft for operator review
> ([ADR-0027](../adr/0027-feature-and-provider-modules.md), proposed).

## Egress and publishing

`egress:` is `none` (the default) or, per host role of the module's own, the registry services and
`internet` it may reach beyond the slots it requires or prefers; a `svc:` target must be a registry service
the site has (a selected slot or instance, or a selected feature or core module's row; a
provider's rows are reached by its slot or instance). A grant names its
targets: `grants.egress.<module>.<role>: [internet, svc:broker, external]`. Every `internet` target
and every authority or privileged service (`svc:secrets`, `svc:broker`, `svc:idp`, the instances
that fill those slots) must be listed for that role, and so must `external` for a `kind: external`
host role, which runs outside the lab and so is egress by itself. Because the grant lists targets,
not roles, a manifest change that adds a target to a granted role is refused until the overlay
lists it too. A host role inside the lab may be `internet-facing` only with
`grants.internet_facing.<module>: [<role>]`. **Every grant** (egress, internet_facing,
public_routes, publish, secrets, units, shared_config, upstreams, cloud_models) names a selected module, and only what
exists for it: an egress target its entry lists, `external` for an external role, an
internet-facing role inside the lab, a row with a `public_hostname` (checked when the rows are
read), static hosting the module reaches, one of its units (when the unit specs are read), a
`shared_config` target it declares, a broker, idp or remote-admin upstream it reaches
(`upstreams`), a model role it requires whose prompts can leave the lab (`cloud_models`), and a credential another selected module holds (a grant of
the module's own secret is redundant and refused). For secrets that is as far as the manifest
goes: who actually reads a granted credential (an adapter, a gate's identity) is not visible in
it, so an unused secrets grant is not detected. A grant waiting for a role, row or target to appear
would switch it on with a module upgrade or a placement line nobody reads as a grant, so it is
refused ("... remove the grant"). So **a grant lands in the same overlay change as the module
version (its pin in the lock, or the checkout for an in-tree module) that first uses it, and is
deleted with the version that stops using it**; unselecting a module means deleting its grants. A
`svc:` target is checked even before the rows are read: a selected slot, an instance, or a name
bound to a selected feature or core module (whose rows then decide). **The egress generator** (follow-up 6): `homelabnext.modules.egress.render(site, modules, rows,
units)` turns it into an nftables ruleset per lab host that limits the connections a module role's
processes open. A socket in a role's slice (the `hnx-<id_>-<role_>.slice` of
[footprint limits](slots.md#footprint-and-resources), matched as `socket cgroupv2 level 3`) jumps to the
role's chain, which accepts:

- DNS to the selected `dns` instances (their rows' ports, or udp and tcp 53);
- each slot the module requires or prefers, and a preference's fallback only when the preferred
  slot is not selected: the provider's rows at their placed host's addresses and ports, or every
  port of its placed hosts when it has no row (address-granular: give the provider rows to narrow
  it); a provider with no host role runs outside the lab and is reached only over `internet`;
- each `svc:` target (a feature or core module's row, a slot or an instance);
- with `internet`, global unicast only, except DNS (port 53) and DNS over TLS and over QUIC (port
  853), tcp and udp, so the role resolves through the lab's resolvers (the `dns` allows above; a
  `dns` provider that runs outside the lab is not reached): every special-purpose range (private,
  shared, loopback, link-local, documentation, benchmarking, multicast, reserved, NAT64 and the
  other IPv4-embedding prefixes), `scope.trusted.nets` and `scope.trusted.wan` (the lab's own
  public addresses, so not the port forwards behind them either; both read by the strict scope
  reader, which refuses a dynamic WAN source), every host's `addresses` and, when `hnx modules render --network FILE` (with `--overlay DIR`,
  `DIR/lab/site.yml` by default; or `egress.render(..., network=)`) gives the network model, every zone's `subnet6` and every `delegated_prefixes6`
  prefix are never the internet. Over IPv6 the accept also requires `2000::/3`, so nothing
  outside global unicast passes whatever the deny-list holds. **Without the network model**
  a lab IPv6 address in none of those lists (a guest's SLAAC address, say) is treated as the
  internet: the render prints a note and the generated README says so.

It logs and drops the rest; an `isolated` role reaches nothing, and any other socket in
`hnx.slice` is dropped. Hosts carry their own `addresses` in the selection
(`hosts.<name>.addresses`: one address each, private, documentation ranges in a public example; a
stand-in, like `capacity`; a host that references a guest takes its guest record's `network.ip` and
`extra_addresses` instead, see [selection](selection.md#hosts-that-are-guests)). Every address, port, protocol and name is checked before it reaches the ruleset.
`hnx-egress.service` loads it only on the unified cgroup v2 hierarchy with every role slice's
cgroup present, before `network-pre.target`; the module's fleet units start only after it, and
`hnx-egress.timer` reloads it every 30 seconds, because nftables resolves a cgroup once (a
restarted role slice falls under the `hnx.slice` drop until then). A failed load keeps the policy
already loaded; before the first successful load at boot `hnx.slice` is unfiltered, so watch the
service for failure. A requirement or preference reaches its slot for the host roles its `hosts`
names, and for every role of the module when it names none, authority slots included. **A slot
reached by requirement needs no egress grant**, privileged or not: its gate is the review tier
(human for a privileged slot, [Trust tiers](contributes.md#trust-tiers-what-selecting-a-module-grants)), and `hosts` is how a module keeps a
role that never uses the secrets store or the broker from reaching it. The grant covers only the
`egress:` targets above.

**What it does not cover**: connections the module accepts (inbound is the network model's and the
edge's; replies pass as established); loopback, so modules on one host reach each other's local
services; containers with their own network namespace (forwarded, not output from a socket in the
slice); a process with root or `CAP_NET_ADMIN`, which can change the ruleset or its own cgroup;
flows established before a change; DNS over HTTPS from a role with `internet` (it is HTTPS on
443, which this layer cannot tell apart); and DNS as a channel through the lab's resolver. Place modules
that must not reach each other on different hosts, and run them unprivileged. **Publishing is the only egress
for published content** because the overlay says so, not because publishing says so: only a module
in `grants.publish` may require, prefer or fall back to `cap:static-hosting`, and the core criterion
`core-modules/egress-publish-grant` checks it (deferred until the loader has run at deploy time on
a real lab; the loader's site rules apply it). The static host's deploy credential is `holder: granted` to the
publish gate only.

The gate **verifies** a producer's TLP, never trusts it: an item's sidecar TLP is a claim; red,
amber and unknown are excluded; the body is scanned for TLP markers and deny-listed names, which
override the claim; only inert media types are accepted (`text/markdown`, `application/json`,
`image/png`) and the gate renders HTML itself. **`green` is not public** (ADR-0033 decision 9):
`tlp_allowed` stays `clear` by default. A selection whose `tlp_allowed` (its value, else the
manifest's default) is `green` must also set `audience: community` and name the access control
that restricts the publication to that community (`access_control`, a sentence: the community's
sign-in on the static host, say). The loader's site rules refuse it without both
(`features.publishing.config.tlp_allowed: green is not public ...`), and anything above `green`
(`amber`, `amber+strict`, `red`, and a value that does not read, which is `red`) outright: no
audience or control lets a publication out at that label. A placeholder is not an access control:
`none`, `n/a`, `x`, `tbd`, `public` and the like, and anything with fewer than three letters, are
refused (`PLACEHOLDER_CONTROLS` in `homelabnext/modules/rules.py`). That is a deny-list, and its
limit is plain: the selection records no access control the name could be checked against, so a
made-up sentence passes, and the review of the overlay is what catches it. The rule holds for any
module that declares a `tlp_allowed` key, read with `homelabnext.tlp.read`. A module that requires a **model role whose prompts
can leave the lab** (a role-table binding marked `leaves_lab`, model roles 1.3) needs
`grants.cloud_models` (see [Trust tiers](contributes.md#trust-tiers-what-selecting-a-module-grants)), and the
role has a TLP ceiling besides ([Model-role ceilings](tlp.md#model-role-ceilings-adr-0033-decision-10)).

### Egress points (ADR-0033 decision 13)

Data leaves its store at the points below. `homelabnext.tlp_egress` is the shared check each of them
is to apply before anything leaves; the last column says where it is applied today. The check: the
item's label is the strictest of the label it claims, the label recorded for it (`recorded` is a
required argument, `NO_RECORD` for an item with none, so a caller cannot loosen an item by
forgetting its record) and every TLP marker in its body; it leaves only at or below the
destination's ceiling (`egress_check`). A body is read after folding look-alike and hidden
characters (NFKC, format characters dropped); bytes are read as UTF-8, a mapping or a list leaf by
leaf with its keys, and a body that cannot be scanned is `red`. A marker is `TLP:` and a word in any
ASCII case (`TLP:AMBER+STRICT` with spaces allowed around `+`), or `TLP` and a label word after any
run of white space and up to three other characters that are neither a letter nor a digit, or none
(`TLP RED`, `TLP    RED`, `TLP-AMBER`, `TLP_RED`, `TLP/AMBER`, `[TLP=RED]`, `TLP  -  RED`,
`TLPRED`); white space is never counted against the three, so padding cannot hide a marker; any other
spelling of `amber+strict`, an unknown word or a dangling `+` is `red`.

| Egress point | Its ceiling comes from | What lets a module use it today | Checked today |
|---|---|---|---|
| the publishing gate (the static host) | `tlp_allowed` (`clear`, `green` for a community audience) | `grants.publish` | `tlp_allowed` checked at load (never above `green`); the per-item check is the gate module's |
| the status hub's public view and exports | `clear` | not a module grant: the hub's release transforms decide what is shown | the hub's view ceilings and release transforms |
| model requests to a role that leaves the lab | the role's TLP ceiling | `grants.cloud_models` | the model gateway: each key's sending ceiling; the per-request `model_tlp.admit` has no caller yet ([developer follow-ups](#developer-follow-ups)) |
| enrichment lookups to an external analyzer | the analyzer's declared maximum (`analyzers_for`) | `grants.egress` (`internet`) | none in this repository yet (`job_label`, `analyzers_for` are for the client) |
| notification channels | the channel's reader ceiling | `cap:notify` (a send class) | `notify.CeilingSender`: the broker's, the status hub's and the invariants runner's pages (`--notify-ceiling`, required with `--notify-cmd`); no producer labels its messages yet, so below `red` every page arrives as the withheld notice |
| webhooks | the receiver's ceiling | `grants.egress` | not yet |
| backups and off-site copies | the backup target's reader ceiling | `grants.egress` for off site (`cap:backup` itself stays in the lab) | not yet |
| the bus | its subscribers' ceilings | `cap:events` | not yet |
| records and tickets (ADR-0010, ADR-0020) | their readers' ceilings | `cap:records`, `cap:cases` | not yet |
| memory and embedding stores | their readers' ceilings | the agent's memory grants | the agent memory store (`MemoryStore`, ADR-0037): each record's label is the strictest of its pack's, its sources' and the entry's, and `read`, `history` and `as_of` withhold what is above the reader's ceiling (its attested `tlp_ceiling`, else its `data_tier`), as a count per scope, never by key; while packs carry no labels all memory is `red`. Embedding stores: not yet |
| generated pages committed to a repository | `clear` for the public repository (ADR-0011) | not a module grant: the leak scans | the leak scans (no TLP check) |
| logs and error text that reach a notification | the channel's ceiling | not a module grant: the screeners | what reaches a page in a message: `notify.CeilingSender` scans its title, body, tags, link, topic and email; no log screener applies the check |

Where the last column says "not yet", what is enforced is the reach, not the content: a module
reaches beyond the lab only through a grant the overlay gives (`grants.egress` for any host role's
network egress, `grants.publish` for the static host, `grants.cloud_models` for a model role that
leaves the lab). A slot through which data leaves its store is flagged `egress` in the slot
registry; the slots this list names are `static-hosting`, `notify`, `events`, `backup`, `records`
and `cases` (`rules.EGRESS_SLOTS`, and a test holds the example registry to exactly these). A
module that requires, prefers, falls back to or provides an egress slot not on the list is
refused, so a new way out is not used before it is added here. Flagging a slot is a change to the
slot registry, which is human-approve (the review tier). An
enrichment lookup is labelled by the records that cause it (`job_label`: their strictest label,
`red` with none, raised to the submitter's ceiling) and is to be sent only to analyzers whose
declared maximum admits it; an analyzer with no maximum, or one that is not a canonical label, is
sent nothing.

A broker request built by the reader-to-actor handoff carries the label of the data its params
came from (`tlp`, `broker/request` 1.1, bound by the request digest; see
[Actors act only on validated structured input](../agent.md#actors-act-only-on-validated-structured-input-g-04)):
the strictest of what the reader may hold, the pack's label and any marker in the output. So a
handler that sends a request's params out of the lab has the label `egress_check` needs; no handler
applies it yet. The handoff itself refuses an actor whose receive ceiling is below that label.

### Developer follow-ups

Work on the code, tracked here rather than in `TODO.md` (which holds only the operator's stand-up
tasks):

1. **Per-request model admission (ADR-0033 decision 11, amendment).**
   `homelabnext.registry.model_tlp.admit(roles, role, claimed, sender=)` has no caller. Its call
   site is the agent runner, at the point it sends a session's context to the model gateway:
   after `homelabnext.agent.access.start_session` returns the pack and before each model
   request, with `claimed` the strictest of `homelabnext.agent.pack.pack_label(pack)`, the labels
   of the MCP tool results and broker results the session has added since, and any marker in them
   (`tlp_egress.egress_label`), and `sender` the profile's `send_ceiling(tlp_ceiling, data_tier)`;
   the runner logs `Admission.record()` for every request, allowed or refused, and does not send a
   refused one. Dependencies: the runner is not in this repository; pack labels exist
   (`pack_label`, ADR-0037 PR 2), but every session pack is `red` until records, pages and
   manifests declare labels (ADR-0037 follow-up 6), so until then a wired `admit` refuses every
   request to a role that leaves the lab, which key scope already does. Until it is wired, key
   scope and the `--check` audit are the enforcement
   ([TLP labels on model requests](../llm-gateway.md#tlp-labels-on-model-requests)).
2. **Broker requests' labels (ADR-0033 decision 6).** A handoff's broker request carries the
   label of the data its params came from (`broker/request` 1.1 `tlp`, set by
   `homelabnext.agent.handoff.build_request`), but nothing enforces it yet: `accept` and `act`
   have no production caller, and the broker passes `tlp` through without reading it. A handler
   that sends params out of the lab must apply `homelabnext.tlp_egress.egress_check` to
   `request["tlp"]` and treat a request without `tlp` as `red`. Dependencies: the agent runner
   that calls `accept`/`act` (out of tree, as for item 1) and the handler's egress point being
   listed in this module's egress table.
