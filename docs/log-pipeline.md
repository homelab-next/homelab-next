---
summary: 'The log-pipeline contract: hnx_runtime from the guest model by the address the collector saw, hnx_tlp from the route''s declaration; never the event.'
summary_of: outline:sha256:a49158449fd20cc4
---
<!-- SPDX-License-Identifier: Apache-2.0 -->
# The log pipeline and its labels

The `log-pipeline` slot (stage 2 of the SOC bundle, [modules](modules.md#the-soc-bundle-by-pipeline-stage))
moves events from the collectors to the index and the lake. It has two contractual duties, each a
label it sets and never takes from the event: the TLP label of every event
([below](#the-tlp-label)), and the label of the events of a **model runtime**, a guest that serves models or runs model-written code
(`cap:inference`, `cap:codemode-executor`; [compute model](compute-model.md#model-runtimes)), so
that the detections written for them can tell those events from everyone else's.

## Why the label is not the event's

`det:model-runtime-egress-drop`, `det:model-runtime-object-store-lookup` and
`det:model-runtime-object-store-request` match `labels.hnx_runtime: model`. The thing they watch
is the model runtime, and on a model runtime the model's output decides what the guest logs
and, with a shell, what its log shipper sends. A label that came with the event is a claim by the
watched party: a runtime that wrote `hnx_runtime: none` would never alert, and a guest that wrote
`model` would raise a false one. So the pipeline:

1. drops whatever label the event carries, nested (`labels.hnx_runtime`) or as the flat dotted key
   `"labels.hnx_runtime"` (the engine reads a flat key first, so leaving it would let it win),
   and any spelling of either that differs only in case or surrounding white space
   (`Labels.HNX_RUNTIME`, `"hnx_runtime "`): this engine reads exact names, but a back end that
   folds field names would read those as the label;
2. looks up the **observed source**: the address the collector itself saw, never a field of the
   event body (`source.ip`, `host.name` and the like are what the runtime wrote);
3. sets the table's value for that address, `model` or `none`; an address the table does not
   hold, no address, or one that is not a bare IP address (a port, a zone id, a host name) leaves
   the event **without** the label.

The observed source is the peer address of the connection a host's log arrived on, or, for a log
written by another service about a client (a resolver's query log, a proxy's access log), the
client address that service recorded. The collector supplies it beside the event. The table is
keyed by address only: a host name in a log line is the sender's own claim.

The rule for one event is `homelabnext.logpipeline.enrich(event, observed, table)`. A record that
is not an object (an array, a string, null) has nowhere to carry the label and nothing the rule
reads, so it passes through unchanged rather than failing the batch it came in.

## The table

```
hnx guests render <guests> --site <site> --target runtime-labels --out <dir>
```

writes `runtime-labels.json` (`homelabnext.logpipeline.runtime_labels/v1`): every address of every
guest (`network.ip`, and each of its `network.extra_addresses`, guest 1.6) with `model` (it is a
model runtime by capability or inventory group, the same test validation uses for default-deny egress) or `none`, and the guest and capability for a reader. Addresses are
canonical (IPv6 compressed and lower case) and ordered; two guests on one address is an error.
`RuntimeTable.load` refuses any other shape, value or key. A reload replaces the table, so a guest
that stops being a model runtime stops being labelled one.

Loading the table is the provider's job: this repository renders it and checks the example's for
drift, but nothing here deploys it to a provider or reloads it when the guests change. A provider
whose table is older than the guests labels by the older guests.

The example lab's table, rendered from `examples/minimal/guests`, is committed at
[`examples/log-pipeline/runtime-labels.json`](../examples/log-pipeline/runtime-labels.json);
`make gates` and CI re-render it with `hnx guests plan ... --exit-code` and fail on any drift.

## The contract and its suite

The contract is `conformance/protocols/log_pipeline.py` (`LogPipeline`: `load_runtimes(table)`
and `process(records)`, each record an `Observed(event, observed)`). It is an extended suite,
`hnx conform run log-pipeline`, against a target that names the provider's adapter (the example
provider's is `examples/modules/example-log-pipeline/conformance/target.yml`). Its twenty-four MUST
checks cover, for the runtime label:

- a model runtime's event is `model`, a known other guest's is `none`, whatever either said;
- an unknown address, no address, and something that is not an address give no label;
- the event body is never joined on, and the flat key and every case or white-space spelling of
  either key are dropped;
- an IPv4-mapped IPv6 peer is its IPv4 address, and IPv6 spellings fold to the table's key;
- every other field leaves unchanged, the caller's records are not modified, a batch keeps its
  order and count, a record that is not an object comes back unchanged, and a reloaded table
  replaces the earlier one;

and for the TLP label ([below](#the-tlp-label)):

- an event on a declared route with no label of its own takes the declaration, keeping its
  runtime label and its own `tlp` field;
- an unknown route, no route, or a route the event names itself is `red`, and a route in another
  case, padded or not a string is no table key;
- a TLP label the event arrived with, nested, flat or in another case, is replaced;
- a stricter item label, in any of its places and the strictest of several, is kept and one that
  is not a label is `red`; a looser one is raised to the declaration unless the dataset honours
  item labels;
- a reloaded source table replaces the earlier one.

Each of its twenty-one mutants is caught by its named check alone.

The end-to-end evasion fixtures in `tests/logpipeline/evasion/` run the enrichment over the
example table and then the rule. They show that a self-set label changes nothing:

- a runtime calling itself `none`, setting the flat key, or spelling either in another case,
  still fires;
- a runtime naming another guest as its source still fires;
- a runtime behind a dual-stack peer still fires;
- a guest or an unknown source calling itself `model` stays silent, and so does a known guest
  that runs no model sending a PUT to a cloud bucket;
- an event with no observed address stays silent whatever its host fields say.

## The TLP label

The pipeline also gives every object event its TLP label, `labels.hnx_tlp` (ADR-0033 decisions 3
and 5), which the lake stores as the row's `tlp` column and every reader is filtered by. Like the
runtime label it is never the event's word: the rule is
`homelabnext.logpipeline.enrich_tlp(event, route, table)`.

- **The route** names the dataset the collector input feeds, `<module>/<dataset>`, and is
  supplied by the collector beside the event (`Observed.route`), never read out of it. A route the
  table does not hold, no route, or one that is not exactly a table key is `red`: unlike the
  runtime label, an unknown source cannot stay unlabelled, because a missing label must never
  read as a looser one.
- **The declaration** is the dataset's `tlp` (absent is `red`) and `honour_item_labels`
  ([modules](modules.md#data-and-lifecycle-safety)), applied with `homelabnext.tlp.item_label`.
  An item label the event carries in its `tlp` field, the flat `"labels.tlp"` key or
  `labels.tlp` (any spelling of each up to case and surrounding white space; several give the
  strictest) is kept when stricter, and when looser only where the dataset honours item labels;
  one that is not a label, `null` included, is `red`. The label is decided by the event as it
  arrived: an item label another stage drops still counts.
- **Self-set labels** in `labels.hnx_tlp`, the flat `"labels.hnx_tlp"` key or any spelling of
  either are replaced. The event's own `tlp` field is left as it came: it is an input, and the
  lake writer stores `labels.hnx_tlp`, never it.

The table is `tlp-sources.json` (`homelabnext.logpipeline.tlp_sources/v1`), written by
`hnx modules render` from the site's selection: one source per dataset of every module the site
runs, with its declaration. `SourceTable.load` refuses any other shape, a label that is not
canonical, a non-boolean honour flag or a route its entry does not spell. An empty table labels
every event `red`. As with the runtime table, deploying it to the provider and reloading it when
the selection changes is the provider's job.

## Limits

The TLP label:

- **The route is the collector's word.** A collector input wired to the wrong dataset labels its
  events by that dataset's declaration. Give each input exactly one route, and review a change of
  route as a change of declaration.
- **`honour_item_labels` trusts the source.** A dataset that honours item labels takes a looser
  label from the provider's own marking; that is why the field is human-approve.
- **Pass-through.** A site with no `log-pipeline` stage sets no `hnx_tlp`, so its writer has no
  label to store: the lake refuses an unlabelled row, and the writer must not invent one.
- **Non-objects.** A record that is not an object carries no label; it is not a row the lake
  would store.

The runtime label:

- **Pass-through.** A site whose `log-pipeline` is `pass-through` (single-box and small-lab in
  the examples) has no stage to apply the label, so no event carries it and the three rules never
  fire there. They are silent, not wrong. Give such a site a provider, or have its SIEM apply
  the same table as a lookup at ingest.
- **The observed address is the collector's word.** A runtime with root on a shared segment can
  spoof the source of a connectionless (UDP syslog) datagram. Ship logs over TCP or TLS, where
  the peer address is the handshake's, and keep collectors off the model runtimes' zone.
- **Unknown is the same as `none`.** An address the table does not hold gives no label, and
  the rules match `model` only, so to the detections an unknown source and a known guest that
  runs no model are the same: silent. That is deliberate (labelling an unknown source `model`
  would let anything unlisted raise the alarm, and the event's own word is not evidence), but it
  fails open for a runtime seen from an address the table lacks.
- **Only the addresses the guest model names.** A guest's `network.ip` and its
  `network.extra_addresses` (guest 1.6: a second interface, a macvlan or bridge address its
  containers use, its IPv6 address, each with a `why`) are labelled alike, so a
  runtime that sends from any address written there is still a runtime. Validation holds each
  extra address to one that names this guest and no other wherever a collector sees it: canonical, with no IPv4 written inside IPv6; not loopback, link-local, multicast, reserved or a cloud metadata address; in IPv4, inside the guest's own zone subnet (or a zone-less overlay range, a tailnet's) and never inside another zone's; in IPv6, never an anycast address of its /64, and inside the guest's own zone's `subnet6` (site 1.4) and never inside another zone's, or, where the guest's zone has no `subnet6`, a unique-local or documentation address outside every zone's; not a zone's gateway, network or broadcast address, a gateway a guest names, or inside a DHCP pool; not an address the site's static DNS names for something else; and not one any guest already names.
- **IPv6 is held against the zone's prefix.** A zone may give its IPv6 prefix (`subnet6`, site
  1.4, a /48 to a /64), and then an IPv6 extra address of a guest in it must sit inside that
  prefix, global (a SLAAC address included) or not; an address inside another zone's prefix is
  that zone's. An anycast address of its /64 is refused wherever it is (the subnet-router one,
  with no host part, and the top 128 interface identifiers RFC 2526 reserves). The prefixes are
  read as `hnx site validate` reads them even where it has not run: when any zone's `subnet`
  or given `subnet6` does not read (an empty or non-text `subnet6` included), or the guest's
  zone is not in the site model, every IPv6 extra address is refused, and the IPv4 ones are
  judged against the zones that read.
  Without a `subnet6` on its zone, a global IPv6 address is refused (nothing says whose it is)
  and a unique-local or documentation one is accepted with no ownership check beyond "no other
  guest names it and no zone's prefix holds it": review it as you would a new `network.ip`. A
  SLAAC address is only stable while the interface keeps its identifier (EUI-64 or a stable
  privacy address); a temporary privacy address changes and cannot be listed.
- **First come, first named.** Two guests naming one address is refused on whichever sorts
  second, and nothing ties an extra address to the guest's owner: review a guest file that adds
  one (CODEOWNERS) the way you review a change of `network.ip`, since claiming an address labels
  everything sent from it.
- **What stays unlabelled:** an address nobody wrote down; a DHCP lease or an IPv6 privacy
  address that changes (pin it, or it cannot be listed); a NAT or proxy that several guests leave
  by, which the collector sees for all of them and which therefore cannot name one; a collector
  behind a proxy that hides its peers; and a peer the collector sees through NAT64 (an IPv4
  address under the RFC 6052 well-known prefix): the table folds only IPv4-mapped forms
  (`::ffff:a.b.c.d`), so a translated peer is not found and stays unlabelled
  (`tests/logpipeline/test_runtime_labels.py` records it). A provider SHOULD count the
  events it leaves unlabelled, per collector, so a rise is visible; that metric is a follow-up.
- The example provider's adapter (`hnx_modules.example_log_pipeline.log_pipeline:make`) is part
  of the fictional product. The reference behaviour is the fake in
  `conformance/fakes/log_pipeline.py`, which applies the library rule.
