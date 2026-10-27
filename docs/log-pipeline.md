---
summary: 'The log-pipeline slot contract: the hnx_runtime label set from a table generated from the guest model, joined on the address the collector saw, never the event.'
summary_of: outline:sha256:da0b27b9ecb06f1a
---
<!-- SPDX-License-Identifier: Apache-2.0 -->
# The log pipeline and the runtime label

The `log-pipeline` slot (stage 2 of the SOC bundle, [modules](modules.md#the-soc-bundle-by-pipeline-stage))
moves events from the collectors to the index and the lake. It has one contractual duty: to label
the events of a **model runtime**, a guest that serves models or runs model-written code
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
   `"labels.hnx_runtime"` (the engine reads a flat key first, so leaving it would let it win);
2. looks up the **observed source**: the address the collector itself saw, never a field of the
   event body (`source.ip`, `host.name` and the like are what the runtime wrote);
3. sets the table's value for that address, `model` or `none`; an address the table does not
   hold, no address, or one that is not a bare IP address (a port, a zone id, a host name) leaves
   the event **without** the label.

The observed source is the peer address of the connection a host's log arrived on, or, for a log
written by another service about a client (a resolver's query log, a proxy's access log), the
client address that service recorded. The collector supplies it beside the event. The table is
keyed by address only: a host name in a log line is the sender's own claim.

The rule for one event is `homelabnext.logpipeline.enrich(event, observed, table)`.

## The table

```
hnx guests render <guests> --site <site> --target runtime-labels --out <dir>
```

writes `runtime-labels.json` (`homelabnext.logpipeline.runtime_labels/v1`): every guest's address
with `model` (it is a model runtime by capability or inventory group, the same test validation
uses for default-deny egress) or `none`, and the guest and capability for a reader. Addresses are
canonical (IPv6 compressed and lower case) and ordered; two guests on one address is an error.
`RuntimeTable.load` refuses any other shape, value or key. The provider loads the table at
deploy time and again whenever the guests change; a reload replaces the table, so a guest that
stops being a model runtime stops being labelled one.

The example lab's table, rendered from `examples/minimal/guests`, is committed at
[`examples/log-pipeline/runtime-labels.json`](../examples/log-pipeline/runtime-labels.json);
`make gates` and CI re-render it with `hnx guests plan ... --exit-code` and fail on any drift.

## The contract and its suite

The contract is `conformance/protocols/log_pipeline.py` (`LogPipeline`: `load_runtimes(table)`
and `process(records)`, each record an `Observed(event, observed)`). It is an extended suite,
`hnx conform run log-pipeline`, against a target that names the provider's adapter (the example
provider's is `examples/modules/example-log-pipeline/conformance/target.yml`). Its fifteen MUST
checks cover:

- a model runtime's event is `model`, a known other guest's is `none`, whatever either said;
- an unknown address, no address, and something that is not an address give no label;
- the event body is never joined on, and the flat key is dropped;
- an IPv4-mapped IPv6 peer is its IPv4 address, and IPv6 spellings fold to the table's key;
- every other field leaves unchanged, the caller's records are not modified, a batch keeps its
  order and count, and a reloaded table replaces the earlier one.

Each of its eleven mutants is caught by its named check alone.

The end-to-end evasion fixtures in `tests/logpipeline/evasion/` run the enrichment over the
example table and then the rule. They show that a self-set label changes nothing:

- a runtime calling itself `none`, or setting the flat key, still fires;
- a runtime naming another guest as its source still fires;
- a runtime behind a dual-stack peer still fires;
- a guest or an unknown source calling itself `model` stays silent;
- an event with no observed address stays silent whatever its host fields say.

## Limits

- **Pass-through.** A site whose `log-pipeline` is `pass-through` (single-box and small-lab in
  the examples) has no stage to apply the label, so no event carries it and the three rules never
  fire there. They are silent, not wrong. Give such a site a provider, or have its SIEM apply
  the same table as a lookup at ingest.
- **The observed address is the collector's word.** A runtime with root on a shared segment can
  spoof the source of a connectionless (UDP syslog) datagram. Ship logs over TCP or TLS, where
  the peer address is the handshake's, and keep collectors off the model runtimes' zone.
- **One address per guest.** The guest model has one address per guest. A runtime reached
  through NAT, or seen by a collector behind a proxy that hides its peers, is labelled by the
  address the collector sees, which may be the gateway's.
- The example provider's adapter (`hnx_modules.example_log_pipeline.log_pipeline:make`) is part
  of the fictional product. The reference behaviour is the fake in
  `conformance/fakes/log_pipeline.py`, which applies the library rule.
