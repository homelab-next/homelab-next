# SPDX-License-Identifier: Apache-2.0
"""``log-pipeline`` (extended): the runtime label comes from the guest model, never the event."""

from __future__ import annotations

import copy
import ipaddress

from conformance.fakes.log_pipeline import (
    FakeLogPipeline,
    JoinsOnEventSourcePipeline,
    KeepsFlatKeyPipeline,
    KeepsUnknownLabelPipeline,
    MergesTablesPipeline,
    MissingObservedFromHostPipeline,
    MutatesInputPipeline,
    NoMappedV4Pipeline,
    ReplacesLabelsPipeline,
    ReversesBatchPipeline,
    StripsPortPipeline,
    TrustsSelfNonePipeline,
)
from conformance.protocols.log_pipeline import Observed
from homelabnext.conform.core import Mutant, Suite
from homelabnext.logpipeline import FLAT_KEY, LABEL, RuntimeTable, table_doc

from ._util import ip

SUITE = Suite(
    "log-pipeline",
    "labels.hnx_runtime from the guest model's table, joined on the observed address only",
    "conformance.protocols.log_pipeline:LogPipeline",
    tier="extended",
)

RUNTIME = ip(130, 1)  # a model runtime (cap:inference)
RUNTIME_V6 = "2001:db8::5"  # a model runtime on IPv6
LONG_V6 = ipaddress.ip_address(RUNTIME_V6).exploded.upper()  # the same, written long
OTHER = ip(40, 1)  # a known guest that runs no model
UNKNOWN = ip(9, 2)  # not in the guest model


def _table(*, without: str | None = None) -> RuntimeTable:
    rows = [
        (RUNTIME, "model", "guest:infer-core", "cap:inference"),
        (RUNTIME_V6, "model", "guest:exec-core", "cap:codemode-executor"),
        (OTHER, "none", "guest:lake-core", "cap:lake-query"),
    ]
    return RuntimeTable.from_doc(table_doc(r for r in rows if r[0] != without))


def _one(t, event, observed):
    t.load_runtimes(_table())
    out = t.process([Observed(event, observed)])
    assert isinstance(out, list) and len(out) == 1, f"one record in, {out!r} out"
    return out[0]


def _label(event):
    labels = event.get("labels")
    nested = labels.get(LABEL) if isinstance(labels, dict) else None
    return nested, event.get(FLAT_KEY)


def _labelled(event, want):
    nested, flat = _label(event)
    assert flat is None, f"the flat {FLAT_KEY!r} key survived: {flat!r}"
    assert nested == want, f"{LABEL} is {nested!r}, expected {want!r}"


def _dns(name="example-bucket.storage.invalid", **extra):
    return {"dns": {"question": {"name": name}}, **extra}


@SUITE.check("labels-model-runtime", "an event observed from a model runtime is labelled model")
def _(t):
    _labelled(_one(t, _dns(), RUNTIME), "model")


@SUITE.check("labels-known-non-runtime", "an event observed from a known other guest is none")
def _(t):
    _labelled(_one(t, _dns(), OTHER), "none")


@SUITE.check(
    "self-set-none-overwritten",
    "a model runtime's event that calls itself none is labelled model (evasion)",
)
def _(t):
    _labelled(_one(t, _dns(labels={LABEL: "none"}), RUNTIME), "model")


@SUITE.check(
    "self-set-model-overwritten",
    "a known other guest's event that calls itself model is labelled none",
)
def _(t):
    _labelled(_one(t, _dns(labels={LABEL: "model"}), OTHER), "none")


@SUITE.check(
    "unknown-source-unlabelled",
    "an address the table does not hold gives no label, whatever the event said",
)
def _(t):
    _labelled(_one(t, _dns(labels={LABEL: "model"}), UNKNOWN), None)


@SUITE.check(
    "missing-observed-unlabelled",
    "with no observed address the event leaves unlabelled; its own host fields are not read",
)
def _(t):
    event = _dns(labels={LABEL: "model"}, host={"ip": RUNTIME, "name": "infer-core"})
    _labelled(_one(t, event, None), None)


@SUITE.check(
    "body-never-joined",
    "the event's own source.ip is ignored: the observed address decides",
)
def _(t):
    event = _dns(source={"ip": RUNTIME})
    _labelled(_one(t, event, OTHER), "none")
    event = _dns(source={"ip": OTHER})
    _labelled(_one(t, event, RUNTIME), "model")


@SUITE.check(
    "flat-key-dropped",
    'a flat "labels.hnx_runtime" key the event arrived with is removed',
)
def _(t):
    _labelled(_one(t, {**_dns(), FLAT_KEY: "none"}, RUNTIME), "model")


@SUITE.check(
    "ipv4-mapped-is-ipv4",
    "a dual-stack peer ::ffff:a.b.c.d is looked up as a.b.c.d",
)
def _(t):
    _labelled(_one(t, _dns(), "::ffff:" + RUNTIME), "model")


@SUITE.check(
    "ipv6-spelling-folded",
    "an IPv6 address written long or upper-case is the table's compressed key",
)
def _(t):
    _labelled(_one(t, _dns(), LONG_V6), "model")


@SUITE.check(
    "not-an-address-unlabelled",
    "address:port, a zone id or a host name is not an address and gives no label",
)
def _(t):
    for observed in (f"{RUNTIME}:514", f"{RUNTIME_V6}%eth0", "infer-core", f" {RUNTIME}", ""):
        _labelled(_one(t, _dns(), observed), None)


@SUITE.check(
    "other-fields-unchanged",
    "every other field, other labels included, leaves exactly as it came",
)
def _(t):
    event = _dns(
        labels={"site": "lab-a", "zone": "compute"},
        message=f"query from {RUNTIME}",
        tags=["a", "b"],
    )
    got = _one(t, event, RUNTIME)
    want = copy.deepcopy(event)
    want["labels"][LABEL] = "model"
    assert got == want, f"event changed beyond the label: {got!r}"


@SUITE.check("input-not-modified", "the records passed in are not changed")
def _(t):
    event = _dns(labels={LABEL: "none", "site": "lab-a"})
    before = copy.deepcopy(event)
    _one(t, event, RUNTIME)
    assert event == before, f"the caller's event became {event!r}"


@SUITE.check("batch-order-and-count", "one event out per record in, in the same order")
def _(t):
    t.load_runtimes(_table())
    sources = [RUNTIME, OTHER, UNKNOWN, None, RUNTIME_V6]
    records = [Observed({"seq": i, **_dns()}, s) for i, s in enumerate(sources)]
    out = t.process(records)
    assert [e.get("seq") for e in out] == list(range(len(sources))), f"sequence {out!r}"
    assert [_label(e)[0] for e in out] == ["model", "none", None, None, "model"]


@SUITE.check(
    "reload-replaces-table",
    "a later table replaces the earlier: an address it drops is no longer labelled",
)
def _(t):
    t.load_runtimes(_table())
    t.load_runtimes(_table(without=RUNTIME))
    (got,) = t.process([Observed(_dns(), RUNTIME)])
    _labelled(got, None)


def make_fake():
    return FakeLogPipeline()


MUTANTS = {
    "trusts-self-none": Mutant(
        TrustsSelfNonePipeline,
        "self-set-none-overwritten",
        "an event that calls itself none keeps that label",
    ),
    "keeps-unknown-label": Mutant(
        KeepsUnknownLabelPipeline,
        "unknown-source-unlabelled",
        "an address outside the table leaves the event's own label",
    ),
    "joins-on-event-source": Mutant(
        JoinsOnEventSourcePipeline, "body-never-joined", "the event's source.ip decides the label"
    ),
    "keeps-flat-key": Mutant(
        KeepsFlatKeyPipeline, "flat-key-dropped", 'the flat "labels.hnx_runtime" key survives'
    ),
    "no-mapped-v4": Mutant(
        NoMappedV4Pipeline, "ipv4-mapped-is-ipv4", "a dual-stack peer is never found"
    ),
    "strips-port": Mutant(
        StripsPortPipeline, "not-an-address-unlabelled", "address:port is read as the address"
    ),
    "missing-observed-from-host": Mutant(
        MissingObservedFromHostPipeline,
        "missing-observed-unlabelled",
        "no observed address falls back to the event's host.ip",
    ),
    "replaces-labels": Mutant(
        ReplacesLabelsPipeline, "other-fields-unchanged", "the event's other labels are lost"
    ),
    "mutates-input": Mutant(
        MutatesInputPipeline, "input-not-modified", "the caller's event is labelled in place"
    ),
    "reverses-batch": Mutant(
        ReversesBatchPipeline, "batch-order-and-count", "a batch comes back reversed"
    ),
    "merges-tables": Mutant(
        MergesTablesPipeline,
        "reload-replaces-table",
        "a new table is merged over the old one",
    ),
}
