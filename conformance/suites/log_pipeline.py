# SPDX-License-Identifier: Apache-2.0
"""``log-pipeline`` (extended): the runtime label comes from the guest model and the TLP label from
the source's declaration, never the event."""

from __future__ import annotations

import copy
import ipaddress

from conformance.fakes.log_pipeline import (
    DropsNonObjectPipeline,
    FakeLogPipeline,
    JoinsOnEventSourcePipeline,
    KeepsCaseVariantPipeline,
    KeepsFlatKeyPipeline,
    KeepsUnknownLabelPipeline,
    MergesTablesPipeline,
    MissingObservedFromHostPipeline,
    MutatesInputPipeline,
    NoMappedV4Pipeline,
    ReplacesLabelsPipeline,
    ReversesBatchPipeline,
    StripsPortPipeline,
    TlpDropsStricterClaimPipeline,
    TlpHonoursEverySourcePipeline,
    TlpIgnoresDeclarationPipeline,
    TlpKeepsSelfSetPipeline,
    TlpMergesSourcesPipeline,
    TlpNeverHonoursPipeline,
    TlpNoRouteUnlabelledPipeline,
    TrustsSelfNonePipeline,
)
from conformance.protocols.log_pipeline import Observed
from homelabnext import tlp
from homelabnext.conform.core import Mutant, Suite
from homelabnext.logpipeline import FLAT_KEY, LABEL, RuntimeTable, SourceTable, table_doc
from homelabnext.logpipeline import tlp_labels as tl

from ._util import ip

SUITE = Suite(
    "log-pipeline",
    "labels.hnx_runtime from the guest model, joined on the observed address only, and"
    " labels.hnx_tlp from the route's declaration",
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
    "case-variants-dropped",
    "a label spelled in another case or with white space, nested or flat, is removed",
)
def _(t):
    event = {
        **_dns(labels={"HNX_RUNTIME": "none", "hnx_runtime ": "none"}),
        "Labels.HNX_Runtime": "none",
        " labels.hnx_runtime": "none",
        "Labels": {"Hnx_Runtime": "none"},
    }
    got = _one(t, event, RUNTIME)
    _labelled(got, "model")
    survivors = [k for k in got if _folds_to(k, FLAT_KEY)]
    for key, labels in got.items():
        if _folds_to(key, "labels") and isinstance(labels, dict):
            survivors += [f"{key}.{k}" for k in labels if _folds_to(k, LABEL)]
    assert survivors == [f"labels.{LABEL}"], f"a variant spelling of the label survived: {got!r}"


def _folds_to(key, name):
    return isinstance(key, str) and key.strip().casefold() == name


@SUITE.check(
    "non-object-passes-through",
    "a record that is not an object comes back unchanged and costs the batch nothing",
)
def _(t):
    t.load_runtimes(_table())
    for odd in (["not", "an", "object"], "a bare string", None):
        out = t.process([Observed(odd, RUNTIME), Observed(_dns(), RUNTIME)])
        assert isinstance(out, list) and len(out) == 2, f"2 records in, {out!r} out"
        assert odd in out, f"the record {odd!r} did not come back unchanged: {out!r}"
        (labelled,) = [e for e in out if isinstance(e, dict)]
        _labelled(labelled, "model")


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
    "address:port, a zone id, a host name, a trailing dot or zero padding gives no label",
)
def _(t):
    zero_padded = ".".join(f"{int(o):03d}" for o in RUNTIME.split("."))
    for observed in (
        f"{RUNTIME}:514",
        f"{RUNTIME_V6}%eth0",
        "infer-core",
        f" {RUNTIME}",
        "",
        f"{RUNTIME}.",
        zero_padded,
    ):
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
    got.get("labels", {}).pop(tl.LABEL, None)  # the TLP label's own checks are below
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


# ---------------------------------------------------------------- the TLP label (ADR-0033)
FEED = "example-feeds/open"  # an open feed, declared clear
INTEL = "example-feeds/partner"  # third-party enrichment, declared amber
HONOURED = "example-feeds/community"  # a community feed, declared green, item labels honoured
SIGHTINGS = "example-sensor/sightings"  # the lab's own data, declared red
UNKNOWN_ROUTE = "example-feeds/unlisted"


def _sources(*, without: str | None = None) -> SourceTable:
    rows = [
        (FEED, tlp.Label.CLEAR, False),
        (INTEL, tlp.Label.AMBER, False),
        (HONOURED, tlp.Label.GREEN, True),
        (SIGHTINGS, tlp.Label.RED, False),
    ]
    return SourceTable.from_doc(tl.table_doc(r for r in rows if r[0] != without))


def _routed(t, event, route):
    t.load_runtimes(_table())
    t.load_sources(_sources())
    out = t.process([Observed(event, OTHER, route)])
    assert isinstance(out, list) and len(out) == 1, f"one record in, {out!r} out"
    return out[0]


def _tlp_is(event, want):
    labels = event.get("labels")
    got = labels.get(tl.LABEL) if isinstance(labels, dict) else None
    assert event.get(tl.FLAT_KEY) is None, f"the flat {tl.FLAT_KEY!r} key survived: {event!r}"
    assert got == want, f"{tl.LABEL} is {got!r}, expected {want!r}"


@SUITE.check(
    "tlp-declared-source",
    "an event on a declared route that carries no label of its own takes the declaration",
)
def _(t):
    _tlp_is(_routed(t, _dns(), FEED), "clear")
    _tlp_is(_routed(t, _dns(), INTEL), "amber")
    _tlp_is(_routed(t, _dns(), HONOURED), "green")
    got = _routed(t, _dns(message="m"), FEED)
    assert got.get("message") == "m" and got.get("dns") == _dns()["dns"], f"changed: {got!r}"


@SUITE.check(
    "tlp-unknown-route-red",
    "a route the table does not hold, none, or one the event names itself, gives red",
)
def _(t):
    _tlp_is(_routed(t, _dns(), UNKNOWN_ROUTE), "red")
    _tlp_is(_routed(t, _dns(), None), "red")
    _tlp_is(_routed(t, _dns(), FEED.upper()), "red")
    _tlp_is(_routed(t, _dns(event={"dataset": FEED}, route=FEED), None), "red")


@SUITE.check(
    "tlp-self-set-replaced",
    "a TLP label the event arrived with, nested, flat or in another case, is replaced",
)
def _(t):
    event = {
        **_dns(labels={tl.LABEL: "clear", "HNX_TLP": "clear"}),
        tl.FLAT_KEY: "clear",
        "Labels.Hnx_Tlp ": "clear",
    }
    got = _routed(t, event, SIGHTINGS)
    _tlp_is(got, "red")
    survivors = [k for k in got if _folds_to(k, tl.FLAT_KEY)]
    for key, labels in got.items():
        if _folds_to(key, "labels") and isinstance(labels, dict):
            survivors += [f"{key}.{k}" for k in labels if _folds_to(k, tl.LABEL)]
    assert survivors == [f"labels.{tl.LABEL}"], f"a self-set TLP label survived: {got!r}"


@SUITE.check(
    "tlp-stricter-claim-kept",
    "an item label stricter than the declaration is kept; one that is not a label is red",
)
def _(t):
    _tlp_is(_routed(t, _dns(tlp="amber"), FEED), "amber")
    _tlp_is(_routed(t, _dns(TLP="TLP:RED"), FEED), "red")
    _tlp_is(_routed(t, _dns(tlp=None), FEED), "red")
    _tlp_is(_routed(t, _dns(tlp="amber-strict"), FEED), "red")


@SUITE.check(
    "tlp-looser-claim-raised",
    "an item label looser than an unhonoured declaration is raised to it",
)
def _(t):
    _tlp_is(_routed(t, _dns(tlp="clear"), INTEL), "amber")
    _tlp_is(_routed(t, _dns(tlp="clear"), SIGHTINGS), "red")


@SUITE.check(
    "tlp-honoured-claim-kept",
    "a looser item label is kept where the dataset honours item labels",
)
def _(t):
    _tlp_is(_routed(t, _dns(tlp="clear"), HONOURED), "clear")
    _tlp_is(_routed(t, _dns(tlp="tlp:clear"), HONOURED), "clear")


@SUITE.check(
    "tlp-reload-replaces-sources",
    "a later source table replaces the earlier: a route it drops is red",
)
def _(t):
    t.load_sources(_sources())
    t.load_sources(_sources(without=FEED))
    (got,) = t.process([Observed(_dns(), OTHER, FEED)])
    _tlp_is(got, "red")


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
    "keeps-case-variant": Mutant(
        KeepsCaseVariantPipeline,
        "case-variants-dropped",
        "a label spelled in another case survives",
    ),
    "drops-non-object": Mutant(
        DropsNonObjectPipeline,
        "non-object-passes-through",
        "a record that is not an object is dropped from the batch",
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
    "tlp-ignores-declaration": Mutant(
        TlpIgnoresDeclarationPipeline,
        "tlp-declared-source",
        "an event with no label of its own is red whatever its source declares",
    ),
    "tlp-no-route-unlabelled": Mutant(
        TlpNoRouteUnlabelledPipeline,
        "tlp-unknown-route-red",
        "an event with no route leaves without a TLP label",
    ),
    "tlp-keeps-self-set": Mutant(
        TlpKeepsSelfSetPipeline, "tlp-self-set-replaced", "an event's own labels.hnx_tlp survives"
    ),
    "tlp-drops-stricter-claim": Mutant(
        TlpDropsStricterClaimPipeline,
        "tlp-stricter-claim-kept",
        "an item label stricter than the declaration is dropped",
    ),
    "tlp-honours-every-source": Mutant(
        TlpHonoursEverySourcePipeline,
        "tlp-looser-claim-raised",
        "every source's looser item labels win",
    ),
    "tlp-never-honours": Mutant(
        TlpNeverHonoursPipeline,
        "tlp-honoured-claim-kept",
        "honour_item_labels is ignored",
    ),
    "tlp-merges-sources": Mutant(
        TlpMergesSourcesPipeline,
        "tlp-reload-replaces-sources",
        "a new source table is merged over the old one",
    ),
}
