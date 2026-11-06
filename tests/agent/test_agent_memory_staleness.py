# SPDX-License-Identifier: Apache-2.0
"""Agent memory staleness (ADR-0037 PR 4, decision 15): a model reasserts a fact (``add``,
``replace`` and ``verify`` set ``reasserted_at``); only a :class:`Verifier` verifies one
(``verified_at``); ``op: verify`` takes no value, bumps ``rev`` and must cite a non-``mem:``
source the pack rendered; ``read``/``as_of`` with ``stale_after`` report stale entries, and the
pack's memory block carries them.  Every store test runs on both backends."""

from datetime import UTC, datetime, timedelta

import pytest
from agent_support import item, labelled_pack, library, spec, uid, verified

from homelabnext.agent import SpecError, compile_profile, validate_report
from homelabnext.agent.memory import (
    FileBackend,
    InMemoryBackend,
    MemoryStore,
    MemoryUpdateError,
    Verifier,
    VerifyRequest,
    fold,
    memory_block_input,
)

T0 = datetime(2026, 11, 6, 9, 0, tzinfo=UTC)
FL = "fleet-ledger"


def stamp(t):
    return t.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


class Clock:
    def __init__(self, t=T0):
        self.t = t

    def __call__(self):
        return self.t

    def tick(self, minutes=1):
        self.t += timedelta(minutes=minutes)
        return self.t


class StubVerifier(Verifier):
    """A test :class:`Verifier` (none ships): confirms what ``answer`` says and records every
    request."""

    def __init__(self, answer=True):
        self.answer = answer
        self.asked: list[VerifyRequest] = []

    def verify(self, request):
        self.asked.append(request)
        if isinstance(self.answer, Exception):
            raise self.answer
        return self.answer


def _profile(**extra):
    s = spec()
    s.update(extra)
    return verified(compile_profile(s, library()))


@pytest.fixture
def reader():
    return _profile()


@pytest.fixture(params=["memory", "file"])
def backend(request, tmp_path):
    if request.param == "memory":
        return InMemoryBackend()
    return FileBackend(tmp_path / "memory.json", deny_path=tmp_path / "memory-deny.json")


def up(op, key, value=None, scope="analyst", sources=None):
    u = {"scope": scope, "op": op, "key": key}
    if value is not None:
        u["value"] = value
    if sources is not None:
        u["sources"] = sources
    return u


def report(profile, pack_hash, updates):
    return {
        "pack_id": pack_hash,
        "profile": profile["id"],
        "status": "ok",
        "summary": "one burst",
        "cites": [{"source": "findings", "ref": "f1"}],
        "unknowns": [],
        "memory_updates": updates,
    }


def put(store, profile, updates, findings=None, **kw):
    findings = findings if findings is not None else [item(1, "clear")]
    pack, h = labelled_pack(list(findings), [item(999, "clear")], profile=profile, **kw)
    return store.apply_updates(profile, updates, pack=pack, pack_hash=h)


def entry(backend, profile, key, scope="analyst"):
    return backend.load(profile["id"])["entries"][scope][key]


# ---------------------------------------------------------------- the verify op
def test_verify_with_a_value_is_refused(reader, backend):
    store = MemoryStore(backend, now=Clock())
    put(store, reader, [up("add", "k", "v", sources=[uid(1)])])
    before = backend.load(reader["id"])
    pack, h = labelled_pack([item(1, "clear")], [item(999, "clear")])
    rep = report(reader, h, [up("verify", "k", "v2", sources=[uid(1)])])
    assert any("verify takes no value" in p for p in validate_report(rep, pack, h))
    with pytest.raises(MemoryUpdateError, match="verify takes no value"):
        store.apply_report(reader, rep, pack=pack, pack_hash=h)
    with pytest.raises(MemoryUpdateError, match="verify takes no value"):
        put(store, reader, [up("verify", "k", "v2", sources=[uid(1)])])
    assert backend.load(reader["id"]) == before


def test_verify_citing_only_mem_sources_or_nothing_is_refused(reader, backend):
    store = MemoryStore(backend, now=Clock())
    put(store, reader, [up("add", "j", "J", sources=[uid(1)]), up("add", "k", "K")])
    before = backend.load(reader["id"])
    mem = memory_block_input(store, reader, ["analyst"])
    ref = f"mem:{reader['id']}/analyst/j@1"
    pack, h = labelled_pack([item(1, "clear")], [item(999, "clear")], memory_block=mem)
    for sources in ([ref], [], None):
        rep = report(reader, h, [up("verify", "k", sources=sources)])
        assert any("not a mem: revision" in p for p in validate_report(rep, pack, h))
        with pytest.raises(MemoryUpdateError, match="not a mem: revision"):
            store.apply_report(reader, rep, pack=pack, pack_hash=h)
    # a mem: source beside a rendered one is fine
    rep = report(reader, h, [up("verify", "k", sources=[ref, uid(1)])])
    assert validate_report(rep, pack, h) == []
    assert backend.load(reader["id"]) == before


def test_verify_citing_an_unrendered_source_is_refused(reader, backend):
    store = MemoryStore(backend, now=Clock())
    put(store, reader, [up("add", "k", "K")])
    before = backend.load(reader["id"])
    with pytest.raises(MemoryUpdateError, match="not an identifier this pack rendered"):
        put(store, reader, [up("verify", "k", sources=[uid(7)])])  # the pack rendered uid(1)
    assert backend.load(reader["id"]) == before


def test_verify_needs_a_live_key_and_a_checked_write(reader, backend):
    store = MemoryStore(backend, now=Clock())
    with pytest.raises(MemoryUpdateError, match="verify of a key that is not live"):
        put(store, reader, [up("verify", "k", sources=[uid(1)])])
    put(store, reader, [up("add", "k", "K")])
    put(store, reader, [up("retire", "k")])
    with pytest.raises(MemoryUpdateError, match="verify of a key that is not live"):
        put(store, reader, [up("verify", "k", sources=[uid(1)])])
    ledger = _profile(memory_scopes=["analyst", FL], platform_scopes=[FL])
    store.apply_updates(ledger, [up("add", "c", "C", scope=FL)], unchecked=True)
    with pytest.raises(MemoryUpdateError, match="verify is a checked write only"):
        store.apply_updates(ledger, [up("verify", "c", scope=FL, sources=[uid(1)])], unchecked=True)


def test_add_replace_and_verify_reassert_and_verify_keeps_the_value(reader, backend):
    clock = Clock()
    store = MemoryStore(backend, now=clock)
    put(store, reader, [up("add", "k", "v1", sources=[uid(1)])])
    assert entry(backend, reader, "k")["reasserted_at"] == stamp(T0)
    put(store, reader, [up("replace", "k", "v2")])  # same time: reassertion moves with it
    clock.tick(10)
    put(store, reader, [up("replace", "k", "v3")])
    assert entry(backend, reader, "k")["reasserted_at"] == stamp(clock.t)
    clock.tick(10)
    applied = put(store, reader, [up("verify", "k", sources=[uid(2)])], [item(2, "clear")])
    assert applied["revs"] == {"analyst/k": 4}  # verify bumps rev
    e = entry(backend, reader, "k")
    assert e["value"] == "v3" and e["rev"] == 4 and e["op"] == "verify"
    assert e["reasserted_at"] == e["updated_at"] == stamp(clock.t)
    assert e["sources"] == [uid(1), uid(2)]  # a verify adds sources, never removes them
    assert "verified_at" not in e  # no verifier: a model's verify is not verification
    rec = store.history(reader, "analyst", "k")["records"][-1]
    assert rec["op"] == "verify" and "value" not in rec and "verified_at" not in rec
    assert (
        rec["value_digest"] == store.history(reader, "analyst", "k")["records"][2]["value_digest"]
    )
    # retire keeps the reassertion it retires
    clock.tick(10)
    put(store, reader, [up("retire", "k")])
    assert entry(backend, reader, "k")["reasserted_at"] == stamp(clock.t - timedelta(minutes=10))


# ---------------------------------------------------------------- verified_at and the Verifier
def test_only_a_verifier_sets_verified_at_and_then_read_reports_fresh(reader, backend):
    clock = Clock()
    stub = StubVerifier()
    plain = MemoryStore(backend, now=clock)
    put(plain, reader, [up("add", "a", "A")])
    assert "verified_at" not in entry(backend, reader, "a")
    store = MemoryStore(backend, now=clock, verifier=stub)
    clock.tick(5)
    put(store, reader, [up("verify", "a", sources=[uid(1)])])
    (ask,) = stub.asked
    assert (ask.owner, ask.scope, ask.key, ask.op, ask.rev, ask.value) == (
        reader["id"], "analyst", "a", "verify", 2, "A"
    )  # fmt: skip
    assert ask.checked is True and ask.sources == (uid(1),)
    assert entry(backend, reader, "a")["verified_at"] == stamp(clock.t)
    assert store.history(reader, "analyst", "a")["records"][-1]["verified_at"] == stamp(clock.t)
    read = store.read(reader, "analyst", stale_after=timedelta(hours=1))
    assert read["entries"] == {"a": "A"} and read["stale"] == {}
    # past the budget the entry is stale again, with both stamps beside it
    clock.tick(120)
    read = store.read(reader, "analyst", stale_after=timedelta(hours=1))
    assert read["stale"] == {
        "a": {"reasserted_at": stamp(T0 + timedelta(minutes=5)),
              "verified_at": stamp(T0 + timedelta(minutes=5))}
    }  # fmt: skip


def test_an_unconfirmed_replace_clears_verified_at_and_an_unconfirmed_verify_keeps_it(
    reader, backend
):
    clock = Clock()
    stub = StubVerifier()
    store = MemoryStore(backend, now=clock, verifier=stub)
    put(store, reader, [up("add", "a", "A"), up("add", "b", "B")])
    assert entry(backend, reader, "a")["verified_at"] == stamp(T0)
    stub.answer = False
    clock.tick()
    put(store, reader, [up("verify", "a", sources=[uid(1)]), up("replace", "b", "B2")])
    assert entry(backend, reader, "a")["verified_at"] == stamp(T0)  # the same value, still
    assert "verified_at" not in entry(backend, reader, "b")  # a new value is unverified
    stub.answer = "yes"  # only True confirms
    put(store, reader, [up("add", "c", "C")])
    assert "verified_at" not in entry(backend, reader, "c")


def test_a_verifier_that_raises_verifies_nothing_and_refuses_nothing(reader, backend, caplog):
    stub = StubVerifier(RuntimeError("boom sha256:" + "a" * 64))
    store = MemoryStore(backend, now=Clock(), verifier=stub)
    assert put(store, reader, [up("add", "a", "A")])["revs"] == {"analyst/a": 1}
    assert "verified_at" not in entry(backend, reader, "a")
    assert "RuntimeError" in caplog.text and "boom" not in caplog.text
    with pytest.raises(TypeError, match="verifier must implement Verifier"):
        MemoryStore(backend, verifier=object())


def test_unverified_entries_are_stale_under_any_budget(reader, backend):
    clock = Clock()
    store = MemoryStore(backend, now=clock)
    put(store, reader, [up("add", "a", "A")])
    clock.tick()
    put(store, reader, [up("verify", "a", sources=[uid(1)])])
    for budget in (timedelta(0), timedelta(days=36500)):
        read = store.read(reader, "analyst", stale_after=budget)
        assert read["stale"] == {"a": {"reasserted_at": stamp(clock.t)}}
    assert "stale" not in store.read(reader, "analyst")  # only asked for
    with pytest.raises(ValueError, match="non-negative timedelta"):
        store.read(reader, "analyst", stale_after=timedelta(seconds=-1))
    with pytest.raises(ValueError, match="non-negative timedelta"):
        store.read(reader, "analyst", stale_after=3600)


# ---------------------------------------------------------------- history, as_of and the fold
def test_history_as_of_and_the_fold_carry_both_stamps(reader, backend):
    clock = Clock()
    stub = StubVerifier()
    store = MemoryStore(backend, now=clock, verifier=stub)
    put(store, reader, [up("add", "a", "A")])  # verified at T0
    stub.answer = False
    clock.tick(30)
    put(store, reader, [up("verify", "a", sources=[uid(1)])])  # reasserted at T0+30, unverified
    stub.answer = True
    clock.tick(30)
    put(store, reader, [up("replace", "a", "A2")])  # verified at T0+60
    stored = backend.load(reader["id"])
    assert fold(stored["log"]) == stored["entries"]
    recs = store.history(reader, "analyst", "a")["records"]
    assert [r.get("verified_at") for r in recs] == [stamp(T0), None, stamp(clock.t)]
    hour = timedelta(hours=1)
    mid = store.as_of(reader, "analyst", T0 + timedelta(minutes=45), stale_after=hour)
    assert mid["entries"] == {"a": "A"} and mid["stale"] == {}
    late = store.as_of(reader, "analyst", T0 + timedelta(minutes=45), stale_after=timedelta(0))
    assert late["stale"] == {
        "a": {"reasserted_at": stamp(T0 + timedelta(minutes=30)), "verified_at": stamp(T0)}
    }
    now = store.as_of(reader, "analyst", clock.t, stale_after=timedelta(0))
    assert now["entries"] == {"a": "A2"} and now["stale"] == {}
    assert "stale" not in store.as_of(reader, "analyst", clock.t)


def test_compaction_keeps_the_stamps_of_what_it_folds(backend):
    ledger = _profile(
        memory_scopes=["analyst", FL],
        platform_scopes=[FL],
        memory_limits={"keep_last": {FL: {"cursor": 1}}},
    )
    clock = Clock()
    store = MemoryStore(backend, now=clock, verifier=StubVerifier())
    store.apply_updates(ledger, [up("add", "cursor", "1", scope=FL)], unchecked=True)
    for n in range(2, 5):
        clock.tick()
        store.apply_updates(ledger, [up("replace", "cursor", str(n), scope=FL)], unchecked=True)
    stored = backend.load(ledger["id"])
    first = stored["log"][0]
    assert first["compacted"] == "range" and first["verified_at"] == stamp(
        clock.t - timedelta(minutes=1)
    )
    assert fold(stored["log"]) == stored["entries"]
    assert stored["entries"][FL]["cursor"]["verified_at"] == stamp(clock.t)


# ---------------------------------------------------------------- the pack's memory block
def test_the_pack_memory_block_reports_stale_entries(reader, backend):
    clock = Clock()
    stub = StubVerifier(False)
    store = MemoryStore(backend, now=clock, verifier=stub)
    put(store, reader, [up("add", "a", "A")])
    stub.answer = True
    put(store, reader, [up("add", "b", "B")])
    clock.tick(5)
    mem = memory_block_input(store, reader, ["analyst"], stale_after=timedelta(hours=1))
    assert [(m["key"], m["stale"], m["reasserted_at"], m.get("verified_at")) for m in mem] == [
        ("a", True, stamp(T0), None),
        ("b", False, stamp(T0), stamp(T0)),
    ]
    pack, _ = labelled_pack([item(2, "clear")], [item(3, "clear")], memory_block=mem)
    assert [(m["key"], m["stale"]) for m in pack["memory"]] == [("a", True), ("b", False)]
    assert pack["memory"][1]["verified_at"] == stamp(T0)
    assert "closure" not in pack["memory"][0]
    # without stale_after the block is what it was (and so is the pack's hash)
    plain = memory_block_input(store, reader, ["analyst"])
    assert all("stale" not in m for m in plain)
    # a malformed staleness report is refused at assembly
    bad = [{**mem[0], "stale": "yes"}]
    with pytest.raises(SpecError, match="stale is a boolean"):
        labelled_pack([item(2)], [item(3)], memory_block=bad)
    half = [{k: v for k, v in mem[0].items() if k != "reasserted_at"}]
    with pytest.raises(SpecError, match="when staleness is reported"):
        labelled_pack([item(2)], [item(3)], memory_block=half)
