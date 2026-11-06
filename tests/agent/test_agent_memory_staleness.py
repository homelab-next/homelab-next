# SPDX-License-Identifier: Apache-2.0
"""Agent memory staleness (ADR-0037 PR 4, decision 15): a model reasserts a fact (``add``,
``replace`` and ``verify`` set ``reasserted_at``); only a :class:`Verifier` verifies one
(``verified_at``); ``op: verify`` takes no value, bumps ``rev`` and must cite a non-``mem:``
source the pack rendered; ``read``/``as_of`` with ``stale_after`` report stale entries, and the
pack's memory block carries them.  Every store test runs on both backends."""

from datetime import UTC, datetime, timedelta

import pytest
from agent_support import item, labelled_pack, library, spec, uid, verified
from memory_admin_support import operator

from homelabnext.agent import SpecError, compile_profile, validate_report
from homelabnext.agent.memory import (
    FileBackend,
    InMemoryBackend,
    MemoryLimitError,
    MemoryStore,
    MemoryUpdateError,
    Verifier,
    VerifyRequest,
    _size,
    fold,
    memory_block_input,
)
from homelabnext.memory_admin import MemoryAdmin

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
    """A test :class:`Verifier` (none ships): answers what ``answer`` says (a list: one answer
    per request, in order) and records every request."""

    def __init__(self, answer=True):
        self.answer = answer
        self.asked: list[VerifyRequest] = []

    def verify(self, request):
        self.asked.append(request)
        answer = self.answer.pop(0) if isinstance(self.answer, list) else self.answer
        if isinstance(answer, Exception):
            raise answer
        return answer


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


def test_an_unconfirmed_replace_or_a_refuted_verify_clears_verified_at(reader, backend):
    clock = Clock()
    stub = StubVerifier()
    store = MemoryStore(backend, now=clock, verifier=stub)
    put(store, reader, [up("add", "a", "A"), up("add", "b", "B"), up("add", "d", "D")])
    assert entry(backend, reader, "a")["verified_at"] == stamp(T0)
    clock.tick()
    # a verifier that cannot tell (it raises, or answers anything but a bool) keeps the stamp
    stub.answer = [RuntimeError("down"), "yes", False]
    put(
        store,
        reader,
        [
            up("verify", "a", sources=[uid(1)]),
            up("verify", "d", sources=[uid(1)]),
            up("replace", "b", "B2"),
        ],
    )
    assert entry(backend, reader, "a")["verified_at"] == stamp(T0)  # the same value, still
    assert entry(backend, reader, "d")["verified_at"] == stamp(T0)
    assert "verified_at" not in entry(backend, reader, "b")  # a new value is unverified
    # an explicit False on a verify says the fact does not hold: the old stamp goes
    stub.answer = False
    clock.tick()
    put(store, reader, [up("verify", "a", sources=[uid(1)])])
    assert "verified_at" not in entry(backend, reader, "a")
    rec = store.history(reader, "analyst", "a")["records"][-1]
    assert rec["refuted"] is True and "verified_at" not in rec
    stored = backend.load(reader["id"])
    assert fold(stored["log"]) == stored["entries"]
    assert store.read(reader, "analyst", stale_after=timedelta(days=1))["stale"]["a"] == {
        "reasserted_at": stamp(clock.t)
    }
    stub.answer = "yes"  # only True confirms
    put(store, reader, [up("add", "c", "C")])
    assert "verified_at" not in entry(backend, reader, "c")


def test_the_verifier_is_asked_only_about_an_accepted_batch_and_gets_the_label(reader, backend):
    stub = StubVerifier()
    store = MemoryStore(backend, now=Clock(), verifier=stub)
    with pytest.raises(MemoryUpdateError, match="replace of a key that is not live"):
        put(store, reader, [up("add", "a", "secret A"), up("replace", "z", "Z")])
    assert stub.asked == []  # a refused batch's values never reach the verifier
    put(store, reader, [up("add", "a", "A")], [item(1, "amber")])
    put(store, reader, [up("add", "b", "B")], [item(1, "green")])
    assert [ask.tlp for ask in stub.asked] == ["amber", "green"]
    assert [entry(backend, reader, k)["tlp"] for k in "ab"] == ["amber", "green"]


def test_a_batch_refused_by_the_record_cap_never_reaches_the_verifier(backend):
    p = _profile(memory_limits={"records": {"analyst": 1}})
    stub = StubVerifier()
    clock = Clock()
    store = MemoryStore(backend, now=clock, verifier=stub)
    put(store, p, [up("add", "a", "A")])
    before = backend.load(p["id"])
    clock.tick()
    with pytest.raises(MemoryLimitError) as exc:
        put(store, p, [up("add", "b", "SECRET")])
    assert exc.value.unit == "records"
    assert [r.value for r in stub.asked] == ["A"]  # never the refused batch's value
    assert backend.load(p["id"]) == before


def test_a_batch_refused_by_the_byte_cap_never_reaches_the_verifier(backend):
    p = _profile(memory_limits={"bytes": {"analyst": 1024}})
    stub = StubVerifier()
    store = MemoryStore(backend, now=Clock(), verifier=stub)
    with pytest.raises(MemoryLimitError) as exc:
        put(store, p, [up("add", "a", "SECRET" + "x" * 1100)])
    assert exc.value.unit == "bytes" and stub.asked == []
    assert not backend.load(p["id"]).get("log")


def test_the_byte_cap_reserves_the_stamp_the_verifier_may_add(tmp_path):
    """A batch that fits only without its ``verified_at`` stamp is refused before the verifier
    is asked (the trial run reserves the stamp); the same batch with no verifier fits."""
    cap = 1024
    p = _profile(memory_limits={"bytes": {"analyst": cap}})
    probe = InMemoryBackend()
    put(MemoryStore(probe, now=Clock()), p, [up("add", "a", "v")])
    (rec,) = probe.load(p["id"])["log"]
    fill = "v" + "x" * (cap - _size(rec))  # exactly the cap, unstamped
    plain = InMemoryBackend()
    put(MemoryStore(plain, now=Clock()), p, [up("add", "a", fill)])
    assert _size(plain.load(p["id"])["log"][0]) == cap
    stub = StubVerifier()
    with pytest.raises(MemoryLimitError, match="byte cap"):
        put(MemoryStore(InMemoryBackend(), now=Clock(), verifier=stub), p, [up("add", "a", fill)])
    assert stub.asked == []


def test_a_batch_refused_by_the_exposure_budget_never_reaches_the_verifier(backend):
    p = _profile(memory_limits={"exposure_bytes": 65536})
    first, h1 = labelled_pack([item(n, "clear") for n in range(1, 300)], [item(900)], profile=p)
    second, h2 = labelled_pack(
        [item(n, "clear") for n in range(1000, 1300)], [item(1900)], profile=p
    )
    stub = StubVerifier()
    clock = Clock()
    store = MemoryStore(backend, now=clock, verifier=stub)
    store.apply_updates(p, [up("add", "a", "A")], pack=first, pack_hash=h1)
    clock.tick()
    with pytest.raises(MemoryLimitError) as exc:
        store.apply_updates(p, [up("add", "b", "SECRET")], pack=second, pack_hash=h2)
    assert exc.value.unit == "exposure"
    assert [r.value for r in stub.asked] == ["A"]


def test_a_verify_in_the_same_batch_as_its_add_keeps_the_adds_stamp(reader, backend):
    stub = StubVerifier([True, RuntimeError("down")])
    store = MemoryStore(backend, now=Clock(), verifier=stub)
    put(store, reader, [up("add", "a", "A"), up("verify", "a", sources=[uid(1)])])
    assert [r.op for r in stub.asked] == ["add", "verify"]
    e = entry(backend, reader, "a")
    assert e["rev"] == 2 and e["verified_at"] == stamp(T0)


def test_a_verified_at_from_the_future_reads_stale_after_a_restamp(reader, backend, tmp_path):
    ahead = Clock(T0 + timedelta(days=365))
    store = MemoryStore(backend, now=ahead, verifier=StubVerifier())
    put(store, reader, [up("add", "a", "A")])
    assert entry(backend, reader, "a")["verified_at"] == stamp(ahead.t)
    back = Clock(T0)
    admin = MemoryAdmin(backend, now=back)
    admin.restamp(reader["id"], "clock ran a year ahead", by=operator(tmp_path), expect_now=T0)
    back.tick(60 * 24 * 30)
    late = MemoryStore(backend, now=back)
    assert late.read(reader, "analyst", stale_after=timedelta(days=1))["stale"] == {
        "a": {"reasserted_at": stamp(T0), "verified_at": stamp(ahead.t)}
    }
    (mem,) = memory_block_input(late, reader, ["analyst"], stale_after=timedelta(days=1))
    assert mem["stale"] is True
    seen = late.as_of(reader, "analyst", back.t, stale_after=timedelta(days=1))
    assert seen["stale"] == {"a": {"reasserted_at": stamp(T0), "verified_at": stamp(ahead.t)}}


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


def test_a_budget_reaching_past_the_calendar_marks_only_unverified_entries_stale(reader, backend):
    clock = Clock()
    store = MemoryStore(backend, now=clock, verifier=StubVerifier([True, False]))
    put(store, reader, [up("add", "a", "A"), up("add", "b", "B")])
    for budget in (timedelta.max, T0 - datetime(999, 1, 1, tzinfo=UTC)):
        read = store.read(reader, "analyst", stale_after=budget)
        assert read["stale"] == {"b": {"reasserted_at": stamp(T0)}}
        seen = store.as_of(reader, "analyst", T0, stale_after=budget)
        assert seen["stale"] == read["stale"]
        mem = memory_block_input(store, reader, ["analyst"], stale_after=budget)
        assert [m["stale"] for m in mem] == [False, True]


# ---------------------------------------------------------------- history, as_of and the fold
def test_history_as_of_and_the_fold_carry_both_stamps(reader, backend):
    clock = Clock()
    stub = StubVerifier()
    store = MemoryStore(backend, now=clock, verifier=stub)
    put(store, reader, [up("add", "a", "A")])  # verified at T0
    stub.answer = RuntimeError("down")
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


def test_as_of_judges_staleness_at_t_not_at_now(reader, backend):
    clock = Clock()
    store = MemoryStore(backend, now=clock, verifier=StubVerifier())
    put(store, reader, [up("add", "a", "A")])  # verified at T0
    clock.tick(60)
    half = timedelta(minutes=30)
    then = store.as_of(reader, "analyst", T0 + timedelta(minutes=20), stale_after=half)
    assert then["entries"] == {"a": "A"} and then["stale"] == {}  # fresh at T0+20
    assert store.read(reader, "analyst", stale_after=half)["stale"] == {
        "a": {"reasserted_at": stamp(T0), "verified_at": stamp(T0)}
    }  # stale now, at T0+60


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


def test_a_folded_record_carries_verified_at_into_the_fold(backend):
    ledger = _profile(
        memory_scopes=["analyst", FL],
        platform_scopes=[FL],
        memory_limits={"keep_last": {FL: {"cursor": 1}}},
    )
    clock = Clock()
    store = MemoryStore(backend, now=clock, verifier=StubVerifier())
    store.apply_updates(ledger, [up("add", "cursor", "1", scope=FL)], unchecked=True)
    clock.tick()
    store.apply_updates(ledger, [up("retire", "cursor", scope=FL)], unchecked=True)
    stored = backend.load(ledger["id"])
    (folded,) = [r for r in stored["log"] if r["key"] == "cursor"]
    assert folded["compacted"] and folded["verified_at"] == stamp(T0)
    # the retired entry's stamp comes from the folded record alone
    assert fold(stored["log"])[FL]["cursor"]["verified_at"] == stamp(T0)
    assert fold(stored["log"]) == stored["entries"]
    read = store.read(ledger, FL, include_retired=True, stale_after=timedelta(days=1))
    assert read["stale"] == {}


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
    fresh = [{**mem[0], "stale": False}]  # no verified_at: it cannot be fresh
    with pytest.raises(SpecError, match="no verified_at is stale"):
        labelled_pack([item(2)], [item(3)], memory_block=fresh)
