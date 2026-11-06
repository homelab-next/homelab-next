# SPDX-License-Identifier: Apache-2.0
"""Agent memory after its security audit and design review (ADR-0037 PR 1): no refusal quotes a
secret, migration keeps no legacy secret, the clock never goes backwards in the log, cap pages
are keyed per pair, reports cannot write platform scopes, and platform scopes stay bounded
(decision 6 as amended).  Store tests run on both backends."""

import json
import threading
from datetime import UTC, datetime, timedelta

import pytest
from agent_support import inputs, library, manifest, spec, verified, write

from homelabnext.agent import assemble_pack, compile_profile
from homelabnext.agent.memory import (
    CAP_TITLE,
    CLOCK_CLEARED,
    CLOCK_TITLE,
    MAX_UPDATES,
    FileBackend,
    InMemoryBackend,
    MemoryAccessError,
    MemoryClockError,
    MemoryLimitError,
    MemoryStore,
    MemoryUpdateError,
    fold,
    tombstone_budget,
)
from homelabnext.notify import FakeSender, Notifier
from homelabnext.state import StateStore

T0 = datetime(2026, 11, 5, 9, 0, tzinfo=UTC)
FL = "fleet-ledger"


class Clock:
    def __init__(self, t=T0):
        self.t = t

    def __call__(self):
        return self.t

    def tick(self, minutes=1):
        self.t += timedelta(minutes=minutes)
        return self.t


def _profile(**extra):
    s = spec()
    s.update(extra)
    return verified(compile_profile(s, library()))


def _ledger(**limits):
    return _profile(memory_scopes=["analyst", FL], platform_scopes=[FL], memory_limits=limits)


@pytest.fixture
def reader():
    return _profile()


@pytest.fixture(params=["memory", "file"])
def backend(request, tmp_path):
    if request.param == "memory":
        return InMemoryBackend()
    return FileBackend(tmp_path / "memory.json")


def seed(backend, owner, value):
    if isinstance(backend, InMemoryBackend):
        backend._data[owner] = value
    else:
        backend._store.put(owner, value)


def up(op, key, value=None, scope="analyst"):
    u = {"scope": scope, "op": op, "key": key}
    if value is not None:
        u["value"] = value
    return u


# secrets are built at run time, so this file holds no credential shape for the leak scanner
SLACK = "xox" + "b-" + "1234567890-abcdefghij"  # also a valid slug: a key or scope can hold it
JWT = "eyJ" + "a" * 10 + ".eyJ" + "b" * 10 + "." + "c" * 10
AWS = "AKIA" + "Z7" * 8
SHAPES = {
    "age-secret-key": "AGE-SECRET-" + "KEY-1" + "Q" * 58,
    "vault-blob": "$ANSIBLE_" + "VAULT;1.1;AES256",
    "aws-secret-key": "aws_secret_" + "access_key = " + "Ab12" * 10,
}


def _leaks(secret, text):
    """Whether any 8-character piece of ``secret`` appears in ``text``."""
    return any(secret[i : i + 8] in text for i in range(len(secret) - 7))


# ---------------------------------------------------------------- F1: no refusal quotes a secret
@pytest.mark.parametrize("kind", sorted(SHAPES))
def test_the_leak_scanners_marker_shapes_are_refused(reader, backend, kind):
    with pytest.raises(MemoryUpdateError) as exc:
        write(MemoryStore(backend), reader, [up("add", "k", "note " + SHAPES[kind])])
    assert kind in str(exc.value) and not _leaks(SHAPES[kind], str(exc.value))
    assert backend.load("profile:reader") == {}


@pytest.mark.parametrize(
    ("updates", "where"),
    [
        ([up("add", "k", None) | {"value": {"nested": JWT}}], "memory_updates/0/value/#0"),
        ([up("add", "k", None) | {"value": ["x", JWT]}], "memory_updates/0/value/1"),
        ([up("add", "k", "v", scope=SLACK)], "memory_updates/0/scope"),
        ([{"scope": "analyst", "op": SLACK, "key": "k"}], "memory_updates/0/op"),
        ([up("add", "k", "v") | {SLACK: "x"}], "memory_updates/0: property #4 name"),
        ({"scope": JWT}, "memory_updates/scope"),
        (JWT, "memory_updates"),
    ],
)
def test_a_secret_anywhere_in_the_updates_is_refused_and_never_quoted(reader, updates, where):
    with pytest.raises(MemoryUpdateError) as exc:
        write(MemoryStore(), reader, updates)
    msg = str(exc.value)
    assert where in msg and "holds a secret" in msg
    assert not _leaks(JWT, msg) and not _leaks(SLACK, msg)


@pytest.mark.parametrize(
    "updates",
    [
        [up("add", "k", None) | {"value": 4111111111111111}],
        [up("add", "Not A Slug Zebracorn", "v")],
        [up("add", "k", "v") | {"zebracorn": "x"}],
        [{"scope": "analyst", "op": "zebracorn", "key": "k"}],
        {"zebracorn": "x"},
    ],
)
def test_schema_refusals_name_path_and_keyword_never_the_value(reader, updates):
    with pytest.raises(MemoryUpdateError) as exc:
        write(MemoryStore(), reader, updates)
    msg = str(exc.value)
    assert "fails" in msg
    assert "4111" not in msg and "Zebracorn" not in msg and "zebracorn" not in msg


def _report(profile, pack_hash, updates, **fields):
    rep = {
        "pack_id": pack_hash,
        "profile": profile["id"],
        "status": "ok",
        "summary": "one burst",
        "cites": [{"source": "findings", "ref": "f1"}],
        "unknowns": [],
        "memory_updates": updates,
    }
    rep.update(fields)
    return rep


@pytest.mark.parametrize(
    ("field", "value", "secret"),
    [
        ("status", JWT, JWT),
        ("summary", "seen key " + AWS, AWS),
        ("cites", [{"source": "findings", "ref": SLACK}], SLACK),
        ("unknowns", ["token " + JWT], JWT),
    ],
)
def test_a_secret_in_any_report_field_is_refused_and_never_quoted(
    reader, backend, field, value, secret
):
    pack, h = assemble_pack(manifest(), inputs(), profile=reader)
    rep = _report(reader, h, [up("add", "k", "v")], **{field: value})
    for kwargs in ({}, {"pack": pack, "pack_hash": h}):
        with pytest.raises(MemoryUpdateError, match="holds a secret") as exc:
            MemoryStore(backend).apply_report(reader, rep, **kwargs)
        assert not _leaks(secret, str(exc.value))
    assert backend.load("profile:reader") == {}


def test_a_report_value_padded_past_the_schema_limit_never_quotes_its_secret(reader, backend):
    pack, h = assemble_pack(manifest(), inputs(), profile=reader)
    secret = "pass" + "word=" + "Tr0ub4dor-horse-9-staple"
    for value in (secret + " " + "x" * 2100, "x" * 2100 + " " + secret):
        rep = _report(reader, h, [up("add", "k", value)])
        with pytest.raises(MemoryUpdateError) as exc:
            MemoryStore(backend).apply_report(reader, rep, pack=pack, pack_hash=h)
        assert "memory_updates/0/value: holds a secret" in str(exc.value)
        assert not _leaks(secret, str(exc.value))


def test_a_non_secret_overlong_report_value_is_refused_by_path_only(reader):
    pack, h = assemble_pack(manifest(), inputs(), profile=reader)
    rep = _report(reader, h, [up("add", "k", "zebracorn " * 300)])
    with pytest.raises(MemoryUpdateError) as exc:
        MemoryStore().apply_report(reader, rep, pack=pack, pack_hash=h)
    assert "memory_updates/0/value: fails maxLength" in str(exc.value)
    assert "zebracorn" not in str(exc.value)


def test_access_refusals_do_not_echo_an_unscreened_name(reader):
    store = MemoryStore()
    for call in (
        lambda: store.read(reader, SLACK)["entries"],
        lambda: store.history(reader, SLACK, "k"),
        lambda: store.as_of(reader, SLACK, T0),
        lambda: store.read(reader, "analyst", owner=SLACK)["entries"],
    ):
        with pytest.raises(MemoryAccessError) as exc:
            call()
        assert not _leaks(SLACK, str(exc.value)) and "not shown" in str(exc.value)
    with pytest.raises(MemoryAccessError, match="'responder' is not in its memory_scopes"):
        store.read(reader, "responder")["entries"]


def test_a_batch_holds_at_most_64_updates(reader, backend):
    store = MemoryStore(backend)
    many = [up("add", f"k{i}", "v") for i in range(MAX_UPDATES + 1)]
    with pytest.raises(MemoryUpdateError, match=f"at most {MAX_UPDATES}"):
        write(store, reader, many)
    write(store, reader, many[:MAX_UPDATES])
    assert len(store.read(reader, "analyst")["entries"]) == MAX_UPDATES


# ---------------------------------------------------------------- F2: migration keeps no secret
@pytest.mark.parametrize("written", [False, True])
def test_migration_keeps_only_the_purged_marker_for_legacy_secrets(
    reader, backend, caplog, written
):
    legacy = {
        "analyst": {
            "fine": {"status": "live", "op": "add", "value": "ok"},
            "creds": {"status": "live", "op": "add", "value": "key " + AWS},
            SLACK: {"status": "live", "op": "add", "value": "harmless"},
        }
    }
    seed(backend, "profile:reader", legacy)
    clock = Clock()
    store = MemoryStore(backend, now=clock)
    if written:
        write(store, reader, [up("add", "new", "n")])
        stored = backend.load("profile:reader")
        assert fold(stored["log"]) == stored["entries"]
    seen = store.read(reader, "analyst", include_retired=True)["entries"]
    log_text = json.dumps(store.history(reader, "analyst", "creds"))
    everything = json.dumps([seen, log_text, backend.load("profile:reader") if written else {}])
    assert not _leaks(AWS, everything) and not _leaks(SLACK, everything)
    assert seen["fine"] == "ok" and seen["creds"] is None
    (creds,) = store.history(reader, "analyst", "creds")["records"]
    # no digest of either: an unsalted digest of a low-entropy secret confirms a guess offline
    assert creds["purged"] is True and "value" not in creds and "value_digest" not in creds
    renamed = [k for k in seen if k.startswith("purged-")]
    assert renamed == ["purged-2"] and seen["purged-2"] is None  # named by its position
    (rec,) = store.history(reader, "analyst", "purged-2")["records"]
    assert rec["purged"] is True and "key_digest" not in rec and "value_digest" not in rec
    said = [r.message for r in caplog.records if "migration kept only the" in r.message]
    assert len(said) == 1
    assert "scope #0 entry #0 (value)" in said[0] and "(key)" in said[0]
    assert not _leaks(AWS, said[0]) and not _leaks(SLACK, said[0])


# ---------------------------------------------------------------- the clock
def test_a_small_clock_lag_is_absorbed_and_a_large_one_refused_and_paged(
    reader, backend, tmp_path, caplog
):
    sender = FakeSender()
    notifier = Notifier(sender, StateStore(tmp_path / "n.json"))
    clock = Clock(T0 + timedelta(hours=1))
    store = MemoryStore(backend, now=clock, notifier=notifier)
    write(store, reader, [up("add", "a", "1")])
    clock.t = T0 + timedelta(minutes=56)  # 4 minutes back: stamped at the log's time
    write(store, reader, [up("add", "b", "1")])
    ats = [r["at"] for r in backend.load("profile:reader")["log"]]
    assert ats == ["2026-11-05T10:00:00.000000Z", "2026-11-05T10:00:00.000000Z"]
    before = backend.load("profile:reader")
    clock.t = T0  # an hour back: refused, nothing written, one page
    for _ in range(2):
        with pytest.raises(MemoryClockError, match=r"behind .* by 1:00:00") as exc:
            write(store, reader, [up("add", "c", "1")])
    assert exc.value.behind == timedelta(hours=1)
    assert backend.load("profile:reader") == before
    assert sender.titles == [CLOCK_TITLE] and "1:00:00" in sender.sent[0].body
    clock.t = T0 + timedelta(hours=2)
    write(store, reader, [up("add", "c", "1")])
    assert backend.load("profile:reader")["log"][-1]["at"] == "2026-11-05T11:00:00.000000Z"
    assert sender.titles == [CLOCK_TITLE, CLOCK_CLEARED]
    # without a notifier the lag is logged once
    quiet = MemoryStore(backend, now=lambda: T0)
    for _ in range(2):
        with pytest.raises(MemoryClockError):
            write(quiet, reader, [up("add", "d", "1")])
    assert len([r for r in caplog.records if "clock is behind its log" in r.message]) == 1


class _Flagged:
    """A backend that marks when its transaction runs, so the clock can prove where it is read."""

    def __init__(self, inner):
        self.inner = inner
        self.inside = False

    def load(self, owner):
        return self.inner.load(owner)

    def transact(self, owner, fn):
        def wrapped(cur):
            self.inside = True
            try:
                return fn(cur)
            finally:
                self.inside = False

        return self.inner.transact(owner, wrapped)


def test_the_clock_is_read_inside_the_transaction(reader, backend):
    flagged = _Flagged(backend)
    reads = []

    def clock():
        reads.append(flagged.inside)
        return T0

    write(MemoryStore(flagged, now=clock), reader, [up("add", "k", "v")])
    assert reads == [True]


# ---------------------------------------------------------------- paging
def test_cap_pages_of_two_pairs_never_share_a_key(backend, tmp_path):
    def prof(pid, scope):
        s = spec()
        s.update(id=pid, memory_scopes=[scope], memory_limits={"records": {scope: 1}})
        return verified(compile_profile(s, library()))

    # the old sanitised key was agent-memory-cap-profile-x-y-z for both
    a, b = prof("profile:x-y", "z"), prof("profile:x", "y-z")
    sender = FakeSender()
    store = MemoryStore(
        backend, now=Clock(), notifier=Notifier(sender, StateStore(tmp_path / "n.json"))
    )
    write(store, a, [up("add", "k1", "v", scope="z")])
    with pytest.raises(MemoryLimitError):
        write(store, a, [up("add", "k2", "v", scope="z")])
    write(store, b, [up("add", "k1", "v", scope="y-z")])  # b's accepted write
    assert sender.titles == [CAP_TITLE]  # did not clear a's page
    with pytest.raises(MemoryLimitError):
        write(store, b, [up("add", "k2", "v", scope="y-z")])
    assert sender.titles == [CAP_TITLE, CAP_TITLE]  # b's own crossing pages


def test_cap_advice_depends_on_the_scope_kind(backend, tmp_path):
    p = _ledger(records={"analyst": 1, FL: 1})
    sender = FakeSender()
    clock = Clock()
    store = MemoryStore(
        backend, now=clock, notifier=Notifier(sender, StateStore(tmp_path / "n.json"))
    )
    write(store, p, [up("add", "a", "1")])  # a model scope is written checked, with its pack
    write(store, p, [up("add", "a", "1", scope=FL)])  # a platform scope unchecked
    clock.tick()
    before = backend.load(p["id"])
    with pytest.raises(MemoryLimitError) as model:
        write(store, p, [up("add", "b", "1")])
    assert "raise memory_limits.records in the reviewed profile (or an operator purge" in str(
        model.value
    )
    assert "keep_last" not in str(model.value)
    clock.tick()
    with pytest.raises(MemoryLimitError) as plat:
        write(store, p, [up("add", "b", "1", scope=FL)])
    assert "keep_last" in str(plat.value) and "operator purge" not in str(plat.value)
    assert backend.load(p["id"]) == before  # the clock moved; nothing was written
    assert "operator purge" in sender.sent[0].body and "keep_last" in sender.sent[1].body


# ---------------------------------------------------------------- platform scopes and reports
def test_a_report_may_not_write_a_platform_scope(backend):
    p = _ledger()
    pack, h = assemble_pack(manifest(), inputs(), profile=p)
    rep = _report(p, h, [up("add", "k", "v"), up("add", "item-a", "v", scope=FL)])
    with pytest.raises(
        MemoryUpdateError, match="memory_updates/1: scope 'fleet-ledger' is a platform"
    ):
        MemoryStore(backend).apply_report(p, rep, pack=pack, pack_hash=h)
    assert backend.load(p["id"]) == {}
    write(MemoryStore(backend), p, [up("add", "item-a", "v", scope=FL)])  # platform code


# ---------------------------------------------------------------- decision 6, amended
def test_a_platform_scope_stays_bounded_under_ten_times_its_cap(backend):
    cap = 40
    p = _ledger(records={FL: cap}, keep_last={FL: {"cursor": 2}})
    assert tombstone_budget(p, FL) == 4
    clock = Clock()
    store = MemoryStore(backend, now=clock)
    write(store, p, [up("add", "cursor", "0", scope=FL)])
    for i in range(10 * cap):
        clock.tick()
        write(
            store,
            p,
            [
                up("replace", "cursor", str(i + 1), scope=FL),
                up("add", f"item-{i}", "x", scope=FL),
                up("retire", f"item-{i}", scope=FL),
            ],
        )
        stored = backend.load(p["id"])
        assert len(stored["log"]) <= cap
    assert fold(stored["log"]) == stored["entries"]
    assert store.read(p, FL)["entries"] == {"cursor": str(10 * cap)}
    tombs = [r for r in stored["log"] if r.get("compacted") == "whole"]
    (aged,) = [r for r in stored["log"] if r["op"] == "aged"]
    assert len(tombs) == 4 and aged["count"] == 10 * cap - 4 and aged["key"] is None
    cursor = store.history(p, FL, "cursor")["records"]
    assert [r["rev"] for r in cursor] == [10 * cap - 1, 10 * cap, 10 * cap + 1]
    assert cursor[0]["compacted"] == "range" and cursor[0]["rev_from"] == 1
    # an aged-out key comes back above the scope's high-water rev: rev never reused
    issued = aged["rev"]
    assert store.history(p, FL, "item-0") == {"records": [], "withheld": 0}
    write(store, p, [up("add", "item-0", "again", scope=FL)])
    assert store.history(p, FL, "item-0")["records"][0]["rev"] == issued + 1
    # as_of over the aged range says so; after it, it does not
    early = store.as_of(p, FL, T0 + timedelta(minutes=5))
    assert early["aged_out"] is True and early["compacted"] == ["cursor"]
    assert store.as_of(p, FL, clock.tick(60))["aged_out"] is False


def test_compaction_keeps_unions_and_the_strictest_label_of_what_it_folds(backend):
    """Seeded records carry sources, closures and labels (as PR 2 will write them)."""
    p = _ledger(keep_last={FL: {"item-*": 1}})
    owner = p["id"]

    def rec(key, op, rev, at, value, **kw):
        r = {
            "at": f"2026-11-05T08:{at:02d}:00.000000Z",
            "scope": FL,
            "key": key,
            "op": op,
            "rev": rev,
            "pack_id": f"sha256:{rev:064d}",
            "sources": kw.get("sources", []),
            "checked": kw.get("checked", True),
            "tlp": kw.get("tlp", "green"),
            "closure": kw.get("closure", []),
        }
        if value is not None:
            r["value"] = value
            r["value_digest"] = "sha256:" + str(rev) * 64
        return r

    log = [
        rec("item-a", "add", 1, 0, "a1", sources=["s1"], closure=["c1"], tlp="amber"),
        rec("item-a", "replace", 2, 1, "a2", sources=["s2"], closure=["c2"], tlp="green"),
        rec("item-b", "add", 1, 2, "b1", sources=["s3"], closure=["c3"], tlp="green"),
    ]
    seed(backend, owner, {"entries": fold(log), "log": log})
    store = MemoryStore(backend, now=Clock())
    write(store, p, [up("replace", "item-a", "a3", scope=FL), up("retire", "item-b", scope=FL)])
    rng = store.history(p, FL, "item-a")["records"][0]
    assert rng["compacted"] == "range"
    assert rng["sources"] == ["s1", "s2"] and rng["closure"] == ["c1", "c2"]
    assert rng["tlp"] == "amber" and rng["checked"] is True
    assert rng["pack_ids"] == [f"sha256:{1:064d}", f"sha256:{2:064d}"]
    (tomb,) = store.history(p, FL, "item-b")["records"]
    # the retire's closure is the key's effective sources (decision 10), unioned into the tombstone
    assert tomb["sources"] == ["s3"] and tomb["closure"] == ["c3", "s3"]
    assert tomb["tlp"] == "red" and tomb["checked"] is False  # its retire record is red, unchecked
    stored = backend.load(owner)
    assert fold(stored["log"]) == stored["entries"]
    assert stored["entries"][FL]["item-a"]["sources"] == ["s1", "s2"]


def test_overlapping_keep_last_globs_take_the_largest(backend):
    p = _ledger(keep_last={FL: {"item-*": 1, "item-a*": 3}})
    clock = Clock()
    store = MemoryStore(backend, now=clock)
    write(store, p, [up("add", "item-ab", "0", scope=FL), up("add", "item-b", "0", scope=FL)])
    for v in range(1, 5):
        clock.tick()
        write(
            store,
            p,
            [up("replace", "item-ab", str(v), scope=FL), up("replace", "item-b", str(v), scope=FL)],
        )
    whole = [r for r in store.history(p, FL, "item-ab")["records"] if not r.get("compacted")]
    assert len(whole) == 3
    whole = [r for r in store.history(p, FL, "item-b")["records"] if not r.get("compacted")]
    assert len(whole) == 1


def test_tombstones_budget_is_configurable_and_platform_only(backend):
    p = _ledger(tombstones={FL: 2})
    assert tombstone_budget(p, FL) == 2
    from homelabnext.agent import SpecError

    with pytest.raises(SpecError, match=r"memory_limits\.tombstones: 'analyst' is not a platform"):
        _ledger(tombstones={"analyst": 2})
    store = MemoryStore(backend, now=Clock())
    for i in range(5):
        write(store, p, [up("add", f"k{i}", "v", scope=FL), up("retire", f"k{i}", scope=FL)])
    tombs = [r["key"] for r in backend.load(p["id"])["log"] if r.get("compacted") == "whole"]
    assert tombs == ["k3", "k4"]  # the oldest aged out first


def test_empty_memory_limits_normalise_away(reader):
    assert _profile(memory_limits={})["digest"] == reader["digest"]
    assert _profile(memory_limits={"records": {}, "keep_last": {}})["digest"] == reader["digest"]


def test_the_in_memory_backend_serialises_writers(reader):
    backend = InMemoryBackend()
    store = MemoryStore(backend)
    threads = [
        threading.Thread(target=write, args=(store, reader, [up("add", f"k{i}", "v")]))
        for i in range(16)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(backend.load("profile:reader")["log"]) == 16
    assert isinstance(backend._lock, type(threading.Lock()))
