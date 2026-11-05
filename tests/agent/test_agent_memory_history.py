# SPDX-License-Identifier: Apache-2.0
"""Agent memory is historied (ADR-0037 PR 1, decisions 1 to 6): a change log written in the same
transaction as the entry, entries derived from it, an injected clock, the secret screen, owner-
scoped history reads, and per-scope caps with compaction.  Every store test runs on both
backends."""

from datetime import UTC, datetime, timedelta

import pytest
from agent_support import inputs, library, manifest, spec, verified

from homelabnext.agent import SpecError, assemble_pack, compile_profile
from homelabnext.agent.memory import (
    CAP_CLEARED,
    CAP_TITLE,
    DEFAULT_PLATFORM_RECORDS,
    DEFAULT_RECORDS,
    FileBackend,
    InMemoryBackend,
    MemoryAccessError,
    MemoryLimitError,
    MemoryStore,
    MemoryUpdateError,
    fold,
    record_cap,
)
from homelabnext.notify import FakeSender, Notifier
from homelabnext.state import StateStore

T0 = datetime(2026, 11, 5, 9, 0, tzinfo=UTC)
OWNER = "profile:reader"


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


@pytest.fixture
def reader():
    return _profile()


@pytest.fixture
def ledger():
    """A profile with a platform scope, a record cap of 4 on it and keep_last 2 for items."""
    return _profile(
        memory_scopes=["analyst", "fleet-ledger"],
        platform_scopes=["fleet-ledger"],
        memory_limits={
            "records": {"analyst": 3, "fleet-ledger": 4},
            "keep_last": {"fleet-ledger": {"item-*": 2}},
        },
    )


@pytest.fixture(params=["memory", "file"])
def backend(request, tmp_path):
    if request.param == "memory":
        return InMemoryBackend()
    return FileBackend(tmp_path / "memory.json")


def raw(backend, owner=OWNER):
    return backend.load(owner)


def seed(backend, owner, value):
    """Write a stored value directly, as an older release (or nothing at all) would have."""
    if isinstance(backend, InMemoryBackend):
        backend._data[owner] = value
    else:
        backend._store.put(owner, value)


def up(op, key, value=None, scope="analyst"):
    u = {"scope": scope, "op": op, "key": key}
    if value is not None:
        u["value"] = value
    return u


# ---------------------------------------------------------------- decisions 1 and 2
def test_every_update_appends_one_record_with_the_decided_fields(reader, backend):
    clock = Clock()
    store = MemoryStore(backend, now=clock)
    store.apply_updates(reader, [up("add", "burst", "seen once")], pack_id="sha256:" + "2" * 64)
    (rec,) = store.history(reader, "analyst", "burst")["records"]
    assert rec == {
        "at": "2026-11-05T09:00:00.000000Z",
        "scope": "analyst",
        "key": "burst",
        "op": "add",
        "rev": 1,
        "value": "seen once",
        "value_digest": "sha256:" + __import__("hashlib").sha256(b"seen once").hexdigest(),
        "pack_id": "sha256:" + "2" * 64,
        "sources": [],
        "checked": False,
        "tlp": "red",
        "closure": [],
    }
    clock.tick()
    store.apply_updates(reader, [up("retire", "burst")])
    retire = store.history(reader, "analyst", "burst")["records"][1]
    assert "value" not in retire and retire["value_digest"] == rec["value_digest"]
    assert retire["op"] == "retire" and retire["pack_id"] is None and "reason" not in retire


@pytest.mark.parametrize(
    "batch",
    [
        [up("add", "good", "v"), up("replace", "missing", "v")],  # a semantic refusal
        [up("add", "good", "v"), up("add", "k", "v" * 2001)],  # a schema refusal
        [up("add", "good", "v"), up("add", "k", "aws " + "AKIA" + "Q" * 16)],  # the screen
        [up("add", "good", "v"), up("add", "good", "again")],  # within one batch
    ],
)
def test_a_failed_batch_writes_neither_entry_nor_record(reader, backend, batch):
    store = MemoryStore(backend, now=Clock())
    store.apply_updates(reader, [up("add", "kept", "v")])
    before = raw(backend)
    with pytest.raises(MemoryUpdateError):
        store.apply_updates(reader, batch)
    assert raw(backend) == before
    assert len(before["log"]) == 1 and store.read(reader, "analyst") == {"kept": "v"}


def test_a_batch_over_the_cap_writes_neither_entry_nor_record(ledger, backend):
    store = MemoryStore(backend, now=Clock())
    store.apply_updates(ledger, [up("add", "a", "1"), up("add", "b", "2")])
    before = raw(backend, ledger["id"])
    with pytest.raises(MemoryLimitError):
        store.apply_updates(ledger, [up("add", "c", "3"), up("add", "d", "4")])
    assert raw(backend, ledger["id"]) == before


def _workload(store, ledger, clock):
    store.apply_updates(ledger, [up("add", "a", "1"), up("add", "b", "1")])
    clock.tick()
    store.apply_updates(ledger, [up("replace", "a", "2"), up("retire", "b")])
    clock.tick()
    store.apply_updates(ledger, [up("add", "b", "again")], pack_id="sha256:" + "3" * 64)
    clock.tick()
    store.apply_updates(ledger, [up("add", "item-x", "1", scope="fleet-ledger")])
    for v in ("2", "3"):
        clock.tick()
        store.apply_updates(ledger, [up("replace", "item-x", v, scope="fleet-ledger")])
    clock.tick()
    store.apply_updates(ledger, [up("add", "item-y", "1", scope="fleet-ledger")])
    clock.tick()
    store.apply_updates(ledger, [up("retire", "item-y", scope="fleet-ledger")])


def test_folding_the_log_reproduces_the_entries(ledger, backend):
    ledger = _profile(
        memory_scopes=["analyst", "fleet-ledger"],
        platform_scopes=["fleet-ledger"],
        memory_limits={"keep_last": {"fleet-ledger": {"item-*": 2}}},
    )
    clock = Clock()
    store = MemoryStore(backend, now=clock)
    _workload(store, ledger, clock)
    stored = raw(backend, ledger["id"])
    assert set(stored) == {"entries", "log"}
    assert fold(stored["log"]) == stored["entries"]
    assert stored["entries"]["analyst"]["b"]["pack_id"] == "sha256:" + "3" * 64
    assert store.read(ledger, "fleet-ledger") == {"item-x": "3"}
    assert store.read(ledger, "analyst") == {"a": "2", "b": "again"}


def test_rev_never_restarts_through_retire_and_re_add(reader, backend):
    clock = Clock()
    store = MemoryStore(backend, now=clock)
    for batch in (
        [up("add", "k", "one")],
        [up("replace", "k", "two")],
        [up("retire", "k")],
        [up("add", "k", "three")],
    ):
        store.apply_updates(reader, batch)
        clock.tick()
    revs = [r["rev"] for r in store.history(reader, "analyst", "k")["records"]]
    assert revs == [1, 2, 3, 4]
    entry = raw(backend)["entries"]["analyst"]["k"]
    assert entry["rev"] == 4 and entry["status"] == "live" and entry["value"] == "three"
    assert entry["updated_at"] == entry["reasserted_at"] == "2026-11-05T09:03:00.000000Z"
    assert (entry["checked"], entry["tlp"], entry["sources"]) == (False, "red", [])


def test_retire_keeps_reasserted_at_and_updated_at_moves(reader, backend):
    clock = Clock()
    store = MemoryStore(backend, now=clock)
    store.apply_updates(reader, [up("add", "k", "v")])
    clock.tick(5)
    store.apply_updates(reader, [up("retire", "k")])
    entry = raw(backend)["entries"]["analyst"]["k"]
    assert entry["reasserted_at"] == "2026-11-05T09:00:00.000000Z"
    assert entry["updated_at"] == "2026-11-05T09:05:00.000000Z"


def test_pre_log_memory_migrates_once_on_the_next_write(reader, backend):
    legacy = {
        "analyst": {
            "old-fact": {
                "status": "live",
                "op": "replace",
                "value": "v",
                "pack_id": "sha256:" + "4" * 64,
            },
            "gone": {"status": "retired", "op": "retire", "value": "was"},
        }
    }
    seed(backend, OWNER, legacy)
    clock = Clock()
    store = MemoryStore(backend, now=clock)
    # readable before the migration is written, as the migrated shape
    assert store.read(reader, "analyst") == {"old-fact": "v"}
    assert store.read(reader, "analyst", include_retired=True)["gone"] == "was"
    assert raw(backend) == legacy  # a read writes nothing
    clock.tick()
    store.apply_updates(reader, [up("replace", "old-fact", "w")])
    stored = raw(backend)
    first = [r for r in stored["log"] if r.get("migrated")]
    assert {(r["key"], r["rev"], r["checked"], r["tlp"], len(r["sources"])) for r in first} == {
        ("old-fact", 1, False, "red", 0),
        ("gone", 1, False, "red", 0),
    }
    assert all(r["at"] == "2026-11-05T09:01:00.000000Z" for r in first)
    assert stored["entries"]["analyst"]["old-fact"]["rev"] == 2
    assert stored["entries"]["analyst"]["gone"]["value"] == "was"
    assert fold(stored["log"]) == stored["entries"]
    clock.tick()
    store.apply_updates(reader, [up("add", "new", "x")])
    assert len([r for r in raw(backend)["log"] if r.get("migrated")]) == 2  # once
    # before the migration its history is unknown: compacted, never a value
    before = store.as_of(reader, "analyst", T0)
    assert before["entries"] == {} and before["compacted"] == ["gone", "old-fact"]


# ---------------------------------------------------------------- decision 3
def test_the_clock_is_injected_and_must_be_aware(reader, backend):
    store = MemoryStore(backend, now=lambda: datetime(2030, 1, 2, 3, 4, 5, tzinfo=UTC))
    store.apply_updates(reader, [up("add", "k", "v")])
    assert raw(backend)["log"][0]["at"] == "2030-01-02T03:04:05.000000Z"
    naive = MemoryStore(backend, now=lambda: datetime(2030, 1, 2))
    with pytest.raises(ValueError, match="aware UTC"):
        naive.apply_updates(reader, [up("add", "j", "v")])
    assert len(raw(backend)["log"]) == 1


# ---------------------------------------------------------------- decision 4
def _secrets():
    # built at run time, so this file holds no credential shape for the leak scanner
    return {
        "aws-access-key": "key " + "AKIA" + "Z7" * 8,
        "jwt": "eyJ" + "a" * 10 + ".eyJ" + "b" * 10 + "." + "c" * 10,
        "private-key": "-----BEGIN " + "RSA PRIVATE KEY-----\nMIIB",
        "secret": "pass" + "word=" + "Tr0ub4dor-horse-9",
    }


@pytest.mark.parametrize("kind", sorted(_secrets()))
def test_a_secret_value_refuses_the_batch_naming_position_and_type_only(reader, backend, kind):
    secret = _secrets()[kind]
    store = MemoryStore(backend, now=Clock())
    with pytest.raises(MemoryUpdateError) as exc:
        store.apply_updates(reader, [up("add", "fine", "v"), up("add", "creds", secret)])
    msg = str(exc.value)
    assert "memory_updates/1 value: holds a secret" in msg
    assert kind in msg or "token" in msg
    assert secret not in msg and secret.split()[-1] not in msg
    assert raw(backend) == {}


def test_the_screen_runs_before_the_schema_check_so_no_message_quotes_a_secret(reader):
    secret = _secrets()["aws-access-key"]
    with pytest.raises(MemoryUpdateError) as exc:
        MemoryStore().apply_updates(reader, [up("add", "k", secret + " " + "x" * 2001)])
    assert "holds a secret" in str(exc.value) and "AKIA" not in str(exc.value)


def test_a_report_carrying_a_secret_is_refused_before_validation(reader, backend):
    pack, h = assemble_pack(manifest(), inputs())
    report = {
        "pack_id": h,
        "profile": reader["id"],
        "status": "ok",
        "summary": "one burst",
        "cites": [{"source": "findings", "ref": "f1"}],
        "unknowns": [],
        "memory_updates": [up("add", "k", _secrets()["jwt"])],
    }
    with pytest.raises(MemoryUpdateError, match=r"memory_updates/0 value: holds a secret \(jwt"):
        MemoryStore(backend).apply_report(reader, report, pack=pack, pack_hash=h)
    assert raw(backend) == {}


def test_plain_facts_pass_the_screen(reader, backend):
    store = MemoryStore(backend, now=Clock())
    facts = [
        up("add", "scanner", "10 login failures from one scanner, tokens rotated on 2026-11-01"),
        up("add", "cve", "CVE-2026-12345 seen; sha256 of the dropper noted in the case"),
    ]
    store.apply_updates(reader, facts)
    assert len(store.read(reader, "analyst")) == 2


# ---------------------------------------------------------------- decision 5
def test_history_and_as_of_are_owner_scoped(reader, backend):
    s = spec()
    s["id"] = "profile:other-reader"
    other = verified(compile_profile(s, library()))
    store = MemoryStore(backend, now=Clock())
    store.apply_updates(reader, [up("add", "hunch", "v")])
    with pytest.raises(MemoryAccessError, match="cross-agent read"):
        store.history(other, "analyst", "hunch", owner=reader["id"])
    with pytest.raises(MemoryAccessError, match="cross-agent read"):
        store.as_of(other, "analyst", T0, owner=reader["id"])
    with pytest.raises(MemoryAccessError, match="memory_scopes"):
        store.history(reader, "responder", "hunch")
    with pytest.raises(MemoryAccessError, match="memory_scopes"):
        store.as_of(reader, "responder", T0)
    assert store.history(other, "analyst", "hunch") == {"records": [], "withheld": 0}
    assert store.as_of(other, "analyst", T0)["entries"] == {}
    assert store.history(reader, "analyst", "hunch", owner=reader["id"])["withheld"] == 0


def test_as_of_rebuilds_what_was_believed_at_each_time(reader, backend):
    clock = Clock()
    store = MemoryStore(backend, now=clock)
    store.apply_updates(reader, [up("add", "a", "a1"), up("add", "b", "b1")])  # 09:00
    clock.tick(10)
    store.apply_updates(reader, [up("replace", "a", "a2")])  # 09:10
    clock.tick(10)
    store.apply_updates(reader, [up("retire", "b")])  # 09:20
    clock.tick(10)
    store.apply_updates(reader, [up("add", "b", "b2")])  # 09:30

    def at(minutes):
        return store.as_of(reader, "analyst", T0 + timedelta(minutes=minutes))

    assert store.as_of(reader, "analyst", T0 - timedelta(seconds=1))["entries"] == {}
    assert at(0)["entries"] == {"a": "a1", "b": "b1"}
    assert at(5)["entries"] == {"a": "a1", "b": "b1"}
    assert at(10)["entries"] == {"a": "a2", "b": "b1"}
    assert at(25)["entries"] == {"a": "a2"}
    assert at(30)["entries"] == {"a": "a2", "b": "b2"}
    assert at(30) == {
        "at": "2026-11-05T09:30:00.000000Z",
        "entries": {"a": "a2", "b": "b2"},
        "compacted": [],
        "withheld": 0,
    }
    assert store.read(reader, "analyst") == at(60)["entries"]
    with pytest.raises(ValueError, match="aware UTC"):
        store.as_of(reader, "analyst", datetime(2026, 11, 5))


def test_history_and_as_of_are_read_only(reader, backend):
    store = MemoryStore(backend, now=Clock())
    store.apply_updates(reader, [up("add", "k", "v")])
    before = raw(backend)
    store.history(reader, "analyst", "k")["records"][0]["value"] = "changed"
    store.as_of(reader, "analyst", T0)["entries"]["k"] = "changed"
    assert raw(backend) == before


# ---------------------------------------------------------------- decision 6
def test_default_caps_are_code_constants(reader, ledger):
    assert record_cap(reader, "analyst") == DEFAULT_RECORDS == 10_000
    platform = _profile(memory_scopes=["analyst", "fleet-ledger"], platform_scopes=["fleet-ledger"])
    assert record_cap(platform, "fleet-ledger") == DEFAULT_PLATFORM_RECORDS == 100_000
    assert record_cap(platform, "analyst") == DEFAULT_RECORDS
    assert record_cap(ledger, "analyst") == 3 and record_cap(ledger, "fleet-ledger") == 4


def test_a_scope_at_its_cap_refuses_writes_and_pages_once_per_crossing(ledger, backend, tmp_path):
    sender = FakeSender()
    notifier = Notifier(sender, StateStore(tmp_path / "notify.json"))
    store = MemoryStore(backend, now=Clock(), notifier=notifier, topic="ops")
    fl = "fleet-ledger"
    store.apply_updates(ledger, [up("add", "a", "1", scope=fl), up("add", "b", "1", scope=fl)])
    store.apply_updates(ledger, [up("add", "c", "1", scope=fl), up("add", "d", "1", scope=fl)])
    for _ in range(3):  # three refusals, one page
        with pytest.raises(MemoryLimitError) as exc:
            store.apply_updates(ledger, [up("add", "e", "1", scope=fl)])
    assert exc.value.scopes == {fl: (5, 4)}
    assert sender.titles == [CAP_TITLE]
    page = sender.sent[0]
    assert page.topic == "ops" and fl in page.body and ledger["id"] in page.body
    # a model-written scope has its own cap: the ledger at its cap does not stop the analyst
    store.apply_updates(ledger, [up("add", "note", "v")])
    # retiring a platform key compacts it whole, which makes room: the write lands, recovery
    store.apply_updates(ledger, [up("retire", "a", scope=fl)])
    assert sender.titles == [CAP_TITLE, CAP_CLEARED]
    store.apply_updates(ledger, [up("replace", "b", "2", scope=fl), up("retire", "b", scope=fl)])
    assert sender.titles == [CAP_TITLE, CAP_CLEARED]  # already clear: no page
    with pytest.raises(MemoryLimitError):  # a new crossing pages again
        store.apply_updates(ledger, [up("add", "e", "1", scope=fl)])
    assert sender.titles == [CAP_TITLE, CAP_CLEARED, CAP_TITLE]


def test_a_crossing_without_a_notifier_is_logged_once(ledger, backend, caplog):
    store = MemoryStore(backend, now=Clock())
    store.apply_updates(ledger, [up("add", k, "v") for k in ("a", "b", "c")])
    for _ in range(2):
        with pytest.raises(MemoryLimitError, match="record cap"):
            store.apply_updates(ledger, [up("add", "d", "v")])
    assert [r.message for r in caplog.records].count(
        f"{ledger['id']}: memory scope analyst refuses writes: 4 records would exceed the cap of 3"
    ) == 1


def test_keep_last_drops_values_beyond_the_last_n_and_keeps_every_other_field(ledger, backend):
    clock = Clock()
    store = MemoryStore(backend, now=clock)
    fl = "fleet-ledger"
    ledger = _profile(
        memory_scopes=["analyst", fl],
        platform_scopes=[fl],
        memory_limits={"keep_last": {fl: {"item-*": 2}}},
    )
    store.apply_updates(
        ledger, [up("add", "item-a", "v1", scope=fl), up("add", "other", "o", scope=fl)]
    )
    for v in ("v2", "v3", "v4"):
        clock.tick(10)
        store.apply_updates(
            ledger, [up("replace", "item-a", v, scope=fl), up("replace", "other", v, scope=fl)]
        )
    recs = store.history(ledger, fl, "item-a")["records"]
    assert [r["rev"] for r in recs] == [1, 2, 3, 4]
    assert [r.get("value") for r in recs] == [None, None, "v3", "v4"]
    for r in recs[:2]:
        assert r["compacted"] is True
        assert {"rev", "value_digest", "sources", "closure", "tlp", "pack_id"} <= set(r)
    # a key no pattern matches keeps every value
    assert all("value" in r for r in store.history(ledger, fl, "other")["records"])
    # as_of in a compacted range answers compacted, never a wrong value
    early = store.as_of(ledger, fl, T0 + timedelta(minutes=5))
    assert early["compacted"] == ["item-a"] and early["entries"] == {"other": "o"}
    late = store.as_of(ledger, fl, T0 + timedelta(minutes=25))
    assert late["entries"] == {"item-a": "v3", "other": "v3"} and late["compacted"] == []


def test_keep_last_is_for_platform_scopes_only(backend):
    with pytest.raises(SpecError, match="not a platform scope"):
        _profile(memory_scopes=["analyst"], memory_limits={"keep_last": {"analyst": {"*": 1}}})
    with pytest.raises(SpecError, match="platform_scopes: 'ledger' is not one of"):
        _profile(platform_scopes=["ledger"])
    with pytest.raises(SpecError, match=r"memory_limits\.records: 'other' is not one of"):
        _profile(memory_limits={"records": {"other": 5}})
    with pytest.raises(SpecError, match="must be a list"):
        _profile(platform_scopes="analyst")


def test_a_profile_without_limits_keeps_its_digest(reader):
    assert "memory_limits" not in reader and "platform_scopes" not in reader
    assert _profile(platform_scopes=[])["digest"] == reader["digest"]


def test_a_retired_platform_key_compacts_whole_to_one_tombstone(ledger, backend):
    clock = Clock()
    store = MemoryStore(backend, now=clock)
    fl = "fleet-ledger"
    ledger = _profile(memory_scopes=["analyst", fl], platform_scopes=[fl])
    store.apply_updates(ledger, [up("add", "item-a", "v1", scope=fl)], pack_id="sha256:" + "5" * 64)
    clock.tick(10)
    store.apply_updates(
        ledger, [up("replace", "item-a", "v2", scope=fl)], pack_id="sha256:" + "6" * 64
    )
    clock.tick(10)
    store.apply_updates(ledger, [up("retire", "item-a", scope=fl)])
    (tomb,) = store.history(ledger, fl, "item-a")["records"]
    assert tomb["compacted"] == "whole" and tomb["op"] == "retire" and tomb["rev"] == 3
    assert tomb["pack_ids"] == ["sha256:" + "5" * 64, "sha256:" + "6" * 64]
    assert tomb["since"] == "2026-11-05T09:00:00.000000Z"
    assert tomb["at"] == "2026-11-05T09:20:00.000000Z"
    assert (tomb["sources"], tomb["closure"], tomb["tlp"]) == ([], [], "red")
    assert len(tomb["value_digests"]) == 2 and "value" not in tomb
    assert store.as_of(ledger, fl, T0 + timedelta(minutes=15))["compacted"] == ["item-a"]
    assert store.as_of(ledger, fl, T0 + timedelta(minutes=25)) == {
        "at": "2026-11-05T09:25:00.000000Z",
        "entries": {},
        "compacted": [],
        "withheld": 0,
    }
    assert store.as_of(ledger, fl, T0 - timedelta(minutes=1))["compacted"] == []
    # the key comes back with the next rev, and a second compaction keeps the first's range
    clock.tick(10)
    store.apply_updates(ledger, [up("add", "item-a", "v3", scope=fl)])
    assert store.history(ledger, fl, "item-a")["records"][-1]["rev"] == 4
    clock.tick(10)
    store.apply_updates(ledger, [up("retire", "item-a", scope=fl)])
    (tomb2,) = store.history(ledger, fl, "item-a")["records"]
    assert tomb2["rev"] == 5 and tomb2["since"] == tomb["since"]
    assert len(tomb2["value_digests"]) == 3
    stored = raw(backend, ledger["id"])
    assert fold(stored["log"]) == stored["entries"]
    # a model-written scope is never compacted
    store.apply_updates(ledger, [up("add", "k", "v")])
    store.apply_updates(ledger, [up("retire", "k")])
    assert len(store.history(ledger, "analyst", "k")["records"]) == 2
