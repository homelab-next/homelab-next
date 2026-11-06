# SPDX-License-Identifier: Apache-2.0
"""Agent memory's invariants under tombstone aging, re-adds and random histories (ADR-0037
decision 6, amended; the re-audit's R1 and R3): the cache is the fold, no key's revs overlap or
repeat, a live key never ages out, and what was believed now is what is read.  Store tests run
on both backends."""

import contextlib
import json
import random
import threading
import time
from datetime import UTC, datetime, timedelta

import pytest
from agent_support import library, spec, verified

from homelabnext.agent import SpecError, compile_profile
from homelabnext.agent.memory import (
    FileBackend,
    InMemoryBackend,
    MemoryClockError,
    MemoryLimitError,
    MemoryStore,
    fold,
)

T0 = datetime(2026, 11, 5, 9, 0, tzinfo=UTC)
FL = "fleet-ledger"
AWS = "AKIA" + "Z7" * 8  # built at run time: this file holds no credential shape


class Clock:
    def __init__(self, t=T0):
        self.t = t

    def __call__(self):
        return self.t

    def tick(self, minutes=1):
        self.t += timedelta(minutes=minutes)
        return self.t


def _ledger(**limits):
    s = spec()
    s.update(memory_scopes=["analyst", FL], platform_scopes=[FL], memory_limits=limits)
    return verified(compile_profile(s, library()))


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


def up(op, key, value=None, scope=FL):
    u = {"scope": scope, "op": op, "key": key}
    if value is not None:
        u["value"] = value
    return u


def invariants(store, profile, backend, scopes, when):
    """The cache is the fold (dict equality: both ways, missing keys included); no key's revs
    overlap or repeat across its records, so no ``(key, rev)`` names two values; and what was
    believed at ``when`` (after every record) is what is read."""
    stored = backend.load(profile["id"])
    assert fold(stored["log"]) == stored["entries"]
    top: dict = {}
    for r in stored["log"]:
        if r["op"] == "aged":
            continue
        lo, k = r.get("rev_from", r["rev"]), (r["scope"], r["key"])
        assert k not in top or lo > top[k], (k, lo, top.get(k))
        top[k] = r["rev"]
    for scope in scopes:
        assert store.as_of(profile, scope, when)["entries"] == store.read(profile, scope)


def test_a_re_added_key_never_ages_out_with_its_old_tombstone(backend):
    p = _ledger(tombstones={FL: 1})
    clock = Clock()
    store = MemoryStore(backend, now=clock)
    store.apply_updates(p, [up("add", "x", "first"), up("retire", "x")])
    store.apply_updates(p, [up("add", "x", "LIVE-FACT")])
    for k in ("y", "z", "w"):  # tombstones past the budget of 1
        clock.tick()
        store.apply_updates(p, [up("add", k, "v"), up("retire", k)])
        assert store.read(p, FL) == {"x": "LIVE-FACT"}
        invariants(store, p, backend, [FL], clock.t + timedelta(days=1))
    clock.tick()
    store.apply_updates(p, [up("replace", "x", "different")])
    recs = store.history(p, FL, "x")["records"]
    assert [(r.get("rev_from"), r["rev"]) for r in recs] == [(1, 2), (None, 3), (None, 4)]
    invariants(store, p, backend, [FL], clock.t + timedelta(days=1))
    # retired again, x's tombstone is its last record and ages like any other
    store.apply_updates(p, [up("retire", "x")])
    for k in ("v", "u"):
        clock.tick()
        store.apply_updates(p, [up("add", k, "v"), up("retire", k)])
    assert store.history(p, FL, "x")["records"] == []
    store.apply_updates(p, [up("add", "x", "back")])
    assert store.history(p, FL, "x")["records"][0]["rev"] > 5
    invariants(store, p, backend, [FL], clock.t + timedelta(days=1))


def test_the_high_water_rev_is_the_largest_aged_not_the_latest(backend):
    p = _ledger(tombstones={FL: 1})
    clock = Clock()
    store = MemoryStore(backend, now=clock)
    store.apply_updates(p, [up("add", "a", "0")])
    for v in range(1, 8):
        store.apply_updates(p, [up("replace", "a", str(v))])
    store.apply_updates(p, [up("retire", "a")])  # a's tombstone: rev 9
    clock.tick()
    store.apply_updates(p, [up("add", "b", "v"), up("retire", "b")])  # b's: rev 2; a ages
    clock.tick()
    store.apply_updates(p, [up("add", "c", "v"), up("retire", "c")])  # b ages
    (aged,) = [r for r in backend.load(p["id"])["log"] if r["op"] == "aged"]
    assert aged["count"] == 2 and aged["rev"] == 9
    store.apply_updates(p, [up("add", "a", "again")])
    assert store.history(p, FL, "a")["records"][0]["rev"] == 10


def test_a_folded_record_keeps_the_purged_marker(backend):
    p = _ledger(keep_last={FL: {"item-*": 1}})
    seed(backend, p["id"], {FL: {"item-a": {"status": "live", "op": "add", "value": "k " + AWS}}})
    clock = Clock()
    store = MemoryStore(backend, now=clock)
    for v in ("1", "2"):
        clock.tick()
        store.apply_updates(p, [up("replace", "item-a", v)])
    rng = store.history(p, FL, "item-a")["records"][0]
    assert rng["compacted"] == "range" and rng["purged"] is True
    assert AWS not in json.dumps(backend.load(p["id"]))
    store.apply_updates(p, [up("retire", "item-a")])
    (tomb,) = store.history(p, FL, "item-a")["records"]
    assert tomb["purged"] is True and tomb["value_digests"] and "value" not in tomb


def test_a_tombstone_budget_must_be_below_the_record_cap():
    with pytest.raises(SpecError, match="not fewer than its record cap 10;"):
        _ledger(records={FL: 10}, tombstones={FL: 10})
    with pytest.raises(SpecError, match="not fewer than its record cap 100000"):
        _ledger(tombstones={FL: 100_000})
    _ledger(records={FL: 10}, tombstones={FL: 9})


def test_writers_overlap_and_the_lock_serialises_them():
    p = _ledger()
    backend = InMemoryBackend()

    def slow_clock():
        time.sleep(0.001)  # inside the transaction: without the lock, writers interleave here
        return T0

    store = MemoryStore(backend, now=slow_clock)
    threads = [
        threading.Thread(target=store.apply_updates, args=(p, [up("add", f"k{i}", "v")]))
        for i in range(16)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    stored = backend.load(p["id"])
    assert len(stored["log"]) == 16 and len(stored["entries"][FL]) == 16


@pytest.mark.parametrize("seed_", [1, 2, 3, 4])
def test_random_histories_keep_the_invariants(backend, seed_):
    rnd = random.Random(seed_)
    p = _ledger(records={FL: 60}, tombstones={FL: 3}, keep_last={FL: {"c*": 2, "k1": 1}})
    clock = Clock()
    store = MemoryStore(backend, now=clock)
    keys = ["c1", "c2", "k1", "k2", "k3", "k4"]
    for _ in range(120):
        clock.t += timedelta(seconds=rnd.choice([-120, -1, 0, 1, 30, 600]))  # some lag past 5 min
        batch, seen = [], set()
        for _ in range(rnd.randint(1, 4)):
            scope, k = rnd.choice([FL, "analyst"]), rnd.choice(keys)
            if (scope, k) in seen:
                continue
            seen.add((scope, k))
            if k in store.read(p, scope):
                op = rnd.choice(["replace", "retire"])
                batch.append(up(op, k, str(rnd.random()) if op == "replace" else None, scope))
            else:
                batch.append(up("add", k, str(rnd.random()), scope))
        with contextlib.suppress(MemoryLimitError, MemoryClockError):  # refused: unchanged
            store.apply_updates(p, batch)
        invariants(store, p, backend, [FL, "analyst"], clock.t + timedelta(days=1))
