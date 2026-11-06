# SPDX-License-Identifier: Apache-2.0
"""Agent memory's invariants under tombstone aging, re-adds and random histories (ADR-0037
decision 6, amended; the re-audit's R1 and R3): the cache is the fold, no key's revs overlap or
repeat, a live key never ages out, and what was believed now is what is read.  With sources and
labels (PR 2, decisions 7 to 10), the random histories also hold every checked source to its
pack, every label to its floor, and exposure to what the log points at.  Store tests run
on both backends."""

import json
import random
import threading
import time
from datetime import UTC, datetime, timedelta

import pytest
from agent_support import digest, item, labelled_pack, library, spec, verified, write
from memory_admin_support import operator

from homelabnext.agent import SpecError, compile_profile
from homelabnext.agent.deny import active_retractions
from homelabnext.agent.memory import (
    EVENT_OPS,
    MAX_CLOSURE,
    FileBackend,
    InMemoryBackend,
    MemoryClockError,
    MemoryLimitError,
    MemoryStore,
    MemoryUpdateError,
    denied,
    fold,
)
from homelabnext.agent.pack import pack_label, rendered_identifiers
from homelabnext.memory_admin import MemoryAdmin
from homelabnext.tlp import LABELS

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
    return FileBackend(tmp_path / "memory.json", deny_path=tmp_path / "memory-deny.json")


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
        if r["op"] in EVENT_OPS:
            continue
        lo, k = r.get("rev_from", r["rev"]), (r["scope"], r["key"])
        assert k not in top or lo > top[k], (k, lo, top.get(k))
        top[k] = r["rev"]
    for scope in scopes:
        assert store.as_of(profile, scope, when)["entries"] == store.read(profile, scope)["entries"]


def test_a_re_added_key_never_ages_out_with_its_old_tombstone(backend):
    p = _ledger(tombstones={FL: 1})
    clock = Clock()
    store = MemoryStore(backend, now=clock)
    write(store, p, [up("add", "x", "first"), up("retire", "x")])
    write(store, p, [up("add", "x", "LIVE-FACT")])
    for k in ("y", "z", "w"):  # tombstones past the budget of 1
        clock.tick()
        write(store, p, [up("add", k, "v"), up("retire", k)])
        assert store.read(p, FL)["entries"] == {"x": "LIVE-FACT"}
        invariants(store, p, backend, [FL], clock.t + timedelta(days=1))
    clock.tick()
    write(store, p, [up("replace", "x", "different")])
    recs = store.history(p, FL, "x")["records"]
    assert [(r.get("rev_from"), r["rev"]) for r in recs] == [(1, 2), (None, 3), (None, 4)]
    invariants(store, p, backend, [FL], clock.t + timedelta(days=1))
    # retired again, x's tombstone is its last record and ages like any other
    write(store, p, [up("retire", "x")])
    for k in ("v", "u"):
        clock.tick()
        write(store, p, [up("add", k, "v"), up("retire", k)])
    assert store.history(p, FL, "x")["records"] == []
    write(store, p, [up("add", "x", "back")])
    assert store.history(p, FL, "x")["records"][0]["rev"] > 5
    invariants(store, p, backend, [FL], clock.t + timedelta(days=1))


def test_the_high_water_rev_is_the_largest_aged_not_the_latest(backend):
    p = _ledger(tombstones={FL: 1})
    clock = Clock()
    store = MemoryStore(backend, now=clock)
    write(store, p, [up("add", "a", "0")])
    for v in range(1, 8):
        write(store, p, [up("replace", "a", str(v))])
    write(store, p, [up("retire", "a")])  # a's tombstone: rev 9
    clock.tick()
    write(store, p, [up("add", "b", "v"), up("retire", "b")])  # b's: rev 2; a ages
    clock.tick()
    write(store, p, [up("add", "c", "v"), up("retire", "c")])  # b ages
    (aged,) = [r for r in backend.load(p["id"])["log"] if r["op"] == "aged"]
    assert aged["count"] == 2 and aged["rev"] == 9
    write(store, p, [up("add", "a", "again")])
    assert store.history(p, FL, "a")["records"][0]["rev"] == 10


def test_a_folded_record_keeps_the_purged_marker(backend):
    p = _ledger(keep_last={FL: {"item-*": 1}})
    seed(backend, p["id"], {FL: {"item-a": {"status": "live", "op": "add", "value": "k " + AWS}}})
    clock = Clock()
    store = MemoryStore(backend, now=clock)
    for v in ("1", "2"):
        clock.tick()
        write(store, p, [up("replace", "item-a", v)])
    rng = store.history(p, FL, "item-a")["records"][0]
    assert rng["compacted"] == "range" and rng["purged"] is True
    assert AWS not in json.dumps(backend.load(p["id"]))
    write(store, p, [up("retire", "item-a")])
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
        threading.Thread(target=write, args=(store, p, [up("add", f"k{i}", "v")]))
        for i in range(16)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    stored = backend.load(p["id"])
    assert len(stored["log"]) == 16 and len(stored["entries"][FL]) == 16


def _packs(profile):
    """Packs of different labels to draw checked batches from: by hash, ``(pack, hash)``."""
    out = {}
    for static, items in (
        ("clear", [item(1, "clear"), item(2, "green")]),
        ("green", [item(3, "amber"), item(4, "green"), item(5, "clear")]),
        ("clear", [item(6, "clear")]),
        (None, [item(7, "green")]),  # an unlabelled static section: red
    ):
        # every input section declares its items: an input section without any is red
        pack, h = labelled_pack(
            items, [item(100 + len(out), "clear")], static=static, profile=profile
        )
        out[h] = (pack, h)
    return out


def label_invariants(backend, profile, packs):
    """Sources and labels (ADR-0037 decisions 7 to 10): every checked record's sources are
    identifiers its pack rendered and its label is no looser than its pack's or any source's; an
    unchecked record is red; a key's label never falls; a record's closure holds its sources and
    stays under the cap; and exposure is stored once per pack still pointed at, and no other."""
    stored = backend.load(profile["id"])
    rank = {label: i for i, label in enumerate(LABELS)}
    last: dict = {}
    pointed = set()
    for r in stored["log"]:
        if r["op"] in EVENT_OPS:
            continue
        assert set(r["sources"]) <= set(r["closure"]) and len(r["closure"]) <= MAX_CLOSURE
        k = (r["scope"], r["key"])
        assert rank[r["tlp"]] >= last.get(k, 0), (k, r["tlp"])  # never lowered, op after op
        last[k] = rank[r["tlp"]]
        if r.get("reason") is not None:  # an operator's retire (ADR-0037 PR 3): no pack
            assert r["op"] == "retire" and r["checked"] is False and r["pack_id"] is None
            assert r["reason"].startswith("retracted:")
            continue
        if r["scope"] == FL:
            assert r["checked"] is False and r["tlp"] == "red"  # unchecked platform writes
            continue
        assert r["checked"] is True
        pack, h = packs[r["pack_id"]]
        known = rendered_identifiers(pack)
        assert set(r["sources"]) <= set(known)
        floor = [pack_label(pack), *(known[s] for s in r["sources"])]
        assert rank[r["tlp"]] >= max(rank[x] for x in floor)
        ex = stored["exposure"][h]
        assert ex["rendered"] == sorted(known) and ex["memory"] == []
        # every pairing names what the pack rendered, by index (decision 13)
        assert {ex["rendered"][i] for g in ex["pairs"] for i in g} <= set(known)
        every = {x for pk, _ in packs.values() for x in rendered_identifiers(pk)}
        assert set(r["closure"]) <= every  # sources and their aliases only
        pointed.add(h)
    for r in stored["log"]:
        pointed.update(p for p in [r.get("pack_id"), *(r.get("pack_ids") or ())] if p)
    assert set(stored["exposure"]) <= pointed


def retraction_invariants(store, backend, profile):
    """A retraction sticks (ADR-0037 decisions 13 and 14): no live entry's current closure
    reaches an active denied name, and the deny log and reach index only ever grew."""
    deny = denied(backend)
    stored = backend.load(profile["id"])
    if not stored:
        return
    last = {}
    for r in stored["log"]:
        if r["op"] not in EVENT_OPS:
            last[(r["scope"], r["key"])] = r
    for scope, keys in stored["entries"].items():
        for key, e in keys.items():
            if e["status"] == "live" and (scope, key) in last:
                assert not deny.denies(last[(scope, key)]["closure"]), (scope, key)


@pytest.mark.parametrize("seed_", [1, 2, 3, 4])
def test_random_histories_keep_the_invariants(backend, seed_, tmp_path):
    """Random histories of checked model-scope batches (each against a labelled pack, citing what
    it rendered, sometimes something it did not) and unchecked platform batches, with operator
    retractions (of a rendered identifier, its dry run confirmed) and lifts in between."""
    admin_t = [T0]

    def admin_now():  # the operator acts on a corrected clock: never behind the log
        admin_t[0] = max(admin_t[0], clock.t)
        return admin_t[0]

    admin = MemoryAdmin(backend, now=admin_now)
    by = operator(tmp_path)
    grown = {"log": 0, "reach": 0}
    rnd = random.Random(seed_)
    p = _ledger(records={FL: 60}, tombstones={FL: 3}, keep_last={FL: {"c*": 2, "k1": 1}})
    packs = _packs(p)
    clock = Clock()
    store = MemoryStore(backend, now=clock)
    keys = ["c1", "c2", "k1", "k2", "k3", "k4"]
    # every step re-reads the deny state and the file backend rewrites its file: fewer steps (and
    # fewer still on file, which the 4 seeds of each backend cover alike) keep tests/agent in its
    # coverage budget
    for _ in range(80 if isinstance(backend, InMemoryBackend) else 40):
        clock.t += timedelta(seconds=rnd.choice([-120, -1, 0, 1, 30, 600]))  # some lag past 5 min
        admin_t[0] = max(admin_t[0], clock.t)  # the latest time any write was stamped at
        scope = rnd.choice([FL, "analyst"])
        pack, h = packs[rnd.choice(sorted(packs))]
        ids = sorted(rendered_identifiers(pack))
        forged = scope != FL and rnd.random() < 0.15
        batch, seen = [], set()
        for _ in range(rnd.randint(1, 4)):
            k = rnd.choice(keys)
            if k in seen:
                continue
            seen.add(k)
            if k in store.read(p, scope)["entries"]:
                op = rnd.choice(["replace", "retire"])
                u = up(op, k, str(rnd.random()) if op == "replace" else None, scope)
            else:
                u = up("add", k, str(rnd.random()), scope)
            if scope == FL:  # the platform's own sources: unchecked, so anything well formed
                u["sources"] = [digest(900 + rnd.randint(0, 3))] if rnd.random() < 0.5 else []
            else:
                u["sources"] = rnd.sample(ids, rnd.randint(0, min(3, len(ids))))
            batch.append(u)
        if forged:
            batch[-1]["sources"] = [*batch[-1]["sources"][:2], digest(999)]
        roll = rnd.random()
        if roll < 0.1:  # an operator retracts something a pack rendered
            src = rnd.choice(ids)
            wide = rnd.random() < 0.5
            plan = admin.dependents(src, by=by, include_exposed=wide)
            admin.retract(src, "fuzz", by=by, confirm=plan["confirm"], include_exposed=wide)
        elif roll < 0.2:  # or lifts one
            active = active_retractions(backend.load_deny()["log"]).values()
            live_ids = sorted({recs[0]["source"] for recs in active})
            if live_ids:
                admin.lift(rnd.choice(live_ids), "fuzz", by=by)
        deny_now = backend.load_deny()
        assert len(deny_now["log"]) >= grown["log"] and len(deny_now["reach"]) >= grown["reach"]
        grown = {k: len(v) for k, v in deny_now.items()}
        retraction_invariants(store, backend, p)
        before = backend.load(p["id"])
        refused = (MemoryLimitError, MemoryClockError) + ((MemoryUpdateError,) if forged else ())
        if denied(backend):  # a write the deny log refuses is refused whole
            refused += (MemoryUpdateError,)
        try:
            if scope == FL:
                store.apply_updates(p, batch, unchecked=True)
            else:
                store.apply_updates(p, batch, pack=pack, pack_hash=h)
            assert not forged, "a source the pack did not render was accepted"
        except refused:
            assert backend.load(p["id"]) == before  # refused: unchanged
        invariants(store, p, backend, [FL, "analyst"], clock.t + timedelta(days=1))
        label_invariants(backend, p, packs)
        retraction_invariants(store, backend, p)
    log_ = backend.load(p["id"])["log"]
    assert any(r["sources"] for r in log_ if r["checked"])  # the run exercised sources
    assert len({r["tlp"] for r in log_ if r["scope"] == "analyst"}) > 1  # and labels below red
    for recs in active_retractions(backend.load_deny()["log"]).values():  # lift what is left
        admin.lift(recs[0]["source"], "fuzz", by=by)
    assert denied(backend) == denied(InMemoryBackend())  # nothing denied once all is lifted
    deny_log = backend.load_deny()["log"]
    assert {"retract", "lift"} <= {r["op"] for r in deny_log}  # the run retracted and lifted
    assert any((r.get("reason") or "").startswith("retracted:") for r in log_)  # and retired
