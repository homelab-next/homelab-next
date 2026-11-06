# SPDX-License-Identifier: Apache-2.0
"""Regressions for the PR #256 security audit and design review (ADR-0037 decisions 9 and 12 to
14, amended 2026-11-06): narrow alias closure, a ``mem:`` source reaching its own revision,
write-time checks following cited lineage, truncated ranges and unchecked exposure, settings on
a rerun, the input-item censorship lever, purge leaving no guessable digest, report author
binding, the deny copy, a concurrent lift, lone digests, and the mutants that survived.  Store
tests run on both backends."""

import hashlib
import json
from datetime import UTC, datetime, timedelta

import pytest
from agent_support import digest, item, labelled_pack, library, spec, uid, verified
from memory_admin_support import operator

from homelabnext.agent import compile_profile, validate_report
from homelabnext.agent.knowledge import Selection
from homelabnext.agent.memory import (
    FileBackend,
    InMemoryBackend,
    MemoryStore,
    MemoryUpdateError,
    denied,
    fold,
    memory_block_input,
)
from homelabnext.memory_admin import MemoryAdmin, MemoryAdminError

T0 = datetime(2026, 11, 6, 9, 0, tzinfo=UTC)
FL = "fleet-ledger"


class Clock:
    def __init__(self, t=T0):
        self.t = t

    def __call__(self):
        self.t += timedelta(seconds=1)
        return self.t


def _profile(pid="profile:reader", **extra):
    s = spec()
    s["id"] = pid
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


@pytest.fixture
def op(tmp_path):
    return operator(tmp_path)


@pytest.fixture
def clock():
    return Clock()


def up(op_, key, value=None, scope="analyst", sources=None):
    u = {"scope": scope, "op": op_, "key": key}
    if value is not None:
        u["value"] = value
    if sources is not None:
        u["sources"] = sources
    return u


def mref(owner, key, rev, scope="analyst"):
    return f"mem:{owner}/{scope}/{key}@{rev}"


def put(store, profile, updates, findings=(), memory=None, **kw):
    if memory is not None:
        kw["memory_block"] = memory
    pack, h = labelled_pack(list(findings), [item(999, "clear")], profile=profile, **kw)
    return store.apply_updates(profile, updates, pack=pack, pack_hash=h), (pack, h)


def live(store, profile, scope="analyst"):
    return set(store.read(profile, scope)["entries"])


def retract(admin, source, by, **kw):
    plan = admin.dependents(source, by=by, **kw)
    return plan, admin.retract(source, "r", by=by, confirm=plan["confirm"], **kw)


def row(n, d):
    """Input item ``n`` stored with digest ``d`` (a reader's stored row)."""
    return {"uid": uid(n), "digest": d, "tlp": "clear"}


# ---------------------------------------------------------------- audit H2: alias closure
def test_the_attacker_probe_cannot_get_a_good_record_retracted(reader, backend, clock, op):
    """An attacker row first carries the good record's digest, then the poison.  Retracting the
    poison denies the attacker's uid, never the good uid, and the shared digest only by name."""
    store = MemoryStore(backend, now=clock)
    good, poison = digest(2), digest(66)
    put(store, reader, [up("add", "good", "G", sources=[uid(2)])], [row(2, good)])
    put(store, reader, [up("add", "early", "E", sources=[uid(9)])], [row(9, good)])
    put(store, reader, [up("add", "bad", "B", sources=[uid(9)])], [row(9, poison)])
    admin = MemoryAdmin(backend, now=clock)
    plan, done = retract(admin, poison, op)
    assert plan["aliases"] == sorted([poison, uid(9)])  # never uid(2), never the good digest
    assert plan["ambiguous"] == [{"digest": good, "uids": [uid(2)]}]
    assert live(store, reader) == {"good"}
    assert {r["key"] for r in done["retired"]} == {"early", "bad"}
    # retracting the shared digest itself: ambiguous, so only by name unless a uid is included
    shared = admin.dependents(good, by=op)
    assert shared["ambiguous"] == [{"digest": good, "uids": sorted([uid(2), uid(9)])}]
    assert shared["aliases"] == [good]
    wide = admin.dependents(good, by=op, include_alias=[uid(2)])
    assert set(wide["aliases"]) == {good, uid(2)} and wide["include_alias"] == [uid(2)]
    with pytest.raises(MemoryAdminError, match="include_alias takes record uids"):
        admin.dependents(good, by=op, include_alias=["not-a-uid"])


def test_a_graph_id_closes_to_its_uid_and_the_uids_digests(reader, backend, clock, op):
    """A multi-hop chain: lesson:<uid> -> uid -> the digests of two revisions in two packs."""
    store = MemoryStore(backend, now=clock)

    def lesson(text):
        h = "sha256:" + hashlib.sha256(text.encode()).hexdigest()
        inc = {"id": f"lesson:{uid(7)}", "kind": "lesson", "title": "t", "path": None,
               "reviewed": [], "distance": 0, "score": 1.0, "via": "seed", "from": "x",
               "rules": [0], "max_chars": 1000, "digest": h, "text": text, "rank": 1,
               "section": "knowledge-001-lesson"}  # fmt: skip
        sel = Selection(profile="profile:reader", profile_digest="sha256:" + "a" * 64,
                        graph_digest="sha256:" + "b" * 64, rules=(), seeds=(), excluded=(),
                        included=(inc,))  # fmt: skip
        return h, sel

    h1, s1 = lesson("first revision")
    h2, s2 = lesson("second revision")
    put(store, reader, [up("add", "one", "1", sources=[h1])], [item(1)], knowledge=s1)
    put(store, reader, [up("add", "two", "2", sources=[h2])], [item(1)], knowledge=s2)
    plan, _ = retract(MemoryAdmin(backend, now=clock), f"lesson:{uid(7)}", op)
    assert set(plan["aliases"]) == {f"lesson:{uid(7)}", uid(7), h1, h2}
    assert live(store, reader) == set()


def test_revision_all_on_a_lone_digest_warns(reader, backend, clock, op):
    store = MemoryStore(backend, now=clock)
    put(store, reader, [up("add", "a", "A")], [item(1)])
    plan = MemoryAdmin(backend, now=clock).dependents(digest(500), by=op)
    assert plan["aliases"] == [digest(500)] and "lone digest" in plan["warnings"][0]


# ---------------------------------------------------------------- design M1: own revision
def test_a_mem_source_reaches_its_own_revision(reader, backend, clock, op):
    store = MemoryStore(backend, now=clock)
    put(store, reader, [up("add", "a", "A")], [item(1)])
    shows_a = memory_block_input(store, reader, ["analyst"])
    stale = labelled_pack([item(2)], [item(999)], profile=reader, memory_block=shows_a)
    ref = mref(reader["id"], "a", 1)
    plan, done = retract(MemoryAdmin(backend, now=clock), ref, op)
    assert [r["key"] for r in plan["cited"]] == ["a"] and done["retired"][0]["key"] == "a"
    assert denied(backend).marked(reader["id"], "analyst", "a", 1)
    assert memory_block_input(store, reader, ["analyst"]) == []  # retired: in no block
    pack, _ = labelled_pack([item(2)], [item(999)], memory_block=shows_a, retracted=denied(backend))
    assert pack["memory"] == [] and pack["retracted"]["memory"] == 1
    with pytest.raises(MemoryUpdateError, match="memory block shows a revision"):
        store.apply_updates(reader, [up("add", "n", "N")], pack=stale[0], pack_hash=stale[1])


def test_a_mem_source_retires_its_key_only_while_that_revision_is_current(
    reader, backend, clock, op
):
    store = MemoryStore(backend, now=clock)
    put(store, reader, [up("add", "a", "A")], [item(1)])
    put(store, reader, [up("replace", "a", "A2")], [item(1)])
    _, done = retract(MemoryAdmin(backend, now=clock), mref(reader["id"], "a", 1), op)
    assert done["retired"] == [] and live(store, reader) == {"a"}


# ---------------------------------------------------------------- audit M3: cited lineage
def mark(backend, owner, key, rev, scope="analyst"):
    """A deny state that marks ``key@rev`` alone (as a walk part-way through leaves it)."""
    backend.transact_deny(lambda d: {
        "log": [*d["log"], {"op": "retract", "deny_id": "deny:t", "source": "x",
                            "revision": "all", "name": "unrelated-name"}],
        "reach": [*d["reach"], {"deny_id": "deny:t", "owner": owner, "scope": scope,
                                "key": key, "rev_from": rev, "rev": rev}],
    })  # fmt: skip


def test_writes_follow_the_cited_lineage(reader, backend, clock):
    store = MemoryStore(backend, now=clock)
    put(store, reader, [up("add", "d", "D")], [item(1)])
    mem = memory_block_input(store, reader, ["analyst"])
    put(store, reader, [up("add", "h", "H", sources=[mref(reader["id"], "d", 1)])], [item(2)],
        memory=mem)  # fmt: skip
    put(store, reader, [up("replace", "h", "H2")], [item(2)])  # h@2 still closes over d@1
    mark(backend, reader["id"], "d", 1)
    shows_h = [m for m in memory_block_input(store, reader, ["analyst"]) if m["key"] == "h"]
    assert shows_h[0]["rev"] == 2
    with pytest.raises(MemoryUpdateError, match="cites a revision a retraction reached"):
        put(store, reader, [up("add", "z", "Z", sources=[mref(reader["id"], "h", 2)])],
            [item(3)], memory=shows_h)  # fmt: skip
    pack, _ = labelled_pack([item(3)], [item(999)], memory_block=shows_h,
                            retracted=denied(backend))  # fmt: skip
    assert pack["memory"] == [] and pack["retracted"]["memory"] == 1  # h@2 cites d@1


# ---------------------------------------------------------------- audit M2: truncated ranges
def test_a_platform_record_never_points_at_an_exposure(backend, clock, op):
    """Platform scopes are written unchecked, which stores no exposure; even a pack id that an
    exposure is keyed by is provenance there, never exposure, so a range cut at 256 pack ids
    loses no exposure."""
    p = _profile(memory_scopes=["analyst", FL], platform_scopes=[FL],
                 memory_limits={"keep_last": {FL: {"cursor-*": 1}}})  # fmt: skip
    store = MemoryStore(backend, now=clock)
    _, (_pack, h) = put(store, p, [up("add", "m", "M", sources=[uid(1)])], [item(1)])
    store.apply_updates(p, [up("add", "cursor-a", "0", scope=FL)], unchecked=True, pack_id=h)
    stored = backend.load(p["id"])
    platform = [r for r in stored["log"] if r["scope"] == FL]
    assert all(r["checked"] is False for r in platform)
    plan = MemoryAdmin(backend, now=clock).dependents(uid(1), by=op)
    assert [r["key"] for r in plan["exposed"]] == []  # cursor-a's pack id is not exposure


def test_a_truncated_range_its_sources_reach_is_listed_once_flagged(clock, op):
    backend = InMemoryBackend()
    p = _profile(memory_scopes=["analyst", FL], platform_scopes=[FL])
    rng = {"at": "2026-11-06T08:00:00.000000Z", "scope": FL, "key": "k", "op": "replace",
           "rev": 300, "rev_from": 1, "compacted": "range", "status": "live", "since": None,
           "value_digests": [], "pack_id": None, "pack_ids": [], "sources": [uid(1)],
           "effective": [], "checked": False, "tlp": "red", "closure": [uid(1)],
           "reasserted_at": None, "truncated": True}  # fmt: skip
    backend._data[p["id"]] = {"entries": fold([rng]), "log": [rng], "exposure": {}}
    plan = MemoryAdmin(backend, now=clock).dependents(uid(1), by=op)
    assert [r.get("truncated") for r in plan["cited"]] == [True] and plan["exposed"] == []


# ---------------------------------------------------------------- audit M4: censorship lever
def test_an_input_item_is_denied_by_uid_or_by_digest_only_under_revision_this(
    reader, backend, clock, op, tmp_path
):
    from homelabnext.agent.pack import quarantine_page
    from homelabnext.notify import FakeSender, Notifier
    from homelabnext.state import StateStore

    store = MemoryStore(backend, now=clock)
    put(store, reader, [up("add", "a", "A", sources=[uid(1)])], [item(1)])
    retract(MemoryAdmin(backend, now=clock), digest(1), op)  # revision=all: by uid(1)
    deny = denied(backend)
    other_uid = labelled_pack([row(5, digest(1))], [item(999)], retracted=deny)[0]
    assert "findings" not in other_uid["omitted"]  # the digest alone under another uid passes
    same_uid = labelled_pack([item(1)], [item(999)], retracted=deny)[0]
    assert same_uid["retracted"]["quarantined"] == ["findings"]
    sender = FakeSender()
    notifier = Notifier(sender, StateStore(tmp_path / "n.json"))
    quarantine_page(notifier, same_uid, reader["id"])
    assert any("left out required section(s) findings" in m.body for m in sender.sent)
    quarantine_page(notifier, other_uid, reader["id"])  # the recovery
    assert len(sender.sent) == 2
    retract(MemoryAdmin(backend, now=clock), digest(1), op, revision="this")
    this = labelled_pack([row(5, digest(1))], [item(999)], retracted=denied(backend))[0]
    assert this["retracted"]["quarantined"] == ["findings"]


# ---------------------------------------------------------------- audit M5: purge digests
def test_a_purged_value_cannot_be_brute_forced_from_history(reader, backend, clock, op):
    store = MemoryStore(backend, now=clock)
    put(store, reader, [up("add", "pin", "4711")], [item(1)])
    put(store, reader, [up("replace", "pin", "0000")], [item(1)])
    vd = store.history(reader, "analyst", "pin")["records"][0]["value_digest"]
    admin = MemoryAdmin(backend, now=clock)
    admin.purge(reader["id"], "analyst/pin@1", "a pin", by=op)
    text = json.dumps(store.history(reader, "analyst", "pin")) + json.dumps(
        backend.load(reader["id"])
    )
    guesses = {"sha256:" + hashlib.sha256(f"{n:04d}".encode()).hexdigest() for n in range(10_000)}
    found = {g for g in guesses if g in text}
    assert vd not in text and found == {
        "sha256:" + hashlib.sha256(b"0000").hexdigest()
    }  # only the unpurged value
    assert admin.purge("*", vd, "again", by=op)["purged"] == []  # a rerun appends nothing
    before = backend.load(reader["id"])
    admin.purge(reader["id"], "analyst/pin@1", "again", by=op)
    assert backend.load(reader["id"]) == before


def test_purge_with_two_records_sharing_a_digest_under_one_owner(reader, backend, clock, op):
    store = MemoryStore(backend, now=clock)
    put(store, reader, [up("add", "k", "V")], [item(1)])
    put(store, reader, [up("replace", "k", "W")], [item(1)])
    put(store, reader, [up("replace", "k", "V")], [item(1)])
    vd = store.history(reader, "analyst", "k")["records"][0]["value_digest"]
    dry = MemoryAdmin(backend, now=clock).purge(reader["id"], vd, "r", by=op, dry_run=True)
    assert dry["purged"] == [{"owner": reader["id"], "scope": "analyst", "key": "k", "revs": [1, 3], "retired": True,
                              "digest": vd}]  # fmt: skip
    MemoryAdmin(backend, now=clock).purge(reader["id"], vd, "r", by=op)
    recs = store.history(reader, "analyst", "k")["records"]
    assert [r["op"] for r in recs] == ["add", "replace", "replace", "retire", "purge"]
    assert [bool(r.get("purged")) for r in recs[:4]] == [True, False, True, True]
    tokens = {r["value_digest"] for r in recs if r.get("purged") or r["op"] == "purge"}
    assert len(tokens) == 1 and tokens.pop().startswith("purged:")
    assert recs[1]["value"] == "W" and live(store, reader) == set()


# ---------------------------------------------------------------- audit L1: author binding
def test_a_report_names_the_profile_its_pack_was_assembled_for(reader):
    pack, h = labelled_pack([item(1)], [item(2)], profile=reader)
    rep = {"pack_id": h, "profile": "profile:someone-else", "status": "ok", "summary": "s",
           "cites": [{"source": "findings", "ref": "f"}], "unknowns": [], "memory_updates": []}  # fmt: skip
    assert "profile is not the profile the pack was assembled for" in validate_report(rep, pack, h)
    assert validate_report({**rep, "profile": reader["id"]}, pack, h) == []


# ---------------------------------------------------------------- audit L3, L4; M5 mutants
def test_a_backend_hands_fn_a_copy_of_the_deny_state(backend):
    backend.transact_deny(lambda d: {"log": [{"op": "x"}], "reach": []})

    def fn(cur, deny):
        deny["log"].clear()
        return cur

    backend.transact("profile:reader", fn)
    assert backend.load_deny()["log"] == [{"op": "x"}]


class _LiftDuring:
    """A backend that lifts every retraction the first time an owner is written."""

    def __init__(self, inner, admin_lift):
        self.inner, self.lift, self.armed = inner, admin_lift, True

    def __getattr__(self, name):
        return getattr(self.inner, name)

    def transact(self, owner, fn):
        if self.armed:
            self.armed = False
            self.lift()
        return self.inner.transact(owner, fn)


def test_a_lift_during_a_retraction_stops_it_cleanly(reader, backend, clock, op):
    store = MemoryStore(backend, now=clock)
    put(store, reader, [up("add", "a", "A", sources=[uid(1)])], [item(1)])
    plain = MemoryAdmin(backend, now=clock)
    wrapped = _LiftDuring(backend, lambda: plain.lift(uid(1), "changed my mind", by=op))
    admin = MemoryAdmin(wrapped, now=clock)
    plan = admin.dependents(uid(1), by=op)
    with pytest.raises(MemoryAdminError, match="was lifted while it ran"):
        admin.retract(uid(1), "r", by=op, confirm=plan["confirm"])
    assert live(store, reader) == {"a"}  # the transaction re-checked and retired nothing


class _DenyInside:
    """A backend that appends a deny record inside ``transact``, before it calls ``fn``."""

    def __init__(self, inner, name):
        self.inner, self.name = inner, name

    def __getattr__(self, attr):
        return getattr(self.inner, attr)

    def transact(self, owner, fn):
        self.inner.transact_deny(lambda d: {"log": [*d["log"], {
            "op": "retract", "deny_id": "deny:inside", "source": self.name, "revision": "all",
            "name": self.name}], "reach": d["reach"]})  # fmt: skip
        return self.inner.transact(owner, fn)


def test_the_deny_state_is_read_inside_the_transaction(reader, backend, clock):
    store = MemoryStore(_DenyInside(backend, uid(1)), now=clock)
    with pytest.raises(MemoryUpdateError, match="retracted source"):
        put(store, reader, [up("add", "a", "A", sources=[uid(1)])], [item(1)])


def test_a_walk_that_needs_a_second_pass(clock, op):
    """A record logged before the record it was exposed through (compaction moves a range to its
    last record's place): only a second pass reaches it."""
    backend = InMemoryBackend()
    owner = "profile:reader"
    p1, p2 = "sha256:" + "1" * 64, "sha256:" + "2" * 64

    def rec(key, rev, pack_id, closure):
        return {"at": f"2026-11-06T08:0{rev}:00.000000Z", "scope": "analyst", "key": key,
                "op": "add", "rev": rev, "value": key, "value_digest": digest(rev),
                "pack_id": pack_id, "sources": [], "checked": True, "tlp": "clear",
                "closure": closure}  # fmt: skip

    log = [rec("x", 1, p2, []), rec("k", 2, p1, [])]
    exposure = {
        p1: {"rendered": [uid(1)], "memory": [], "pairs": []},
        p2: {"rendered": [], "memory": [f"mem:{owner}/analyst/k@2"], "pairs": []},
    }
    backend._data[owner] = {"entries": fold(log), "log": log, "exposure": exposure}
    plan = MemoryAdmin(backend, now=clock).dependents(uid(1), by=op)
    assert [r["key"] for r in plan["exposed"]] == ["k", "x"]


# ---------------------------------------------------------------- re-audit M-A, M-B; design #1
def _file(tmp_path, deny="memory-deny.json"):
    return FileBackend(tmp_path / "memory.json", deny_path=tmp_path / deny)


def test_a_file_backend_needs_its_deny_path(tmp_path):
    with pytest.raises(TypeError):
        FileBackend(tmp_path / "memory.json")  # type: ignore[call-arg]
    with pytest.raises(TypeError, match="deny_path"):
        FileBackend(tmp_path / "memory.json", deny_path="")


def test_the_deny_file_is_read_even_without_its_lock(tmp_path):
    """Fail closed: a deny file whose lock is missing is still the deny state."""
    backend = _file(tmp_path)
    backend.transact_deny(lambda d: {"log": [{"op": "retract", "deny_id": "d", "name": "n"}],
                                     "reach": []})  # fmt: skip
    backend.deny.lock_path.unlink()
    assert denied(backend).names == {"n"}


def _store(backend, tmp_path):
    from homelabnext.notify import FakeSender, Notifier
    from homelabnext.state import StateStore

    sender = FakeSender()
    notifier = Notifier(sender, StateStore(tmp_path / "n.json"))
    return MemoryStore(backend, now=Clock(), notifier=notifier), sender


@pytest.mark.parametrize("damage", ["missing", "shorter", "other path"])
def test_the_runtime_refuses_a_deny_file_that_does_not_match_the_stamp(
    reader, tmp_path, damage, op
):
    from homelabnext.agent.memory import DenyFileProblem
    from homelabnext.notify.core_pairs import AGENT_MEMORY_DENY

    backend = _file(tmp_path)
    store, sender = _store(backend, tmp_path)
    put(store, reader, [up("add", "a", "A", sources=[uid(1)])], [item(1)])
    retract(MemoryAdmin(backend, now=Clock()), uid(1), op)  # stamps the state file
    if damage == "missing":
        backend.deny.path.unlink()
        runtime = backend
    elif damage == "shorter":
        backend.deny.path.write_text('{"log": [], "reach": []}', encoding="utf-8")
        runtime = backend
    else:  # the runtime pointed at another (empty) deny file: split brain
        runtime = _file(tmp_path, deny="elsewhere.json")
    store, sender = _store(runtime, tmp_path)
    with pytest.raises(DenyFileProblem, match=r"stamped|one deny path"):
        put(store, reader, [up("add", "b", "B")], [item(2)])
    assert any(m.title == AGENT_MEMORY_DENY[0] for m in sender.sent)


def test_the_runtime_refuses_a_deny_file_it_can_write(reader, tmp_path, monkeypatch):
    from homelabnext.agent import memory
    from homelabnext.agent.memory import DenyFileProblem
    from homelabnext.notify.core_pairs import AGENT_MEMORY_DENY

    monkeypatch.setattr(memory, "_CHECK_DENY_WRITABLE", True)
    monkeypatch.setattr(memory.os, "geteuid", lambda: 4242)  # a runtime, not root
    store, sender = _store(_file(tmp_path), tmp_path)
    with pytest.raises(DenyFileProblem, match="writable by this process"):
        put(store, reader, [up("add", "a", "A")], [item(1)])
    assert [m.title for m in sender.sent] == [AGENT_MEMORY_DENY[0]]


def test_a_deny_lock_held_forever_is_refused_not_waited_on(tmp_path, monkeypatch):
    import fcntl
    import os

    from homelabnext.agent.memory import DenyFile, DenyFileProblem

    backend = _file(tmp_path)
    backend.transact_deny(lambda d: d)  # creates the lock
    monkeypatch.setattr(DenyFile, "LOCK_TRIES", 3)
    monkeypatch.setattr(DenyFile, "LOCK_WAIT", 0.01)
    fd = os.open(backend.deny.lock_path, os.O_RDONLY)
    try:
        fcntl.flock(fd, fcntl.LOCK_SH)  # the runtime's lock, never released
        with pytest.raises(DenyFileProblem, match="locked by another process"):
            backend.transact_deny(lambda d: d)
    finally:
        os.close(fd)
    fd = os.open(backend.deny.lock_path, os.O_RDWR)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)  # an operator's lock, never released
        with pytest.raises(DenyFileProblem, match="locked by another process"):
            backend.transact("profile:reader", lambda cur, deny: cur)
    finally:
        os.close(fd)


# ---------------------------------------------------------------- second re-audit R1 to R5
def test_r2_a_runtime_on_the_wrong_deny_path_never_reads_an_empty_deny_set(reader, tmp_path, op):
    """The auditor's probe: the operator retracts through one deny path; a runtime pointed at
    another reads its deny set for new packs.  It must refuse and page, not return nothing."""
    from homelabnext.agent.memory import DenyFileProblem
    from homelabnext.notify import FakeSender, Notifier
    from homelabnext.notify.core_pairs import AGENT_MEMORY_DENY
    from homelabnext.state import StateStore

    operator_side = _file(tmp_path)
    store = MemoryStore(operator_side, now=Clock())
    put(store, reader, [up("add", "a", "A", sources=[uid(1)])], [item(1)])
    retract(MemoryAdmin(operator_side, now=Clock()), uid(1), op)
    assert len(denied(operator_side).names) == 2
    runtime = _file(tmp_path, deny="wrong-deny.json")
    sender = FakeSender()
    notifier = Notifier(sender, StateStore(tmp_path / "n.json"))
    with pytest.raises(DenyFileProblem, match="one deny path"):
        denied(runtime, notifier=notifier)
    assert [m.title for m in sender.sent] == [AGENT_MEMORY_DENY[0]]
    with pytest.raises(DenyFileProblem):
        runtime.load_deny()
    denied(operator_side, notifier=notifier)  # the recovery, on a good read
    assert [m.title for m in sender.sent] == list(AGENT_MEMORY_DENY)


def test_r2_a_read_refuses_a_deny_file_the_runtime_can_write(tmp_path, monkeypatch):
    from homelabnext.agent import memory
    from homelabnext.agent.memory import DenyFileProblem

    monkeypatch.setattr(memory, "_CHECK_DENY_WRITABLE", True)
    monkeypatch.setattr(memory.os, "geteuid", lambda: 4242)
    with pytest.raises(DenyFileProblem, match="writable by this process"):
        denied(_file(tmp_path))


def test_r5_the_runtime_walks_the_whole_chain_above_the_deny_file(tmp_path, monkeypatch):
    """A directory two levels up that anyone can write lets the deny file be replaced."""
    import os

    from homelabnext.agent import memory

    top = tmp_path / "top"
    (top / "mid").mkdir(parents=True)
    top.chmod(0o777)
    deny = memory.DenyFile(top / "mid" / "deny.json")
    monkeypatch.setattr(memory, "_CHAIN_STOP", tmp_path)
    monkeypatch.setattr(memory.os, "access", lambda *a, **k: False)  # not writable by us
    assert f"{top} is writable by its group or others" in (deny.problem() or "")
    top.chmod(0o755)
    assert deny.problem() is None
    assert os.stat(top).st_mode & 0o777 == 0o755


def test_r1_a_held_state_lock_is_refused_not_waited_on(tmp_path, monkeypatch):
    import fcntl
    import os

    from homelabnext.state import StateLockBusy

    backend = FileBackend(
        tmp_path / "memory.json", deny_path=tmp_path / "memory-deny.json", lock_timeout=0.1
    )
    backend.transact("profile:reader", lambda cur, deny: {"entries": {}, "log": []})
    fd = os.open(tmp_path / "memory.json.lock", os.O_RDWR)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)  # the runtime mid-write, forever
        with pytest.raises(StateLockBusy, match="locked by another process"):
            backend.owners()
    finally:
        os.close(fd)
    assert backend.owners() == ["profile:reader"]


ROOT = pytest.mark.skipif(
    not hasattr(__import__("os"), "geteuid") or __import__("os").geteuid() != 0,
    reason="changing a file's owner (root) is not available",
)


@ROOT
def test_r3_a_failed_id_change_never_leaves_the_ids_changed(tmp_path, monkeypatch):
    import os

    from homelabnext.agent import memory

    state = tmp_path / "memory.json"
    state.write_text("{}", encoding="utf-8")
    os.chown(state, 4242, 4242)
    groups, egid = os.getgroups(), os.getegid()
    real = os.seteuid

    def failing(uid):
        if uid != 0:
            raise PermissionError("simulated")
        real(uid)

    monkeypatch.setattr(memory.os, "seteuid", failing)
    with pytest.raises(PermissionError, match="simulated"), memory._as_owner(state):
        pass  # never reached
    assert (os.geteuid(), os.getegid(), os.getgroups()) == (0, egid, groups)


@ROOT
def test_r4_an_owner_change_or_a_second_hard_link_is_refused(tmp_path):
    import os

    from homelabnext.agent import memory
    from homelabnext.agent.memory import MemoryAccessError

    state = tmp_path / "memory.json"
    state.write_text("{}", encoding="utf-8")
    os.chown(state, 4242, 4242)
    with memory._as_owner(state, (4242, 4242)):
        assert os.geteuid() == 4242
    started = pytest.raises(MemoryAccessError, match="the operator run started with")
    with started, memory._as_owner(state, (4343, 4343)):
        pass
    os.link(state, tmp_path / "other")
    with pytest.raises(MemoryAccessError, match="2 hard links"), memory._as_owner(state):
        pass
    assert os.geteuid() == 0


# ---------------------------------------------------------------- final review
def test_a_malformed_deny_file_is_refused_and_paged_never_read_empty(tmp_path):
    from homelabnext.agent.memory import DenyFileProblem
    from homelabnext.notify import FakeSender, Notifier
    from homelabnext.notify.core_pairs import AGENT_MEMORY_DENY
    from homelabnext.state import StateStore

    backend = _file(tmp_path)
    backend.deny.path.write_text("{not json", encoding="utf-8")
    sender = FakeSender()
    with pytest.raises(DenyFileProblem, match="cannot read the deny file"):
        denied(backend, notifier=Notifier(sender, StateStore(tmp_path / "n.json")))
    assert [m.title for m in sender.sent] == [AGENT_MEMORY_DENY[0]]


def test_a_deny_file_shorter_but_not_empty_is_refused(reader, tmp_path, op):
    from homelabnext.agent.memory import DenyFileProblem

    backend = _file(tmp_path)
    store = MemoryStore(backend, now=Clock())
    put(store, reader, [up("add", "a", "A", sources=[uid(1)])], [item(1)])
    retract(MemoryAdmin(backend, now=Clock()), uid(1), op)  # two deny records, stamped
    doc = json.loads(backend.deny.path.read_text(encoding="utf-8"))
    assert len(doc["log"]) == 2
    doc["log"] = doc["log"][:1]  # one record lost: shorter than the stamp, not empty
    backend.deny.path.write_text(json.dumps(doc), encoding="utf-8")
    with pytest.raises(DenyFileProblem, match="shorter than the operator stamped"):
        denied(backend)
    with pytest.raises(DenyFileProblem, match="shorter than the operator stamped"):
        put(store, reader, [up("add", "b", "B")], [item(2)])
