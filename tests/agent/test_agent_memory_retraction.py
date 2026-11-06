# SPDX-License-Identifier: Apache-2.0
"""Agent memory is retractable (ADR-0037 PR 3, decisions 11 to 14, 17 and 18): a ``mem:`` source
names a revision the pack's memory block showed; ``MemoryAdmin`` (an operator tool outside the
agent's reach) denies every platform-issued name of a source first, records what it reached
through exposure, and retires what was built on it; every write re-checks the deny log under
the backend's lock; new packs leave denied items out; lift releases marks; purge blanks values.
Every store test runs on both backends."""

import copy
import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from agent_support import (
    digest,
    item,
    labelled_pack,
    library,
    spec,
    uid,
    verified,
)
from memory_admin_support import RUNTIME_UID, operator, operators_file

from homelabnext.agent import SpecError, compile_profile, validate_report
from homelabnext.agent.deny import DenySet, deny_set
from homelabnext.agent.knowledge import Selection
from homelabnext.agent.memory import (
    FileBackend,
    InMemoryBackend,
    MemoryAccessError,
    MemoryClockError,
    MemoryStore,
    MemoryUpdateError,
    denied,
    fold,
    memory_block_input,
)
from homelabnext.agent.pack import assemble_pack
from homelabnext.agent.report import MEM_OWN_KEY, MEM_REFUSAL, served_report
from homelabnext.memory_admin import MemoryAdmin, MemoryAdminError, OperatorPrincipal

T0 = datetime(2026, 11, 6, 9, 0, tzinfo=UTC)
FL = "fleet-ledger"
ROOT = Path(__file__).resolve().parents[2]


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


@pytest.fixture
def other():
    return _profile("profile:other-reader")


@pytest.fixture
def ledger():
    return _profile("profile:ledger", memory_scopes=["analyst", FL], platform_scopes=[FL])


@pytest.fixture(params=["memory", "file"])
def backend(request, tmp_path):
    if request.param == "memory":
        return InMemoryBackend()
    return FileBackend(tmp_path / "memory.json")


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
    """Apply ``updates`` checked against a pack of ``findings`` items (and a memory block)."""
    if memory is not None:
        kw["memory_block"] = memory
    pack, h = labelled_pack(list(findings), [item(999, "clear")], profile=profile, **kw)
    return store.apply_updates(profile, updates, pack=pack, pack_hash=h), (pack, h)


def state(backend):
    """Everything the backend holds, owners and the deny state, for equality checks."""
    return {o: backend.load(o) for o in backend.owners()} | {"deny": backend.load_deny()}


def live(store, profile, scope="analyst"):
    return set(store.read(profile, scope)["entries"])


def build_web(store, reader, other):
    """The history the retraction tests share.  ``uid(1)`` is the bad feed item.

    * ``a`` cites uid(1); ``b`` cites a@1 (one hop through memory); ``c`` cites b@1 (two);
    * ``d`` cites only uid(4), from a pack whose memory block showed a@1 (exposed through
      memory, one hop); ``e`` cites only uid(5), from a pack that rendered uid(1) (exposed);
    * ``g`` cites uid(2), the good record, rendered beside nothing bad;
    * ``other``'s ``x`` cites uid(1) too (across owners)."""
    put(store, reader, [up("add", "a", "A", sources=[uid(1)])], [item(1, "clear")])
    put(store, reader, [up("add", "g", "G", sources=[uid(2)])], [item(2, "clear")])
    mem = memory_block_input(store, reader, ["analyst"])
    put(store, reader, [up("add", "b", "B", sources=[mref(reader["id"], "a", 1)])],
        [item(3, "clear")], memory=mem)  # fmt: skip
    mem = memory_block_input(store, reader, ["analyst"])
    put(store, reader, [up("add", "c", "C", sources=[mref(reader["id"], "b", 1)])],
        [item(3, "clear")], memory=mem)  # fmt: skip
    mem = [m for m in memory_block_input(store, reader, ["analyst"]) if m["key"] == "a"]
    put(store, reader, [up("add", "d", "D", sources=[uid(4)])], [item(4, "clear")], memory=mem)
    put(
        store, reader, [up("add", "e", "E", sources=[uid(5)])], [item(1, "clear"), item(5, "clear")]
    )
    put(store, other, [up("add", "x", "X", sources=[uid(1)])], [item(1, "clear")])


def keys(rows):
    return {(r["owner"].split(":")[1], r["key"]) for r in rows}


# ---------------------------------------------------------------- decision 11: the memory block
def test_the_pack_carries_a_memory_block_and_its_labels(reader, backend, clock):
    store = MemoryStore(backend, now=clock)
    put(store, reader, [up("add", "a", "A", sources=[uid(1)])], [item(1, "amber")])
    mem = memory_block_input(store, reader, ["analyst"])
    assert mem == [
        {"scope": "analyst", "key": "a", "rev": 1, "value_digest": mem[0]["value_digest"],
         "tlp": "amber", "closure": [uid(1), digest(1)]}
    ]  # fmt: skip
    pack, _ = labelled_pack(
        [item(2, "clear")], [item(3, "clear")], static="clear", memory_block=mem
    )
    assert pack["memory"] == [{k: v for k, v in mem[0].items() if k != "closure"}]
    assert pack["provenance"]["tlp"] == "amber"  # what the block shows counts toward the label
    plain, _ = labelled_pack([item(2, "clear")], [item(3, "clear")], static="clear")
    assert "memory" not in plain and plain["provenance"]["tlp"] == "clear"
    with pytest.raises(SpecError, match="memory= needs profile="):
        assemble_pack({"id": "m", "persona": "p", "budget_chars": 10, "sections": [
            {"name": "s", "tier": "stable", "source": "static", "required": True,
             "max_chars": 5, "text": "x"}]}, {}, memory=mem)  # fmt: skip
    with pytest.raises(SpecError, match="not one of the profile's memory_scopes"):
        labelled_pack([item(2)], [item(3)], memory_block=[{**mem[0], "scope": "responder"}])


def test_a_mem_source_is_valid_only_when_the_block_shows_it(reader, backend, clock):
    store = MemoryStore(backend, now=clock)
    put(store, reader, [up("add", "a", "A", sources=[uid(1)])], [item(1, "clear")])
    put(store, reader, [up("replace", "a", "A2")], [item(1, "clear")])
    mem = memory_block_input(store, reader, ["analyst"])  # shows a@2
    assert [m["rev"] for m in mem] == [2]
    with pytest.raises(MemoryUpdateError, match="memory block shows"):
        put(store, reader, [up("add", "b", "B", sources=[mref(reader["id"], "a", 1)])],
            memory=mem)  # fmt: skip
    applied, _ = put(store, reader, [up("add", "b", "B", sources=[mref(reader["id"], "a", 2)])],
                     memory=mem)  # fmt: skip
    assert applied["revs"] == {"analyst/b": 1}
    (rec,) = store.history(reader, "analyst", "b")["records"]
    # the closure takes the cited revision's own closure (decision 10)
    assert rec["closure"] == [mref(reader["id"], "a", 2), uid(1), digest(1)]
    stored = backend.load(reader["id"])
    assert stored["exposure"][rec["pack_id"]]["memory"] == [mref(reader["id"], "a", 2)]
    # no update may cite any revision of its own key
    with pytest.raises(MemoryUpdateError, match=MEM_OWN_KEY):
        put(store, reader, [up("replace", "a", "A3", sources=[mref(reader["id"], "a", 2)])],
            memory=mem)  # fmt: skip


def test_a_foreign_mem_source_is_no_existence_oracle(reader, other, backend, clock):
    """A mem: source naming another owner is refused before any lookup, with the message an
    unshown own revision gets, whether or not the revision exists."""
    store = MemoryStore(backend, now=clock)
    put(store, other, [up("add", "k", "secret")], [item(1, "clear")])
    put(store, reader, [up("add", "a", "A")], [item(1, "clear")])
    mem = memory_block_input(store, reader, ["analyst"])
    messages = set()
    for src in (
        mref(other["id"], "k", 1),  # exists
        mref(other["id"], "nope", 7),  # does not
        mref(reader["id"], "nope", 7),  # own, not shown
    ):
        with pytest.raises(MemoryUpdateError) as exc:
            put(store, reader, [up("add", "b", "B", sources=[src])], memory=mem)
        assert src not in str(exc.value) and "secret" not in str(exc.value)
        messages.add(str(exc.value))
    assert len(messages) == 1 and MEM_REFUSAL in messages.pop()


def test_a_block_entry_must_be_the_profiles_own(reader, other, backend, clock):
    store = MemoryStore(backend, now=clock)
    put(store, reader, [up("add", "a", "A")], [item(1, "clear")])
    assert memory_block_input(store, other, ["analyst"]) == []  # its own memory: empty
    with pytest.raises(MemoryAccessError, match="not in its memory_scopes"):
        memory_block_input(store, other, ["responder"])


# ---------------------------------------------------------------- decision 13: dependents
def test_retraction_reaches_two_levels_of_mem_and_exposure(reader, other, backend, clock, op):
    store = MemoryStore(backend, now=clock)
    build_web(store, reader, other)
    admin = MemoryAdmin(backend, now=clock)
    dry = admin.dependents(uid(1), by=op)
    assert dry["aliases"] == sorted([uid(1), digest(1)])  # the platform's own pairing
    assert keys(dry["cited"]) == {("reader", "a"), ("reader", "b"), ("reader", "c"),
                                  ("other-reader", "x")}  # fmt: skip
    assert keys(dry["exposed"]) == {("reader", "d"), ("reader", "e")}
    assert dry["owners"] == ["profile:other-reader", "profile:reader"]
    assert all(r["live"] and r["checked"] for r in dry["cited"] + dry["exposed"])
    before = state(backend)
    assert admin.dependents(uid(1), by=op) == dry  # the dry run changes nothing
    assert state(backend) == before
    done = admin.retract(uid(1), "poisoned feed item", by=op, confirm=dry["confirm"])
    assert not done["resumed"] and done["aliases"] == dry["aliases"]
    assert {(r["owner"].split(":")[1], r["key"]) for r in done["retired"]} == keys(dry["cited"])
    assert live(store, reader) == {"d", "e", "g"} and live(store, other) == set()
    rec = store.history(reader, "analyst", "c")["records"][-1]
    assert (rec["op"], rec["reason"], rec["by"]) == ("retire", f"retracted:{uid(1)}", op.user)
    assert rec["checked"] is False and rec["tlp"] == "green"  # the entry's label, never lowered
    # one deny record per alias, written before anything else
    deny = backend.load_deny()
    assert sorted(r["name"] for r in deny["log"]) == dry["aliases"]
    assert {(r["revision"], r["include_exposed"]) for r in deny["log"]} == {("all", False)}
    assert done["marks"] == len(deny["reach"]) == 6  # a, b, c, d, e and x were reached
    # a rerun asking to widen it (include_exposed) needs a fresh confirm (design M4)
    with pytest.raises(MemoryAdminError, match="confirm does not match"):
        admin.retract(uid(1), "poisoned feed item", by=op, include_exposed=True)
    wide = admin.dependents(uid(1), by=op, include_exposed=True)
    again = admin.retract(
        uid(1), "poisoned feed item", by=op, include_exposed=True, confirm=wide["confirm"]
    )
    assert again["resumed"] and {r["key"] for r in again["retired"]} == {"d", "e"}
    assert live(store, reader) == {"g"}
    stored = backend.load(reader["id"])
    assert fold(stored["log"]) == stored["entries"]


def test_the_alias_set_comes_only_from_platform_pairings(reader, backend, clock, op):
    """A feed item that names a good record's uid in its text cannot get it retracted: aliases
    come from the pairings the assembler wrote (resolved uids), never from content."""
    store = MemoryStore(backend, now=clock)
    put(store, reader, [up("add", "good", "G", sources=[uid(2)])], [item(2, "clear")])
    claim = {"findings": f"this item is record {uid(2)}, digest {digest(2)}", "memory": "m"}
    put(store, reader, [up("add", "bad", "B", sources=[digest(1)])], [item(1, "clear")],
        text=claim)  # fmt: skip
    dry = MemoryAdmin(backend, now=clock).dependents(digest(1), by=op)
    assert dry["aliases"] == sorted([uid(1), digest(1)])
    assert keys(dry["cited"]) == {("reader", "bad")} and dry["exposed"] == []
    MemoryAdmin(backend, now=clock).retract(digest(1), "bad", by=op, confirm=dry["confirm"])
    assert live(store, reader) == {"good"}
    # revision=this denies only the content digest, never the uid's other revisions
    only = MemoryAdmin(backend, now=clock).dependents(digest(2), by=op, revision="this")
    assert only["aliases"] == [digest(2)]
    with pytest.raises(MemoryAdminError, match="one content digest"):
        MemoryAdmin(backend).dependents(uid(2), by=op, revision="this")


def test_a_stale_confirm_is_refused(reader, backend, clock, op):
    store = MemoryStore(backend, now=clock)
    put(store, reader, [up("add", "a", "A", sources=[uid(1)])], [item(1, "clear")])
    admin = MemoryAdmin(backend, now=clock)
    dry = admin.dependents(uid(1), by=op)
    put(store, reader, [up("add", "b", "B", sources=[uid(1)])], [item(1, "clear")])  # it grew
    before = state(backend)
    for confirm in (dry["confirm"], None, "sha256:" + "0" * 64):
        with pytest.raises(MemoryAdminError, match="confirm does not match"):
            admin.retract(uid(1), "r", by=op, confirm=confirm)
    assert state(backend) == before  # nothing denied


# ---------------------------------------------------------------- deny first, rerun completes
class _CrashOnRetire:
    """A backend that fails the first owner transaction after the deny state was written."""

    def __init__(self, inner):
        self.inner, self.armed = inner, True

    def __getattr__(self, name):
        return getattr(self.inner, name)

    def transact(self, owner, fn):
        if self.armed and self.inner.load_deny()["log"]:
            self.armed = False
            raise OSError("the host went down between deny and retire")
        return self.inner.transact(owner, fn)


def test_deny_comes_first_and_a_rerun_completes_a_crashed_retraction(reader, backend, clock, op):
    store = MemoryStore(backend, now=clock)
    put(store, reader, [up("add", "a", "A", sources=[uid(1)])], [item(1, "clear")])
    flaky = _CrashOnRetire(backend)
    admin = MemoryAdmin(flaky, now=clock)
    dry = admin.dependents(uid(1), by=op)
    with pytest.raises(OSError, match="between deny and retire"):
        admin.retract(uid(1), "r", by=op, confirm=dry["confirm"])
    assert backend.load_deny()["log"] and live(store, reader) == {"a"}  # denied, not yet retired
    # the deny already sticks: a new write citing the source is refused under the lock
    with pytest.raises(MemoryUpdateError, match="retracted source"):
        put(store, reader, [up("add", "b", "B", sources=[uid(1)])], [item(1, "clear")])
    done = admin.retract(uid(1), "r", by=op)  # no confirm: the deny records exist
    assert done["resumed"] and [r["key"] for r in done["retired"]] == ["a"]
    assert live(store, reader) == set()


def test_retracting_twice_changes_nothing(reader, other, backend, clock, op):
    store = MemoryStore(backend, now=clock)
    build_web(store, reader, other)
    admin = MemoryAdmin(backend, now=clock)
    dry = admin.dependents(uid(1), by=op)
    admin.retract(uid(1), "r", by=op, confirm=dry["confirm"])
    after = state(backend)
    second = admin.retract(uid(1), "r", by=op)
    assert second["resumed"] and second["retired"] == []
    assert state(backend) == after


# ---------------------------------------------------------------- decision 14: enforcement
def test_a_report_validated_before_a_retraction_is_refused_after_it(reader, backend, clock, op):
    store = MemoryStore(backend, now=clock)
    put(store, reader, [up("add", "a", "A", sources=[uid(1)])], [item(1, "clear")])
    pack, h = labelled_pack([item(1, "clear"), item(2, "clear")], [item(3, "clear")])
    rep = {
        "pack_id": h, "profile": reader["id"], "status": "ok", "summary": "s",
        "cites": [{"source": "findings", "ref": "f"}], "unknowns": [],
        "memory_updates": [up("add", "n", "N", sources=[uid(2)])],
    }  # fmt: skip
    assert validate_report(rep, pack, h) == []  # valid when it was checked
    admin = MemoryAdmin(backend, now=clock)
    admin.retract(uid(1), "r", by=op, confirm=admin.dependents(uid(1), by=op)["confirm"])
    before = backend.load(reader["id"])
    # the pack rendered the denied source: refused whatever the report cites
    with pytest.raises(MemoryUpdateError, match="pack rendered a retracted source"):
        store.apply_report(reader, rep, pack=pack, pack_hash=h)
    assert backend.load(reader["id"]) == before
    # a later revision of the same record (a new digest under the denied uid) is covered too
    newer = {"uid": uid(1), "digest": digest(101), "tlp": "clear"}
    with pytest.raises(MemoryUpdateError, match="retracted source"):
        put(store, reader, [up("add", "m", "M")], [newer], stored={uid(1): {"digest": digest(101),
            "tlp": "clear"}, uid(999): "clear"})  # fmt: skip


def test_a_checked_batch_is_refused_whole_and_an_unchecked_one_drops_and_pages(
    ledger, backend, clock, op, tmp_path
):
    from homelabnext.notify import FakeSender, Notifier
    from homelabnext.notify.core_pairs import AGENT_MEMORY_DROPPED
    from homelabnext.state import StateStore

    sender = FakeSender()
    store = MemoryStore(
        backend, now=clock, notifier=Notifier(sender, StateStore(tmp_path / "n.json"))
    )
    store.apply_updates(ledger, [up("add", "k", "v", scope=FL, sources=[digest(7)])],
                        unchecked=True)  # fmt: skip
    mem = memory_block_input(store, ledger, [FL])
    put(store, ledger, [up("add", "m", "M", sources=[mref(ledger["id"], "k", 1, FL)])],
        [item(2, "clear")], memory=mem)  # fmt: skip
    # the deny records alone, as a retraction's first step leaves them (no walk yet)
    backend.transact_deny(lambda d: {"log": [*d["log"], {
        "op": "retract", "deny_id": "deny:test", "at": "2026-11-06T09:00:00.000000Z",
        "source": digest(7), "revision": "all", "name": digest(7), "reason": "r", "by": op.user,
    }], "reach": d["reach"]})  # fmt: skip
    before = backend.load(ledger["id"])
    with pytest.raises(MemoryUpdateError, match="memory_updates/1: its closure reaches"):
        put(store, ledger, [up("add", "ok", "v"),
                            up("add", "no", "v", sources=[mref(ledger["id"], "k", 1, FL)])],
            [item(3, "clear")], memory=mem)  # fmt: skip
    assert backend.load(ledger["id"]) == before  # refused whole
    got = store.apply_updates(
        ledger,
        [up("add", "j", "v", scope=FL), up("add", "k2", "v", scope=FL, sources=[digest(7)])],
        unchecked=True,
    )
    assert got["revs"] == {"fleet-ledger/j": 2} or "fleet-ledger/k2" not in got["revs"]
    assert len(got["dropped"]) == 1 and "retracted source" in got["dropped"][0]
    assert live(store, ledger, FL) == {"j", "k"}
    title, _ = AGENT_MEMORY_DROPPED
    assert any(m.title == title and "retracted" in m.body for m in sender.sent)
    # completing the retraction retires the platform key too (ADR-0035 decision 10, amended)
    done = MemoryAdmin(backend, now=clock).retract(digest(7), "r", by=op)
    assert done["resumed"] and done["deny_id"] == "deny:test"
    assert {(r["scope"], r["key"]) for r in done["retired"]} == {(FL, "k"), ("analyst", "m")}
    assert live(store, ledger, FL) == {"j"}


def test_new_packs_leave_denied_items_out(reader, backend, clock, op):
    store = MemoryStore(backend, now=clock)
    put(store, reader, [up("add", "a", "A", sources=[uid(1)])], [item(1, "clear")])
    put(store, reader, [up("add", "g", "G", sources=[uid(2)])], [item(2, "clear")])
    admin = MemoryAdmin(backend, now=clock)
    admin.retract(uid(1), "r", by=op, confirm=admin.dependents(uid(1), by=op)["confirm"])
    deny = denied(backend)
    assert deny.names == {uid(1), digest(1)}
    # an input section declaring a denied item is left out whole (its text cannot be split); a
    # required one is quarantined (listed, and paged by the caller), not deferred silently
    pack, _ = labelled_pack([item(1, "clear")], [item(2, "clear")], retracted=deny)
    assert pack["status"] == "ready" and "findings" in pack["omitted"]
    assert pack["retracted"]["quarantined"] == ["findings"]
    assert pack["retracted"]["inputs"] == [{"section": "findings", "uid": uid(1)}]
    assert all(i["uid"] != uid(1) for i in pack["provenance"]["inputs"])
    # memory: an entry whose closure reaches a denied name is left out of the block
    mem = memory_block_input(store, reader, ["analyst"])
    mem.append({**mem[0], "key": "z", "closure": [uid(1)]})  # as an older store would hold it
    pack, _ = labelled_pack(
        [item(3, "clear")], [item(2, "clear")], memory_block=mem, retracted=deny
    )
    assert [m["key"] for m in pack["memory"]] == ["g"] and pack["retracted"]["memory"] == 1
    with pytest.raises(SpecError, match="retracted must be a DenySet"):
        labelled_pack([item(3)], [item(2)], retracted=[uid(1)])


def test_assemble_pack_drops_a_retracted_knowledge_item():
    sel = Selection(
        profile="profile:reader", profile_digest="sha256:" + "a" * 64,
        graph_digest="sha256:" + "b" * 64, rules=(), seeds=(), excluded=(),
        included=({"id": f"lesson:{uid(7)}", "kind": "lesson", "title": "t", "path": None,
                   "reviewed": [], "distance": 0, "score": 1.0, "via": "seed", "from": "x",
                   "rules": [0], "max_chars": 1000, "digest": digest(7), "text": "lesson",
                   "rank": 1, "section": "knowledge-001-lesson"},),
    )  # fmt: skip
    pack, _ = labelled_pack([item(1)], [item(2)], knowledge=sel,
                            retracted=DenySet(frozenset({uid(7)})))  # fmt: skip
    assert pack["provenance"]["knowledge"] == [] and pack["retracted"]["knowledge"] == [
        f"lesson:{uid(7)}"
    ]
    # the pack's knowledge record no longer lists it as included (design nit)
    assert pack["knowledge"]["included"] == []
    assert {"id": f"lesson:{uid(7)}", "reason": "retracted"} in pack["knowledge"]["excluded"]


# ---------------------------------------------------------------- lift
def test_lift_releases_marks_and_restores_nothing(reader, backend, clock, op):
    store = MemoryStore(backend, now=clock)
    put(store, reader, [up("add", "a", "A", sources=[uid(1)])], [item(1, "clear")])
    mem = memory_block_input(store, reader, ["analyst"])
    put(store, reader, [up("add", "d", "D", sources=[uid(4)])], [item(4, "clear")], memory=mem)
    shows_d = memory_block_input(store, reader, ["analyst"])
    stale_pack = labelled_pack([item(5, "clear")], [item(999, "clear")], memory_block=shows_d)
    admin = MemoryAdmin(backend, now=clock)
    admin.retract(uid(1), "r", by=op, confirm=admin.dependents(uid(1), by=op)["confirm"])
    assert live(store, reader) == {"d"}  # exposed, not retired
    deny = denied(backend)
    assert deny.marked(reader["id"], "analyst", "d", 1)
    # a pack showing d@1 is refused, and a new block leaves it out
    with pytest.raises(MemoryUpdateError, match="memory block shows a revision"):
        store.apply_updates(reader, [up("add", "n", "N")], pack=stale_pack[0],
                            pack_hash=stale_pack[1])  # fmt: skip
    pack, _ = labelled_pack(
        [item(5, "clear")],
        [item(999, "clear")],
        memory_block=memory_block_input(store, reader, ["analyst"]),
        retracted=deny,
    )
    assert pack["memory"] == [] and pack["retracted"]["memory"] == 1
    assert admin.lift(uid(1), "fine after all", by=op, dry_run=True)["lifted"] == []
    lifted = admin.lift(uid(1), "fine after all", by=op)
    assert len(lifted["lifted"]) == 1 and denied(backend) == DenySet()
    store.apply_updates(reader, [up("add", "n", "N")], pack=stale_pack[0], pack_hash=stale_pack[1])
    assert live(store, reader) == {"d", "n"}  # a was not restored
    assert backend.load_deny()["reach"]  # the marks are still there, not counting
    assert admin.lift(uid(1), "again", by=op)["lifted"] == []


def test_the_deny_state_is_append_only_and_apart_from_memory(backend, tmp_path):
    backend.transact_deny(lambda d: {"log": [*d["log"], {"op": "x"}], "reach": d["reach"]})
    with pytest.raises(MemoryAccessError, match="append-only"):
        backend.transact_deny(lambda d: {"log": [], "reach": d["reach"]})
    for key in ("@memory-deny-log", "@anything"):
        with pytest.raises(MemoryAccessError, match="reserved"):
            backend.load(key)
        with pytest.raises(MemoryAccessError, match="reserved"):
            backend.transact(key, lambda cur, deny: cur)
    assert backend.owners() == []
    if isinstance(backend, FileBackend):  # its own file, never the runtime's state file
        assert backend.deny.path.exists() and not (tmp_path / "memory.json").exists()
        assert oct(backend.deny.path.stat().st_mode & 0o777) == "0o644"
    assert deny_set([{"op": "retract", "deny_id": "d1", "name": "n"}]).names == {"n"}


# ---------------------------------------------------------------- purge
def test_purge_across_owners(reader, other, backend, clock, op):
    store = MemoryStore(backend, now=clock)
    put(store, reader, [up("add", "k", "leaked value")], [item(1, "clear")])
    put(store, reader, [up("replace", "k", "fine now")], [item(1, "clear")])
    put(store, other, [up("add", "q", "leaked value")], [item(1, "clear")])
    vd = store.history(reader, "analyst", "k")["records"][0]["value_digest"]
    admin = MemoryAdmin(backend, now=clock)
    dry = admin.purge("*", vd, "a secret the screen missed", by=op, dry_run=True)
    assert {(p["owner"], p["key"], p["retired"]) for p in dry["purged"]} == {
        (reader["id"], "k", False), (other["id"], "q", True)
    }  # fmt: skip
    t_before = clock.t
    done = admin.purge("*", vd, "a secret the screen missed", by=op)
    assert done["purged"] == [{k: v for k, v in p.items() if k != "digest"} for p in dry["purged"]]
    for o in (reader["id"], other["id"]):
        assert "leaked value" not in json.dumps(backend.load(o))
    recs = store.history(reader, "analyst", "k")["records"]
    assert recs[0]["purged"] is True and "value" not in recs[0]
    assert recs[0]["value_digest"].startswith("purged:")  # no plaintext digest stays (audit M5)
    assert vd not in json.dumps(backend.load(reader["id"])) and dry["purged"][0]["digest"] == vd
    assert recs[-1]["op"] == "purge" and recs[-1]["by"] == op.user
    assert store.read(reader, "analyst")["entries"] == {"k": "fine now"}
    assert live(store, other) == set()  # its current revision was retired first
    q = store.history(other, "analyst", "q")["records"]
    assert [r["op"] for r in q] == ["add", "retire", "purge"]
    assert store.as_of(other, "analyst", t_before)["purged"] == ["q"]
    assert store.as_of(other, "analyst", t_before)["entries"] == {}
    stored = backend.load(other["id"])
    assert fold(stored["log"]) == stored["entries"]
    with pytest.raises(MemoryAdminError, match='"\\*" takes a value digest'):
        admin.purge("*", "analyst/k@1", "r", by=op)
    one = admin.purge(reader["id"], "analyst/k@2", "by revision", by=op, dry_run=True)
    assert one["purged"][0]["revs"] == [2] and one["purged"][0]["retired"] is True


# ---------------------------------------------------------------- restamp (decision 3)
def test_an_operator_restamp_recovers_a_log_stamped_in_the_future(reader, backend, op):
    ahead = Clock(T0 + timedelta(days=1))
    store = MemoryStore(backend, now=ahead)
    put(store, reader, [up("add", "k", "v")], [item(1, "clear")])
    back = Clock(T0)
    with pytest.raises(MemoryClockError):
        put(MemoryStore(backend, now=back), reader, [up("add", "j", "v")], [item(1, "clear")])
    admin = MemoryAdmin(backend, now=back)
    dry = admin.restamp(reader["id"], "clock ran a day ahead", by=op, dry_run=True)
    assert dry["restamped"] == 1 and dry["changes"][0]["from"].startswith("2026-11-07")
    assert dry["changes"][0]["to"].startswith("2026-11-06")
    with pytest.raises(MemoryAdminError, match="needs expect_now"):
        admin.restamp(reader["id"], "clock ran a day ahead", by=op)
    with pytest.raises(MemoryAdminError, match="away from expect_now"):
        admin.restamp(reader["id"], "r", by=op, expect_now=T0 + timedelta(hours=1))
    done = admin.restamp(reader["id"], "clock ran a day ahead", by=op, expect_now=T0)
    assert done["restamped"] == 1
    put(MemoryStore(backend, now=back), reader, [up("add", "j", "v")], [item(1, "clear")])
    (rec,) = store.history(reader, "analyst", "k")["records"]
    assert rec["restamped_from"]["at"].startswith("2026-11-07") and rec["at"] < "2026-11-07"
    stored = backend.load(reader["id"])
    assert fold(stored["log"]) == stored["entries"] and stored["log"][1]["op"] == "restamp"


# ---------------------------------------------------------------- decision 12: out of reach
def test_a_profile_or_a_string_cannot_act_as_an_operator(reader, backend, op):
    admin = MemoryAdmin(backend)
    for by in (reader, reader["id"], "root", {"user": "root"}, None):
        for call in (
            lambda b: admin.dependents(uid(1), by=b),
            lambda b: admin.retract(uid(1), "r", by=b),
            lambda b: admin.lift(uid(1), "r", by=b),
            lambda b: admin.purge("*", digest(1), "r", by=b),
            lambda b: admin.restamp(reader["id"], "r", by=b),
        ):
            with pytest.raises(TypeError, match="OperatorPrincipal"):
                call(by)
    with pytest.raises(TypeError, match="built only by the hnx agent memory command"):
        OperatorPrincipal("root", 0, "x")
    with pytest.raises(TypeError, match="sealed"):
        type("Sub", (OperatorPrincipal,), {})
    with pytest.raises(AttributeError):
        op.user = "someone"  # type: ignore[misc]
    with pytest.raises(MemoryAdminError, match="secret"):
        admin.retract(uid(1), "key " + "AKIA" + "Z7" * 8, by=op)


# ---------------------------------------------------------------- decision 18: served reports
def test_a_report_served_to_another_profile_carries_only_a_count(reader, other):
    rep = {
        "pack_id": digest(1), "profile": reader["id"], "status": "ok", "summary": "s",
        "cites": [], "unknowns": [],
        "memory_updates": [up("add", "hunch-key", "the hunch", sources=[uid(9)])],
    }  # fmt: skip
    from homelabnext.agent.digest import digest_of

    shelf = {digest_of(rep): rep}  # reports by digest, as a level read serves them
    served = served_report(shelf[digest_of(rep)], reader=other)
    assert served["memory_updates"] == {"count": 1}
    text = json.dumps(served)
    assert "hunch-key" not in text and "the hunch" not in text and uid(9) not in text
    assert served_report(rep, reader=reader) == rep  # its author reads it whole
    assert rep["memory_updates"][0]["key"] == "hunch-key"  # the stored report is untouched
    with pytest.raises(Exception, match="VerifiedProfile"):
        served_report(rep, reader=other["id"])


# ---------------------------------------------------------------- the CLI
def _cli(args, capsys):
    from homelabnext.cli import main

    code = main(["agent", "memory", *args])
    out = capsys.readouterr()
    return code, out.out, out.err


def _cli_env(monkeypatch, tmp_path, owner=RUNTIME_UID):
    """The CLI as the deployment runs it (through sudo, the runtime owning the state file), on
    a host where the test's own uid stands in for root."""
    from homelabnext.memory_admin import cli, principal

    monkeypatch.setattr(principal, "_TRUST_ABOVE", tmp_path)
    monkeypatch.setattr(principal, "_ROOT_OWNERS", frozenset({0, os.getuid()}))
    monkeypatch.setattr(cli, "_euid", lambda: 0)
    if owner is not None:
        monkeypatch.setattr(cli, "_owner", lambda path: owner)


def test_the_cli_is_operator_only_and_a_dry_run_by_default(reader, tmp_path, capsys, monkeypatch):
    from homelabnext.memory_admin import cli

    _cli_env(monkeypatch, tmp_path)
    state_file = tmp_path / "memory.json"
    store = MemoryStore(FileBackend(state_file), now=Clock(datetime(2026, 1, 1, tzinfo=UTC)))
    put(store, reader, [up("add", "a", "A", sources=[uid(1)])], [item(1, "clear")])
    ops = str(operators_file(tmp_path))
    common = ["--state", str(state_file), "--operators", ops]
    code, out, _ = _cli(["dependents", uid(1), *common], capsys)
    assert code == 0 and json.loads(out)["cited"][0]["key"] == "a"
    before = state_file.read_bytes()
    code, out, _ = _cli(["retract", uid(1), "--reason", "bad", *common], capsys)
    dry = json.loads(out)
    assert code == 0 and dry["dry_run"] is True and state_file.read_bytes() == before
    code, _, err = _cli(["retract", uid(1), "--reason", "bad", "--apply", *common], capsys)
    assert code == 1 and "confirm does not match" in err
    code, out, _ = _cli(["retract", uid(1), "--reason", "bad", "--apply", "--confirm",
                         dry["confirm"], *common], capsys)  # fmt: skip
    assert code == 0 and json.loads(out)["retired"][0]["key"] == "a"
    for cmd in (["lift", uid(1)], ["purge", "*", digest(5)], ["restamp", reader["id"]]):
        code, out, _ = _cli([*cmd, "--reason", "r", *common], capsys)
        assert code == 0 and json.loads(out)["dry_run"] is True
    code, _, err = _cli(["restamp", reader["id"], "--reason", "r", "--apply", "--expect-now",
                         "yesterday", *common], capsys)  # fmt: skip
    assert code == 1 and "ISO 8601" in err
    monkeypatch.setattr(cli, "_owner", lambda path: os.stat(path).st_uid)
    code, _, err = _cli(["dependents", uid(1), "--state", str(tmp_path / "none.json"),
                         "--operators", ops], capsys)  # fmt: skip
    assert code == 2 and "no memory state file" in err
    monkeypatch.setattr(cli, "_owner", lambda path: RUNTIME_UID)
    (tmp_path / "bad.yml").write_text("operators: [", encoding="utf-8")
    code, _, err = _cli(["dependents", uid(1), "--state", str(state_file), "--operators",
                         str(tmp_path / "bad.yml")], capsys)  # fmt: skip
    assert code == 2 and "cannot parse" in err  # an unreadable operators file is exit 2
    monkeypatch.setattr(cli, "_euid", lambda: 1000)  # --operators is root's alone
    code, _, err = _cli(["dependents", uid(1), *common], capsys)
    assert code == 1 and "honoured only for root" in err
    monkeypatch.setattr(cli, "_euid", lambda: 0)
    # the state file's owner is refused even when the operators file lists that user
    monkeypatch.setattr(cli, "_owner", lambda path: os.getuid())
    code, _, err = _cli(["dependents", uid(1), *common], capsys)
    assert code == 1 and "owns the memory state file" in err
    monkeypatch.setattr(cli, "_owner", lambda path: RUNTIME_UID)
    # a deny file the runtime could rewrite is refused
    deny = tmp_path / "memory.json.deny.json"
    deny.chmod(0o666)
    code, _, err = _cli(["dependents", uid(1), *common], capsys)
    assert code == 1 and "the deny file must be owned by root" in err
    deny.chmod(0o644)
    monkeypatch.setattr(os, "getuid", lambda: RUNTIME_UID)
    code, _, err = _cli(["dependents", uid(1), *common], capsys)
    assert code == 1 and "refused" in err and "agent runtime or the broker" in err


CHOWN = "changing a file's owner (root) is not available"


@pytest.mark.skipif(not hasattr(os, "geteuid") or os.geteuid() != 0, reason=CHOWN)
def test_an_operator_write_keeps_the_runtimes_ownership(reader, tmp_path, capsys, monkeypatch):
    """The deployment: the runtime (4242:4242) owns its state file and its lock; the operator
    writes as root through sudo; both keep their owner (audit H1)."""
    _cli_env(monkeypatch, tmp_path, owner=None)  # the real owner, read from the file
    state_file = tmp_path / "memory.json"
    store = MemoryStore(FileBackend(state_file), now=Clock(datetime(2026, 1, 1, tzinfo=UTC)))
    put(store, reader, [up("add", "a", "A", sources=[uid(1)])], [item(1, "clear")])
    lock = tmp_path / "memory.json.lock"
    for f in (state_file, lock):
        os.chown(f, RUNTIME_UID, RUNTIME_UID)
    lock.unlink()  # a lock the operator creates gets the state file's owner too
    common = ["--state", str(state_file), "--operators", str(operators_file(tmp_path))]
    code, out, _ = _cli(["dependents", uid(1), *common], capsys)
    code, out, _ = _cli(["retract", uid(1), "--reason", "bad", "--apply", "--confirm",
                         json.loads(out)["confirm"], *common], capsys)  # fmt: skip
    assert code == 0 and json.loads(out)["retired"][0]["key"] == "a"
    for f in (state_file, lock):
        assert (f.stat().st_uid, f.stat().st_gid) == (RUNTIME_UID, RUNTIME_UID)
    deny = tmp_path / "memory.json.deny.json"
    assert deny.stat().st_uid == 0 and deny.stat().st_mode & 0o777 == 0o644


def test_a_skip_names_a_registered_cause(request):
    from tests.suite_policy import skip_reason_allowed

    assert skip_reason_allowed(CHOWN, request.config.getini("skip_reasons"))


def test_a_memory_state_copy_is_left_as_it_was_by_a_dry_run(reader, backend, clock, op):
    store = MemoryStore(backend, now=clock)
    put(store, reader, [up("add", "k", "v")], [item(1, "clear")])
    before = copy.deepcopy(state(backend))
    admin = MemoryAdmin(backend, now=clock)
    admin.purge(reader["id"], "analyst/k@1", "r", by=op, dry_run=True)
    admin.restamp(reader["id"], "r", by=op, dry_run=True)
    assert admin.purge(reader["id"], "analyst/k@9", "r", by=op)["purged"] == []
    admin.lift(uid(1), "r", by=op, dry_run=True)
    assert state(backend) == before
