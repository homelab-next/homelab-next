# SPDX-License-Identifier: Apache-2.0
"""``records``: propose -> decide -> complete, with agents confined to the inbox lane."""

from __future__ import annotations

from conformance.fakes.records_target import (
    DeniedCompletingRecordsTarget,
    FakeRecordsTarget,
    InboxCompletingRecordsTarget,
    NamesakeRecordsTarget,
    OverwritingRecordsTarget,
    PartialCompleteRecordsTarget,
    ReapprovingRecordsTarget,
    RedenyingRecordsTarget,
    TraversingRecordsTarget,
    UnconfinedReadRecordsTarget,
)
from homelabnext.conform.core import Mutant, Skip, Suite

from ._util import Inconclusive, interleavings, raises, uniq

SUITE = Suite(
    "records",
    "validated proposals in one agent lane; operator-only approve/deny/complete moves",
    "conformance.protocols.records:RecordsTarget",
)

DECIDED = ("decided/approved", "decided/denied", "decided/completed")
LANES = ("inbox", *DECIDED)


def _snapshot(r):
    return {lane: sorted(r.list(lane)) for lane in LANES}


def _note(title=None, **over):
    note = {
        "type": "proposal",
        "title": title or uniq("Raise threshold").replace("-", " "),
        "risk": "low",
        "rollback": "Revert the setting",
        "affects": ["det:auth-failure-burst"],
        "requesting_agent": "profile:triage",
    }
    note.update(over)
    return note


@SUITE.check("propose-lands-in-inbox-only", "a proposal appears in the inbox lane and nowhere else")
def _(r):
    name = r.propose(_note())
    assert name in r.list("inbox"), f"{name} not in inbox: {r.list('inbox')}"
    for lane in DECIDED:
        assert name not in r.list(lane), f"{name} appeared in {lane}"


@SUITE.check("filename-convention", "the name is <date>-<agent>-<slug>.md")
def _(r):
    name = r.propose(_note(created="2026-02-03T04:05:06Z"))
    assert name.startswith("2026-02-03-triage-") and name.endswith(".md"), f"name {name!r}"


@SUITE.check("note-roundtrip", "frontmatter and body read back as written")
def _(r):
    note = _note(title="Round trip title")
    name = r.propose(note, "Body text.\n\nSecond paragraph.")
    fm, body = r.read("inbox", name)
    assert fm["title"] == "Round trip title" and fm["type"] == "proposal", f"frontmatter {fm}"
    assert fm["rollback"] == "Revert the setting" and fm["affects"] == ["det:auth-failure-burst"]
    assert body.strip() == "Body text.\n\nSecond paragraph.", f"body {body!r}"


@SUITE.check(
    "invalid-note-rejected-naming-field",
    "a bad note raises ValueError naming the field and writes nothing",
)
def _(r):
    bad = _note()
    del bad["rollback"]
    before = list(r.list("inbox"))
    exc = raises(lambda: r.propose(bad), "proposal without rollback", ValueError)
    assert "rollback" in str(exc), f"error does not name the field: {exc}"
    assert list(r.list("inbox")) == before, "an invalid note was written"
    raises(lambda: r.propose(_note(type="nonsense")), "unknown type", ValueError)
    raises(
        lambda: r.propose(_note(requesting_agent="triage")), "agent not a profile id", ValueError
    )


def _decide(r, name, lane):
    """Move a freshly proposed note into ``lane`` the way the decision maker does."""
    if lane == "decided/approved":
        r.approve(name)
    elif lane == "decided/denied":
        r.deny(name, "no")
    elif lane == "decided/completed":
        r.approve(name)
        r.complete(r.completion_request([name], "Done.", agent="triage"))


@SUITE.check(
    "propose-never-overwrites",
    "proposing a name taken in any lane - inbox, approved, denied, completed - fails and keeps "
    "the first note",
)
def _(r):
    for lane in LANES:
        note = _note(title=uniq("Same title").replace("-", " "), created="2026-04-01T00:00:00Z")
        name = r.propose(note, "original body")
        _decide(r, name, lane)
        before = _snapshot(r)
        raises(
            lambda n=note: r.propose(n, "replacement body"),
            f"proposing a name already in {lane}",
            FileExistsError,
        )
        assert _snapshot(r) == before, f"a refused namesake of a note in {lane} was filed"
        assert r.read(lane, name)[1].strip() == "original body", f"the note in {lane} was replaced"


@SUITE.check("approve-moves-note", "approve takes the note out of the inbox into decided/approved")
def _(r):
    name = r.propose(_note())
    r.approve(name)
    assert name not in r.list("inbox") and name in r.list("decided/approved")


@SUITE.check("deny-moves-note", "deny moves the note to decided/denied")
def _(r):
    name = r.propose(_note())
    r.deny(name, "not now")
    assert name not in r.list("inbox") and name in r.list("decided/denied")


@SUITE.check(
    "decide-unknown-note-rejected",
    "deciding a name not in the inbox fails; approve/deny/complete refuse '../' names",
)
def _(r):
    raises(lambda: r.approve("2026-01-01-triage-ghost.md"), "approve ghost", FileNotFoundError)
    raises(lambda: r.approve("../escape.md"), "path escape", PermissionError, ValueError)
    # names that, joined onto the inbox, resolve to real notes in other lanes
    approved = r.propose(_note())
    r.approve(approved)
    req = r.completion_request([approved], "Done.", agent="triage")
    before = _snapshot(r)
    for verb, fn, name in (
        ("deny", r.deny, f"../decided/approved/{approved}"),
        ("approve", r.approve, f"../decided/approved/{approved}"),
        ("complete", r.complete, f"../inbox/{req}"),
        ("complete", r.complete, f"./{req}"),
    ):
        raises(lambda f=fn, n=name: f(n), f"{verb} {name!r}", PermissionError, ValueError)
    assert _snapshot(r) == before, "a traversal name moved a note"


@SUITE.check(
    "decisions-are-final",
    "approve or deny of a note already decided is refused and nothing moves",
)
def _(r):
    approved, denied = r.propose(_note()), r.propose(_note())
    r.approve(approved)
    r.deny(denied, "no")
    done = r.propose(_note())
    r.approve(done)
    r.complete(r.completion_request([done], "Done.", agent="triage"))
    before = _snapshot(r)
    for verb, fn, name in (
        ("approve", r.approve, denied),
        ("deny", lambda n: r.deny(n, "changed my mind"), approved),
        ("approve", r.approve, approved),
        ("deny", lambda n: r.deny(n, "again"), denied),
        ("approve", r.approve, done),
        ("deny", lambda n: r.deny(n, "too late"), done),
    ):
        raises(lambda f=fn, n=name: f(n), f"{verb} of decided note {name!r}", FileNotFoundError)
        assert _snapshot(r) == before, f"{verb} re-decided {name!r}"


@SUITE.check(
    "decide-is-atomic",
    "of an approve and a deny raced on one note, never both succeed and the note never ends in "
    "two lanes (single-preemption schedules, deterministic; evidence, not proof)",
    severity="should",
    skippable=True,
)
def _(r):
    lane_of = {"approve": "decided/approved", "deny": "decided/denied"}

    def setup(first):
        name = r.propose(_note())
        ops = {"approve": lambda: r.approve(name), "deny": lambda: r.deny(name, "raced")}
        second = "deny" if first == "approve" else "approve"

        def judge(out1, out2):
            won = [verb for verb, (ok, _) in ((first, out1), (second, out2)) if ok]
            lanes = [lane for lane in LANES if name in r.list(lane)]
            assert len(won) <= 1, f"{first} raced by {second}: both succeeded, note in {lanes}"
            if won:
                assert lanes == [lane_of[won[0]]], f"{won[0]} succeeded, note in {lanes}"
            else:
                # both refused: a correct loser can time out on a lock the harness held paused;
                # only a note that left the inbox anyway is wrong
                assert lanes == ["inbox"], f"both decisions failed, note in {lanes}"

        return ops[first], ops[second], judge

    try:
        for first in ("approve", "deny"):
            interleavings(r, lambda f=first: setup(f))
    except Inconclusive as exc:
        raise Skip(f"could not judge: {exc}") from None


@SUITE.check(
    "completion-moves-related-notes", "completing a request moves each related note to completed"
)
def _(r):
    a, b = r.propose(_note()), r.propose(_note())
    r.approve(a)
    r.approve(b)
    req = r.completion_request([a, b], "Both implemented.", agent="triage")
    r.complete(req)
    done = r.list("decided/completed")
    assert a in done and b in done and req in done, f"completed lane: {done}"
    assert r.list("decided/approved") == [] or all(
        n not in r.list("decided/approved") for n in (a, b)
    ), "approved notes were left behind"


@SUITE.check(
    "completion-needs-existing-approved-notes",
    "a completion request naming a missing note or a path outside approved is refused",
)
def _(r):
    name = r.propose(_note())
    before = list(r.list("inbox"))
    for related in (
        "2026-01-01-triage-ghost.md",
        f"inbox/{name}",
        f"decided/approved/../../inbox/{name}",
        f"../inbox/{name}",
    ):
        raises(
            lambda rel=related: r.completion_request([rel], "x", agent="triage"),
            f"completion of {related!r}",
            ValueError,
            PermissionError,
        )
    assert list(r.list("inbox")) == before, "a refused completion request was still written"


@SUITE.check(
    "completion-only-of-approved-notes",
    "completing an inbox or denied note is refused and nothing moves (all-or-nothing)",
)
def _(r):
    pending = r.propose(_note())
    denied = r.propose(_note())
    r.deny(denied, "no")
    ok = r.propose(_note())
    r.approve(ok)
    before = _snapshot(r)
    for related in ([pending], [denied], [ok, pending], [ok, denied]):
        raises(
            lambda rel=related: r.completion_request(rel, "x", agent="triage"),
            f"completion request for {related}",
            ValueError,
            PermissionError,
        )
        assert _snapshot(r) == before, f"a refused completion request for {related} moved notes"
    # a request that was valid when filed but is stale when completed: nothing may move
    other = r.propose(_note())
    r.approve(other)
    first = r.completion_request([other], "first", agent="triage")
    both = r.completion_request([ok, other], "both", agent="triage")
    r.complete(first)
    mid = _snapshot(r)
    raises(lambda: r.complete(both), "completing a stale request", ValueError, FileNotFoundError)
    assert _snapshot(r) == mid, "a refused completion moved some of its notes"
    assert ok in r.list("decided/approved"), "an approved note was completed by a refused request"


@SUITE.check(
    "unknown-lane-rejected",
    "unknown lanes and '../' reads are refused; a hostile title cannot leave the agent lane",
)
def _(r):
    raises(lambda: r.list("secret-lane"), "unknown lane", ValueError)
    raises(lambda: r.list("../inbox"), "lane traversal", ValueError, PermissionError)
    name = r.propose(_note())
    for lane, bad in (
        ("decided/approved", f"../../inbox/{name}"),
        ("decided/denied", f"../../inbox/{name}"),
        ("inbox", f"../inbox/{name}"),
        ("inbox", f"./{name}"),
    ):
        raises(
            lambda ln=lane, b=bad: r.read(ln, b),
            f"read({lane!r}, {bad!r})",
            ValueError,
            PermissionError,
        )
    before = _snapshot(r)
    try:
        got = r.propose(_note(title="../../decided/approved/escape"))
    except (PermissionError, ValueError):
        got = None
    after = _snapshot(r)
    for lane in DECIDED:
        assert after[lane] == before[lane], f"a proposal reached {lane}"
    if got is not None:
        assert "/" not in got and "\\" not in got and got in after["inbox"], f"name {got!r}"


def make_fake():
    return FakeRecordsTarget()


MUTANTS = {
    "overwrites-existing-note": Mutant(
        OverwritingRecordsTarget,
        "propose-never-overwrites",
        "a repeated proposal silently replaces the first",
    ),
    "namesake-overwrites-decision": Mutant(
        NamesakeRecordsTarget,
        "propose-never-overwrites",
        "a name is checked against the inbox only, so a namesake of an approved note replaces it",
    ),
    "completes-inbox-notes": Mutant(
        InboxCompletingRecordsTarget,
        "completion-only-of-approved-notes",
        "a completion request for a note still in the inbox approves it on the agent path",
    ),
    "completes-denied-notes": Mutant(
        DeniedCompletingRecordsTarget,
        "completion-only-of-approved-notes",
        "a completion request may name a denied note",
    ),
    "partial-completion": Mutant(
        PartialCompleteRecordsTarget,
        "completion-only-of-approved-notes",
        "complete() moves notes one by one and stops halfway on a missing one",
    ),
    "approve-overturns-denial": Mutant(
        ReapprovingRecordsTarget,
        "decisions-are-final",
        "approve accepts a denied note and moves it to approved",
    ),
    "deny-withdraws-approval": Mutant(
        RedenyingRecordsTarget,
        "decisions-are-final",
        "deny accepts an approved note and moves it to denied",
    ),
    "decide-follows-traversal": Mutant(
        TraversingRecordsTarget,
        "decide-unknown-note-rejected",
        "deny/complete join the name onto the lane without refusing '../'",
    ),
    "read-follows-traversal": Mutant(
        UnconfinedReadRecordsTarget,
        "unknown-lane-rejected",
        "read() joins the name onto the lane without refusing '../'",
    ),
}
