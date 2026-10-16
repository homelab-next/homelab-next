# SPDX-License-Identifier: Apache-2.0
"""``records``: propose -> decide -> complete, with agents confined to the inbox lane."""

from __future__ import annotations

from conformance.fakes.records_target import FakeRecordsTarget, OverwritingRecordsTarget
from homelabnext.conform.core import Mutant, Suite

from ._util import raises, uniq

SUITE = Suite(
    "records",
    "validated proposals in one agent lane; operator-only approve/deny/complete moves",
    "conformance.protocols.records:RecordsTarget",
)

DECIDED = ("decided/approved", "decided/denied", "decided/completed")


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


@SUITE.check(
    "propose-never-overwrites", "proposing an existing name fails and keeps the first note"
)
def _(r):
    note = _note(title="Same title", created="2026-04-01T00:00:00Z")
    name = r.propose(note, "original body")
    raises(lambda: r.propose(note, "replacement body"), "duplicate name", FileExistsError)
    assert r.read("inbox", name)[1].strip() == "original body", "the first note was replaced"


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


@SUITE.check("decide-unknown-note-rejected", "deciding a name that is not in the inbox fails")
def _(r):
    raises(lambda: r.approve("2026-01-01-triage-ghost.md"), "approve ghost", FileNotFoundError)
    raises(lambda: r.approve("../escape.md"), "path escape", PermissionError, ValueError)


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
    "a completion request naming a missing note is refused",
)
def _(r):
    before = list(r.list("inbox"))
    raises(
        lambda: r.completion_request(["2026-01-01-triage-ghost.md"], "x", agent="triage"),
        "completion of a missing note",
        ValueError,
    )
    assert list(r.list("inbox")) == before, "a refused completion request was still written"


@SUITE.check("unknown-lane-rejected", "reading an unknown lane is an error")
def _(r):
    raises(lambda: r.list("secret-lane"), "unknown lane", ValueError)


def make_fake():
    return FakeRecordsTarget()


MUTANTS = {
    "overwrites-existing-note": Mutant(
        OverwritingRecordsTarget,
        "propose-never-overwrites",
        "a repeated proposal silently replaces the first",
    ),
}
