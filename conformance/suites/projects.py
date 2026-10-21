# SPDX-License-Identifier: Apache-2.0
"""``projects``: projects, steps and tasks under the board rules, linked to records by uid."""

from __future__ import annotations

import re

from conformance.fakes import project_store as fakes
from conformance.protocols.projects import (
    Conflict,
    InvalidField,
    InvalidReference,
    InvalidTransition,
    NotFound,
    ProjectsError,
)
from homelabnext.conform.core import Mutant, Suite

from ._util import raises, uniq

SUITE = Suite(
    "projects",
    "projects, steps and one-off tasks under the board rules; uid links, versions, a change feed",
    "conformance.protocols.projects:ProjectStore",
)

UUID7 = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
_MISSING = "01890000-0000-7000-8000-000000000000"  # a well-formed uid nothing has


def _project(s, steps=0):
    p = s.create("project", uniq("Project"))
    return p, [s.create("step", uniq("Step"), project=p.uid) for _ in range(steps)]


def _record(s, n=0):
    recs = list(s.records())
    assert len(recs) > n, f"the subject offers {len(recs)} linkable record(s), the suite needs 2"
    return recs[n]


@SUITE.check("uids-are-unique-uuidv7", "every item gets its own UUIDv7 uid, version 1")
def _(s):
    p, steps = _project(s, 2)
    t = s.create("task", uniq("Task"))
    uids = [p.uid, *(x.uid for x in steps), t.uid]
    assert len(set(uids)) == len(uids), f"uids repeat: {uids}"
    bad = [u for u in uids if not UUID7.match(u)]
    assert not bad, f"not canonical UUIDv7: {bad}"
    assert {x.version for x in (p, *steps, t)} == {1}, "a new item is at version 1"
    assert [x.order for x in steps] == [1, 2], f"steps keep their order: {[x.order for x in steps]}"


@SUITE.check("create-is-idempotent-by-external-key", "a second create with a key returns the first")
def _(s):
    key = uniq("ext")
    a = s.create("project", "Upgrade the edge", external_key=key)
    b = s.create("project", "Upgrade the edge", external_key=key)
    assert a.uid == b.uid and b.version == 1, f"{a.uid} then {b.uid} v{b.version}"
    assert [p.uid for p in s.list(kind="project") if p.external_key == key] == [a.uid]
    raises(lambda: s.create("task", "x", external_key=key), "key reused for a task", ProjectsError)


@SUITE.check(
    "fields-and-uids-validated",
    "kind, title, status, assignee and due date are checked; a missing uid is NotFound",
)
def _(s):
    for bad in (
        lambda: s.create("epic", "x"),
        lambda: s.create("task", ""),
        lambda: s.create("task", "two\nlines"),
        lambda: s.create("task", "x", status="waiting"),
        lambda: s.create("task", "x", assignee="alex"),
        lambda: s.create("task", "x", due="next week"),
        lambda: s.create("project", "x", status="in_progress"),
    ):
        raises(bad, "invalid field", InvalidField, ValueError)
    assert all(i.title != "x" for i in s.list()), "an invalid create was stored"
    raises(lambda: s.get(_MISSING), "get", NotFound)
    raises(lambda: s.update(_MISSING, 1, title="x"), "update", NotFound)
    raises(lambda: s.close(_MISSING, "done"), "close", NotFound)
    raises(lambda: s.link(_MISSING, _record(s), "supports"), "link", NotFound)


@SUITE.check(
    "step-needs-an-open-project",
    "a step names an existing project; nothing is created or reopened in a closed one",
)
def _(s):
    raises(lambda: s.create("step", "orphan"), "step without project", InvalidReference)
    raises(lambda: s.create("step", "x", project=_MISSING), "missing project", ProjectsError)
    t = s.create("task", uniq("Task"))
    raises(lambda: s.create("step", "x", project=t.uid), "task as project", InvalidReference)
    p, _ = _project(s)
    s.close(p.uid, "nothing left")
    raises(lambda: s.create("step", "late", project=p.uid), "step in closed project", InvalidTransition)  # fmt: skip
    assert not s.list(project=p.uid), "a step was stored under a closed project"
    p, (a,) = _project(s, 1)
    done = s.close(a.uid, "the only step")  # closes p
    assert s.get(p.uid).status == "closed", "the last step finished, the project is open"
    raises(lambda: s.update(a.uid, done.version, status="todo"), "reopen in closed project", InvalidTransition)  # fmt: skip
    assert s.get(a.uid).status == "done", "a step was reopened in a closed project"


@SUITE.check(
    "last-step-closes-project",
    "a project closes only when its steps have, then in the same write, and for good",
)
def _(s):
    p, (a, b) = _project(s, 2)
    s.close(a.uid, "first step done")
    raises(lambda: s.close(p.uid, "early"), "close with an open step", InvalidTransition)
    assert s.get(p.uid).status == "open", "closed with a step still open"
    cur = s.get(b.uid)
    s.update(b.uid, cur.version, status="cancelled", result="not needed")
    done = s.get(p.uid)
    assert done.status == "closed", f"every step finished, project is {done.status}"
    assert done.result and done.closed_on, "the closed project carries a result and a date"
    assert not [x for x in s.list(kind="project", status="open") if x.uid == p.uid]
    raises(lambda: s.update(p.uid, done.version, status="open"), "reopen", InvalidTransition)


@SUITE.check(
    "open-task-holds-project-open",
    "a task in a project holds it open: no manual close, no auto-close until it finishes too",
)
def _(s):
    p, (a,) = _project(s, 1)
    t = s.create("task", uniq("Task"), project=p.uid)
    s.close(a.uid, "the only step")
    assert s.get(p.uid).status == "open", "closed with a task of the project still open"
    raises(lambda: s.close(p.uid, "early"), "close with an open task", InvalidTransition)
    s.close(t.uid, "the task too")
    done = s.get(p.uid)
    assert done.status == "closed", f"every step and task finished, project is {done.status}"


@SUITE.check("finish-needs-result", "done or cancelled needs a one-line result; the date is kept")
def _(s):
    t = s.create("task", uniq("Task"))
    raises(lambda: s.close(t.uid, ""), "empty result", InvalidField, ValueError)
    raises(lambda: s.close(t.uid, "a\nb"), "two-line result", InvalidField, ValueError)
    raises(lambda: s.update(t.uid, t.version, status="done"), "done without result", ValueError)
    assert s.get(t.uid).status == "todo", "finished without a result"
    done = s.close(t.uid, "shipped")
    assert done.status == "done" and done.result == "shipped" and done.closed_on, f"{done}"


@SUITE.check(
    "stale-version-conflicts",
    "a stale version fails and changes nothing; every change adds one, a no-op none",
)
def _(s):
    t = s.create("task", uniq("Task"))
    s.update(t.uid, t.version, title="first writer")
    raises(lambda: s.update(t.uid, t.version, title="second writer"), "stale", Conflict)
    raises(lambda: s.link(t.uid, _record(s), "supports", version=t.version), "stale link", Conflict)
    now = s.get(t.uid)
    assert now.title == "first writer" and now.version == 2, f"{now.title} v{now.version}"
    t = s.create("task", uniq("Task"))
    t2 = s.update(t.uid, 1, status="in_progress")
    t3 = s.update(t.uid, 2, assignee="profile:responder")
    t4 = s.link(t.uid, _record(s), "supports")
    t5 = s.update(t.uid, 4, assignee="profile:responder")
    assert [x.version for x in (t2, t3, t4, t5)] == [2, 3, 4, 4], "versions"


@SUITE.check(
    "changes-since-is-complete",
    "every item changed after a cursor is reported at its latest version; no cursor: a snapshot",
)
def _(s):
    p, (a,) = _project(s, 1)
    before = s.create("task", uniq("Untouched"))
    cur = s.changes_since(None).cursor
    t = s.create("task", uniq("Task"))
    s.update(t.uid, 1, status="in_progress")
    s.update(a.uid, 1, assignee="profile:reader")
    s.link(p.uid, _record(s), "supports")
    s.close(a.uid, "done")  # also closes p
    got = s.changes_since(cur)
    latest: dict[str, int] = {}
    for c in got.changes:
        latest[c.uid] = c.version
    want = {x.uid: s.get(x.uid).version for x in (p, a, t)}
    assert {u: latest.get(u) for u in want} == want, f"feed {latest} want {want}"
    assert before.uid not in latest, "an unchanged item was reported"
    assert not s.changes_since(got.cursor).changes, "the feed repeats itself"
    snap = {c.uid: c.version for c in s.changes_since(None).changes}  # no cursor: a snapshot
    want = {x.uid: s.get(x.uid).version for x in (p, a, t, before)}
    assert {u: snap.get(u) for u in want} == want, f"snapshot {snap} want {want}"


@SUITE.check("link-integrity", "links name uids that resolve; unknown relations and self refused")
def _(s):
    t = s.create("task", uniq("Task"))
    raises(lambda: s.link(t.uid, _MISSING, "supports"), "dangling record", InvalidReference)
    raises(lambda: s.link(t.uid, _record(s), "inspires"), "unknown relation", InvalidReference)
    raises(lambda: s.link(t.uid, "SO-001", "supports"), "not a uid", InvalidReference)
    raises(lambda: s.link(t.uid, _MISSING, "blocks"), "dangling item", InvalidReference)
    raises(lambda: s.link(t.uid, t.uid, "precedes"), "self", InvalidReference)
    raises(lambda: s.link(t.uid, _record(s), "blocks"), "a record cannot block", InvalidReference)
    assert s.get(t.uid).links == () and s.get(t.uid).version == 1, "a refused link was stored"
    rec = _record(s, 1)
    linked = s.link(t.uid, rec, "answers")
    assert [(lk.relation, lk.target) for lk in linked.links] == [("answers", rec)]


@SUITE.check(
    "no-cycles-and-parents-resolve",
    "blocks, precedes and parent never form a cycle; a parent is an item of the same project",
)
def _(s):
    a, b, c = (s.create("task", uniq("T")) for _ in range(3))
    s.link(a.uid, b.uid, "precedes")
    s.link(b.uid, c.uid, "precedes")
    raises(lambda: s.link(c.uid, a.uid, "precedes"), "cycle", InvalidReference)
    s.link(a.uid, b.uid, "blocks")
    raises(lambda: s.link(b.uid, a.uid, "blocks"), "2-cycle", InvalidReference)
    p, (a, _b) = _project(s, 2)
    child = s.create("step", uniq("Sub"), project=p.uid, parent=a.uid)
    assert child.parent == a.uid
    raises(lambda: s.create("task", "x", parent=_MISSING), "missing parent", InvalidReference)
    raises(lambda: s.create("task", "x", parent=a.uid), "other project", InvalidReference)
    cur = s.get(a.uid)
    raises(lambda: s.update(a.uid, cur.version, parent=child.uid), "cycle", InvalidReference)


@SUITE.check("blocked-item-cannot-finish", "an item does not finish before what blocks it")
def _(s):
    blocker, blocked = s.create("task", uniq("A")), s.create("task", uniq("B"))
    s.link(blocker.uid, blocked.uid, "blocks")
    raises(lambda: s.close(blocked.uid, "early"), "finish while blocked", InvalidTransition)
    s.close(blocker.uid, "unblocked")
    assert s.close(blocked.uid, "after").status == "done"


@SUITE.check("unlink-removes-link", "unlink removes exactly that link; a missing one is NotFound")
def _(s):
    t = s.create("task", uniq("Task"))
    r1, r2 = _record(s), _record(s, 1)
    s.link(t.uid, r1, "supports")
    s.link(t.uid, r2, "measures")
    after = s.unlink(t.uid, r1, "supports")
    assert [(lk.relation, lk.target) for lk in after.links] == [("measures", r2)]
    raises(lambda: s.unlink(t.uid, r1, "supports"), "unlink twice", NotFound)


@SUITE.check(
    "list-filters-and-fields-kept",
    "kind, status, project, assignee and linked_to filters apply; assignee and due persist",
)
def _(s):
    p, (a, b) = _project(s, 2)
    t = s.create("task", uniq("Task"), assignee="human:example-operator")
    s.update(a.uid, 1, status="blocked")
    rec = _record(s)
    s.link(b.uid, rec, "supports")
    uids = lambda xs: {x.uid for x in xs}  # noqa: E731
    assert uids(s.list(kind="step", project=p.uid)) == {a.uid, b.uid}
    assert a.uid in uids(s.list(status="blocked")) and b.uid not in uids(s.list(status="blocked"))
    assert uids(s.list(assignee="human:example-operator")) == {t.uid}
    assert uids(s.list(linked_to=rec)) == {b.uid}
    order = [x.uid for x in s.list(project=p.uid)]
    assert order == sorted(order), "list is in uid (creation) order"
    t = s.create("task", uniq("Task"), assignee="profile:responder", due="2026-12-01")
    got = s.get(t.uid)
    assert (got.assignee, got.due) == ("profile:responder", "2026-12-01"), f"{got}"
    cleared = s.update(t.uid, 1, assignee=None, due=None)
    assert (cleared.assignee, cleared.due) == (None, None)


@SUITE.check(
    "reopen-follows-project", "a finished step reopens only while its project is open",
    severity="should",
)  # fmt: skip
def _(s):
    _p, (a, _b) = _project(s, 2)
    done = s.close(a.uid, "first")
    back = s.update(a.uid, done.version, status="todo")
    assert back.status == "todo" and back.result is None, f"{back}"


def make_fake():
    return fakes.FakeProjectStore()


MUTANTS = {
    "step-in-closed-project": Mutant(
        fakes.ClosedProjectStepStore, "step-needs-an-open-project", "steps land in closed projects"
    ),
    "never-closes": Mutant(
        fakes.NeverClosesStore, "last-step-closes-project", "finished projects stay open"
    ),
    "reopen-in-closed-project": Mutant(
        fakes.ReopenInClosedProjectStore,
        "step-needs-an-open-project",
        "finished steps reopen in closed projects",
    ),
    "steps-only-close": Mutant(
        fakes.StepsOnlyCloseStore,
        "open-task-holds-project-open",
        "projects close over their open tasks",
    ),
    "duplicate-key": Mutant(
        fakes.DuplicateKeyStore, "create-is-idempotent-by-external-key", "keys create duplicates"
    ),
    "last-writer-wins": Mutant(
        fakes.LastWriterWinsStore, "stale-version-conflicts", "stale updates overwrite"
    ),
    "lossy-feed": Mutant(
        fakes.LossyFeedStore, "changes-since-is-complete", "the feed drops changes"
    ),
    "dangling-links": Mutant(
        fakes.DanglingLinkStore, "link-integrity", "links to uids that resolve to nothing"
    ),
    "resultless-finish": Mutant(
        fakes.ResultlessStore, "finish-needs-result", "items finish without a result"
    ),
    "blocked-finishes": Mutant(
        fakes.BlockedFinishesStore, "blocked-item-cannot-finish", "blocked items finish first"
    ),
}
