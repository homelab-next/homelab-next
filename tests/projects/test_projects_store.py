# SPDX-License-Identifier: Apache-2.0
"""The reference store: Markdown files, the change journal, conflicts, hand-edit checks, uids,
the strategy seam, events and the MOP-only completion reading."""

import datetime as dt
import itertools
from pathlib import Path

import pytest

from conformance.fakes.project_store import RECORDS, FakeProjectStore
from homelabnext.events.envelope import event_problems
from homelabnext.projects import (
    Conflict,
    InvalidField,
    MarkdownBackend,
    ProjectStore,
    UidGenerator,
    derived_uid,
    is_uid,
    markdown_store,
    strategy_records,
)
from homelabnext.projects.events import change_event, change_events
from homelabnext.projects.markdown import parse_item, render_item
from homelabnext.projects.measures import completion_reading
from homelabnext.projects.model import Change
from homelabnext.projects.uid import uid_time

REPO = Path(__file__).resolve().parents[2]
EXAMPLE_STRATEGY = REPO / "examples/strategy"
EPOCH = dt.datetime(2026, 10, 1, tzinfo=dt.UTC)


def clock():
    ticks = itertools.count()
    return lambda: EPOCH + dt.timedelta(milliseconds=next(ticks))


def store(path, **kw):
    return ProjectStore(MarkdownBackend(path), records=lambda: RECORDS, clock=clock(), **kw)


# --- uids -----------------------------------------------------------------------------------------


def test_uids_are_uuidv7_and_monotonic_within_one_millisecond():
    gen = UidGenerator(lambda: EPOCH, randbytes=lambda n: bytes(n))
    uids = [gen() for _ in range(5000)]  # past the 12-bit counter: rolls into the next ms
    assert all(is_uid(u) for u in uids) and uids == sorted(uids) and len(set(uids)) == 5000
    assert uid_time(uids[0]) == EPOCH


def test_derived_uid_is_deterministic_and_dated():
    a = derived_uid("ns", "SO-001", dt.date(2026, 10, 20))
    assert a == derived_uid("ns", "SO-001", dt.date(2026, 10, 20)) and is_uid(a)
    assert a != derived_uid("ns", "SO-002", dt.date(2026, 10, 20))
    assert uid_time(a) == dt.datetime(2026, 10, 20, tzinfo=dt.UTC)
    assert not is_uid("01890000-0000-4000-8000-000000000000")  # a v4
    with pytest.raises(ValueError):
        derived_uid("ns", "x", dt.datetime(2026, 1, 1))  # naive


# --- the Markdown files ----------------------------------------------------------------------------


def test_one_file_per_item_named_by_uid_and_round_trips(tmp_path):
    s = store(tmp_path)
    p = s.create("project", "Edge move", external_key="edge", description="Why we move it.")
    step = s.create("step", "Build the guest", project=p.uid, due="2026-12-01")
    s.link(step.uid, RECORDS[0], "supports")
    files = sorted(f.name for f in tmp_path.glob("*.md"))
    assert files == sorted([f"{p.uid}.md", f"{step.uid}.md"])
    text = (tmp_path / f"{step.uid}.md").read_text()
    assert text.startswith(f"---\nuid: {step.uid}\nkind: step\n")
    assert parse_item(text, "x.md")["links"] == [{"relation": "supports", "target": RECORDS[0]}]
    again = store(tmp_path)
    assert again.get(p.uid).description == "Why we move it." and again.get(step.uid).version == 2


def test_no_lock_file_and_no_journal_until_the_first_write(tmp_path):
    s = store(tmp_path)
    assert s.list() == [] and sorted(tmp_path.iterdir()) == []
    s.create("task", "x")
    assert [p.name for p in tmp_path.iterdir() if p.is_dir()] == [".changes"]
    assert not list(tmp_path.rglob("*lock*"))


def test_a_concurrent_writer_is_a_conflict_and_nothing_is_written(tmp_path):
    a, b = store(tmp_path), store(tmp_path)
    t = a.create("task", "shared")
    a.update(t.uid, 1, title="first writer")
    stale = {**parse_item((tmp_path / f"{t.uid}.md").read_text(), "x"), "title": "second"}
    with pytest.raises(Conflict):
        b.backend.write([(stale, 1)], [])  # read at version 1, the file is at 2
    assert b.get(t.uid).title == "first writer"
    with pytest.raises(Conflict):
        b.backend.write([({**stale, "version": 1}, None)], [])  # a create over an existing file


def test_the_journal_is_append_only_and_its_names_strictly_grow(tmp_path):
    frozen = lambda: EPOCH  # noqa: E731  every write in the same microsecond
    s = ProjectStore(MarkdownBackend(tmp_path), records=lambda: RECORDS, clock=frozen)
    cur = s.changes_since(None).cursor
    t = s.create("task", "t")
    for n in range(3):
        s.update(t.uid, n + 1, title=f"t{n}")
    names = sorted(p.name for p in (tmp_path / ".changes").glob("*.json"))
    assert len(names) == 4 and len({n.split("-", 1)[0] for n in names}) == 4
    got = s.changes_since(cur)
    assert [c.version for c in got.changes] == [1, 2, 3, 4]
    assert s.changes_since(got.cursor).changes == ()
    with pytest.raises(InvalidField):
        s.changes_since("not-a-cursor")


def test_check_reports_every_rule_a_hand_edit_breaks(tmp_path):
    s = store(tmp_path)
    p = s.create("project", "P")
    a = s.create("step", "a", project=p.uid)
    b = s.create("task", "b")
    assert s.check() == []

    def edit(uid, **fields):
        f = tmp_path / f"{uid}.md"
        doc = parse_item(f.read_text(), f.name)
        f.write_text(render_item({**doc, **fields}))

    edit(a.uid, status="done")  # finished without a result; project still open
    edit(b.uid, links=[{"relation": "supports", "target": "01890000-0000-7000-8000-000000000000"}])
    (tmp_path / "notes.md").write_text("not an item\n")
    (tmp_path / "01890000-0000-7000-8000-00000000000f.md").write_text(
        render_item({**parse_item((tmp_path / f"{b.uid}.md").read_text(), "x")})
    )  # a copy under another name
    problems = "\n".join(s.check() + s.backend.problems)
    assert "a finished step needs a result and a date" in problems
    assert "every step is finished, so the project must be closed" in problems
    assert "resolves to no record" in problems
    assert "notes.md: no front-matter" in problems
    assert "the file is named <uid>.md for its uid" in problems


def test_check_reports_cycles_and_orphans_written_by_hand(tmp_path):
    s = store(tmp_path)
    x, y = s.create("task", "x"), s.create("task", "y")
    s.link(x.uid, y.uid, "precedes")
    f = tmp_path / f"{y.uid}.md"
    doc = parse_item(f.read_text(), f.name)
    f.write_text(render_item({**doc, "links": [{"relation": "precedes", "target": x.uid}], "project": x.uid}))  # fmt: skip
    problems = "\n".join(s.check())
    assert "precedes links form a cycle" in problems
    assert "names project" in problems and "which does not exist" in problems


def test_parse_item_refuses_malformed_files():
    for text, why in (
        ("---\nuid: x\n", "not closed"),
        ("---\n- a\n---\n", "not a mapping"),
        ("---\nuid: x\nkind: task\ntitle: t\nstatus: todo\nversion: 0\n---\n", "positive integer"),
        (
            "---\nuid: x\nkind: task\ntitle: t\nstatus: todo\nversion: 1\ncolour: red\n---\n",
            "unknown field",
        ),
        ("---\nuid: x\nuid: y\n---\n", "not YAML"),
        (
            "---\nuid: x\nkind: task\ntitle: t\nstatus: todo\nversion: 1\nlinks: [a]\n---\n",
            "links is a list",
        ),
    ):
        with pytest.raises(ValueError, match=why):
            parse_item(text, "f.md")


# --- the strategy seam ------------------------------------------------------------------------------


def test_the_seam_maps_todays_ids_to_stable_uids_and_edges():
    recs = {r.id: r for r in strategy_records(EXAMPLE_STRATEGY)}
    assert {"SO-001", "OO-001", "TO-001", "TT-001", "CCIR-001", "MOP-001", "RFI-002"} <= set(recs)
    assert all(is_uid(r.uid) for r in recs.values())
    assert recs["TO-001"].parent_uid == recs["OO-001"].uid and recs["SO-001"].parent_uid is None
    assert recs["TO-001"].as_dict()["type"] == "TO"
    assert ("serves", recs["CCIR-001"].uid) in recs["FFIR-001"].links
    assert ("measures", recs["OO-001"].uid) in recs["MOP-001"].links
    assert ("raised_by", recs["PIR-001"].uid) in recs["RFI-002"].links
    again = {r.id: r.uid for r in strategy_records(EXAMPLE_STRATEGY)}
    assert again == {k: r.uid for k, r in recs.items()}  # stable across reads


def test_a_record_that_carries_a_uid_keeps_it(tmp_path):
    import shutil

    lab = tmp_path / "strategy"
    shutil.copytree(EXAMPLE_STRATEGY, lab)
    own = "01923456-7890-7abc-8def-0123456789ab"
    f = lab / "objectives/SO-001.md"
    f.write_text(f.read_text().replace("id: SO-001\n", f"id: SO-001\nuid: {own}\n", 1))
    from homelabnext.projects import strategy as seam

    recs = {r.id: r for r in seam.strategy_records(lab)}
    assert recs["SO-001"].uid == own and recs["OO-001"].parent_uid == own


def test_the_example_projects_link_to_example_records_and_pass_check():
    s = markdown_store(REPO / "examples/projects", strategy=EXAMPLE_STRATEGY, create=False)
    assert s.check() == [] and s.backend.problems == []
    assert {i.kind for i in s.list()} == {"project", "step", "task"}


# --- events -------------------------------------------------------------------------------------------


def test_events_validate_and_dedupe_by_uid_and_version():
    s = FakeProjectStore()
    t = s.create("task", "t")
    s.link(t.uid, RECORDS[0], "supports")
    cs = s.changes_since("0")
    items = {i.uid: i for i in s.list()}
    evs = change_events([*cs.changes, *cs.changes], items=items)
    assert len(evs) == 2 and all(event_problems(e) == [] for e in evs)
    assert "links" not in evs[0]["data"] and evs[1]["data"]["links"][0]["relation"] == "supports"
    assert evs[0]["id"] == change_event(cs.changes[0])["id"]  # a pure function of uid + version


def test_openproject_events_are_keyed_by_work_package_version():
    ch = Change("01890000-0000-7000-8000-000000000001", "task", 3, "updated", "todo", "t", None, "2026-01-01T00:00:03Z", ref="wp:42")  # fmt: skip
    a = change_event(ch, origin="openproject", lock_version=2)
    b = change_event(Change(**{**ch.__dict__, "title": "renamed"}), origin="openproject", lock_version=2)  # fmt: skip
    assert a["id"] == b["id"] and a["source"] == "svc:openproject" and event_problems(a) == []
    with pytest.raises(ValueError):
        change_event(Change(**{**ch.__dict__, "ref": None}), origin="openproject", lock_version=2)


# --- MOP readings -----------------------------------------------------------------------------------


def test_completion_feeds_a_mop_and_never_a_moe():
    recs = {r.id: r for r in strategy_records(EXAMPLE_STRATEGY)}
    objective = recs["OO-001"].uid
    s = ProjectStore(
        FakeProjectStore().backend, records=lambda: [objective], clock=clock()
    )  # links to the real objective uid
    a, b, c = (s.create("task", n) for n in "abc")
    for t in (a, b, c):
        s.link(t.uid, objective, "supports")
    s.close(a.uid, "done")
    s.update(c.uid, 2, status="cancelled", result="dropped")
    reading = completion_reading(s.list(), recs["MOP-001"], now=EPOCH)
    assert reading["value"] == 50.0 and reading["sample"] == 2
    with pytest.raises(ValueError, match="activity_never_moe"):
        completion_reading(s.list(), recs["MOE-001"], now=EPOCH)
    empty = completion_reading([], recs["MOP-001"], now=EPOCH)
    assert "finding" in empty and "value" not in empty
