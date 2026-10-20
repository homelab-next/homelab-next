# SPDX-License-Identifier: Apache-2.0
"""Conflict-free writes: sidecar events, derived fields, the write path and the transition decider."""

import datetime as dt
import hashlib
import pathlib
import shutil
import threading

import pytest
import yaml

from homelabnext.records import Records, RecordsReader
from homelabnext.records.decider import init_tree
from homelabnext.registers import RegisterError, build_all, load_register, records
from homelabnext.registers import events as ev
from homelabnext.registers.__main__ import main as registers_main
from homelabnext.registers.migrate import migrate
from homelabnext.registers.schema import record_digest_of, validate_lessons
from homelabnext.registers.transitions import TransitionDecider
from homelabnext.registers.write import write_event, write_events, write_record
from homelabnext.reviews import load_policy

REPO = pathlib.Path(__file__).resolve().parents[2]
EXAMPLES = REPO / "examples" / "registers"
T0 = dt.datetime(2026, 10, 20, 9, 30, tzinfo=dt.UTC)


def _sha(p: pathlib.Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


@pytest.fixture
def lab(tmp_path):
    """A copy of the example registers with the example review policy beside them."""
    src = tmp_path / "lab" / "registers"
    shutil.copytree(EXAMPLES, src)
    shutil.copy(REPO / "examples/review-policy.yml", src.parent / "review-policy.yml")
    return src


def _review(by, kind, role, digest, date="2026-10-20"):
    return {
        "event": "review",
        "by": by,
        "kind": kind,
        "role": role,
        "date": dt.date.fromisoformat(date),
        "verdict": "pass",
        "digest": digest[:19],
    }


def _files(d: pathlib.Path) -> set[pathlib.Path]:
    return {p for p in d.rglob("*") if p.is_file()}


# --- the event files --------------------------------------------------------------------------


def test_two_review_events_in_the_same_second_never_collide(lab):
    rec = lab / "lessons/LL-005.md"
    digest = record_digest_of(load_register(lab / "lessons")["lessons"][4])
    a = write_event(rec, _review("agent:example-checker", "agent", "check", digest), when=T0)
    b = write_event(rec, _review("agent:example-checker", "agent", "check", digest), when=T0)
    assert a != b
    assert a.name == "20261020T093000Z-review-agent-example-checker.yml"
    assert b.name == "20261020T093000Z-review-agent-example-checker-2.yml"
    assert yaml.safe_load(a.read_text())["digest"] == digest[:19]  # neither overwrote the other
    reviews = load_register(lab / "lessons")["lessons"][4]["reviews"]
    assert len(reviews) == 4 and reviews[-1]["date"] == dt.date(2026, 10, 20)


def test_racing_writers_in_one_second_each_get_their_own_file(tmp_path):
    d = tmp_path / "LL-001.events"
    data = {"event": "recurrence", "by": "agent:example-checker", "date": T0.date(), "note": "x"}
    out, errors = [], []

    def one():
        try:
            out.append(ev.create_event(d, data, when=T0))
        except Exception as ex:  # pragma: no cover - the assertion below reports it
            errors.append(ex)

    threads = [threading.Thread(target=one) for _ in range(12)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors and len(set(out)) == 12
    assert sorted(p.name for p in d.iterdir()) == sorted(p.name for p in out)  # no temp left
    problems: list[str] = []
    assert len(ev.read_events(d, problems)) == 12 and problems == []


def test_editing_the_prose_and_adding_events_never_touch_the_same_file(lab):
    rec = lab / "lessons/LL-001.md"
    entry = dict(load_register(lab / "lessons")["lessons"][0])
    digest = record_digest_of(entry)
    events_before = _files(ev.events_dir(rec))
    # an agent appends a review while a human edits the prose in another editor
    added = write_event(rec, _review("agent:example-checker", "agent", "check", digest), when=T0)
    assert _files(ev.events_dir(rec)) == events_before | {added}
    record_bytes = _sha(rec)
    prose = {k: v for k, v in entry.items() if k not in ("reviews", "recurrences")}
    prose["notes"] = "Re-read after the 2026-10 renewal; nothing changed."
    events_now = {p: _sha(p) for p in _files(ev.events_dir(rec))}
    assert write_record(rec, prose) == rec
    assert _sha(rec) != record_bytes  # the prose changed ...
    assert {p: _sha(p) for p in _files(ev.events_dir(rec))} == events_now  # ... no event did
    after = load_register(lab / "lessons")["lessons"][0]
    assert after["notes"].startswith("Re-read") and len(after["reviews"]) == 3
    assert after["recurrences"] == entry["recurrences"]


def test_event_files_are_checked_by_name_and_schema(lab):
    d = lab / "lessons/LL-005.events"
    good = next(d.iterdir())
    (d / "20261020T093000Z-review-agent-someone-else.yml").write_text(good.read_text())
    with pytest.raises(RegisterError, match="writer part must be 'agent-example-"):
        load_register(lab / "lessons")
    for p in d.glob("*someone-else*"):
        p.unlink()
    (d / "20261020T093000Z-recurrence-agent-example-checker.yml").write_text(
        "event: recurrence\nby: agent:example-checker\ndate: 2026-10-20\n"
    )
    with pytest.raises(RegisterError, match="'note' is a required property"):
        load_register(lab / "lessons")
    for p in d.glob("*recurrence*"):
        p.unlink()
    shutil.copytree(d, lab / "lessons/LL-099.events")
    with pytest.raises(RegisterError, match=r"LL-099\.events: no record file LL-099\.md"):
        load_register(lab / "lessons")


# --- derived fields ---------------------------------------------------------------------------


def test_derived_fields_come_from_events(lab):
    rec = lab / "lessons/LL-001.md"
    before = load_register(lab / "lessons")["lessons"][0]
    assert before["recurrences"] == 1 and "recurrences" not in rec.read_text()
    verified = {
        "event": "verified",
        "by": "agent:example-checker",
        "date": T0.date(),
        "outcome": "pass",
        "result": "exit 0: notAfter is 41 days out",
    }
    write_event(rec, verified, when=T0)
    write_event(rec, {**verified, "outcome": "fail", "date": dt.date(2026, 10, 21)}, when=T0)
    after = load_register(lab / "lessons")["lessons"][0]
    assert after["last_verified"] == T0.date()  # the latest *passing* run
    assert record_digest_of(after) == record_digest_of(before)  # a verification is not content
    build_all(lab, lab.parent / "out")  # so the reviews stay current and the build passes
    # a recurrence is recorded even though it sends the controlled claim back to review
    write_event(
        rec,
        {"event": "recurrence", "by": "agent:example-checker", "date": T0.date(), "note": "again"},
        when=T0,
    )
    again = load_register(lab / "lessons")["lessons"][0]
    assert again["recurrences"] == 2
    with pytest.raises(RegisterError, match="status controlled needs agent check, agent challenge"):
        build_all(lab, lab.parent / "out")
    text = rec.read_text().replace("review_by:", "last_verified: 2026-10-20\nreview_by:")
    rec.write_text(text)
    with pytest.raises(RegisterError, match="`last_verified` is derived"):
        load_register(lab / "lessons")


def test_a_transition_whose_from_is_not_current_is_fatal(lab):
    rec = lab / "lessons/LL-003.md"
    event = {
        "event": "transition",
        "by": "human:example-operator",
        "date": T0.date(),
        "from": "partial",
        "to": "controlled",
        "intent": "decided/completed/2026-10-20-example-checker-x.md",
        "requested_by": "profile:example-checker",
        "reason": "written by hand, against the rules",
    }
    with pytest.raises(RegisterError, match="only by the decider"):
        write_event(rec, event, when=T0)
    ev.create_event(ev.events_dir(rec), event, when=T0)  # bypassing the write path
    with pytest.raises(RegisterError, match="is from partial but the record is open"):
        load_register(lab / "lessons")


# --- the migration --------------------------------------------------------------------------


def _inline_copy(dst: pathlib.Path, kind: str) -> dict:
    """The committed registers written the old way (reviews and recurrences inline), beside the
    invariants their references resolve against; returns ``kind``'s document."""
    for k in ("lessons", "runbooks"):
        (dst.parent / k).mkdir(parents=True, exist_ok=True)
        for e in load_register(EXAMPLES / k)[k]:
            (dst.parent / k / f"{e['id']}.md").write_text(records.render_record(e, k))
    shutil.copy(EXAMPLES / "invariants.yml", dst.parent / "invariants.yml")
    return load_register(EXAMPLES / kind)


@pytest.mark.parametrize("kind", ["lessons", "runbooks"])
def test_the_migration_is_lossless_and_idempotent(tmp_path, kind):
    d = tmp_path / "registers" / kind
    derived = _inline_copy(d, kind)
    before = load_register(d)
    assert before == derived and any("reviews:" in p.read_text() for p in d.glob("*.md"))
    written = migrate(d)
    assert written and load_register(d) == before  # deep-equal, every derived field
    for p in d.glob("*.md"):
        fm = yaml.safe_load(p.read_text().split("---")[1])
        assert "reviews" not in fm and "recurrences" not in fm
    assert migrate(d) == []  # nothing inline is left
    for p in d.glob("*.md"):  # the committed examples are exactly this migration's output
        assert p.read_text() == (EXAMPLES / kind / p.name).read_text()


def test_a_migration_interrupted_after_its_events_finishes_without_duplicates(tmp_path):
    d = tmp_path / "registers" / "lessons"
    before = _inline_copy(d, "lessons")
    rec = d / "LL-002.md"
    _, planned = ev.backfill(
        records.parse_record(rec.read_text(), rec.name, "lessons", []), "lessons"
    )
    for data, when in planned[:4]:  # the crash: some events written, the record not rewritten
        ev.create_event(ev.events_dir(rec), data, when=when)
    migrate(d)
    assert load_register(d) == before


def test_migrate_command_moves_system_page_reviews(tmp_path, capsys):
    pages = tmp_path / "docs" / "systems"
    pages.mkdir(parents=True)
    fixture = REPO / "tests/sop/fixtures/dns.reviewed.md"
    (pages / "dns.md").write_text(fixture.read_text())
    inline = yaml.safe_load(fixture.read_text().split("---")[1])["reviews"]
    assert registers_main(["events", "migrate", str(pages)]) == 0
    assert "reviews" not in yaml.safe_load((pages / "dns.md").read_text().split("---")[1])
    from homelabnext.sop.pages import page_reviews

    fm = yaml.safe_load((pages / "dns.md").read_text().split("---")[1])
    assert page_reviews(pages / "dns.md", fm, []) == inline


# --- the write path -----------------------------------------------------------------------------


def test_write_record_refuses_an_invalid_record_without_writing(lab):
    rec = lab / "lessons/LL-003.md"
    entry = {
        k: v for k, v in load_register(lab / "lessons")["lessons"][2].items() if k != "recurrences"
    }
    before = _sha(rec)
    with pytest.raises(RegisterError, match="root_cause is a person"):
        write_record(rec, {**entry, "root_cause": "operator error during the change window"})
    with pytest.raises(RegisterError, match="related LL-404 is not a live lesson"):
        write_record(rec, {**entry, "related": ["LL-404"]})
    with pytest.raises(RegisterError, match="derived from events"):
        write_record(rec, {**entry, "recurrences": 4})
    new = lab / "lessons/LL-NEW-broken.md"
    with pytest.raises(RegisterError):
        write_record(new, {**entry, "id": "LL-NEW", "symptom": "short"})
    assert _sha(rec) == before and not new.exists()
    assert sorted(p.name for p in (lab / "lessons").glob(".*")) == []  # no temp file left


def test_write_event_refuses_invalid_events_without_writing(lab):
    rec = lab / "lessons/LL-005.md"
    before = _files(ev.events_dir(rec))
    with pytest.raises(RegisterError, match="digest"):
        write_event(
            rec,
            {
                "event": "review",
                "by": "agent:x",
                "kind": "agent",
                "role": "check",
                "date": "2026-10-20",
                "verdict": "pass",
            },
            when=T0,
        )
    with pytest.raises(RegisterError, match="agent identity in a human review"):
        write_event(rec, _review("agent:example-checker", "human", "approve", "sha256:" + "0" * 12))
    with pytest.raises(RegisterError, match="recurrence events belong to a pitfall"):
        write_event(rec, {"event": "recurrence", "by": "agent:x", "date": T0.date(), "note": "n"})
    assert _files(ev.events_dir(rec)) == before


def test_add_command_validates_and_appends(lab, tmp_path, capsys):
    f = tmp_path / "e.yml"
    f.write_text("event: verified\nby: agent:example-checker\ndate: 2026-10-20\noutcome: pass\n")
    assert registers_main(["events", "add", str(lab / "lessons/LL-001.md"), str(f)]) == 1
    assert "'result' is a required property" in capsys.readouterr().err
    f.write_text(f.read_text() + "result: exit 0\n")
    assert registers_main(["events", "add", str(lab / "lessons/LL-001.md"), str(f)]) == 0
    assert "-verified-agent-example-checker" in capsys.readouterr().out


# --- transitions -----------------------------------------------------------------------------------


@pytest.fixture
def inbox(tmp_path):
    root = tmp_path / "records"
    init_tree(root)
    return root


def _intent(inbox, slug, **fields):
    agent = Records(inbox, clock=lambda: T0, agent="example-checker")
    note = {"type": "register-transition", "title": f"Transition {slug}", **fields}
    return agent.submit(note, slug=slug).name


def _give_ll_003_a_control(lab):
    """A human writes the control into the prose; only then may an agent ask for ``partial``."""
    rec = lab / "lessons/LL-003.md"
    entry = load_register(lab / "lessons")["lessons"][2]
    prose = dict(entry)  # as loaded: write_record puts the derived fields back to the base
    prose["preventive_control"] = "A nightly job diffs guest inventory against backup jobs."
    write_record(rec, prose)


def _decider(lab, inbox, policy=None):
    return TransitionDecider(
        lab, inbox, decided_by="human:example-operator", policy=policy, clock=lambda: T0
    )


def _lanes(inbox):
    r = RecordsReader(inbox)
    return {lane: r.list(lane) for lane in ("inbox", "decided/denied", "decided/completed")}


def test_a_transition_the_policy_lets_agents_make_applies_at_once(lab, inbox):
    name = _intent(
        inbox,
        "ll-003-partial",
        record="LL-003",
        **{"from": "open", "to": "partial"},
        reason="a detector exists; the backup gap is still open for new guests",
    )
    _give_ll_003_a_control(lab)
    rec = lab / "lessons/LL-003.md"
    before = _sha(rec)
    [out] = _decider(lab, inbox).decide_all()
    assert out.result == "applied", out
    assert _sha(rec) == before  # the record file is never edited for a status change
    assert load_register(lab / "lessons")["lessons"][2]["status"] == "partial"
    assert _lanes(inbox) == {"inbox": [], "decided/denied": [], "decided/completed": [name]}
    [event] = [e for e in ev.read_events(ev.events_dir(rec), []) if e.kind == "transition"]
    assert event.data["intent"] == f"decided/completed/{name}"
    assert event.data["requested_by"] == "profile:example-checker"


def test_a_runbook_is_superseded_through_an_intent(lab, inbox):
    name = _intent(
        inbox,
        "supersede-rb-001",
        record="RB-001",
        superseded_by="RB-002",
        reason="the proxy renewal is now a step of the generic procedure",
        **{"from": "active", "to": "superseded"},
    )
    out = _decider(lab, inbox).decide(name)
    assert out.result == "applied", out
    rb = load_register(lab / "runbooks")["runbooks"][0]
    assert (
        rb["superseded_by"] == "RB-002"
        and "superseded_by" not in (lab / "runbooks/RB-001.md").read_text().split("---")[1]
    )
    again = _intent(
        inbox,
        "supersede-rb-001-again",
        record="RB-001",
        superseded_by="RB-002",
        reason="a stale copy",
        **{"from": "active", "to": "superseded"},
    )
    assert "RB-001 is superseded" in _decider(lab, inbox).decide(again).reason


@pytest.mark.parametrize("first", ["m17", "m16"])
def test_conflicting_intents_one_applies_the_other_is_denied(lab, inbox, first):
    data = (REPO / "examples/review-policy.yml").read_text()
    free = yaml.safe_load(data)
    free["requirements"]["lesson.pitfall"]["retired"] = []
    from homelabnext.reviews import policy_from

    names = {
        tag: _intent(
            inbox,
            f"retire-ll-001-{tag}",
            record="LL-001",
            retired_by=[ref],
            reason=f"{ref} holds",
            **{"from": "controlled", "to": "retired"},
        )
        for tag, ref in (("m17", "M-17"), ("m16", "M-16"))
    }
    second = "m16" if first == "m17" else "m17"
    d = _decider(lab, inbox, policy_from(free))
    a, b = d.decide(names[first]), d.decide(names[second])
    assert a.result == "applied", a
    assert b.result == "denied" and "`from: controlled` is no longer current" in b.reason
    entry = load_register(lab / "lessons")["lessons"][0]
    assert entry["status"] == "retired" and entry["retired_by"] == [first.replace("m", "M-")]
    assert entry["retired_on"] == T0.date()
    lanes = _lanes(inbox)
    assert lanes["decided/completed"] == [names[first]]
    assert lanes["decided/denied"] == [names[second]]
    side = inbox / "decided/denied" / f"{names[second]}.decision.json"
    assert "no longer current" in side.read_text()


def test_a_retirement_waits_for_a_current_human_approve(lab, inbox):
    name = _intent(
        inbox,
        "retire-ll-001",
        record="LL-001",
        retired_by=["M-17"],
        reason="M-17 holds",
        **{"from": "controlled", "to": "retired"},
    )
    d = _decider(lab, inbox)
    out = d.decide(name)
    assert out.result == "waiting" and "agent check, agent challenge, human approve" in out.reason
    assert _lanes(inbox)["inbox"] == [name]
    rec = lab / "lessons/LL-001.md"
    write_event(rec, _review("agent:example-checker", "agent", "check", out.digest), when=T0)
    write_event(rec, _review("agent:example-challenger", "agent", "challenge", out.digest), when=T0)
    out = d.decide(name)
    assert out.result == "waiting" and out.reason.startswith("needs human approve")
    stale = _review("human:example-operator", "human", "approve", "sha256:" + "ab" * 6)
    write_event(rec, stale, when=T0)  # an approve of other content does not count
    assert d.decide(name).result == "waiting"
    assert load_register(lab / "lessons")["lessons"][0]["status"] == "controlled"
    write_event(rec, _review("human:example-operator", "human", "approve", out.digest), when=T0)
    out = d.decide(name)
    assert out.result == "applied", out
    entry = load_register(lab / "lessons")["lessons"][0]
    assert entry["status"] == "retired" and record_digest_of(entry) == out.digest
    validate_lessons(load_register(lab / "lessons"), load_policy(lab.parent / "review-policy.yml"))
    build_all(lab, lab.parent / "out")


def test_an_invalid_target_is_denied_and_an_applied_one_is_finished_after_a_crash(lab, inbox):
    bad = _intent(
        inbox,
        "retire-ll-001-nowhere",
        record="LL-001",
        retired_by=["M-99"],
        reason="names no mechanism",
        **{"from": "controlled", "to": "retired"},
    )
    out = _decider(lab, inbox).decide(bad)
    assert out.result == "denied" and "M-99 is not a live invariant" in out.reason
    _give_ll_003_a_control(lab)
    name = _intent(
        inbox,
        "ll-003-partial",
        record="LL-003",
        reason="the detector shipped",
        **{"from": "open", "to": "partial"},
    )
    event = {
        "event": "transition",
        "by": "human:example-operator",
        "date": T0.date(),
        "from": "open",
        "to": "partial",
        "intent": f"decided/completed/{name}",
        "requested_by": "profile:example-checker",
        "reason": "the detector shipped",
    }
    write_events(lab / "lessons/LL-003.md", [event], when=T0, _decider=True)  # then: the crash
    out = _decider(lab, inbox).decide(name)
    assert (out.result, out.reason) == ("applied", "already applied")
    assert _lanes(inbox)["decided/completed"] == [name]
    assert load_register(lab / "lessons")["lessons"][2]["status"] == "partial"


def test_decide_command_dry_run_moves_nothing(lab, inbox, capsys):
    _give_ll_003_a_control(lab)
    _intent(
        inbox,
        "ll-003-partial",
        record="LL-003",
        reason="the detector shipped",
        **{"from": "open", "to": "partial"},
    )
    args = ["decide", str(lab), str(inbox), "--as", "human:example-operator", "--dry-run"]
    assert registers_main(args) == 0
    assert "applied  LL-003" in capsys.readouterr().out
    assert len(_lanes(inbox)["inbox"]) == 1
    assert load_register(lab / "lessons")["lessons"][2]["status"] == "open"


def _raw_note(inbox, name, text):
    (inbox / "inbox" / name).write_text(text)
    return name


def test_a_malformed_note_does_not_stop_the_other_intents(lab, inbox, capsys):
    """Regression: pending() schema-validated every inbox note, so one malformed note -- even
    an unrelated proposal -- raised NoteError and the decider decided nothing (and the command
    printed a traceback)."""
    _give_ll_003_a_control(lab)
    good = _intent(
        inbox, "ll-003-partial", record="LL-003", reason="the detector shipped",
        **{"from": "open", "to": "partial"},
    )  # fmt: skip
    _raw_note(inbox, "2026-10-20-example-checker-broken.md", "---\ntype: proposal\n---\n")
    _raw_note(inbox, "2026-10-20-example-checker-junk.md", "no front matter at all\n")
    bad = _raw_note(
        inbox,
        "2026-10-20-example-checker-bad-intent.md",
        "---\ntype: register-transition\ntitle: x\nrecord: LL-001\n---\n",
    )
    outs = {o.note: o for o in _decider(lab, inbox).decide_all()}
    assert set(outs) == {good, bad}
    assert outs[good].result == "applied", outs[good]
    assert outs[bad].result == "invalid" and "fix or withdraw" in outs[bad].reason
    assert bad in _lanes(inbox)["inbox"]
    args = ["decide", str(lab), str(inbox), "--as", "human:example-operator"]
    assert registers_main(args) == 0
    assert "invalid  ?" in capsys.readouterr().out


def test_an_on_key_is_refused_and_retired_on_is_honoured(lab, inbox):
    """Regression: ``on:`` is a YAML 1.1 boolean, so the note's key was True, ``fm.get('on')``
    was None and retired_on silently became the created date.  A boolean key is now a validation
    error naming the pitfall; the field is ``retired_on``."""
    from homelabnext.reviews import policy_from

    free = yaml.safe_load((REPO / "examples/review-policy.yml").read_text())
    free["requirements"]["lesson.pitfall"]["retired"] = []
    d = _decider(lab, inbox, policy_from(free))
    text = (
        "---\ntype: register-transition\ntitle: Retire LL-001\n"
        "requesting_agent: profile:example-checker\ncreated: '2026-10-20T09:30:00Z'\n"
        "record: LL-001\nfrom: controlled\nto: retired\nretired_by: [M-17]\n"
        "on: 2026-10-01\nreason: M-17 holds\n---\n"
    )
    name = _raw_note(inbox, "2026-10-20-example-checker-retire-on.md", text)
    out = d.decide(name)
    assert out.result == "invalid" and "YAML 1.1" in out.reason, out
    assert load_register(lab / "lessons")["lessons"][0]["status"] == "controlled"
    (inbox / "inbox" / name).unlink()
    name = _intent(
        inbox, "retire-ll-001", record="LL-001", retired_by=["M-17"], retired_on="2026-10-01",
        reason="M-17 holds", **{"from": "controlled", "to": "retired"},
    )  # fmt: skip
    assert d.decide(name).result == "applied"
    assert load_register(lab / "lessons")["lessons"][0]["retired_on"] == dt.date(2026, 10, 1)


def test_a_crash_between_approve_and_complete_is_finished(lab, inbox, monkeypatch):
    """Regression: fulfil() moves inbox -> approved -> completed; a crash between the two left
    the intent in decided/approved forever, because recovery looked only in the inbox."""
    from homelabnext.records import decider as movers

    _give_ll_003_a_control(lab)
    name = _intent(
        inbox, "ll-003-partial", record="LL-003", reason="the detector shipped",
        **{"from": "open", "to": "partial"},
    )  # fmt: skip
    real = movers.Decider._move

    def crash(self, note, dest_lane, *a, **kw):
        if dest_lane == movers.COMPLETED:
            raise OSError("power cut")
        return real(self, note, dest_lane, *a, **kw)

    monkeypatch.setattr(movers.Decider, "_move", crash)
    with pytest.raises(OSError):
        _decider(lab, inbox).decide(name)
    monkeypatch.setattr(movers.Decider, "_move", real)
    assert RecordsReader(inbox).list("decided/approved") == [name]
    [out] = _decider(lab, inbox).decide_all()
    assert (out.result, out.reason) == ("applied", "already applied")
    assert _lanes(inbox)["decided/completed"] == [name]
    assert RecordsReader(inbox).list("decided/approved") == []
    assert load_register(lab / "lessons")["lessons"][2]["status"] == "partial"


def test_a_loaded_record_round_trips_through_write_record(lab, inbox):
    """Regression: write_record takes an entry as load_register returns it, but that entry
    carries the derived fields (a transition's status and ``set`` fields, the recurrences
    count), so writing back a transitioned record was refused."""
    _give_ll_003_a_control(lab)
    name = _intent(
        inbox, "ll-003-partial", record="LL-003", reason="the detector shipped",
        **{"from": "open", "to": "partial"},
    )  # fmt: skip
    assert _decider(lab, inbox).decide(name).result == "applied"
    rec = lab / "lessons/LL-003.md"
    base_status = yaml.safe_load(rec.read_text().split("---")[1])["status"]
    entry = load_register(lab / "lessons")["lessons"][2]
    assert entry["status"] == "partial" and "recurrences" in entry
    entry["preventive_control"] = "A nightly job diffs guests against backup jobs, and pages."
    write_record(rec, entry)
    after = load_register(lab / "lessons")["lessons"][2]
    assert after["status"] == "partial" and after["preventive_control"].endswith("and pages.")
    front = yaml.safe_load(rec.read_text().split("---")[1])
    assert front["status"] == base_status and "recurrences" not in front
    entry = dict(after, status="controlled")  # a derived field changed by hand: still refused
    with pytest.raises(RegisterError, match="derived"):
        write_record(rec, entry)
