# SPDX-License-Identifier: Apache-2.0
"""RFIs from gaps: raised through the records inbox and decided, triaged, closed by an answer
or a no-find, or expired by the LTIOV sweep at an injected date."""

import datetime as dt

import pytest
from strategy_helpers import NOW, clock

from homelabnext.records import Records
from homelabnext.strategy import StrategyDecider, gaps, grade_all, load_doctrine, load_tree
from homelabnext.strategy.rfis import RAISE_TYPE, TRANSITION_TYPE, raise_intents, sweep

DECIDER = "human:example-operator"


def decider(lab, records, at=NOW):
    return StrategyDecider(lab, records, decided_by=DECIDER, clock=clock(at))


def file(records, note, at=NOW, agent="profile:example-checker"):
    return Records(records, clock(at), agent=agent).submit(note)


def current_gaps(lab, records=None):
    tree = load_tree(lab)
    return gaps(tree, grade_all(tree, load_doctrine(lab), NOW), NOW.date(), records)


def test_gaps_are_triaged_and_what_has_an_open_rfi_is_left_out(lab):
    found = {g.raised_by: g for g in current_gaps(lab)}
    # MOE-001 is not measurable but RFI-001 is open for it; MOE-005 has none: collection
    # and every requirement supports a red objective (SO-001 and SO-002 roll up red): unmet
    assert set(found) == {"MOE-005", "CCIR-001", "FFIR-001", "PIR-001"}
    assert found["MOE-005"].triage == "collection" and "no denominator" in found["MOE-005"].why
    assert found["PIR-001"].triage == "production" and "SO-002 (red)" in found["PIR-001"].why


def test_a_red_measure_is_a_production_gap(lab):
    tree = load_tree(lab)
    grades = grade_all(tree, load_doctrine(lab), NOW)
    grades["MOE-006"].state, grades["MOE-006"].value = "red", 0.0
    g = next(x for x in gaps(tree, grades, NOW.date()) if x.raised_by == "MOE-006")
    assert g.triage == "production" and g.question.startswith("Why is MOE-006")


def test_raise_files_intents_and_the_decider_creates_the_rfis(lab, records):
    paths = raise_intents(current_gaps(lab, records), records, agent="profile:example-checker", clock=clock())  # fmt: skip
    assert len(paths) == 4 and all(p.parent.name == "inbox" for p in paths)
    assert current_gaps(lab, records) == []  # pending intents count as covered
    out = decider(lab, records).decide_all()
    assert [o.result for o in out] == ["applied"] * 4, [o.line() for o in out]
    tree = load_tree(lab)
    new = {k: r for k, r in tree.of("rfis").items() if k.startswith("RFI-NEW")}
    moe5 = next(r for r in new.values() if r["raised_by"] == "MOE-005")
    assert moe5["status"] == "open" and moe5["triage"] == "collection"
    assert moe5["ltiov"] == dt.date(2026, 11, 19)  # the doctrine's 30 days
    assert moe5["author"] == "profile:example-checker" and moe5["intent"].startswith("decided/completed/")  # fmt: skip
    assert len(list((records / "decided/completed").glob("*.md"))) == 4
    assert current_gaps(lab, records) == []


def test_a_second_rfi_for_the_same_gap_is_denied(lab, records):
    note = {"type": RAISE_TYPE, "title": "Coverage scope", "raised_by": "MOE-001",
            "question": "Which monitors cover the core services?", "triage": "collection"}  # fmt: skip
    file(records, note)
    (o,) = decider(lab, records).decide_all()
    assert o.result == "denied" and "RFI-001 is already open for MOE-001" in o.reason


def test_an_rfi_for_a_record_that_does_not_exist_is_denied(lab, records):
    note = {"type": RAISE_TYPE, "title": "Nothing", "raised_by": "MOP-099",
            "question": "Which monitors cover the core services?", "triage": "production",
            "ltiov": "2026-10-27"}  # fmt: skip
    file(records, note)
    (o,) = decider(lab, records).decide_all()
    assert o.result == "denied" and "not an active measure or requirement" in o.reason


def close(records, record, to, reason="Searched every proxy log of the window; nothing found.", frm="open"):  # fmt: skip
    note = {"type": TRANSITION_TYPE, "title": f"Close {record}", "record": record,
            "from": frm, "to": to, "reason": reason}  # fmt: skip
    return file(records, note)


def test_a_no_find_is_a_valid_closed_outcome(lab, records):
    close(records, "RFI-001", "no-find")
    (o,) = decider(lab, records).decide_all()
    assert o.result == "applied" and o.reason == "open -> no-find"
    r = load_tree(lab).of("rfis")["RFI-001"]
    assert r["status"] == "no-find" and r["resolution"].startswith("Searched every proxy log")
    from homelabnext.graph.query import INACTIVE_STATUSES

    assert "no-find" in INACTIVE_STATUSES


@pytest.mark.parametrize(
    ("record", "frm", "to", "want"),
    [
        ("RFI-002", "open", "answered", "`from: open` is no longer current: RFI-002 is no-find"),
        ("RFI-001", "open", "achieved", "RFI-001 goes from open to answered, expired, no-find, not achieved"),
        ("CCIR-001", "active", "no-find", "goes from active to answered, expired, retired"),
        ("RFI-404", "open", "answered", "no record RFI-404 in rfis/"),
    ],
)  # fmt: skip
def test_a_transition_outside_the_lifecycle_is_denied(lab, records, record, frm, to, want):
    close(records, record, to, frm=frm)
    (o,) = decider(lab, records).decide_all()
    assert o.result == "denied" and want in o.reason, o.line()


def test_answering_a_requirement_waits_for_its_review(lab, records):
    close(records, "CCIR-001", "answered", reason="Every core service has had a monitor up for a month.", frm="active")  # fmt: skip
    (o,) = decider(lab, records).decide_all()
    assert o.result == "waiting" and "needs agent check review(s)" in o.reason
    assert len(list((records / "inbox").glob("*.md"))) == 1  # it stays in the inbox
    from homelabnext.strategy.records import write_events

    review = {"event": "review", "by": "agent:example-checker", "kind": "agent", "role": "check",
              "date": NOW.date(), "verdict": "pass", "digest": o.digest[:19]}  # fmt: skip
    write_events(lab, {lab / "requirements/CCIR-001.md": [(review, NOW)]})
    (o,) = decider(lab, records).decide_all()
    assert o.result == "applied"
    assert load_tree(lab).of("requirements")["CCIR-001"]["status"] == "answered"


def test_the_ltiov_sweep_expires_what_is_past_its_ltiov(lab, records):
    early = dt.datetime(2026, 11, 19, tzinfo=dt.UTC)
    filed, out, skipped = sweep(lab, records, today=early.date(), decided_by=DECIDER, clock=clock(early))  # fmt: skip
    assert (filed, out, skipped) == ([], [], [])  # RFI-001's LTIOV is that very day
    late = early + dt.timedelta(days=1)
    filed, out, _ = sweep(lab, records, today=late.date(), decided_by=DECIDER, clock=clock(late))
    assert len(filed) == 1 and [o.result for o in out] == ["applied"]
    r = load_tree(lab).of("rfis")["RFI-001"]
    assert r["status"] == "expired" and r["resolution"] == "LTIOV 2026-11-19 passed on 2026-11-20 without an answer"  # fmt: skip
    assert sweep(lab, records, today=late.date(), decided_by=DECIDER, clock=clock(late))[0] == []


def test_the_sweep_skips_an_unnumbered_rfi(lab, records):
    raise_intents(current_gaps(lab, records)[:1], records, agent="profile:example-checker", clock=clock())  # fmt: skip
    decider(lab, records).decide_all()
    late = dt.datetime(2026, 12, 31, tzinfo=dt.UTC)
    filed, _, skipped = sweep(
        lab, records, today=late.date(), decided_by=DECIDER, clock=clock(late)
    )
    assert len(filed) == 1 and len(skipped) == 1 and skipped[0].startswith("RFI-NEW-")


def test_a_crash_between_the_record_and_the_move_is_finished(lab, records):
    note = {"type": RAISE_TYPE, "title": "Coverage scope", "raised_by": "MOE-005",
            "question": "Which techniques are in scope for the lab?", "triage": "collection"}  # fmt: skip
    p = file(records, note)
    d = decider(lab, records)
    d.movers.fulfil = lambda *a, **k: (_ for _ in ()).throw(OSError("crash"))  # type: ignore[method-assign]
    (o,) = d.decide_all()
    assert o.result == "error" and p.is_file()
    (o,) = decider(lab, records).decide_all()  # the RFI exists: finish, do not raise twice
    assert (o.result, o.reason) == ("applied", "already raised")
    assert len([k for k in load_tree(lab).of("rfis") if k.startswith("RFI-NEW")]) == 1


def test_a_hand_written_transition_event_is_refused(lab):
    from homelabnext.registers.schema import RegisterError
    from homelabnext.strategy.records import write_events

    ev = {"event": "transition", "by": DECIDER, "date": NOW.date(), "from": "open", "to": "answered",
          "set": {"resolution": "trust me"}, "intent": "decided/completed/x.md",
          "requested_by": "profile:example-checker", "reason": "trust me"}  # fmt: skip
    with pytest.raises(RegisterError, match="written only by the decider"):
        write_events(lab, {lab / "rfis/RFI-001.md": [(ev, NOW)]})
