# SPDX-License-Identifier: Apache-2.0
"""Lesson kinds and lifecycle, review requirements on records, active_only and the review."""

import copy
import datetime as dt
import json
import pathlib
import re
import shutil

import pytest
from register_helpers import U, f

OTHER = "01a15e4e-0000-7000-8000-00000000000f"  # a valid uid no example record has

from homelabnext.registers import RegisterError, build_all, load_register, records
from homelabnext.registers.__main__ import main as registers_main
from homelabnext.registers.due import review
from homelabnext.registers.render import load_sources, render_runbooks
from homelabnext.registers.schema import (
    check_links,
    record_digest_of,
    sync_warnings,
    validate_lessons,
    validate_runbooks,
)
from homelabnext.reviews import load_policy

REPO = pathlib.Path(__file__).resolve().parents[2]
EX = REPO / "examples" / "registers"
POLICY = load_policy(REPO / "examples" / "review-policy.yml")
CRITERIA = {c["id"] for c in load_register(EX / "invariants.yml")["criteria"]}


@pytest.fixture
def ll():
    return load_register(EX / "lessons")


@pytest.fixture
def rb():
    return load_register(EX / "runbooks")


def by_id(doc, kind, code):
    """The example record the code ``LL-001`` named before uids (examples/registers/aliases.yml)."""
    return next(e for e in doc[kind] if e["uid"] == U[code])


def restamp(e, *keep_roles):
    """Re-point the entry's reviews at its current content (what a reviewer would do)."""
    d = record_digest_of(e)
    for r in e.get("reviews") or ():
        r["digest"] = d[:19]


def links(ll, rb):
    check_links(ll["lessons"], rb["runbooks"], CRITERIA, REPO)


def validate_all(ll, rb):
    validate_lessons(ll)
    links(ll, rb)


def test_examples_validate_with_the_policy(ll, rb):
    validate_lessons(ll, POLICY)
    validate_runbooks(rb, POLICY)
    links(ll, rb)
    assert sync_warnings(ll["lessons"], rb["runbooks"]) == []


# --- pitfalls --------------------------------------------------------------------------------


def test_kind_is_required(ll):
    by_id(ll, "lessons", "LL-001").pop("kind")
    with pytest.raises(RegisterError, match="`kind` must be one of"):
        validate_lessons(ll)


def test_retire_without_retired_by_fails(ll):
    e = by_id(ll, "lessons", "LL-002")
    e.pop("retired_by")
    with pytest.raises(RegisterError, match="`retired_by` must be a non-empty list"):
        validate_lessons(ll)
    e["retired_by"] = ["M-17"]
    e.pop("retired_on")
    with pytest.raises(RegisterError, match="needs `retired_on`"):
        validate_lessons(ll)


@pytest.mark.parametrize(
    "ref, needle",
    [
        ("Z-99", "retired_by Z-99 is not a live invariant"),
        ("tests/registers/test_nothing_here.py", "does not exist"),
        ("make:no-such-target", "no such Makefile target"),
        ("be careful", "is not an invariant id"),
    ],
)
def test_retired_by_must_name_a_mechanism_that_exists(ll, rb, ref, needle):
    by_id(ll, "lessons", "LL-002")["retired_by"] = [ref]
    with pytest.raises(RegisterError, match=needle):
        validate_all(ll, rb)


def test_retired_by_accepts_a_make_gate(ll, rb):
    by_id(ll, "lessons", "LL-002")["retired_by"] = ["make:ids-check"]
    validate_lessons(ll)
    links(ll, rb)


def test_retire_without_a_human_approve_fails(ll):
    e = by_id(ll, "lessons", "LL-002")
    e["reviews"] = [r for r in e["reviews"] if r["kind"] != "human"]
    validate_lessons(ll)  # the structure is fine without a policy
    with pytest.raises(RegisterError, match="status retired needs human approve"):
        validate_lessons(ll, POLICY)


def test_editing_a_reviewed_record_drops_its_reviews(ll):
    e = by_id(ll, "lessons", "LL-001")
    e["root_cause"] += " (and nobody asked the client)"
    with pytest.raises(RegisterError, match="needs agent check, agent audit") as ex:
        validate_lessons(ll, POLICY)
    assert f"{len(e['reviews'])} review(s) are of an earlier content" in str(ex.value)
    restamp(e)
    validate_lessons(ll, POLICY)


def test_controlled_pitfall_needs_review_by(ll):
    by_id(ll, "lessons", "LL-001").pop("review_by")
    with pytest.raises(RegisterError, match=r"`review_by` .* is required for status controlled"):
        validate_lessons(ll)


def test_retired_by_only_on_controlled_or_retired(ll):
    by_id(ll, "lessons", "LL-003")["retired_by"] = ["M-17"]
    with pytest.raises(RegisterError, match="belongs on a controlled"):
        validate_lessons(ll)


# --- practices -------------------------------------------------------------------------------


def test_practice_must_name_what_it_applies_to(ll):
    by_id(ll, "lessons", "LL-005").pop("applies_to")
    with pytest.raises(RegisterError, match="`applies_to` must name"):
        validate_lessons(ll)


def test_practice_takes_no_pitfall_fields(ll):
    by_id(ll, "lessons", "LL-005")["root_cause"] = "practices have no root cause at all"
    with pytest.raises(RegisterError, match=r"unknown field.*practice"):
        validate_lessons(ll)


def test_active_practice_needs_review_by(ll):
    by_id(ll, "lessons", "LL-005").pop("review_by")
    with pytest.raises(RegisterError, match="required for status active"):
        validate_lessons(ll)


def test_superseded_practice_needs_superseded_by(ll, rb):
    e = by_id(ll, "lessons", "LL-005")
    e["status"] = "superseded"
    with pytest.raises(RegisterError, match="needs `superseded_by`"):
        validate_lessons(ll)
    e["superseded_by"] = U["LL-003"]  # a pitfall cannot supersede a practice
    validate_lessons(ll)
    with pytest.raises(RegisterError, match=f"superseded_by {U['LL-003']} is not a practice"):
        links(ll, rb)


def test_retired_practice_needs_a_reason(ll):
    e = by_id(ll, "lessons", "LL-005")
    e.update(status="retired", retired_on=dt.date(2026, 10, 19))
    with pytest.raises(RegisterError, match="retired_reason"):
        validate_lessons(ll)


def test_incorporated_without_a_destination_fails(ll):
    by_id(ll, "lessons", "LL-004").pop("incorporated_into")
    with pytest.raises(RegisterError, match="`incorporated_into` must be a non-empty list"):
        validate_lessons(ll)


@pytest.mark.parametrize(
    "dest, needle",
    [
        (OTHER, f"no runbook {OTHER}"),
        (U["RB-002"] + "#9", f"{U['RB-002']} has no step 9"),
        ("RB-002#1", "is a legacy numbered code"),
        ("docs/systems/no-such-service.md", "does not exist"),
        ("docs/notes.md", "is not a runbook"),
    ],
)
def test_incorporated_destination_must_exist(ll, rb, dest, needle):
    by_id(ll, "lessons", "LL-004")["incorporated_into"] = [dest]
    with pytest.raises(RegisterError, match=needle):
        validate_all(ll, rb)


def test_a_system_page_is_a_destination(ll, rb):
    by_id(ll, "lessons", "LL-004")["incorporated_into"] = ["docs/systems/dns.md#use"]
    validate_lessons(ll)
    links(ll, rb)


def test_missing_back_reference_warns(ll, rb):
    by_id(rb, "runbooks", "RB-002")["steps"][0].pop("from_lessons")
    validate_runbooks(rb)
    links(ll, rb)  # not fatal
    (w,) = sync_warnings(ll["lessons"], rb["runbooks"])
    assert "LL 4 is incorporated into RB 2#1 but step 1 of RB 2 does not cite it" in w
    assert f"add `- from_lessons: [[{U['LL-004']}]]`" in w


def test_from_lessons_must_name_a_lesson(ll, rb):
    by_id(rb, "runbooks", "RB-002")["steps"][1]["from_lessons"] = [OTHER]
    with pytest.raises(RegisterError, match=f"from_lessons {OTHER} is not a lesson"):
        links(ll, rb)


def test_from_lessons_round_trips_as_wiki_links():
    text = (EX / "runbooks" / f("RB-002")).read_text()
    assert f"   - from_lessons: [[{U['LL-004']}]]" in text
    step = by_id(load_register(EX / "runbooks"), "runbooks", "RB-002")["steps"][0]
    assert step["from_lessons"] == [U["LL-004"]]


# --- a runbook's own `lessons:` (runbook schema 2.1): lesson uids, resolved like every link -----


def test_runbook_lessons_are_lesson_uids_that_resolve(ll, rb):
    by_id(rb, "runbooks", "RB-001")["lessons"] = [U["LL-001"], U["LL-005"]]
    validate_runbooks(rb)
    links(ll, rb)
    html, _ = render_runbooks(rb, ll["lessons"])
    assert f'<a href="lessons.html#{U["LL-001"]}">LL 1</a>' in html  # the register page


@pytest.mark.parametrize(
    ("value", "needle"),
    [
        (["LL-001"], "'LL-001' is a legacy numbered code"),
        (["lesson-1"], "'lesson-1' is not a uid"),
        ([], "`lessons` must be a non-empty list of lesson uids"),
        ("LL-001", "`lessons` must be a non-empty list of lesson uids"),
        ([U["LL-001"], U["LL-001"]], "`lessons` repeats a uid"),
    ],
)
def test_runbook_lessons_refuse_codes_and_malformed_lists(rb, value, needle):
    by_id(rb, "runbooks", "RB-001")["lessons"] = value
    with pytest.raises(RegisterError, match=re.escape(needle)):
        validate_runbooks(rb)


@pytest.mark.parametrize("target", [OTHER, "RB-002"], ids=["unknown-uid", "a-runbook"])
def test_runbook_lessons_must_name_a_lesson(ll, rb, target):
    ref = U.get(target, target)
    by_id(rb, "runbooks", "RB-001")["lessons"] = [ref]
    with pytest.raises(RegisterError, match=f"lessons {ref} is not a lesson"):
        links(ll, rb)


def test_runbook_lessons_are_written_as_links_and_round_trip():
    entry = dict(by_id(load_register(EX / "runbooks"), "runbooks", "RB-001"))
    entry["lessons"] = [U["LL-005"]]
    text = records.render_record(entry, "runbooks")
    assert f"lessons: [{U['LL-005']}]" in text
    assert f"- Lessons: [[{U['LL-005']}]]" in text  # the generated Links block
    problems: list[str] = []
    back = records.parse_record(text, f("RB-001"), "runbooks", problems)
    assert problems == [] and back["lessons"] == [U["LL-005"]]


# --- active_only and the archive ---------------------------------------------------------------


def test_active_only_skips_graduated_and_replaced_records(tmp_path):
    assert [e["uid"] for e in load_register(EX / "lessons", active_only=True)["lessons"]] == [
        U["LL-001"],
        U["LL-003"],
        U["LL-005"],
    ]
    d = tmp_path / "runbooks"
    shutil.copytree(EX / "runbooks", d)
    p = d / f("RB-001")
    p.write_text(p.read_text().replace("review_by:", f"superseded_by: {U['RB-002']}\nreview_by:"))
    active = [e["uid"] for e in load_register(d, active_only=True)["runbooks"]]
    assert active == [U["RB-002"], U["RB-003"]]
    assert len(load_register(d)["runbooks"]) == 3


def test_archived_records_say_so_in_their_links_block():
    assert (
        "- Archive: retired on 2026-10-19 by `M-17`" in (EX / "lessons" / f("LL-002")).read_text()
    )
    assert (
        f"- Archive: incorporated into [[{U['RB-002']}]] step 1"
        in (EX / "lessons" / f("LL-004")).read_text()
    )
    entry = {"uid": OTHER, "kind": "practice", "status": "superseded", "superseded_by": U["LL-005"]}
    assert f"- Archive: superseded by [[{U['LL-005']}]]" in records.links_block(entry)


# --- the review ------------------------------------------------------------------------------


@pytest.fixture
def src(tmp_path):
    d = tmp_path / "src"
    for kind in ("lessons", "runbooks"):
        shutil.copytree(EX / kind, d / kind)
    for name in ("invariants.yml", "invariants.results.json"):
        shutil.copy(EX / name, d / name)
    shutil.copy(REPO / "examples/review-policy.yml", d / "review-policy.yml")
    return d


def test_review_lists_what_is_due_deterministically(src):
    rep = review(load_sources(src), dt.date(2026, 10, 19))
    assert rep.items == [] and rep.warnings == []
    rep = review(load_sources(src), dt.date(2027, 5, 1))
    assert rep.lines() == [
        "lesson review as of 2027-05-01: 5 item(s) due",
        "incorporate:",
        "  LL 5 Measure certificate lifetime from the client side: candidate runbook(s) "
        "RB 1; incorporated will need human approve",
        "update:",
        "  RB 1 Renew the internal proxy certificate: review_by 2027-04-19; methods and "
        "tools change",
        "  RB 2 Add a lesson to the register: review_by 2027-04-19; methods and tools change",
        "keep:",
        "  LL 1 Certificate expired on the internal reverse proxy: review_by 2027-01-17; name "
        "the mechanism that would retire it in `retired_by`, or bump review_by",
        "  LL 3 Backup job silently skipped a new guest: review_by 2027-01-17; still unsolved: "
        "work it, or bump review_by",
    ]
    assert review(load_sources(src), dt.date(2027, 5, 1)).as_json() == rep.as_json()


def test_review_suggests_retiring_a_pitfall_its_invariant_already_proves(src):
    p = src / "lessons" / f("LL-001")
    p.write_text(
        p.read_text().replace("review_by: 2027-01-17", "review_by: 2027-01-17\nretired_by: [M-03]")
    )
    rep = review(load_sources(src), dt.date(2026, 10, 19))
    (retire,) = [d for d in rep.items if d.action == "retire"]
    assert retire.id == U["LL-001"] and retire.label == "LL 1"
    assert "retired_by M-03 already holds" in retire.reason
    assert "retired will need" in retire.reason
    # the edit made the reviews stale: the record needs re-review, by tier
    (again,) = [d for d in rep.items if d.action == "review"]
    assert again.id == U["LL-001"] and again.reason == "missing agent check, agent audit"


def test_review_suggests_superseding_by_a_newer_practice(src):
    old = src / "lessons" / f("LL-005")
    new = copy.copy(old.read_text())
    newer = "01a15e4f-0000-7000-8000-000000000001"  # created after every example record
    new = new.replace(U["LL-005"], newer).replace("date: 2026-10-19", "date: 2026-12-01")
    (src / "lessons" / f"{newer}.md").write_text(new)
    rep = review(load_sources(src), dt.date(2027, 5, 1))
    (sup,) = [d for d in rep.items if d.action == "supersede"]
    assert (sup.id, sup.label, sup.refs) == (U["LL-005"], "LL 5", (newer,))
    assert sup.reason.startswith("newer practice LL 6 covers")  # named by its number


def test_review_cli_warns_by_default_and_fails_strict(src, capsys):
    args = ["review", str(src), "--today", "2027-05-01"]
    assert registers_main(args) == 0
    assert "keep:" in capsys.readouterr().out
    assert registers_main([*args, "--strict"]) == 1
    capsys.readouterr()
    assert registers_main([*args, "--json"]) == 0
    doc = json.loads(capsys.readouterr().out)
    assert [d["id"] for d in doc["due"]["keep"]] == [U["LL-001"], U["LL-003"]]
    assert [d["label"] for d in doc["due"]["keep"]] == ["LL 1", "LL 3"]
    assert registers_main(["review", str(src), "--today", "2026-10-19", "--strict"]) == 0


def test_build_enforces_the_policy_beside_the_registers(src, tmp_path):
    build_all(src, tmp_path / "ok")
    p = src / "lessons" / f("LL-004")
    p.write_text(p.read_text().replace("never append", "rarely append"))
    with pytest.raises(RegisterError, match=f"LL 4 {U['LL-004']}: status incorporated needs"):
        build_all(src, tmp_path / "bad")
