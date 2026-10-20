# SPDX-License-Identifier: Apache-2.0
import json
import re
import shutil

import pytest
import yaml

from homelabnext.registers import (
    RegisterError,
    build_all,
    load_register,
    render_invariants,
    render_lessons,
    render_runbooks,
    validate_lessons,
)
from homelabnext.registers.__main__ import main as registers_main


def test_example_registers_render_html_and_json(examples, tmp_path):
    written = build_all(examples, tmp_path)
    assert {p.name for p in written} == {
        f"{n}.{x}" for n in ("lessons", "runbooks", "invariants") for x in ("html", "json")
    }
    data = json.loads((tmp_path / "lessons.json").read_text())
    assert data["count"] == 3 and data["by_status"] == {"open": 1, "partial": 1, "controlled": 1}
    rb = json.loads((tmp_path / "runbooks.json").read_text())
    rb1 = next(r for r in rb["runbooks"] if r["id"] == "RB-001")
    assert rb1["related_lessons"] == ["LL-001"]  # joined on shared `systems`


def test_html_is_self_contained(examples, tmp_path):
    build_all(examples, tmp_path)
    for p in tmp_path.glob("*.html"):
        t = p.read_text()
        assert t.startswith("<!doctype html>")
        assert not re.search(r"<script|<link|<img|@import|url\(|src=|https?://", t), p.name


def test_output_is_escaped(lessons):
    lessons["lessons"][0]["title"] = "<script>alert(1)</script> title"
    html, _ = render_lessons(lessons)
    assert "<script>alert" not in html and "&lt;script&gt;" in html


def test_rebuild_is_idempotent(examples, tmp_path):
    build_all(examples, tmp_path)
    mt = {p.name: p.stat().st_mtime_ns for p in tmp_path.iterdir()}
    build_all(examples, tmp_path)
    assert mt == {p.name: p.stat().st_mtime_ns for p in tmp_path.iterdir()}


@pytest.mark.parametrize(
    "mutate, needle",
    [
        (lambda l: l.pop("root_cause"), "root_cause"),
        (lambda l: l.update(root_cause="short"), "root_cause"),
        (
            lambda l: l.update(root_cause="The operator was not careful, plain human error."),
            "person",
        ),
        (lambda l: l.pop("preventive_control"), "preventive_control"),
        (
            lambda l: l.update(preventive_control="Everyone should be careful next time"),
            "exhortation",
        ),
        (lambda l: l.pop("verification"), "verification"),
        (lambda l: l["verification"].pop("expected"), "expected"),
        (lambda l: l["verification"].update(observable="manual inspection of it"), "falsifiable"),
        (lambda l: l.pop("contributing_factor"), "contributing_factor"),
        (lambda l: l.update(status="solved"), "status"),
        (lambda l: l.update(id="LL-7"), "id must look like"),
        (lambda l: l.update(date="yesterday"), "date"),
        (lambda l: l.update(systems=[]), "systems"),
        (lambda l: l.update(recurrences=-1), "recurrences"),
        (lambda l: l.update(surprise=1), "unknown field"),
    ],
)
def test_lesson_defects_are_fatal(lessons, mutate, needle):
    mutate(lessons["lessons"][0])
    with pytest.raises(RegisterError) as ei:
        render_lessons(lessons)
    assert needle in str(ei.value)


def test_open_lesson_without_control_needs_reason(lessons):
    entry = lessons["lessons"][2]
    assert entry["status"] == "open" and "preventive_control" not in entry
    validate_lessons(lessons)  # honest open entry is accepted
    del entry["open_reason"]
    with pytest.raises(RegisterError, match="open_reason"):
        validate_lessons(lessons)


def test_all_problems_reported_together(lessons):
    lessons["lessons"][0].pop("root_cause")
    lessons["lessons"][1].pop("symptom")
    with pytest.raises(RegisterError) as ei:
        validate_lessons(lessons)
    assert len(ei.value.problems) == 2


def test_duplicate_id_is_fatal(lessons):
    lessons["lessons"].append(dict(lessons["lessons"][0]))
    with pytest.raises(RegisterError, match="duplicate id LL-001"):
        validate_lessons(lessons)


def test_runbook_step_without_verify_is_fatal(examples):
    rb = load_register(examples / "runbooks")
    del rb["runbooks"][0]["steps"][1]["verify"]
    with pytest.raises(RegisterError, match="step 2: every step needs its own `verify`"):
        render_runbooks(rb)


def test_invariants_render_with_live_results(examples):
    inv = yaml.safe_load((examples / "invariants.yml").read_text())
    green = {
        "last_run": "2026-01-01",
        "results": {
            c["id"]: {"status": "pass", "evidence": "ok"}
            for c in inv["criteria"]
            if c["evidence"] in ("auto", "plugin")
        },
    }
    html, doc = render_invariants(inv, green)
    assert doc["verdict"] == "ALL INVARIANTS HOLD" and "ALL INVARIANTS HOLD" in html
    red = json.loads(json.dumps(green))
    red["results"]["Q-09"] = {"status": "fail", "evidence": "LICENSE missing"}
    html, doc = render_invariants(inv, red)
    assert doc["verdict"].startswith("1 red") and "LICENSE missing" in html
    _, doc = render_invariants(inv, None)  # no results: untested counts against
    assert doc["verdict"] != "ALL INVARIANTS HOLD"


@pytest.mark.parametrize(
    "mutate, needle",
    [
        (lambda c: c.pop("remediation"), "remediation"),
        (lambda c: c.update(evidence="sometimes"), "evidence"),
        (lambda c: c.update(id="Z-01"), "not declared"),
        (lambda c: c.update(expect_regex="("), "expect_regex"),
        (lambda c: c.pop("observable"), "observable"),
    ],
)
def test_invariant_defects_are_fatal(examples, mutate, needle):
    inv = yaml.safe_load((examples / "invariants.yml").read_text())
    mutate(inv["criteria"][0])
    with pytest.raises(RegisterError, match=needle):
        render_invariants(inv)


def test_build_is_atomic_when_any_register_is_invalid(examples, tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    for n in ("lessons", "runbooks"):
        shutil.copytree(examples / n, src / n)
    (src / "invariants.yml").write_text((examples / "invariants.yml").read_text())
    bad = yaml.safe_load((src / "invariants.yml").read_text())
    del bad["criteria"][0]["remediation"]
    (src / "invariants.yml").write_text(yaml.safe_dump(bad))
    out = tmp_path / "out"
    with pytest.raises(RegisterError):
        build_all(src, out)
    assert not out.exists()


def test_cli_exit_codes(examples, tmp_path, capsys):
    assert registers_main(["build", str(examples), str(tmp_path / "o")]) == 0
    src = tmp_path / "src"
    src.mkdir()
    (src / "lessons.yml").write_text("lessons:\n- id: LL-001\n  title: broken entry here\n")
    assert registers_main(["build", str(src), str(tmp_path / "o2")]) == 1
    assert "FATAL" in capsys.readouterr().err


# --- retired ids: tombstones for ids that were wrong, validated and rendered ---------------------


def test_example_tombstones_render_with_their_replacement(examples, tmp_path):
    build_all(examples, tmp_path)
    doc = json.loads((tmp_path / "invariants.json").read_text())
    assert doc["retired"]["F-02"]["replaced_by"] == "L-07"
    assert {c["id"] for c in doc["criteria"]}.isdisjoint(doc["retired"])
    html = (tmp_path / "invariants.html").read_text()
    assert '<article id="F-02">' in html and '<a href="#L-07">L-07</a>' in html


@pytest.mark.parametrize(
    "tomb, needle",
    [
        ({"Q-09": {"reason": "reused while still live"}}, "also a live entry"),
        ({"F-77": {"reason": "points at nothing real", "replaced_by": "F-99"}}, "not a live"),
        ({"F-77": {"replaced_by": "Q-09"}}, "reason"),
        ({"F-77": {"reason": "a field nobody reads", "when": "x"}}, "unknown field"),
        ({"F-NEW": {"reason": "never allocated, never cited"}}, "only an allocated id"),
        ({"F-77": "just a string"}, "must be a mapping"),
        (["F-77"], "`retired` must be a mapping"),
    ],
)
def test_bad_tombstones_are_fatal(examples, tomb, needle):
    inv = yaml.safe_load((examples / "invariants.yml").read_text())
    inv["retired"] = tomb
    with pytest.raises(RegisterError, match=re.escape(needle)):
        render_invariants(inv)


def test_lessons_and_runbooks_accept_tombstones(lessons):
    lessons["retired"] = {
        "LL-099": {"reason": "merged into LL-001 on review", "replaced_by": "LL-001"}
    }
    assert validate_lessons(lessons)
    lessons["retired"] = {"LL-001": {"reason": "cannot be both retired and live"}}
    with pytest.raises(RegisterError, match="also a live entry"):
        validate_lessons(lessons)
