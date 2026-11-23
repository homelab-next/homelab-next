# SPDX-License-Identifier: Apache-2.0
"""The cutover ledger: load, derive state from events, check, gate, render (ADR-0043)."""

import datetime as dt
import json

import yaml

from homelabnext.cutover import check_ledger, load_ledger, render_json, render_markdown
from homelabnext.cutover.cli import main
from homelabnext.cutover.model import ahead_of_proof, plane_gate
from homelabnext.registers import events as ev

TODAY = dt.date(2026, 11, 22)
A = "01a15e4e-758c-7311-82ff-6357fd41e8c9"
B = "01a15e4e-758c-7312-93c9-0445ca755d11"
C = "01a15e4e-758c-7313-a3c9-0445ca755d12"


def row(uid, **kw):
    doc = {
        "uid": uid,
        "type": "cutover",
        "title": f"Row {uid[-2:]}",
        "kind": "service",
        "old": [f"vm:{uid[-2:]}"],
        "new": "module:x",
        "disposition": "replace",
        "rollback_days": 14,
    }
    doc.update(kw)
    return doc


def write(root, doc, transitions=()):
    p = root / f"{doc['uid']}.md"
    p.write_text(
        "---\n" + yaml.safe_dump(doc, sort_keys=False) + "---\n\nprose\n", encoding="utf-8"
    )
    for i, (frm, to) in enumerate(transitions):
        d = ev.events_dir(p)
        d.mkdir(exist_ok=True)
        data = {
            "event": "transition",
            "by": "agent:test",
            "date": f"2026-11-2{i}",
            "from": frm,
            "to": to,
            "intent": "lab/cutover/x.md",
            "requested_by": "profile:test",
            "reason": "test",
        }
        (d / f"2026112{i}T000000Z-transition-agent-test.yml").write_text(yaml.safe_dump(data))


GOOD = {"data_verified": {"status": "pass"}, "consumers_repointed": {"status": "pass"}}


def test_state_is_derived_from_events(tmp_path):
    write(tmp_path, row(A), [("old", "new-shadow"), ("new-shadow", "new-primary")])
    led = load_ledger(tmp_path)
    assert led.rows[A].state == "new-primary"
    # carry/replace in new-primary without its checks is ahead of its proof: a warning, not a defect
    assert check_ledger(led, TODAY) == []
    assert any("data_verified is pending" in p for p in ahead_of_proof(led))
    assert main(["check", str(tmp_path)]) == 0
    assert main(["check", str(tmp_path), "--strict"]) == 1


def test_clean_ledger(tmp_path):
    write(tmp_path, row(A, checks=GOOD), [("old", "new-shadow"), ("new-shadow", "new-primary")])
    write(tmp_path, row(B, disposition="undecided", new=None))
    assert check_ledger(load_ledger(tmp_path), TODAY) == []


def test_stale_from_and_illegal_transition(tmp_path):
    write(tmp_path, row(A), [("new-shadow", "new-primary")])
    probs = check_ledger(load_ledger(tmp_path), TODAY)
    assert any("transition from 'new-shadow' but the row is 'old'" in p for p in probs)
    write(tmp_path, row(B), [("old", "new-primary")])
    assert any("not an allowed transition" in p for p in check_ledger(load_ledger(tmp_path), TODAY))


def test_double_claimed_old_name(tmp_path):
    write(tmp_path, row(A, old=["vm:same"]))
    write(tmp_path, row(B, old=["vm:same"]))
    assert any("claimed by two rows" in p for p in check_ledger(load_ledger(tmp_path), TODAY))


def test_requires_dangling_unmet_and_cycle(tmp_path):
    write(
        tmp_path,
        row(A, requires=[B], checks=GOOD),
        [("old", "new-shadow"), ("new-shadow", "new-primary")],
    )
    write(tmp_path, row(B, requires=[A]))
    probs = check_ledger(load_ledger(tmp_path), TODAY)
    assert any("required row" in p for p in probs)
    assert any("cycle" in p for p in probs)
    write(tmp_path, row(C, requires=["01a15e4e-0000-7000-8000-00000000000f"]))
    assert any("not a row" in p for p in check_ledger(load_ledger(tmp_path), TODAY))


def test_schema_and_filename(tmp_path):
    write(tmp_path, row(A, new=None))  # replace without a successor
    (tmp_path / f"{B}.md").write_text(yaml.safe_dump(row(C)).join(["---\n", "---\n"]))
    probs = check_ledger(load_ledger(tmp_path), TODAY)
    assert any("is not the file name" in p for p in probs)
    assert any(f"{A}.md" in p for p in probs)


def test_gate_none_yet_blocks_primary(tmp_path):
    write(
        tmp_path,
        row(A, gate="none-yet", checks=GOOD),
        [("old", "new-shadow"), ("new-shadow", "new-primary")],
    )
    assert any("gate none-yet" in p for p in ahead_of_proof(load_ledger(tmp_path)))


def test_plane_gate(tmp_path):
    write(
        tmp_path,
        row(A, plane="soc", checks=GOOD),
        [("old", "new-shadow"), ("new-shadow", "new-primary")],
    )
    write(tmp_path, row(B, plane="soc", disposition="undecided", new=None))
    led = load_ledger(tmp_path)
    fails = plane_gate(led, "soc", TODAY)
    assert len(fails) == 1 and B in fails[0]
    assert plane_gate(led, "nope", TODAY)  # an empty plane measures nothing: fails
    write(tmp_path, row(B, plane="soc", disposition="undecided", new=None), [])
    assert main(["gate", str(tmp_path), "--plane", "soc", "--today", "2026-11-22"]) == 1
    (tmp_path / f"{B}.md").unlink()
    assert main(["gate", str(tmp_path), "--plane", "soc", "--today", "2026-11-22"]) == 0


def test_soaking_drop_is_not_archive_ready(tmp_path):
    drop = row(
        A,
        disposition="drop",
        new=None,
        soak_ends="2026-11-29",
        decision={"by": "human:op", "date": "2026-11-21", "cite": "decision list item 4"},
    )
    write(tmp_path, drop, [("old", "old-retired")])
    led = load_ledger(tmp_path)
    assert check_ledger(led, TODAY) == []
    assert render_json(led, TODAY)["rows"][0]["display_state"] == "old-retired (soaking)"
    assert main(["gate", str(tmp_path), "--archive-gate", "--today", "2026-11-22"]) == 1
    assert main(["gate", str(tmp_path), "--archive-gate", "--today", "2026-11-30"]) == 0


def test_close_only_for_drop_or_retire(tmp_path):
    write(tmp_path, row(A, checks=GOOD), [("old", "old-retired")])
    assert any(
        "close is only for drop or retire" in p for p in check_ledger(load_ledger(tmp_path), TODAY)
    )


def test_render_and_cli(tmp_path, capsys):
    write(tmp_path, row(A, plane="edge", checks=GOOD), [("old", "new-shadow")])
    led = load_ledger(tmp_path)
    rep = render_json(led, TODAY)
    assert rep["schema"] == "homelabnext.cutover.report/1" and rep["counts"]["new-shadow"] == 1
    assert "| edge |" in render_markdown(led, TODAY)
    assert main(["render", str(tmp_path), "--format", "json"]) == 0
    assert json.loads(capsys.readouterr().out)["rows"][0]["uid"] == A
    assert main(["check", str(tmp_path)]) == 0
    assert main(["check", str(tmp_path / "missing")]) == 1
    assert main(["gate", str(tmp_path)]) == 2


def test_cli_uses_the_injected_clock_when_no_today_is_given(tmp_path):
    write(tmp_path, row(A, disposition="undecided", new=None))
    argv = ["gate", str(tmp_path), "--archive-gate"]
    assert main(argv, clock=lambda: dt.date(2026, 11, 22)) == 1
    (tmp_path / f"{A}.md").unlink()
    assert main(argv, clock=lambda: dt.date(2026, 11, 30)) == 0
