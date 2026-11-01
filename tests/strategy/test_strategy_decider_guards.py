# SPDX-License-Identifier: Apache-2.0
"""The strategy decider's guards: time decides an expiry, a reused note name is refused before
anything applies, no review policy fails closed, the sweep decides only its own expiries, and
the events write path takes a strategy record (never a rekey)."""

import datetime as dt
import shutil

import pytest
import yaml
from strategy_helpers import NOW, U, clock, rel

from homelabnext.records import Records, RecordsReader
from homelabnext.records.notes import parse_note, render_note
from homelabnext.registers.schema import RegisterError
from homelabnext.strategy import StrategyDecider, load_tree
from homelabnext.strategy.rfis import SWEEP_AGENT, TRANSITION_TYPE, sweep

DECIDER = "human:example-operator"


def decider(lab, records, at=NOW, **kw):
    return StrategyDecider(lab, records, decided_by=DECIDER, clock=clock(at), **kw)


def transition(records, record, frm, to, *, agent="profile:example-checker", at=NOW, slug=None):
    note = {"type": TRANSITION_TYPE, "title": f"Move {record} to {to}", "record": record,
            "from": frm, "to": to, "reason": "Nobody needs this answered any more, it seems."}  # fmt: skip
    return Records(records, clock(at), agent=agent).submit(note, slug=slug)


# --- an expiry is decided by the clock, never by an agent ---------------------------------------


@pytest.mark.parametrize("agent", ["profile:rogue", SWEEP_AGENT])
def test_a_standing_requirement_never_expires_whoever_files_it(lab, records, agent):
    transition(records, U["CCIR-001"], "active", "expired", agent=agent)
    (o,) = decider(lab, records).decide_all()
    assert o.result == "denied" and "expires only once its dated LTIOV has passed" in o.reason
    assert "'standing'" in o.reason and "answer or retire it instead" in o.reason
    assert load_tree(lab).of("requirements")[U["CCIR-001"]]["status"] == "active"


def test_an_rfi_expires_only_after_its_ltiov(lab, records):
    transition(records, U["RFI-001"], "open", "expired")  # LTIOV 2026-11-19, today 2026-10-20
    (o,) = decider(lab, records).decide_all()
    assert o.result == "denied" and "its LTIOV is 2026-11-19, today is 2026-10-20" in o.reason
    late = dt.datetime(2026, 11, 20, tzinfo=dt.UTC)
    transition(records, U["RFI-001"], "open", "expired", at=late, slug="expire-late")
    (o,) = decider(lab, records, at=late).decide_all()
    assert o.result == "applied"  # past it: time decided, whoever asked


# --- a reused note name ------------------------------------------------------------------------


def test_a_reused_intent_name_is_refused_before_anything_is_applied(lab, records):
    n1 = transition(records, U["RFI-001"], "open", "no-find").name
    (o1,) = decider(lab, records).decide_all()
    assert o1.result == "applied"
    # the completed note, put back in the inbox naming another record: past the records API
    fm, body = parse_note((records / "decided/completed" / n1).read_text(encoding="utf-8"))
    fm.update({"record": U["CCIR-001"], "from": "active", "to": "retired"})
    (records / "inbox" / n1).write_text(render_note(fm, body), encoding="utf-8")
    ccir = lab / rel("CCIR-001")
    events_before = sorted(p.name for p in ccir.with_suffix(".events").glob("*.yml"))
    (o2,) = decider(lab, records).decide_all()
    assert o2.result == "denied" and "already in decided/completed" in o2.reason
    assert sorted(p.name for p in ccir.with_suffix(".events").glob("*.yml")) == events_before
    assert load_tree(lab).of("requirements")[U["CCIR-001"]]["status"] == "active"


# --- no review policy: fail closed ------------------------------------------------------------


def test_no_review_policy_fails_closed_unless_waived(lab, records):
    (lab.parent / "review-policy.yml").unlink()
    transition(records, U["PIR-001"], "active", "retired")  # a human approve, with a policy
    with pytest.raises(RegisterError, match=r"no review-policy\.yml in or beside"):
        decider(lab, records).decide_all()
    assert RecordsReader(records).list("inbox")  # nothing decided
    (o,) = decider(lab, records, policy=False).decide_all()  # the explicit opt-out
    assert o.result == "applied"


def test_the_cli_decide_fails_closed_and_takes_a_policy(lab, records, capsys):
    from homelabnext.strategy.cli import main

    policy = lab.parent / "elsewhere.yml"
    shutil.move(lab.parent / "review-policy.yml", policy)
    transition(records, U["PIR-001"], "active", "retired")
    argv = ["decide", str(lab), str(records), "--as", DECIDER]
    assert main(argv, clock=clock()) == 1
    assert "no review-policy.yml" in capsys.readouterr().err
    assert main([*argv, "--policy", str(policy)], clock=clock()) == 0
    assert "waiting" in capsys.readouterr().out  # the human approve the policy names
    assert main(["check", str(lab)], clock=clock()) == 0
    assert "no review tier is checked" in capsys.readouterr().out


# --- the sweep decides only its own expiries ---------------------------------------------------


def test_the_sweep_leaves_other_intents_for_decide(lab, records):
    other = transition(records, U["RFI-002"], "open", "answered")  # RFI-002 is no-find: denied
    late = dt.datetime(2026, 11, 20, tzinfo=dt.UTC)
    filed, out = sweep(lab, records, today=late.date(), decided_by=DECIDER, clock=clock(late))
    assert len(filed) == 1 and [o.record for o in out] == [U["RFI-001"]]
    assert other.name in RecordsReader(records).list("inbox")


# --- the events write path takes a strategy record ---------------------------------------------


def _event_file(tmp_path, event):
    p = tmp_path / "event.yml"
    p.write_text(yaml.safe_dump(event), encoding="utf-8")
    return str(p)


def test_events_add_writes_a_review_of_a_strategy_record(lab, tmp_path, capsys):
    from homelabnext.registers.__main__ import main
    from homelabnext.strategy.records import record_digest

    rec = lab / rel("MOE-005")
    digest = record_digest(load_tree(lab).get(U["MOE-005"]))
    review = {"event": "review", "by": "agent:example-checker", "kind": "agent", "role": "check",
              "date": "2026-10-20", "verdict": "pass", "digest": digest[:19]}  # fmt: skip
    assert main(["events", "add", str(rec), _event_file(tmp_path, review)]) == 0
    assert capsys.readouterr().out.strip().endswith(".yml")
    assert any(r["digest"] == digest[:19] for r in load_tree(lab).get(U["MOE-005"])["reviews"])


@pytest.mark.parametrize(
    ("event", "want"),
    [
        ({"event": "transition", "by": DECIDER, "date": "2026-10-20", "from": "active",
          "to": "retired", "set": {"resolution": "trust me"}, "intent": "decided/completed/x.md",
          "requested_by": "profile:rogue", "reason": "trust me"}, "only by the decider"),
        ({"event": "rekey", "by": "hnx:migrate", "date": "2026-10-20", "from": "sha256:" + "1" * 64,
          "to": "sha256:" + "2" * 64, "reason": "identity rewrite, content unchanged"},
         "only by the uid migration"),
    ],
)  # fmt: skip
def test_events_add_refuses_a_transition_or_rekey_on_a_strategy_record(lab, tmp_path, capsys, event, want):  # fmt: skip
    from homelabnext.registers.__main__ import main

    rec = lab / rel("MOE-005")
    before = sorted(rec.with_suffix(".events").glob("*")) if rec.with_suffix(".events").is_dir() else []  # fmt: skip
    assert main(["events", "add", str(rec), _event_file(tmp_path, event)]) == 1
    assert want in capsys.readouterr().err
    after = sorted(rec.with_suffix(".events").glob("*")) if rec.with_suffix(".events").is_dir() else []  # fmt: skip
    assert after == before
