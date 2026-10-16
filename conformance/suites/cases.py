# SPDX-License-Identifier: Apache-2.0
"""``cases``: alert triage and case lifecycle - every disposition has a reason."""

from __future__ import annotations

from conformance.fakes.case_store import FakeCaseStore, NoReasonCaseStore
from conformance.protocols.cases import CaseClosed, InvalidTransition, NotFound
from homelabnext.conform.core import Mutant, Suite

from ._util import raises, uniq

SUITE = Suite(
    "cases",
    "alerts, dismissal with a reason, promotion to cases, notes and the status machine",
    "conformance.protocols.cases:CaseStore",
)


def _alert(s, **kw):
    return s.create_alert("sensor-a", uniq("Alert"), kw.pop("severity", "medium"), **kw)


@SUITE.check("severity-validated", "an unknown severity is refused")
def _(s):
    raises(lambda: s.create_alert("sensor-a", "t", "catastrophic"), "bad severity", ValueError)


@SUITE.check(
    "dedup-key-collapses-open-alerts", "same dedup_key while 'new' bumps count, not a new alert"
)
def _(s):
    key = uniq("dk")
    a = _alert(s, dedup_key=key)
    b = _alert(s, dedup_key=key)
    assert b.id == a.id, "a duplicate created a second alert"
    assert b.count == 2, f"count is {b.count}"


@SUITE.check("promote-creates-linked-case", "promotion creates an open case and links both ways")
def _(s):
    a = _alert(s)
    case = s.promote(a.id)
    assert case.status == "open" and a.id in case.alert_ids, f"case {case}"
    after = s.get_alert(a.id)
    assert after.status == "promoted" and after.case_id == case.id, f"alert {after}"


@SUITE.check("promote-is-idempotent", "promoting twice returns the same case")
def _(s):
    a = _alert(s)
    assert s.promote(a.id).id == s.promote(a.id).id
    assert len([x for x in s.list_alerts("promoted") if x.id == a.id]) == 1


@SUITE.check(
    "dismiss-requires-reason", "dismissing without a reason is refused and changes nothing"
)
def _(s):
    a = _alert(s)
    for bad in ("", "   "):
        raises(lambda r=bad: s.dismiss(a.id, r), "reasonless dismissal", ValueError)
    assert s.get_alert(a.id).status == "new", "alert was dismissed without a reason"
    done = s.dismiss(a.id, "benign scanner")
    assert done.status == "dismissed" and done.reason == "benign scanner"


@SUITE.check("dismissed-cannot-be-promoted", "a dismissed alert stays dismissed")
def _(s):
    a = _alert(s)
    s.dismiss(a.id, "false positive")
    raises(lambda: s.promote(a.id), "promote dismissed", InvalidTransition)


@SUITE.check("notes-append-in-order", "notes are kept oldest first and never rewritten")
def _(s):
    case = s.promote(_alert(s).id)
    s.add_note(case.id, "analyst-a", "first")
    s.add_note(case.id, "analyst-b", "second")
    notes = s.get_case(case.id).notes
    assert notes == (("analyst-a", "first"), ("analyst-b", "second")), f"notes {notes}"


@SUITE.check(
    "illegal-transitions-rejected", "the status machine is open -> in_progress -> closed -> open"
)
def _(s):
    case = s.promote(_alert(s).id)
    raises(
        lambda: s.set_status(case.id, "reopened"), "unknown status", InvalidTransition, ValueError
    )
    s.set_status(case.id, "closed", resolution="done")
    raises(lambda: s.set_status(case.id, "in_progress"), "closed -> in_progress", InvalidTransition)


@SUITE.check("close-requires-resolution", "closing needs a non-empty resolution")
def _(s):
    case = s.promote(_alert(s).id)
    raises(lambda: s.set_status(case.id, "closed"), "close without resolution", ValueError)
    assert s.get_case(case.id).status == "open"
    closed = s.set_status(case.id, "closed", resolution="resolved: scanner")
    assert closed.resolution == "resolved: scanner"


@SUITE.check(
    "closed-case-rejects-notes-until-reopened", "no notes on a closed case; reopening allows them"
)
def _(s):
    case = s.promote(_alert(s).id)
    s.set_status(case.id, "closed", resolution="done")
    raises(lambda: s.add_note(case.id, "a", "late"), "note on closed case", CaseClosed)
    s.set_status(case.id, "open")
    s.add_note(case.id, "a", "after reopen")
    assert len(s.get_case(case.id).notes) == 1


@SUITE.check("unknown-ids-raise-not-found", "missing alerts and cases raise NotFound")
def _(s):
    raises(lambda: s.get_alert("alert-missing"), "missing alert", NotFound)
    raises(lambda: s.get_case("case-missing"), "missing case", NotFound)
    raises(lambda: s.promote("alert-missing"), "promote missing", NotFound)


@SUITE.check("list-filters-by-status", "list_alerts(status) returns only that status")
def _(s):
    a, b = _alert(s), _alert(s)
    assert a.id != b.id, "two alerts share an id"
    s.dismiss(b.id, "noise")
    new_ids = {x.id for x in s.list_alerts("new")}
    dis_ids = {x.id for x in s.list_alerts("dismissed")}
    assert a.id in new_ids and b.id not in new_ids
    assert b.id in dis_ids and a.id not in dis_ids


def make_fake():
    return FakeCaseStore()


MUTANTS = {
    "dismiss-without-reason": Mutant(
        NoReasonCaseStore, "dismiss-requires-reason", "alerts can be dismissed with no reason"
    ),
}
