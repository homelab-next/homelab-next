# SPDX-License-Identifier: Apache-2.0
"""R-04: a risky action without an approval of its exact payload digest does not run.

The table drives an executor through every approval shape - none, bound, payload altered after
approval, another request's approval, denied, unlisted approver, self-approval, expired, replayed -
and the reference :class:`BrokerExecutor` must answer each one as the table says.  Three mutant
executors (one ignores approvals, one checks only that an approval exists, one is a runner that
re-binds the presented approval to whatever request it is about to send) must each be caught,
both by the table and by the validator's ``approval-binding`` rule on the shipped phishing pack.
"""

import copy

import pytest
from wf_support import manifest, pack, rules, step

from homelabnext import broker
from homelabnext.workflows import BrokerExecutor, Outcome, run_fixture

NOW = "2026-01-01T09:05:00Z"
ACTOR = "profile:workflow-soc"


def _request(action="dns.block-domains", rid="block-0001", **params):
    req = {
        "request_id": rid,
        "action": action,
        "actor": ACTOR,
        "target": "svc:dns",
        "params": params or {"domains": ["login.example.org"], "ttl_hours": 72},
        "created": "2026-01-01T09:00:00Z",
    }
    req["digest"] = broker.request_digest(req)
    return req


def _approval(req, **over):
    a = {
        "approval_id": "apr-0001",
        "request_id": req["request_id"],
        "request_digest": req["digest"],
        "decision": "approved",
        "approver": {"issuer": "sso", "subject": "approver-one"},
        "approved_at": "2026-01-01T09:03:00Z",
    }
    a.update(over)
    return a


def _altered(req):
    out = copy.deepcopy(req)
    out["params"]["domains"].append("pay-verify.example.net")
    out["digest"] = broker.request_digest(out)
    return out


# name -> (request sent, approval presented, expected result, expected reason)
def _cases():
    r = _request()
    other = _request(rid="block-0002")
    return {
        "no-approval-is-held": (r, None, "held", "approval-required"),
        "bound-approval-executes": (r, _approval(r), "executed", "approved"),
        "payload-altered-after-approval": (
            _altered(r),
            _approval(r),
            "denied",
            "approval-digest-mismatch",
        ),
        "approval-of-another-request": (r, _approval(other), "denied", "approval-digest-mismatch"),
        "denied-approval": (r, _approval(r, decision="denied"), "denied", "approval-denied"),
        "approver-not-allowlisted": (
            r,
            _approval(r, approver={"issuer": "sso", "subject": "someone-else"}),
            "denied",
            "approval-approver-not-allowed",
        ),
        "self-approval": (
            r,
            _approval(r, approver={"issuer": "sso", "subject": "workflow-soc"}),
            "denied",
            "approval-self-approved",
        ),
        "expired-approval": (
            r,
            _approval(r, approved_at="2026-01-01T09:00:00Z", expires_at="2026-01-01T09:01:00Z"),
            "denied",
            "approval-expired",
        ),
        "non-risky-action-needs-none": (
            _request(action="case.open", rid="case-0001", alert_id="ALT-0001"),
            None,
            "executed",
            "allowed",
        ),
    }


def table_failures(factory) -> list[str]:
    """Every row the executor built by ``factory`` answers differently from the table."""
    out = []
    for name, (req, appr, result, reason) in _cases().items():
        ex = factory(manifest(), now=NOW)
        got = ex.execute(req, appr)
        if (got.result, got.reason) != (result, reason):
            out.append(f"{name}: got {got.result}/{got.reason}, expected {result}/{reason}")
    # replay: one approval allows exactly one request
    r = _request()
    ex = factory(manifest(), now=NOW)
    first, second = ex.execute(r, _approval(r)), ex.execute(r, _approval(r))
    if (first.result, second.result) != ("executed", "denied"):
        out.append(f"replay: got {first.result} then {second.result}, expected executed, denied")
    return out


# ---------------------------------------------------------------- mutants
class SkipApprovalExecutor:
    """Runs anything the manifest lists: never looks at approvals."""

    def __init__(self, manifest, *, now):
        self.manifest = manifest

    def execute(self, request, approval):
        listed = any(a["action"] == request["action"] for a in self.manifest["actions"])
        return Outcome("executed", "allowed") if listed else Outcome("denied", "default-deny")


class PresenceOnlyExecutor(BrokerExecutor):
    """Asks for an approval on risky actions but accepts any approved one, whatever it bound."""

    def execute(self, request, approval):
        if approval is not None and approval["decision"] == "approved":
            approval = {**approval, "request_digest": request["digest"]}
            approval["request_id"] = request["request_id"]
        return super().execute(request, approval)


class RebindingRunnerExecutor(BrokerExecutor):
    """A runner that 'helpfully' re-binds the presented approval to the request it sends - the
    approval check is still called, but it no longer checks anything."""

    def execute(self, request, approval):
        if approval is not None:
            approval = {**approval, "request_digest": request["digest"]}
        return super().execute(request, approval)


MUTANTS = [SkipApprovalExecutor, PresenceOnlyExecutor, RebindingRunnerExecutor]


# ---------------------------------------------------------------- the tests
def test_reference_executor_matches_the_table():
    assert table_failures(BrokerExecutor) == []


@pytest.mark.parametrize("mutant", MUTANTS, ids=lambda m: m.__name__)
def test_table_catches_each_mutant(mutant):
    failures = table_failures(mutant)
    assert failures, f"{mutant.__name__} passed the R-04 table"
    assert any(f.startswith(("no-approval", "payload-altered")) for f in failures)


@pytest.mark.parametrize("mutant", MUTANTS, ids=lambda m: m.__name__)
def test_validator_catches_each_mutant(mutant):
    """The same mutants plugged into the offline validator fail the shipped phishing pack."""
    found = rules(pack("phishing-report"), executor_factory=mutant)
    assert "approval-binding" in found
    assert rules(pack("phishing-report")) == set()


def test_executor_runs_handler_only_on_enforced_allow():
    r = _request()
    ex = BrokerExecutor(manifest(), now=NOW)
    ex.execute(r, None)
    ex.execute(_altered(r), _approval(r))
    assert ex.ran == []
    ex.execute(r, _approval(r))
    assert [x["request_id"] for x in ex.ran] == ["block-0001"]


def test_shadow_manifest_runs_nothing():
    m = manifest()
    m["mode"] = "shadow"
    r = _request()
    ex = BrokerExecutor(m, now=NOW)
    assert ex.execute(r, _approval(r)).result == "shadow"
    assert ex.ran == []


def test_runner_payload_altered_after_approval_is_denied():
    """End to end through the runner: the shipped approval, the block list changed afterwards."""
    doc = pack("phishing-report")
    fx = doc["fixtures"][0]

    def tamper(step_, req):
        if step_["id"] == "block":
            req = {**req, "params": {**req["params"], "domains": ["login.example.org"]}}
        return req

    calls = {c.step: c for c in run_fixture(doc, fx, manifest=manifest(), tamper=tamper).calls}
    assert (calls["block"].result, calls["block"].reason) == ("denied", "approval-digest-mismatch")
    calls = {c.step: c for c in run_fixture(doc, fx, manifest=manifest()).calls}
    assert calls["block"].result == "executed"


def test_risky_action_never_executed_in_a_fixture_fails():
    doc = pack("phishing-report")
    doc["fixtures"] = [f for f in doc["fixtures"] if f["name"] != "phishing-blocked-with-approval"]
    assert rules(doc) == {"risky-untested"}


def test_fixture_expecting_execution_without_approval_fails():
    doc = pack("phishing-report")
    held = next(f for f in doc["fixtures"] if f["name"] == "phishing-held-without-approval")
    held["expect"]["calls"][1].update(result="executed", reason="approved")
    assert "round-trip" in rules(doc)


def test_privileged_action_needs_a_grant_and_approval():
    doc = pack("phishing-report")
    step(doc, "block")["action"] = "host.isolate"
    assert "grant" in rules(doc)  # the workflow actor's grant stops at execute
