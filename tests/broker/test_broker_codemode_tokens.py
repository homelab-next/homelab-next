# SPDX-License-Identifier: Apache-2.0
"""Code Mode capability tokens in the reference broker (ADR-0031, CM-5a): issued only for a
running ``codemode.execute`` and only to a runner, narrowed to the actor's grants, held and
counted server side across processes, paused by a submit, never stored or echoed, and carried
over the socket by the runner and sandbox peers of manifest 1.7."""

from __future__ import annotations

import json
import os
import shutil
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from conformance.protocols.broker import CODEMODE_EXECUTE, BrokerError, Denied, InvalidArguments
from homelabnext.agent.schemas import schema_errors
from homelabnext.broker.execute import file_digest
from homelabnext.broker.server import PeerMap, handle_request
from homelabnext.broker.service import BrokerService, validate_manifest
from homelabnext.conform.runner import mutation_runs, run_capability

ROOT = Path(__file__).resolve().parents[2]
EXAMPLE = ROOT / "examples" / "broker" / "manifest.yml"
AGENT = "profile:triage"
RUNNER = "svc:codemode-runner"
T0 = datetime(2026, 1, 15, 10, 0, tzinfo=UTC)
#: a well-formed secret no token has
UNKNOWN = "hnxcmt_" + "z" * 43


class Clock:
    def __init__(self) -> None:
        self.t = T0

    def __call__(self) -> datetime:
        return self.t

    def advance(self, seconds: float) -> None:
        self.t += timedelta(seconds=seconds)


def _svc(tmp_path, manifest=None, *, clock=None, state="state"):
    """The example manifest (dev identity), plus in-process ``echo.*`` commands for the agent."""
    if manifest is None:
        svc = BrokerService.from_manifest(
            EXAMPLE,
            tmp_path / state,
            data_root=tmp_path / "data",
            clock=clock or Clock(),
            resolve_secret={"DEMO_API_TOKEN": "fake-demo-token-4b1d"}.__getitem__,
        )
    else:
        svc = BrokerService(
            tmp_path / state, manifest, data_root=tmp_path / "data", clock=clock or Clock()
        )
    from conformance.protocols.broker import ArgSpec

    for name in ("echo.one", "echo.two"):
        svc.register(name, lambda **kw: {"echo": kw["text"]}, {"text": ArgSpec("str")})
    svc.allow(AGENT, [CODEMODE_EXECUTE, "echo.one", "echo.two"])
    return svc


def _execute(svc, program, *, actor=AGENT, eid="exec-0001", code="x = 1", resume=False, **budget):
    """Run ``program(request)`` as ``codemode.execute``'s in-process runner; return its value."""
    out = {}

    def handler(request):
        try:
            out["value"] = program(request)
        except Exception as exc:  # the broker contains a handler's error: hand it back here
            out["raised"] = exc
        return {"status": "ok"}

    svc._runners[RUNNER] = handler  # re-registering per call: one runner per test service
    params = {"execution_id": eid, "language": "python", "code": code}
    if budget:
        params["budget"] = budget
    if resume:
        params["resume"] = True
    svc.call(actor, CODEMODE_EXECUTE, params)
    if "raised" in out:
        raise out["raised"]
    return out["value"]


def _issue(svc, req, actions=("echo.one",), **kw):
    kw.setdefault("sandbox_id", "sandbox-01")
    return svc.issue_token(RUNNER, req["request_id"], actions=list(actions), **kw)


def _reason(fn):
    try:
        fn()
    except BrokerError as exc:
        return getattr(exc, "reason", "") or type(exc).__name__
    return None


# -- the conformance suite ------------------------------------------------------------------------


def test_reference_service_passes_the_token_suite():
    run = run_capability("broker-tokens", "broker-reference", ROOT)
    assert run.error is None and run.too_few is None
    assert [r.status for r in run.results] == ["pass"] * len(run.results), [
        r.evidence for r in run.results
    ]


def test_the_token_suite_catches_every_mutant():
    runs = mutation_runs("broker-tokens", ROOT)
    assert len(runs) == 14 and all(m.detected for m in runs), [m.name for m in runs]


# -- issue --------------------------------------------------------------------------------------


def test_a_token_is_issued_only_to_a_runner_and_only_while_its_execute_runs(tmp_path):
    svc = _svc(tmp_path)
    reqs = []
    stranger = _execute(
        svc,
        lambda req: (
            reqs.append(req)
            or _reason(
                lambda: svc.issue_token(
                    AGENT, req["request_id"], sandbox_id="sandbox-01", actions=["echo.one"]
                )
            )
        ),
    )
    assert stranger == "not-a-codemode-runner"
    after = _reason(lambda: _issue(svc, reqs[0]))
    assert after == "execution-not-in-flight", "a finished codemode.execute was issued a token"
    unknown = _reason(
        lambda: svc.issue_token(RUNNER, "req-nothing", sandbox_id="s", actions=["echo.one"])
    )
    assert unknown == "execution-not-in-flight"


def test_the_claims_are_the_requests_and_validate(tmp_path):
    svc = _svc(tmp_path)
    req, tok = _execute(
        svc,
        lambda req: (req, _issue(svc, req, ["echo.one", "service.status"])),
        code="y = 2",
        wall_s=20,
        max_calls=7,
    )
    c = tok.claims
    assert schema_errors("codemode", "token", dict(c)) == []
    assert (c["actor"], c["request_id"], c["execution_id"]) == (
        AGENT,
        req["request_id"],
        "exec-0001",
    )
    assert c["max_calls"] == 7, "max_calls is the request's budget when the runner names none"
    issued = datetime.fromisoformat(c["issued_at"].replace("Z", "+00:00"))
    expires = datetime.fromisoformat(c["expires_at"].replace("Z", "+00:00"))
    assert (expires - issued).total_seconds() == 20 + 10, "wall budget plus the default margin"
    assert tok.secret.startswith("hnxcmt_") and len(tok.secret) > 40


@pytest.mark.parametrize(
    ("kw", "reason"),
    [
        ({"actions": ["echo.one", "memory.write"]}, None),
        ({"actions": ["service.status", "nope.nothing"]}, "token-action-not-admitted"),
        ({"actions": ["echo.one", "echo.one"]}, "token-action-not-admitted"),
        ({"actions": [CODEMODE_EXECUTE]}, "token-action-codemode"),
        ({"max_calls": 51}, "token-max-calls-exceeded"),
        ({"ttl_s": 71}, "token-ttl-exceeded"),
        ({"ttl_s": 70}, None),
        ({"max_calls": 0}, "invalid-params"),
        ({"sandbox_id": "Not A Slug"}, "invalid-params"),
    ],
)
def test_what_a_token_may_carry(tmp_path, kw, reason):
    svc = _svc(tmp_path)
    assert _execute(svc, lambda req: _reason(lambda: _issue(svc, req, **kw))) == reason


def test_a_reader_profiles_token_cannot_reach_a_write(tmp_path):
    svc = _svc(tmp_path)
    svc.allow("profile:reader", [CODEMODE_EXECUTE])
    got = _execute(
        svc,
        lambda req: _reason(lambda: _issue(svc, req, ["service.restart"])),
        actor="profile:reader",
    )
    assert got == "token-action-not-admitted", "a token widened the reader's grant"


def test_the_manifest_caps_calls_lifetime_and_live_tokens(tmp_path):
    manifest = {
        "manifest_id": "cm",
        "default": "deny",
        "mode": "enforce",
        "actions": [],
        "grants": [],
        "codemode": {
            "max_calls": 3,
            "ttl_margin_s": 0,
            "default_wall_s": 5,
            "max_live_tokens_per_actor": 1,
            "runners": [{"uid": 3001, "service": RUNNER}],
        },
    }
    assert schema_errors("broker", "manifest", manifest) == []
    svc = _svc(tmp_path, manifest)
    svc.register_runner(RUNNER, lambda req: None)

    def program(req):
        refused = [
            _reason(lambda: _issue(svc, req, max_calls=4)),
            _reason(lambda: _issue(svc, req, ttl_s=6)),
        ]
        tok = _issue(svc, req)
        nested = _reason(lambda: _execute(svc, lambda r: _issue(svc, r), eid="exec-0002"))
        return refused, tok, nested

    refused, tok, nested = _execute(svc, program)
    assert refused == ["token-max-calls-exceeded", "token-ttl-exceeded"]
    assert tok.claims["max_calls"] == 3
    assert nested == "too-many-live-tokens", "a second live token for the actor was issued"


def _pause(svc, eid="exec-0001", *, actor=AGENT, code="x = 1", **budget):
    """A first run of ``eid`` that ends paused on a submitted ``echo.one``: (token, answer)."""

    def program(req):
        tok = _issue(svc, req)
        return tok, svc.token_submit(tok.secret, "echo.one", {"text": "later"})

    return _execute(svc, program, actor=actor, eid=eid, code=code, **budget)


def test_one_token_per_run_and_resume_rules(tmp_path):
    svc = _svc(tmp_path)

    def first(req):
        tok = _issue(svc, req)
        return tok, _reason(lambda: _issue(svc, req))

    _tok, again = _execute(svc, first, eid="exec-done", code="a = 1")
    assert again == "request-has-token"
    fresh = _reason(lambda: _execute(svc, lambda r: _issue(svc, r), eid="exec-done"))
    assert fresh == "execution-exists"
    finished = _reason(
        lambda: _execute(svc, lambda r: _issue(svc, r), eid="exec-done", code="a = 1", resume=True)
    )
    assert finished == "execution-not-resumable", "a finished execution resumed"
    paused, _ = _pause(svc, code="a = 1")
    assert (
        _reason(lambda: _execute(svc, lambda r: _issue(svc, r), eid="exec-none", resume=True))
        == "execution-not-resumable"
    )
    new = _execute(svc, lambda r: _issue(svc, r), code="a = 1", resume=True)
    assert new.claims["token_id"] != paused.claims["token_id"]


def test_execution_ids_are_each_actors_own(tmp_path):
    svc = _svc(tmp_path)
    svc.allow("profile:other", [CODEMODE_EXECUTE, "echo.one"])
    _pause(svc, code="a = 1")  # triage's exec-0001, paused
    foreign = _reason(
        lambda: _execute(
            svc, lambda r: _issue(svc, r), actor="profile:other", code="a = 1", resume=True
        )
    )
    assert foreign == "execution-not-resumable", "another actor resumed the execution"
    theirs = _execute(svc, lambda r: _issue(svc, r), actor="profile:other", code="b = 2")
    assert theirs.claims["execution_id"] == "exec-0001", "the same id was blocked for another actor"


def test_a_resume_carries_what_is_left_of_the_cap(tmp_path):
    svc = _svc(tmp_path)

    def program(req):
        tok = _issue(svc, req)
        svc.token_call(tok.secret, "echo.one", {"text": "1"})
        svc.token_call(tok.secret, "echo.one", {"text": "2"})
        return svc.token_submit(tok.secret, "echo.one", {"text": "3"})

    _execute(svc, program, max_calls=4)
    resumed = _execute(svc, lambda r: _issue(svc, r), resume=True)
    assert resumed.claims["max_calls"] == 1
    # spent: nothing left, so a further resume of a re-paused execution is refused at issue
    ex = svc.tokens.execution(svc.tokens.token(resumed.claims["token_id"])["exec_key"])
    assert svc.tokens.calls_of(ex) == 3 and ex["max_calls"] == 4


# -- enforcement --------------------------------------------------------------------------------


def test_the_call_cap_is_counted_by_the_broker_across_processes(tmp_path):
    clock = Clock()
    svc = _svc(tmp_path, clock=clock)
    other = _svc(tmp_path, clock=clock)  # a second broker process over the same state

    def program(req):
        tok = _issue(svc, req, max_calls=3)
        got = [
            _reason(lambda: svc.token_call(tok.secret, "echo.one", {"text": "1"})),
            _reason(lambda: other.token_call(tok.secret, "echo.one", {"bad": 1})),
            _reason(lambda: other.token_call(tok.secret, "echo.one", {"text": "3"})),
            _reason(lambda: svc.token_call(tok.secret, "echo.one", {"text": "4"})),
        ]
        return tok, got

    tok, got = _execute(svc, program)
    assert got == [None, "invalid-params", None, "call-cap-reached"]
    assert svc.tokens.token(tok.claims["token_id"])["calls"] == 3


def test_concurrent_calls_never_exceed_the_cap(tmp_path):
    svc = _svc(tmp_path)

    def program(req):
        tok = _issue(svc, req, max_calls=5)
        answers = []

        def worker():
            answers.append(_reason(lambda: svc.token_call(tok.secret, "echo.one", {"text": "x"})))

        threads = [threading.Thread(target=worker) for _ in range(12)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        return answers

    answers = _execute(svc, program)
    assert answers.count(None) == 5 and answers.count("call-cap-reached") == 7, answers


def test_refusal_order_and_audit(tmp_path):
    clock = Clock()
    svc = _svc(tmp_path, clock=clock)

    def program(req):
        tok = _issue(svc, req, ["echo.one", "echo.two"], ttl_s=30)
        s = tok.secret
        got = {
            "unknown": _reason(lambda: svc.token_call("hnxcmt_" + "a" * 43, "echo.one", {})),
            "wrong": _reason(
                lambda: svc.token_call(s[:-1] + ("b" if s[-1] != "b" else "c"), "echo.one", {})
            ),
            "not-a-string": _reason(lambda: svc.token_call(None, "echo.one", {})),
            "sandbox": _reason(
                lambda: svc.token_call(s, "echo.one", {"text": "x"}, sandbox_id="sandbox-02")
            ),
            "action": _reason(lambda: svc.token_call(s, "service.status", {})),
            "ok": _reason(
                lambda: svc.token_call(s, "echo.one", {"text": "x"}, sandbox_id="sandbox-01")
            ),
        }
        clock.advance(31)
        got["expired"] = _reason(lambda: svc.token_call(s, "echo.one", {"text": "x"}))
        return tok, got

    tok, got = _execute(svc, program)
    assert got == {
        "unknown": "token-invalid",
        "wrong": "token-invalid",
        "not-a-string": "token-invalid",
        "sandbox": "token-sandbox-mismatch",
        "action": "token-action-not-allowed",
        "ok": None,
        "expired": "token-expired",
    }
    docs = list(svc.state.audit_records())
    for doc in docs:
        assert schema_errors("broker", "audit", doc) == [], doc
    refused = [d for d in docs if d["outcome"] == "denied" and d["operation"] == "call"]
    # three unknown secrets in one window: one record (coalesced), naming no token
    unknown = [d for d in refused if d["caller"] == "token:unknown"]
    assert len(unknown) == 1 and "token_id" not in unknown[0], unknown
    assert unknown[0]["reason"] == "token-invalid"
    named = [d for d in docs if d.get("token_id") == tok.claims["token_id"]]
    ops = [(d["operation"], d["outcome"], d["reason"]) for d in named]
    assert ("token-issue", "ok", "") in ops and ("call", "ok", "") in ops
    assert ("call", "denied", "token-expired") in ops and ("token-spend", "ok", "") in ops, ops
    assert all(d.get("execution_id") == "exec-0001" for d in named)


def test_a_call_needing_approval_pauses_and_a_resume_runs_it(tmp_path):
    svc = _svc(tmp_path)
    actions = ["service.restart", "service.status"]

    def program(req):
        tok = _issue(svc, req, actions)
        ans = svc.token_call(tok.secret, "service.restart", {"grace_s": 5}, target="svc:queue")
        after = _reason(
            lambda: svc.token_call(tok.secret, "service.status", {}, target="svc:queue")
        )
        return tok, ans, after, svc.token_status(RUNNER, tok.claims["token_id"])

    tok, ans, after, status = _execute(svc, program)
    rid = ans["request_id"]
    assert ans["state"] == "pending" and ans["target"] == "svc:queue"
    assert ans["request_digest"] == svc.detail(AGENT, rid)["request"]["digest"]
    assert after == "token-paused"
    assert (status["state"], status["paused_by"], status["paused_by_state"], status["calls"]) == (
        "paused",
        rid,
        "pending",
        1,
    )
    detail = svc.detail(AGENT, rid)
    assert detail["verdict"] == "needs-approval" and detail["state"] == "pending"
    ops = [d["operation"] for d in svc.state.audit_records() if d.get("token_id")]
    assert "token-pause" in ops, "the pause left no audit record"
    svc.spend_token(RUNNER, tok.claims["token_id"], "paused")

    def early(req):
        t = _issue(svc, req, actions)
        return _reason(lambda: svc.token_run(t.secret, rid))

    # not approved yet: a resume may be issued, and its token_run is refused (not counted); the
    # runner reads paused_by_state first, because a resumed run that ends unpaused finishes
    assert _execute(svc, early, resume=True) == "request-not-approved"
    svc.approve(rid, "sso:operator-one")
    assert svc.token_status(RUNNER, tok.claims["token_id"])["paused_by_state"] == "approved"
    resumed_ex = svc.tokens.execution(svc.tokens.token(tok.claims["token_id"])["exec_key"])
    assert resumed_ex["state"] == "finished", resumed_ex


def test_a_resume_runs_the_approved_request(tmp_path):
    svc = _svc(tmp_path)
    actions = ["service.restart"]

    def program(req):
        tok = _issue(svc, req, actions)
        return tok, svc.token_call(
            tok.secret, "service.restart", {"grace_s": 5}, target="svc:queue"
        )

    tok, ans = _execute(svc, program)
    rid = ans["request_id"]
    svc.approve(rid, "sso:operator-one")

    def resumed(req):
        t = _issue(svc, req, actions)
        return svc.token_run(t.secret, rid)

    ran = _execute(svc, resumed, resume=True)
    assert ran["request_id"] == rid and ran["request_digest"] == ans["request_digest"]
    assert ran["result"]["exit_code"] == 0
    assert svc.token_status(RUNNER, tok.claims["token_id"])["paused_by_state"] == "done"


def test_answers_and_post_admission_refusals_name_the_request(tmp_path):
    svc = _svc(tmp_path)

    def program(req):
        tok = _issue(svc, req, ["echo.one", "service.status"])
        ok = svc.token_call(tok.secret, "echo.one", {"text": "x"})
        with pytest.raises(InvalidArguments) as bad:
            svc.token_call(tok.secret, "echo.one", {"nope": 1})
        with pytest.raises(BrokerError) as pre:
            svc.token_call(tok.secret, "dns.lookup", {})
        return ok, bad.value, pre.value

    ok, bad, pre = _execute(svc, program)
    assert ok["result"] == {"echo": "x"} and ok["request_digest"].startswith("sha256:")
    assert bad.request_id.startswith("req-") and bad.request_digest.startswith("sha256:")
    assert getattr(bad, "admitted", False)
    assert not hasattr(pre, "request_id") and not getattr(pre, "admitted", False)


def test_a_token_dies_with_its_execute_and_on_spend(tmp_path):
    svc = _svc(tmp_path)

    def program(req):
        a = _issue(svc, req)
        return a

    tok = _execute(svc, program)
    assert _reason(lambda: svc.token_call(tok.secret, "echo.one", {"text": "x"})) == "token-spent"
    assert (
        _reason(lambda: svc.spend_token(AGENT, tok.claims["token_id"])) == "not-a-codemode-runner"
    )
    assert _reason(lambda: svc.spend_token(RUNNER, "tok-nothing")) == "unknown-token"
    svc.spend_token(RUNNER, tok.claims["token_id"])  # spending a spent token is a no-op


def test_the_secret_is_never_written(tmp_path):
    svc = _svc(tmp_path)

    def program(req):
        tok = _issue(svc, req, ["echo.one", "service.restart"], max_calls=2)
        for action, args in (("echo.one", {"text": "x"}), ("echo.two", {}), ("echo.one", {})):
            _reason(lambda a=action, k=args: svc.token_call(tok.secret, a, k))
        _reason(lambda: svc.token_submit(tok.secret, "echo.one", {"text": "late"}))
        return tok

    tok = _execute(svc, program)
    needle = tok.secret.encode()
    for path in (tmp_path / "state").rglob("*"):
        if path.is_file():
            assert needle not in path.read_bytes(), f"the secret was written to {path}"
    assert tok.secret not in json.dumps(dict(tok.claims))


def test_codemode_execute_params_are_an_execution_request(tmp_path):
    svc = _svc(tmp_path)
    svc.register_runner(RUNNER, lambda req: None)
    for bad in (
        {"execution_id": "e1", "language": "cobol", "code": "x"},
        {"execution_id": "e1", "language": "python", "code": "x", "actor": AGENT},
    ):
        with pytest.raises(InvalidArguments):
            svc.call(AGENT, CODEMODE_EXECUTE, bad)
    with pytest.raises(ValueError):
        svc.register(CODEMODE_EXECUTE, lambda **kw: None, {})


def test_a_manifest_exec_codemode_execute_is_in_flight_while_its_handler_runs(tmp_path):
    base = tmp_path / "m"
    (base / "handlers").mkdir(parents=True)
    script = base / "handlers" / "codemode-execute.sh"
    script.write_text('#!/bin/sh\nsleep 1\necho \'{"status": "ok"}\'\n')
    os.chmod(script, 0o700)  # an owner-run test handler
    doc = {
        "action": CODEMODE_EXECUTE,
        "handler": "handlers/codemode-execute.sh",
        "handler_digest": file_digest(script),
        "tier": "write",
        "requires_approval": False,
        "params_schema": {"type": "object"},
        "timeout_s": 10,
        "audit": True,
        "idempotent": False,
        "description": "stand-in for the runner's client",
    }
    (base / "handlers" / "codemode-execute.handler.json").write_text(json.dumps(doc))
    manifest = {
        "manifest_id": "cm",
        "default": "deny",
        "mode": "enforce",
        "handler_docs": ["handlers/codemode-execute.handler.json"],
        "actions": [
            {
                "action": CODEMODE_EXECUTE,
                "tier": "write",
                "handler": "handlers/codemode-execute.sh",
                "requires_approval": False,
            }
        ],
        "grants": [{"profile": AGENT, "actions": [CODEMODE_EXECUTE], "max_tier": "write"}],
        "codemode": {
            "runners": [
                {"user": "hnx-codemode", "service": RUNNER},
                {"user": "hnx-codemode-two", "service": "svc:other-runner"},
            ]
        },
    }
    _, problems = validate_manifest(manifest, base)
    assert problems == [f"{CODEMODE_EXECUTE}: codemode.runners lists several; name its runner"]
    manifest["actions"][0]["runner"] = "svc:nobody"
    _, problems = validate_manifest(manifest, base)
    assert problems == [f"{CODEMODE_EXECUTE}: runner svc:nobody is not in codemode.runners"]
    manifest["actions"][0]["runner"] = RUNNER
    docs, problems = validate_manifest(manifest, base)
    assert problems == []
    svc = BrokerService(tmp_path / "state", manifest, base_dir=base, handler_docs=docs)
    with pytest.raises(ValueError):
        svc.register_runner(RUNNER, lambda req: None)
    result = {}
    params = {"execution_id": "exec-0009", "language": "python", "code": "z = 3"}
    t = threading.Thread(target=lambda: result.update(r=svc.call(AGENT, CODEMODE_EXECUTE, params)))
    t.start()
    try:
        for _ in range(200):
            inflight = list((svc.tokens.root / "inflight").glob("*.json"))
            if inflight:
                break
            threading.Event().wait(0.01)
        assert inflight, "the running codemode.execute is not in flight"
        rid = inflight[0].stem
        with pytest.raises(Denied) as other:  # the run is RUNNER's: no other runner may ask
            svc.issue_token("svc:other-runner", rid, sandbox_id="s", actions=["dns.lookup"])
        assert other.value.reason == "execution-not-in-flight"
        with pytest.raises(Denied) as exc:  # granted nothing but codemode.execute
            svc.issue_token(RUNNER, rid, sandbox_id="sandbox-01", actions=["dns.lookup"])
        assert exc.value.reason == "token-action-not-admitted"
    finally:
        t.join()
    assert result["r"]["output"] == {"status": "ok"}
    assert svc.tokens.inflight(rid) is None


# -- the socket transport -------------------------------------------------------------------------

RUNNER_UID, OTHER_RUNNER_UID, SANDBOX_UID, POOL_UID, AGENT_UID = 3001, 3002, 3101, 3102, 2001


def _transport_manifest():
    return {
        "manifest_id": "cm",
        "default": "deny",
        "mode": "enforce",
        "actions": [],
        "grants": [],
        "callers": [{"uid": AGENT_UID, "profile": AGENT}],
        "codemode": {
            "runners": [
                {"uid": RUNNER_UID, "service": RUNNER},
                {"uid": OTHER_RUNNER_UID, "service": "svc:other-runner"},
            ],
            "sandboxes": [{"uid": SANDBOX_UID, "sandbox_id": "sandbox-01"}, {"uid": POOL_UID}],
        },
    }


def _ask(svc, peers, uid, bearer=None, **body):
    """One socket request; ``bearer`` is a sandbox's token line, never a body field."""
    return handle_request(svc, peers, uid, json.dumps(body).encode(), bearer=bearer)


def test_runner_and_sandbox_peers_over_the_socket(tmp_path):
    manifest = _transport_manifest()
    assert schema_errors("broker", "manifest", manifest) == []
    svc = _svc(tmp_path, manifest)
    peers = PeerMap(svc.manifest)

    def program(req):
        issued = _ask(
            svc,
            peers,
            RUNNER_UID,
            op="token-issue",
            request_id=req["request_id"],
            sandbox_id="sandbox-pool",
            actions=["echo.one"],
        )
        assert issued["ok"], issued
        secret = issued["secret"]
        call = {"op": "token-call", "action": "echo.one", "params": {"text": "x"}}
        bad = {**call, "params": {"nope": 1}}
        # a body naming a token is refused, whatever it holds (not this run's secret: nothing
        # secret is ever put in a body)
        in_body = {"op": "token-call", "token": UNKNOWN, "action": "echo.one", "params": {}}
        return {"secret": secret, "claims": issued["result"]["claims"]}, {
            "pool": _ask(svc, peers, POOL_UID, bearer=secret, **call),
            "bound": _ask(svc, peers, SANDBOX_UID, bearer=secret, **call),
            "invalid": _ask(svc, peers, POOL_UID, bearer=secret, **bad),
            "agent": _ask(svc, peers, AGENT_UID, bearer=secret, **call),
            "runner-call": _ask(svc, peers, RUNNER_UID, bearer=secret, **call),
            "sandbox-issue": _ask(
                svc,
                peers,
                POOL_UID,
                op="token-issue",
                request_id=req["request_id"],
                sandbox_id="s",
                actions=["x.y"],
            ),
            "actor": _ask(svc, peers, POOL_UID, bearer=secret, **call, actor="profile:other"),
            "in-body": _ask(svc, peers, POOL_UID, **in_body),
            "no-bearer": _ask(svc, peers, POOL_UID, op="token-call", action="echo.one"),
            "other-runner": _ask(
                svc,
                peers,
                OTHER_RUNNER_UID,
                op="token-status",
                token_id=issued["result"]["claims"]["token_id"],
            ),
            "submit": _ask(
                svc,
                peers,
                POOL_UID,
                op="token-submit",
                bearer=secret,
                action="echo.one",
                params={"text": "s"},
            ),
        }

    issued, got = _execute(svc, program)
    assert got["pool"]["ok"] and got["pool"]["result"]["result"] == {"echo": "x"}
    assert got["pool"]["result"]["request_digest"].startswith("sha256:")
    assert got["bound"]["error"] == "token-sandbox-mismatch", "a dedicated peer used a pool token"
    assert got["invalid"]["error"] == "invalid-params" and got["invalid"]["request_id"]
    assert "_admitted" not in got["invalid"], "the transport's own marker leaked"
    assert got["agent"]["error"] == "not-a-sandbox"
    assert got["runner-call"]["error"] == "not-a-sandbox"
    assert got["sandbox-issue"]["error"] == "not-a-codemode-runner"
    assert got["actor"]["error"] == "actor-in-body"
    assert got["in-body"]["error"] == "request-invalid", "a token in the body was accepted"
    assert got["no-bearer"]["error"] == "request-invalid", got["no-bearer"]
    assert got["other-runner"]["error"] == "unknown-token", "another runner read the token"
    assert got["submit"]["result"]["state"] == "pending"
    for name, resp in got.items():
        assert issued["secret"] not in json.dumps(resp), f"{name}: the answer echoed the secret"
    status = _ask(svc, peers, RUNNER_UID, op="token-status", token_id=issued["claims"]["token_id"])
    assert status["result"]["state"] == "paused" and status["result"]["calls"] == 3
    vias = {d.get("via") for d in svc.state.audit_records() if d.get("token_id")}
    assert f"uid:{POOL_UID}" in vias and f"uid:{RUNNER_UID}" in vias


def test_a_dedicated_sandboxs_token_is_its_own(tmp_path):
    svc = _svc(tmp_path, _transport_manifest())
    peers = PeerMap(svc.manifest)

    def program(req):
        secret = _ask(
            svc,
            peers,
            RUNNER_UID,
            op="token-issue",
            request_id=req["request_id"],
            sandbox_id="sandbox-01",
            actions=["echo.one"],
        )["secret"]
        call = {"op": "token-call", "action": "echo.one", "params": {"text": "x"}}
        return (
            _ask(svc, peers, POOL_UID, bearer=secret, **call),
            _ask(svc, peers, SANDBOX_UID, bearer=secret, **call),
        )

    from_pool, own = _execute(svc, program)
    assert from_pool["error"] == "token-sandbox-mismatch", "a pool peer used a dedicated token"
    assert own["ok"], own


def test_one_program_cannot_rate_limit_another_on_a_pool(tmp_path):
    from homelabnext.broker.server import UNKNOWN_TOKEN_FACTOR, RefusalLimiter

    manifest = _transport_manifest()
    manifest["codemode"]["max_calls"] = 200
    svc = _svc(tmp_path, manifest)
    svc.allow("profile:other", [CODEMODE_EXECUTE, "echo.one"])
    peers = PeerMap(svc.manifest)
    limiter = RefusalLimiter(60, 600)

    def ask(uid, bearer=None, **body):
        raw = json.dumps(body).encode()
        return handle_request(svc, peers, uid, raw, limiter=limiter, bearer=bearer)

    def issue(req, **kw):
        out = ask(
            RUNNER_UID,
            op="token-issue",
            request_id=req["request_id"],
            sandbox_id="sandbox-pool",
            actions=["echo.one"],
            **kw,
        )
        assert out["ok"], out
        return out["secret"]

    call = {"op": "token-call", "action": "echo.one", "params": {"text": "x"}}

    def noisy(req):
        bearer = issue(req, max_calls=1)
        first = ask(POOL_UID, bearer=bearer, **call)["ok"]
        own_cap = [ask(POOL_UID, bearer=bearer, **call)["error"] for _ in range(61)]
        garbage = [
            ask(POOL_UID, bearer=f"hnxcmt_garbage{i:036d}", **call)["error"] for i in range(61)
        ]
        return first, own_cap, garbage

    first, own_cap, garbage = _execute(svc, noisy, max_calls=200)
    assert first and own_cap[:60] == ["call-cap-reached"] * 60, own_cap[:3]
    assert own_cap[60] == "rate-limited", "a program past its limit is limited, itself"
    assert set(garbage) == {"token-invalid"}, "61 garbage tokens hit the normal limit"

    def admitted_noise(req):
        bearer = issue(req)
        bad = {**call, "params": {"nope": 1}}
        return [ask(POOL_UID, bearer=bearer, **bad)["error"] for _ in range(61)]

    errors = _execute(svc, admitted_noise, actor="profile:other", eid="exec-noise", max_calls=200)
    assert set(errors) == {"invalid-params"}, "refusals after admission rate-limited the pool"
    # 61 refused resumes by one actor, asked by the runner, do not lock the runner out
    for _ in range(61):
        refused = _execute(
            svc,
            lambda r: ask(
                RUNNER_UID,
                op="token-issue",
                request_id=r["request_id"],
                sandbox_id="sandbox-pool",
                actions=["echo.one"],
            ),
            eid="exec-nothing",
            resume=True,
        )
        assert refused["error"] == "execution-not-resumable", refused

    def quiet(req):
        return ask(POOL_UID, bearer=issue(req), **call)

    got = _execute(svc, quiet, actor="profile:other", eid="exec-quiet")
    assert got["ok"], f"another program on the same pool uid was locked out: {got}"
    # garbage past the uid's ceiling is limited, and a valid token still is not
    for i in range(60 * UNKNOWN_TOKEN_FACTOR):
        ask(POOL_UID, bearer=f"hnxcmt_flood{i:038d}", **call)
    assert ask(POOL_UID, bearer=UNKNOWN, **call)["error"] == "rate-limited"
    got = _execute(svc, quiet, actor="profile:other", eid="exec-after")
    assert got["ok"], f"a garbage flood rate-limited a valid token: {got}"
    invalid = [d for d in svc.state.audit_records() if d.get("reason") == "token-invalid"]
    assert len(invalid) <= 2, f"refused unknown secrets were not coalesced: {len(invalid)} records"


def test_a_peer_is_listed_once_across_the_four_roles(tmp_path):
    manifest = _transport_manifest()
    manifest["codemode"]["sandboxes"].append({"uid": AGENT_UID})
    _, problems = validate_manifest(manifest, tmp_path)
    assert any("codemode.sandboxes: uid 2001 is already listed in callers" in p for p in problems)


def test_the_conformance_factory_declares_the_feature_and_the_clock_hook():
    from homelabnext.broker.service import make

    svc = make()
    assert {"codemode-tokens", "clock-control"} <= set(svc.features)
    before = svc.clock()
    svc.tick(120)
    assert (svc.clock() - before).total_seconds() >= 120


def test_a_state_directory_copy_keeps_the_tokens_state(tmp_path):
    svc = _svc(tmp_path)
    tok = _execute(svc, lambda req: _issue(svc, req))
    shutil.copytree(tmp_path / "state", tmp_path / "copy")
    again = _svc(tmp_path, state="copy")
    assert _reason(lambda: again.token_call(tok.secret, "echo.one", {"text": "x"})) == "token-spent"


# -- spend outcomes, the sweep and retention --------------------------------------------------------


def test_spend_outcomes(tmp_path):
    svc = _svc(tmp_path)

    def program(req):
        tok = _issue(svc, req)
        tid = tok.claims["token_id"]
        return [
            _reason(lambda: svc.spend_token(RUNNER, tid, "paused")),
            _reason(lambda: svc.spend_token(RUNNER, tid, "abandoned")),
            _reason(lambda: svc.token_status(AGENT, tid)),
            _reason(lambda: svc.spend_token(AGENT, tid)),
        ]

    assert _execute(svc, program) == [
        "token-not-paused",
        "invalid-params",
        "not-a-codemode-runner",
        "not-a-codemode-runner",
    ]
    spends = [d for d in svc.state.audit_records() if d["operation"] == "token-spend"]
    assert spends[-1]["args"] == {"outcome": "finished"} and spends[-1]["outcome"] == "ok"


def test_a_crashed_run_is_spent_and_never_resumes(tmp_path, monkeypatch):
    clock = Clock()
    svc = _svc(tmp_path, clock=clock)

    def program(req):
        tok = _issue(svc, req)
        monkeypatch.setattr(svc.state, "instance_alive", lambda iid: False)  # its broker is gone
        swept = svc.sweep_tokens(force=True)
        monkeypatch.undo()
        return tok, swept, _reason(lambda: svc.token_call(tok.secret, "echo.one", {"text": "x"}))

    tok, swept, after = _execute(svc, program)
    assert swept["crashed"] == 1 and after == "token-spent"
    doc = svc.tokens.token(tok.claims["token_id"])
    assert (doc["state"], doc["outcome"]) == ("spent", "crashed")
    assert svc.tokens.execution(doc["exec_key"])["state"] == "crashed"
    assert _reason(lambda: _execute(svc, lambda r: _issue(svc, r), resume=True)) == (
        "execution-not-resumable"
    )


def test_a_crashed_paused_run_stays_resumable(tmp_path, monkeypatch):
    svc = _svc(tmp_path)

    def program(req):
        tok = _issue(svc, req)
        svc.token_submit(tok.secret, "echo.one", {"text": "later"})
        monkeypatch.setattr(svc.state, "instance_alive", lambda iid: False)
        svc.sweep_tokens(force=True)
        monkeypatch.undo()

    _execute(svc, program)
    assert _execute(svc, lambda r: _issue(svc, r), resume=True).claims["max_calls"] == 49


def test_the_sweep_drops_expired_live_entries_and_old_executions(tmp_path):
    clock = Clock()
    svc = _svc(tmp_path, clock=clock)

    def program(req):
        tok = _issue(svc, req, ttl_s=5)
        clock.advance(6)
        return tok, svc.sweep_tokens(force=True)

    tok, swept = _execute(svc, program)
    assert swept["expired"] == 1 and not list((svc.tokens.root / "live").glob("*.json"))
    clock.advance(6 * 86400)
    assert svc.sweep_tokens(force=True)["removed"] == 0, "removed before the retention passed"
    clock.advance(2 * 86400)
    assert svc.sweep_tokens(force=True)["removed"] == 1
    assert svc.tokens.token(tok.claims["token_id"]) is None
    assert not list((svc.tokens.root / "secrets").glob("*.json"))
    # the id is free again once its execution is gone
    assert _execute(svc, lambda r: _issue(svc, r)).claims["execution_id"] == "exec-0001"


def test_the_store_lock_nests_and_still_excludes_other_threads(tmp_path):
    from homelabnext.broker.tokens import TokenStore

    store = TokenStore(tmp_path)
    order, done = [], threading.Event()

    def other():
        with store.locked():
            order.append("other")

    def nested():
        with store.locked():
            with store.locked():  # nested in one thread: no second flock, no deadlock
                t = threading.Thread(target=other, daemon=True)
                t.start()
                t.join(0.3)
                order.append("inner" if t.is_alive() else "other got in")
            order.append("outer")
        t.join(5)
        done.set()

    threading.Thread(target=nested, daemon=True).start()  # a deadlock fails, never hangs
    assert done.wait(10), "a nested entry deadlocked on its own lock"
    assert order == ["inner", "outer", "other"], order
    assert store._fd is None and store._depth == 0


def test_a_denied_paused_request_is_refused_by_name(tmp_path):
    svc = _svc(tmp_path)

    def program(req):
        tok = _issue(svc, req, ["service.restart"])
        return svc.token_call(tok.secret, "service.restart", {"grace_s": 5}, target="svc:queue")

    ans = _execute(svc, program)
    svc.deny(ans["request_id"], "sso:operator-one")

    def resumed(req):
        tok = _issue(svc, req, ["service.restart"])
        with pytest.raises(Denied) as exc:
            svc.token_run(tok.secret, ans["request_id"])
        return exc.value

    exc = _execute(svc, resumed, resume=True)
    assert exc.reason == "request-denied"
    assert (exc.request_id, exc.request_digest) == (ans["request_id"], ans["request_digest"])
    rec = [d for d in svc.state.audit_records() if d.get("reason") == "request-denied"]
    assert len(rec) == 1 and rec[0]["request_id"] == ans["request_id"]
    assert rec[0]["request_digest"] == ans["request_digest"]


def test_issue_keeps_the_secret_out_of_everything_but_the_answer(tmp_path, caplog):
    import logging

    svc = _svc(tmp_path, _transport_manifest())
    peers = PeerMap(svc.manifest)
    caplog.set_level(logging.DEBUG)

    def program(req):
        issued = _ask(
            svc,
            peers,
            RUNNER_UID,
            op="token-issue",
            request_id=req["request_id"],
            sandbox_id="sandbox-pool",
            actions=["echo.one"],
        )
        bearer = issued["secret"]
        refusals = [
            _ask(svc, peers, POOL_UID, bearer=bearer, op="token-call", action="nope.no"),
            _ask(svc, peers, POOL_UID, bearer=bearer, op="nope"),
            _ask(svc, peers, RUNNER_UID, op="token-status", token_id="tok-none"),
        ]
        return issued, refusals

    issued, refusals = _execute(svc, program)
    bearer = issued["secret"]
    # the secret is answered beside the result, never in it: what the runner reads and sends
    # back (the claims, the token id) never shared a container with it
    assert set(issued) == {"ok", "result", "secret"} and set(issued["result"]) == {"claims"}
    assert bearer not in json.dumps(issued["result"])
    assert all(bearer not in json.dumps(r) for r in refusals)
    assert all(bearer not in json.dumps(d) for d in svc.state.audit_records())
    assert bearer not in caplog.text, "the secret reached a log line"


def test_the_bearer_line_is_read_apart_from_the_body():
    import socket

    from homelabnext.broker.server import _read_request

    def read(data: bytes, close: bool = True):
        a, b = socket.socketpair()
        with a, b:
            a.sendall(data)
            if close:
                a.shutdown(socket.SHUT_WR)
            return _read_request(b, 1 << 20, 2.0)

    body = b'{"op": "token-call"}'
    assert read(UNKNOWN.encode() + b"\n" + body + b"\n", close=False) == (body, "", UNKNOWN)
    assert read(body + b"\n", close=False) == (body, "", None)
    assert read(body) == (body, "", None)
    assert read(b"hnxcmt_" + b"x" * 300 + b"\n" + body)[1] == "request-too-large"


# -- the wire, the limiter and coalescing ---------------------------------------------------------


class _Conn:
    """A socket stand-in whose recv returns the scripted chunks, then EOF."""

    def __init__(self, *chunks: bytes) -> None:
        self.chunks = list(chunks)

    def settimeout(self, _t) -> None:
        pass

    def recv(self, _n: int) -> bytes:
        return self.chunks.pop(0) if self.chunks else b""


@pytest.mark.parametrize(
    ("chunks", "want"),
    [
        # a bearer split across chunks, and its prefix split mid-word
        ((b"hnxcm", b"t_" + b"a" * 43, b"\n{}", b"\n"), (b"{}", "", "hnxcmt_" + "a" * 43)),
        ((b"hnxcmt_ab\r\n{}\r\n",), (b"{}\r", "", "hnxcmt_ab")),  # a bearer's \r is stripped
        ((b"hnxcmt_ab\n",), (b"", "", "hnxcmt_ab")),  # a bearer, then EOF: no body
        ((b"hnxcmt_ab",), (b"", "", "hnxcmt_ab")),  # no newline at all
        ((b'{"op": "x"}\nhnxcmt_ab\n',), (b'{"op": "x"}', "", None)),  # not first: body only
        ((b"hnxcmt_ab\n", b"{" + b"a" * 2000 + b"}\n"), (None, "request-too-large", None)),
    ],
)
def test_read_request_framing(chunks, want):
    from homelabnext.broker.server import _read_request

    assert _read_request(_Conn(*chunks), 1024, 5.0) == want


def test_a_non_sandbox_bearer_and_a_bad_first_line_are_refused(tmp_path):
    svc = _svc(tmp_path, _transport_manifest())
    peers = PeerMap(svc.manifest)
    caller = _ask(svc, peers, AGENT_UID, bearer=UNKNOWN, op="actions")
    assert caller["error"] == "request-invalid", "a caller's bearer line was accepted"
    junk = handle_request(svc, peers, POOL_UID, b"hnxcmt-not-a-bearer")
    assert junk["error"] == "request-malformed"


def test_the_limiter_keys_a_sandbox_by_token_and_prunes(tmp_path):
    from homelabnext.broker.server import RefusalLimiter, _sandbox_key

    svc = _svc(tmp_path, _transport_manifest())
    tok = _execute(svc, lambda req: _issue(svc, req))
    now = [0.0]
    limiter = RefusalLimiter(2, 10, clock=lambda: now[0])
    key, lim = _sandbox_key(svc, POOL_UID, tok.secret, limiter)
    assert (key, lim) == ((POOL_UID, tok.claims["token_id"]), limiter)
    assert tok.secret not in repr(key)
    unknown_key, unknown = _sandbox_key(svc, POOL_UID, UNKNOWN, limiter)
    assert (unknown_key, unknown) == (POOL_UID, limiter.unknown_tokens)
    assert unknown.max_refusals == 20 and limiter.unknown_tokens is unknown
    for i in range(50):  # one refusal each for 50 tokens: 50 keys, none seen again
        limiter.refused((POOL_UID, f"tok-{i}"))
    assert len(limiter._peers) == 50
    now[0] = 11.0
    limiter.check((POOL_UID, "tok-new"))
    assert limiter._peers == {}, "expired keys were kept"
    now[0] = 5.0  # a clock stepped back ends a window rather than stretching it
    limiter.refused(POOL_UID)
    limiter.refused(POOL_UID)
    assert limiter.check(POOL_UID) == (True, True)
    now[0] = 1.0
    assert limiter.check(POOL_UID) == (False, False)


def test_sandbox_transport_refusals_are_coalesced_and_flushed(tmp_path):
    clock = Clock()
    svc = _svc(tmp_path, _transport_manifest(), clock=clock)
    svc.page_timers = False
    peers = PeerMap(svc.manifest)
    bad = [
        {"op": "token-call", "action": "echo.one"},  # no bearer
        {"op": "token-call", "token": UNKNOWN, "action": "echo.one"},  # a token in the body
        {"op": "nope"},
    ]
    for i in range(600):
        _ask(svc, peers, POOL_UID, **bad[i % 3])
    handle_request(svc, peers, POOL_UID, b"{not json")

    def records():
        return [d for d in svc.state.audit_records() if d.get("via") == f"uid:{POOL_UID}"]

    assert len(records()) == 1, f"601 refusals left {len(records())} records"
    assert svc.flush_coalesced() == 0, "flushed before the window ended"
    clock.advance(61)
    assert svc.flush_coalesced() == 1
    last = records()[-1]
    assert (last["reason"], last["args"]) == ("sandbox-refused", {"coalesced": 600})
    clock.advance(-3600)  # a clock stepped back: the next refusal opens a window, audited
    _ask(svc, peers, POOL_UID, op="nope")
    assert len(records()) == 3


def test_a_flood_of_unknown_secrets_that_stops_still_leaves_its_count(tmp_path):
    clock = Clock()
    svc = _svc(tmp_path, clock=clock)
    svc.page_timers = False
    for _ in range(40):
        _reason(lambda: svc.token_call(UNKNOWN, "echo.one", {"text": "x"}))
    clock.advance(61)
    svc.sweep_tokens(force=True)  # the sweep flushes what a window held back
    invalid = [d for d in svc.state.audit_records() if d.get("reason") == "token-invalid"]
    assert len(invalid) == 2 and invalid[-1]["args"] == {"coalesced": 39}, invalid


def test_polling_token_run_spends_the_cap(tmp_path):
    svc = _svc(tmp_path)
    actions = ["service.restart"]

    def program(req):
        tok = _issue(svc, req, actions)
        return svc.token_call(tok.secret, "service.restart", {"grace_s": 5}, target="svc:queue")

    ans = _execute(svc, program)

    def poll(req):
        tok = _issue(svc, req, actions, max_calls=3)
        return [_reason(lambda: svc.token_run(tok.secret, ans["request_id"])) for _ in range(5)]

    got = _execute(svc, poll, resume=True)
    assert got == ["request-not-approved"] * 3 + ["call-cap-reached"] * 2, got


def test_an_expired_approval_reads_expired_and_waits_for_a_fresh_one(tmp_path):
    clock = Clock()
    svc = _svc(tmp_path, clock=clock)
    actions = ["service.restart"]

    def program(req):
        tok = _issue(svc, req, actions)
        ans = svc.token_call(tok.secret, "service.restart", {"grace_s": 5}, target="svc:queue")
        return tok, ans

    tok, ans = _execute(svc, program)
    svc.approve(ans["request_id"], "sso:operator-one")
    clock.advance(901)  # past approval_ttl_s: the approval expired unused
    status = svc.token_status(RUNNER, tok.claims["token_id"])
    assert status["paused_by_state"] == "expired"
    svc.approve(ans["request_id"], "sso:operator-one")  # a fresh approval is accepted
    assert svc.token_status(RUNNER, tok.claims["token_id"])["paused_by_state"] == "approved"


@pytest.mark.parametrize(
    "bearer", ["hnxcmt_a\rb", "hnxcmt_é", "hnxcmt_a\nb", "nope", "hnxcmt_" + "a" * 300]
)
def test_the_client_refuses_an_unsendable_bearer_as_token_invalid(bearer, tmp_path):
    from homelabnext.broker.client import BrokerClient

    client = BrokerClient(str(tmp_path / "no.sock"))
    with pytest.raises(BrokerError) as exc:
        client.token_call(bearer, "echo.one", {})
    assert type(exc.value) is BrokerError and exc.value.reason == "token-invalid"
