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
    assert len(runs) == 8 and all(m.detected for m in runs), [m.name for m in runs]


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


def test_one_token_per_run_and_resume_rules(tmp_path):
    svc = _svc(tmp_path)

    def first(req):
        tok = _issue(svc, req)
        return tok, _reason(lambda: _issue(svc, req))

    tok, again = _execute(svc, first, code="a = 1")
    assert again == "request-has-token"
    assert (
        _reason(lambda: _execute(svc, lambda r: _issue(svc, r), code="a = 1")) == "execution-exists"
    )
    foreign = _reason(
        lambda: _execute(
            svc, lambda r: _issue(svc, r), actor="profile:other", code="a = 1", resume=True
        )
    )
    assert foreign in ("execution-not-resumable", "not-granted"), foreign
    svc.allow("profile:other", [CODEMODE_EXECUTE, "echo.one"])
    foreign = _reason(
        lambda: _execute(
            svc, lambda r: _issue(svc, r), actor="profile:other", code="a = 1", resume=True
        )
    )
    assert foreign == "execution-not-resumable", "another actor resumed the execution"
    assert (
        _reason(lambda: _execute(svc, lambda r: _issue(svc, r), eid="exec-none", resume=True))
        == "execution-not-resumable"
    )
    new = _execute(svc, lambda r: _issue(svc, r), code="a = 1", resume=True)
    assert new.claims["token_id"] != tok.claims["token_id"]
    doc = svc.tokens.execution("exec-0001")
    assert doc["tokens"] == [tok.claims["token_id"], new.claims["token_id"]]


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
    assert [d["caller"] for d in refused[:3]] == ["token:unknown"] * 3
    assert all("token_id" not in d for d in refused[:3]), "an unknown secret named a token"
    named = [d for d in docs if d.get("token_id") == tok.claims["token_id"]]
    ops = [(d["operation"], d["outcome"], d["reason"]) for d in named]
    assert ("token-issue", "ok", "") in ops and ("call", "ok", "") in ops
    assert ("call", "denied", "token-expired") in ops and ("token-spend", "ok", "") in ops, ops
    assert all(d.get("execution_id") == "exec-0001" for d in named)


def test_a_submit_needing_approval_pauses_the_token(tmp_path):
    svc = _svc(tmp_path)

    def program(req):
        tok = _issue(svc, req, ["service.restart", "service.status"])
        rid = svc.token_submit(tok.secret, "service.restart", {"grace_s": 5}, target="svc:queue")
        after = _reason(
            lambda: svc.token_call(tok.secret, "service.status", {}, target="svc:queue")
        )
        return tok, rid, after, svc.token_status(RUNNER, tok.claims["token_id"])

    tok, rid, after, status = _execute(svc, program)
    assert after == "token-paused"
    assert (status["state"], status["paused_by"], status["calls"]) == ("paused", rid, 1)
    detail = svc.detail(AGENT, rid)
    assert detail["verdict"] == "needs-approval" and detail["state"] == "pending"
    assert svc.token_status(RUNNER, tok.claims["token_id"])["state"] == "paused", (
        "the end of the execute spent a paused token"
    )


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
    os.chmod(script, 0o755)
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
        "codemode": {"runners": [{"user": "hnx-codemode", "service": RUNNER}]},
    }
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
        with pytest.raises(Denied) as exc:  # granted nothing but codemode.execute
            svc.issue_token(RUNNER, rid, sandbox_id="sandbox-01", actions=["dns.lookup"])
        assert exc.value.reason == "token-action-not-admitted"
    finally:
        t.join()
    assert result["r"]["output"] == {"status": "ok"}
    assert svc.tokens.inflight(rid) is None


# -- the socket transport -------------------------------------------------------------------------

RUNNER_UID, SANDBOX_UID, POOL_UID, AGENT_UID = 3001, 3101, 3102, 2001


def _transport_manifest():
    return {
        "manifest_id": "cm",
        "default": "deny",
        "mode": "enforce",
        "actions": [],
        "grants": [],
        "callers": [{"uid": AGENT_UID, "profile": AGENT}],
        "codemode": {
            "runners": [{"uid": RUNNER_UID, "service": RUNNER}],
            "sandboxes": [{"uid": SANDBOX_UID, "sandbox_id": "sandbox-01"}, {"uid": POOL_UID}],
        },
    }


def _ask(svc, peers, uid, **body):
    return handle_request(svc, peers, uid, json.dumps(body).encode())


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
            sandbox_id="sandbox-02",
            actions=["echo.one"],
        )
        assert issued["ok"], issued
        secret = issued["result"]["secret"]
        call = {"op": "token-call", "token": secret, "action": "echo.one", "params": {"text": "x"}}
        return issued["result"], {
            "pool": _ask(svc, peers, POOL_UID, **call),
            "bound": _ask(svc, peers, SANDBOX_UID, **call),
            "agent": _ask(svc, peers, AGENT_UID, **call),
            "runner-call": _ask(svc, peers, RUNNER_UID, **call),
            "sandbox-issue": _ask(
                svc,
                peers,
                POOL_UID,
                op="token-issue",
                request_id=req["request_id"],
                sandbox_id="s",
                actions=["x.y"],
            ),
            "actor": _ask(svc, peers, POOL_UID, **call, actor="profile:other"),
        }

    issued, got = _execute(svc, program)
    assert got["pool"] == {"ok": True, "result": {"result": {"echo": "x"}}}
    assert got["bound"]["error"] == "token-sandbox-mismatch"
    assert got["agent"]["error"] == "not-a-sandbox"
    assert got["runner-call"]["error"] == "not-a-sandbox"
    assert got["sandbox-issue"]["error"] == "not-a-codemode-runner"
    assert got["actor"]["error"] == "actor-in-body"
    for name, resp in got.items():
        assert issued["secret"] not in json.dumps(resp), f"{name}: the answer echoed the secret"
    status = _ask(svc, peers, RUNNER_UID, op="token-status", token_id=issued["claims"]["token_id"])
    assert status["result"]["state"] == "spent" and status["result"]["calls"] == 1
    vias = {d.get("via") for d in svc.state.audit_records() if d.get("token_id")}
    assert f"uid:{POOL_UID}" in vias and f"uid:{RUNNER_UID}" in vias


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
