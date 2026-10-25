# SPDX-License-Identifier: Apache-2.0
"""``broker-tokens``: Code Mode capability tokens, issued, held and enforced by the broker
(ADR-0031 decisions 2, 6 and 7; ``docs/codemode.md`` CM-5a).

The contract is the broker's (:class:`conformance.protocols.broker.CodemodeTokens`, the feature
``codemode-tokens``), and so are the fake and the targets: a broker that does not declare the
feature skips every check.  The checks are a suite of their own because the broker's would pass
the 24-check ceiling with them (``docs/conformance.md``).

Every check drives the broker's own API, never a sandbox: the broker's refusal on a token is the
enforcement, whatever the program does to its client.  The runner stand-in is
``codemode.execute``'s handler; it records what the broker answers, and the check judges it after
the execute returns, because a broker contains a handler's exception."""

from __future__ import annotations

from conformance.fakes.command_broker import (
    AmbientActorBroker,
    AnyRunnerBroker,
    ClientCapBroker,
    DeniedLooksPendingBroker,
    EchoingTokenBroker,
    FakeBroker,
    FinishedResumesBroker,
    NoExpiryBroker,
    PausedStillValidBroker,
    RequestlessRefusalBroker,
    ResumeAnyCodeBroker,
    ResumeFreshCapBroker,
    SpentStillValidBroker,
    TokenRunAnyRequestBroker,
    WideningTokenBroker,
)
from conformance.protocols.broker import (
    CODEMODE_EXECUTE,
    TOKEN_REFUSALS,
    ArgSpec,
    BrokerError,
    Denied,
    InvalidArguments,
    code_digest,
)
from homelabnext.conform.core import Mutant, Suite

from ._util import exc_text, uniq

SUITE = Suite(
    "broker-tokens",
    "Code Mode tokens the broker issues and enforces: narrowed grants, its actor, cap, pause, "
    "spend, expiry, resume",
    "conformance.protocols.broker:CodemodeTokens",
    tier="extended",
)

ARGS = {"name": ArgSpec("str"), "count": ArgSpec("int", required=False)}
TOKENS = ["codemode-tokens"]
SANDBOX = "sandbox-01"


class _Runner:
    """A runner stand-in registered as ``codemode.execute``'s handler.  Each execution runs the
    program registered for its id with the request; what the program returns, or the
    exception it raised, is kept and handed back by :meth:`execute`, outside the broker."""

    def __init__(self, b):
        self.b, self.id = b, f"svc:{uniq('runner')}"
        self.programs, self.out = {}, {}
        b.register_runner(self.id, self._handle)

    def _handle(self, request):
        eid = request["params"]["execution_id"]
        try:
            self.out[eid] = ("ok", self.programs[eid](request))
        except Exception as exc:  # judged by the check, not contained by the broker
            self.out[eid] = ("raised", exc)
        return {"status": "ok"}

    def execute(self, actor, program, *, execution_id=None, code="x = 1", resume=False, **budget):
        eid = execution_id or uniq("exec")
        params = {"execution_id": eid, "language": "python", "code": code}
        if budget:
            params["budget"] = budget
        if resume:
            params["resume"] = True
        self.programs[eid] = program
        self.b.call(actor, CODEMODE_EXECUTE, params)
        kind, value = self.out.pop(eid)
        if kind == "raised":
            raise value
        return value

    def issue(self, request, actions, **kw):
        kw.setdefault("sandbox_id", SANDBOX)
        return self.b.issue_token(self.id, request["request_id"], actions=list(actions), **kw)


def _profile() -> str:
    """An agent: a token's actor is a profile id (``schemas/codemode/token``)."""
    return f"profile:{uniq('agent')}"


def _action_name() -> str:
    """A command name a token may list: ``<namespace>.<name>``, as broker actions are."""
    return f"cm.{uniq('cmd')}"


def _token_setup(b, n=2):
    """A runner, an agent allowed ``codemode.execute`` and ``n`` commands, and its calls."""
    runner, agent, calls = _Runner(b), _profile(), []
    cmds = [_action_name() for _ in range(n)]
    for cmd in cmds:
        b.register(cmd, lambda **kw: calls.append(kw) or {"ok": kw["name"]}, ARGS)
    b.allow(agent, [CODEMODE_EXECUTE, *cmds])
    return runner, agent, cmds, calls


def _reason(fn):
    """The reason a refused call gives (its ``reason``, else its class), or None when it was not
    refused."""
    try:
        fn()
    except BrokerError as exc:
        return getattr(exc, "reason", "") or type(exc).__name__
    return None


@SUITE.check(
    "token-narrows-never-widens",
    "a token lists only actions the actor's own grants admit, never codemode.*, within the cap "
    "and the run's budget; its claims are the codemode.execute request's",
    requires=TOKENS,
)
def _(b):
    runner, agent, (mine, _), _ = _token_setup(b)
    other = _action_name()
    b.register(other, lambda **kw: "not yours", ARGS)
    b.allow(uniq("admin"), [other])

    def program(req):
        refused = {
            "ungranted": _reason(lambda: runner.issue(req, [mine, other])),
            "codemode": _reason(lambda: runner.issue(req, [mine, CODEMODE_EXECUTE])),
            "calls": _reason(lambda: runner.issue(req, [mine], max_calls=6)),
            "ttl": _reason(lambda: runner.issue(req, [mine], ttl_s=10 + 3600)),
        }
        return req, refused, runner.issue(req, [mine], max_calls=5)

    req, refused, tok = runner.execute(agent, program, code="y = 2", wall_s=10, max_calls=5)
    want = {
        "ungranted": "token-action-not-admitted",
        "codemode": "token-action-codemode",
        "calls": "token-max-calls-exceeded",
        "ttl": "token-ttl-exceeded",
    }
    assert refused == want, f"issuing past the actor's grants or the run's budget gave {refused}"
    c = tok.claims
    got = {k: c.get(k) for k in ("actor", "request_id", "execution_id", "actions", "max_calls")}
    assert got == {
        "actor": agent,
        "request_id": req["request_id"],
        "execution_id": req["params"]["execution_id"],
        "actions": [mine],
        "max_calls": 5,
    }, f"the token's claims are not the codemode.execute request's: {got}"
    assert c.get("code_digest") == code_digest("python", "y = 2"), (
        "code_digest is not the program's"
    )
    assert (c.get("issuer"), c.get("audience")) == ("svc:broker", "svc:broker"), c


@SUITE.check(
    "actor-comes-from-the-token",
    "a token-authenticated call runs as the token's actor, whatever other token was issued since",
    requires=TOKENS,
)
def _(b):
    runner, alice, (cmd, _), calls = _token_setup(b)
    bob = _profile()
    b.allow(bob, [CODEMODE_EXECUTE, cmd])

    def bobs(req):
        return runner.issue(req, [cmd])

    def alices(req):
        tok = runner.issue(req, [cmd])
        runner.execute(bob, bobs)  # another agent's run, its token issued after alice's
        before = len(b.audit())
        b.token_call(tok.secret, cmd, {"name": "a"})
        rid = b.token_submit(tok.secret, cmd, {"name": "s"})["request_id"]
        return list(b.audit())[before:], rid

    records, rid = runner.execute(alice, alices)
    callers = {r.caller for r in records if r.outcome == "ok" and r.operation == "call"}
    assert callers == {alice}, f"alice's token ran as {sorted(callers)}, not as alice"
    st = b.status(alice, rid)
    assert st.caller == alice, f"the request submitted with alice's token belongs to {st.caller!r}"
    assert calls == [{"name": "a"}], calls


@SUITE.check(
    "call-cap-enforced-by-the-broker",
    "the broker counts a token's calls, a refused one included, and refuses past max_calls "
    "however the program presents the token",
    requires=TOKENS,
)
def _(b):
    runner, agent, (cmd, _), calls = _token_setup(b)

    def program(req):
        tok = runner.issue(req, [cmd], max_calls=3)
        got = [
            _reason(lambda: b.token_call(tok.secret, cmd, {"name": "1"})),
            _reason(lambda: b.token_call(tok.secret, cmd, {"wrong": "args"})),  # refused: counts
            _reason(lambda: b.token_call(tok.secret, cmd, {"name": "3"})),
        ]
        # a program that drops its client and starts over still holds the same token
        fresh = str(tok.secret)
        got += [_reason(lambda: b.token_call(fresh, cmd, {"name": "4"})) for _ in range(3)]
        return got

    got = runner.execute(agent, program)
    assert got[1] is not None, "a call with invalid arguments was not refused"
    want = [None, got[1], None, *(["call-cap-reached"] * 3)]
    assert got == want, f"three calls under a cap of 3, then three more, were answered {got}"
    assert calls == [{"name": "1"}, {"name": "3"}], f"the handler ran for {calls}"


def _paused_run(b, runner, agent, cmd, eid, *, code="x = 1", calls_first=0, **budget):
    """A first run of ``eid`` that makes ``calls_first`` calls, then submits one request and
    ends paused on it; returns (token, the submit's answer)."""

    def program(req):
        tok = runner.issue(req, [cmd])
        for i in range(calls_first):
            b.token_call(tok.secret, cmd, {"name": f"c{i}"})
        return tok, b.token_submit(tok.secret, cmd, {"name": "approve-me"})

    return runner.execute(agent, program, execution_id=eid, code=code, **budget)


@SUITE.check(
    "call-cap-is-per-execution",
    "a resume's token carries what is left of the execution's cap, never a fresh max_calls",
    requires=TOKENS,
)
def _(b):
    runner, agent, (cmd, _), _ = _token_setup(b)
    eid = uniq("exec")
    first, _ans = _paused_run(b, runner, agent, cmd, eid, calls_first=1, max_calls=3)
    assert first.claims["max_calls"] == 3, first.claims

    def resumed(req):
        over = _reason(lambda: runner.issue(req, [cmd], max_calls=2))
        return over, runner.issue(req, [cmd])

    over, tok = runner.execute(agent, resumed, execution_id=eid, resume=True)
    assert tok.claims["max_calls"] == 1, (
        f"after 2 of 3 calls the resume's token carries {tok.claims['max_calls']}, not 1"
    )
    assert over == "token-max-calls-exceeded", f"asking the resume for 2 calls gave {over!r}"


@SUITE.check(
    "paused-token-refused",
    "an accepted submit through a token pauses it: every later call or submit on it is refused "
    "token-paused",
    requires=TOKENS,
)
def _(b):
    runner, agent, (cmd, two), calls = _token_setup(b)

    def program(req):
        tok = runner.issue(req, [cmd, two])
        ans = b.token_submit(tok.secret, cmd, {"name": "approve-me"})
        return ans, [
            _reason(lambda: b.token_call(tok.secret, two, {"name": "after"})),
            _reason(lambda: b.token_submit(tok.secret, cmd, {"name": "again"})),
        ]

    ans, got = runner.execute(agent, program)
    assert ans.get("state") == "pending", f"a submit through a token answered {ans}"
    assert got == ["token-paused", "token-paused"], f"calls after the pause were answered {got}"
    assert calls == [], "a call after the pause ran"
    assert b.status(agent, ans["request_id"]).state == "pending", "the request is not pending"


@SUITE.check(
    "spent-token-refused",
    "a spent token, or one whose codemode.execute has returned, is refused token-spent, with an "
    "audit record naming the token and the execution",
    requires=TOKENS,
)
def _(b):
    runner, agent, (cmd, _), calls = _token_setup(b)

    def program(req):
        tok = runner.issue(req, [cmd])
        b.spend_token(runner.id, tok.claims["token_id"], "finished")
        before = len(b.audit())
        got = _reason(lambda: b.token_call(tok.secret, cmd, {"name": "late"}))
        return got, list(b.audit())[before:]

    def kept(req):
        return runner.issue(req, [cmd])

    got, records = runner.execute(agent, program)
    assert got == "token-spent", f"a call on a spent token was answered {got!r}"
    assert len(records) == 1, f"the refusal left {len(records)} audit records"
    rec = records[0]
    assert (rec.outcome, rec.reason, rec.caller) == ("denied", "token-spent", agent), rec
    assert rec.token_id and rec.execution_id, f"the refusal's record names no token: {rec}"
    tok = runner.execute(agent, kept)  # the program's token, held past the end of its run
    late = _reason(lambda: b.token_call(tok.secret, cmd, {"name": "after"}))
    assert late == "token-spent", f"a token used after its execute returned was answered {late!r}"
    assert calls == [], f"a spent token's call ran: {calls}"


@SUITE.check(
    "expired-token-refused",
    "a token past expires_at is refused token-expired",
    requires=[*TOKENS, "clock-control"],
)
def _(b):
    runner, agent, (cmd, _), calls = _token_setup(b)

    def program(req):
        tok = runner.issue(req, [cmd], ttl_s=5)
        first = _reason(lambda: b.token_call(tok.secret, cmd, {"name": "in-time"}))
        b.tick(6)
        return first, _reason(lambda: b.token_call(tok.secret, cmd, {"name": "late"}))

    got = runner.execute(agent, program, wall_s=5)
    assert got == (None, "token-expired"), f"before and after expiry the calls got {got}"
    assert calls == [{"name": "in-time"}], f"the handler ran for {calls}"


@SUITE.check(
    "resume-needs-a-paused-execution-and-same-code",
    "only a paused execution resumes, with the same program, and gets a new token; a running or "
    "finished one does not, and a fresh run of an existing execution id is refused",
    requires=TOKENS,
)
def _(b):
    runner, agent, (cmd, _), _ = _token_setup(b)
    eid, done, code = uniq("exec"), uniq("exec"), "lease = 1"

    def resume(req):
        return runner.issue(req, [cmd])

    def first(req):
        tok = runner.issue(req, [cmd])
        # while this run's token is live, a resume of the execution gets nothing
        live = _reason(
            lambda: runner.execute(agent, resume, execution_id=done, code=code, resume=True)
        )
        return tok, live

    _tok, live = runner.execute(agent, first, execution_id=done, code=code)
    assert live == "execution-not-resumable", f"a resume beside a live token was answered {live!r}"
    finished = _reason(
        lambda: runner.execute(agent, resume, execution_id=done, code=code, resume=True)
    )
    assert finished == "execution-not-resumable", f"a finished execution resumed: {finished!r}"
    tok, _ans = _paused_run(b, runner, agent, cmd, eid, code=code)
    other = _reason(
        lambda: runner.execute(agent, resume, execution_id=eid, code="other = 2", resume=True)
    )
    assert other == "resume-code-mismatch", f"a resume with another program was answered {other!r}"
    again = _reason(lambda: runner.execute(agent, resume, execution_id=eid, code=code))
    assert again == "execution-exists", f"a fresh run of an existing execution got {again!r}"
    new = runner.execute(agent, resume, execution_id=eid, code=code, resume=True)
    assert new.claims["token_id"] != tok.claims["token_id"] and new.secret != tok.secret, (
        "the resume was handed the old token"
    )
    assert new.claims["execution_id"] == eid and new.claims["actor"] == agent, new.claims


@SUITE.check(
    "token-run-runs-only-the-paused-request",
    "a resumed program runs the request its execution paused on, and no other request of the "
    "actor's; the run counts and answers with the request",
    requires=TOKENS,
)
def _(b):
    runner, agent, (cmd, _), calls = _token_setup(b)
    eid = uniq("exec")
    _first, paused = _paused_run(b, runner, agent, cmd, eid)
    stray = b.submit(agent, cmd, {"name": "not-paused"})  # the actor's own, outside the program

    def resumed(req):
        tok = runner.issue(req, [cmd], max_calls=1)
        other = _reason(lambda: b.token_run(tok.secret, stray))
        return other, b.token_run(tok.secret, paused["request_id"])

    other, ran = runner.execute(agent, resumed, execution_id=eid, resume=True)
    assert other == "token-request-not-paused", f"a request the run never paused on: {other!r}"
    assert ran.get("request_id") == paused["request_id"], f"token_run answered {ran}"
    assert ran.get("result") == {"ok": "approve-me"}, f"token_run answered {ran}"
    assert calls == [{"name": "approve-me"}], f"the handler ran for {calls}"
    assert b.status(agent, stray).state == "pending", "the stray request was run"


@SUITE.check(
    "token-run-names-a-denied-request",
    "token_run of a paused request its approver denied is refused request-denied, naming the "
    "request (request_id, request_digest): a decided request, not a token refusal",
    requires=[*TOKENS, "approval-control"],
)
def _(b):
    runner, agent, (cmd, _), calls = _token_setup(b)
    eid = uniq("exec")
    _first, paused = _paused_run(b, runner, agent, cmd, eid)
    b.decide_request(paused["request_id"], "denied")

    def resumed(req):
        tok = runner.issue(req, [cmd])
        try:
            b.token_run(tok.secret, paused["request_id"])
        except Denied as exc:
            return exc
        return None

    exc = runner.execute(agent, resumed, execution_id=eid, resume=True)
    assert exc is not None, "a denied request ran"
    assert exc.reason == "request-denied", f"a denied paused request was refused {exc.reason!r}"
    assert exc.reason not in TOKEN_REFUSALS, "request-denied must not be a token refusal"
    named = (getattr(exc, "request_id", None), getattr(exc, "request_digest", None))
    assert named == (paused["request_id"], paused["request_digest"]), (
        f"the refusal names {named}, not the denied request"
    )
    assert calls == [], f"the denied request's handler ran: {calls}"


@SUITE.check(
    "answers-carry-the-request",
    "a token call's answer, and a refusal raised once its request was built, name the request "
    "(request_id, request_digest)",
    requires=TOKENS,
)
def _(b):
    runner, agent, (cmd, _), _ = _token_setup(b)

    def program(req):
        tok = runner.issue(req, [cmd])
        ok = b.token_call(tok.secret, cmd, {"name": "a"})
        try:
            b.token_call(tok.secret, cmd, {"wrong": "args"})
            bad = None
        except InvalidArguments as exc:
            bad = exc
        return ok, bad, b.token_submit(tok.secret, cmd, {"name": "s"})

    ok, bad, sub = runner.execute(agent, program)
    for what, ans in (("call", ok), ("submit", sub)):
        assert isinstance(ans.get("request_id"), str) and ans["request_id"], f"{what}: {ans}"
        assert str(ans.get("request_digest", "")).startswith("sha256:"), f"{what}: {ans}"
    assert ok["result"] == {"ok": "a"}, ok
    assert bad is not None, "a token call with invalid arguments was not refused"
    rid, digest = getattr(bad, "request_id", None), getattr(bad, "request_digest", None)
    assert isinstance(rid, str) and rid and rid != ok["request_id"], (
        f"the refusal names request {rid!r}"
    )
    assert str(digest or "").startswith("sha256:"), f"the refusal names digest {digest!r}"


@SUITE.check(
    "runner-bound-to-its-runs",
    "only the runner a codemode.execute belongs to may be issued its token, spend it or read it; "
    "to another runner it is no run and no token",
    requires=TOKENS,
)
def _(b):
    stranger = _Runner(b)  # a runner too, but not the one codemode.execute's handler is
    runner, agent, (cmd, _), _ = _token_setup(b)

    def program(req):
        foreign = _reason(lambda: stranger.issue(req, [cmd]))
        tok = runner.issue(req, [cmd])
        tid = tok.claims["token_id"]
        return (
            foreign,
            tok,
            [
                _reason(lambda: b.spend_token(stranger.id, tid, "finished")),
                _reason(lambda: b.token_status(stranger.id, tid)),
                _reason(lambda: b.token_status(agent, tid)),
            ],
            b.token_status(runner.id, tid),
        )

    foreign, _tok, refused, mine = runner.execute(agent, program)
    assert foreign == "execution-not-in-flight", f"another runner was issued a token: {foreign!r}"
    assert refused == ["unknown-token", "unknown-token", "not-a-codemode-runner"], (
        f"another runner's spend and status, and a non-runner's status, were answered {refused}"
    )
    assert mine.get("state") == "live", f"the runner's own status read {mine}"


@SUITE.check(
    "secret-never-stored-or-echoed",
    "a token's secret is in no claim, no audit record and no error, refused or not; an unknown "
    "and a wrong secret get one answer",
    requires=TOKENS,
)
def _(b):
    runner, agent, (cmd, _), _ = _token_setup(b)
    before = len(b.audit())

    def program(req):
        tok = runner.issue(req, [cmd], max_calls=2)
        s = tok.secret
        wrong = s[:-1] + ("A" if s[-1] != "A" else "B")
        texts, reasons = [], []
        for presented, command in (
            (s, cmd),  # ok
            (s, _action_name()),  # not in the token
            (wrong, cmd),  # one character off
            ("hnxcmt_" + "x" * 43, cmd),  # unknown
            (s, cmd),  # the cap
        ):
            try:
                b.token_call(presented, command, {"name": "v"})
            except BrokerError as exc:
                texts.append(exc_text(exc))
                reasons.append(getattr(exc, "reason", None))
        b.spend_token(runner.id, tok.claims["token_id"], "finished")
        try:
            b.token_submit(s, cmd, {"name": "late"})
        except BrokerError as exc:
            texts.append(exc_text(exc))
        return tok, wrong, texts, reasons

    tok, wrong, texts, reasons = runner.execute(agent, program)
    assert reasons[1:3] == ["token-invalid", "token-invalid"], (
        f"a wrong and an unknown secret were told apart: {reasons[1:3]}"
    )
    assert repr(dict(tok.claims)).find(tok.secret) < 0, "the secret is a claim"
    for text in texts:
        assert tok.secret not in text and wrong not in text, "a refusal echoed the secret"
    for rec in list(b.audit())[before:]:
        assert tok.secret not in repr(rec) and wrong not in repr(rec), (
            f"the secret reached the audit trail on a {rec.operation!r} record"
        )


def make_fake():
    return FakeBroker()


def _m(factory, check, description, *, clock=False, hooks=()):
    hooks = [*hooks, *(["clock-control"] if clock else [])]
    return Mutant(factory, check, description, features=frozenset([*TOKENS, *hooks]))


MUTANTS = {
    "token-widens-grant": _m(
        WideningTokenBroker,
        "token-narrows-never-widens",
        "a token may list an action the actor is not granted, and its call is then allowed",
    ),
    "ambient-token-actor": _m(
        AmbientActorBroker,
        "actor-comes-from-the-token",
        "a token's call runs as the actor of the latest token issued, not of the one presented",
    ),
    "call-cap-left-to-client": _m(
        ClientCapBroker,
        "call-cap-enforced-by-the-broker",
        "the broker does not count a token's calls; the cap is the sandbox client's alone",
    ),
    "resume-gets-a-fresh-cap": _m(
        ResumeFreshCapBroker,
        "call-cap-is-per-execution",
        "every resume's token starts with a fresh max_calls, so pausing resets the cap",
    ),
    "paused-token-honoured": _m(
        PausedStillValidBroker,
        "paused-token-refused",
        "a paused token still makes calls, so the program runs on past the approval",
    ),
    "spent-token-honoured": _m(
        SpentStillValidBroker,
        "spent-token-refused",
        "a spent token, or one whose run has ended, still makes calls",
    ),
    "expiry-never-checked": _m(
        NoExpiryBroker,
        "expired-token-refused",
        "a token's expires_at is never checked",
        clock=True,
    ),
    "resume-ignores-code": _m(
        ResumeAnyCodeBroker,
        "resume-needs-a-paused-execution-and-same-code",
        "a resume is issued a token for another program than the paused one",
    ),
    "finished-execution-resumes": _m(
        FinishedResumesBroker,
        "resume-needs-a-paused-execution-and-same-code",
        "a finished execution resumes like a paused one",
    ),
    "denied-looks-pending": _m(
        DeniedLooksPendingBroker,
        "token-run-names-a-denied-request",
        "a denied paused request is answered request-not-approved, naming nothing",
        hooks=["approval-control"],
    ),
    "token-run-any-request": _m(
        TokenRunAnyRequestBroker,
        "token-run-runs-only-the-paused-request",
        "token_run runs any pending request of the actor's, not only the paused one",
    ),
    "refusal-without-request": _m(
        RequestlessRefusalBroker,
        "answers-carry-the-request",
        "a refusal raised after the request was built does not name it",
    ),
    "any-runner-holds-any-run": _m(
        AnyRunnerBroker,
        "runner-bound-to-its-runs",
        "any runner may issue for, spend and read another runner's run and token",
    ),
    "refusal-echoes-token": _m(
        EchoingTokenBroker,
        "secret-never-stored-or-echoed",
        "a refused token call names the secret it was given",
    ),
}
