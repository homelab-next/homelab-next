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
    ClientCapBroker,
    EchoingTokenBroker,
    FakeBroker,
    NoExpiryBroker,
    NoPauseBroker,
    ResumeAnyCodeBroker,
    SpentStillValidBroker,
    WideningTokenBroker,
)
from conformance.protocols.broker import CODEMODE_EXECUTE, ArgSpec, BrokerError, code_digest
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
        rid = b.token_submit(tok.secret, cmd, {"name": "s"})
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
        rid = b.token_submit(tok.secret, cmd, {"name": "approve-me"})
        return rid, [
            _reason(lambda: b.token_call(tok.secret, two, {"name": "after"})),
            _reason(lambda: b.token_submit(tok.secret, cmd, {"name": "again"})),
        ]

    rid, got = runner.execute(agent, program)
    assert got == ["token-paused", "token-paused"], f"calls after the pause were answered {got}"
    assert calls == [], "a call after the pause ran"
    assert b.status(agent, rid).state == "pending", "the submitted request is not pending"


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
        b.spend_token(runner.id, tok.claims["token_id"])
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
    "resume-needs-paused-or-spent-and-same-code",
    "a resume is issued a new token only when the execution's token is paused or spent and the "
    "program is the same; a fresh run of an existing execution id is refused",
    requires=TOKENS,
)
def _(b):
    runner, agent, (cmd, _), _ = _token_setup(b)
    eid, code = uniq("exec"), "lease = 1"

    def resume(req):
        return runner.issue(req, [cmd])

    def first(req):
        tok = runner.issue(req, [cmd])
        # while this run's token is live, a resume of the execution gets nothing
        live = _reason(
            lambda: runner.execute(agent, resume, execution_id=eid, code=code, resume=True)
        )
        return tok, live

    tok, live = runner.execute(agent, first, execution_id=eid, code=code)
    assert live == "execution-not-resumable", f"a resume beside a live token was answered {live!r}"
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
        b.spend_token(runner.id, tok.claims["token_id"])
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


MUTANTS = {
    "token-widens-grant": Mutant(
        WideningTokenBroker,
        "token-narrows-never-widens",
        "a token may list an action the actor is not granted, and its call is then allowed",
        features=frozenset(TOKENS),
    ),
    "ambient-token-actor": Mutant(
        AmbientActorBroker,
        "actor-comes-from-the-token",
        "a token's call runs as the actor of the latest token issued, not of the one presented",
        features=frozenset(TOKENS),
    ),
    "call-cap-left-to-client": Mutant(
        ClientCapBroker,
        "call-cap-enforced-by-the-broker",
        "the broker does not count a token's calls; the cap is the sandbox client's alone",
        features=frozenset(TOKENS),
    ),
    "submit-never-pauses": Mutant(
        NoPauseBroker,
        "paused-token-refused",
        "a submit through a token leaves it live, so the program runs on past the approval",
        features=frozenset(TOKENS),
    ),
    "spent-token-honoured": Mutant(
        SpentStillValidBroker,
        "spent-token-refused",
        "a spent token, or one whose run has ended, still makes calls",
        features=frozenset(TOKENS),
    ),
    "expiry-never-checked": Mutant(
        NoExpiryBroker,
        "expired-token-refused",
        "a token's expires_at is never checked",
        features=frozenset([*TOKENS, "clock-control"]),
    ),
    "resume-ignores-code": Mutant(
        ResumeAnyCodeBroker,
        "resume-needs-paused-or-spent-and-same-code",
        "a resume is issued a token for another program than the paused one",
        features=frozenset(TOKENS),
    ),
    "refusal-echoes-token": Mutant(
        EchoingTokenBroker,
        "secret-never-stored-or-echoed",
        "a refused token call names the secret it was given",
        features=frozenset(TOKENS),
    ),
}
