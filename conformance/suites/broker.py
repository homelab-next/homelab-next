# SPDX-License-Identifier: Apache-2.0
"""``broker``: allowlisted commands, validated arguments, one audit record per call, and deferred
requests bound to the caller that submitted them.

``submit`` is a call that runs later, so every gate on ``call`` - the allowlist, argument
validation, redaction - is checked on ``submit`` (and its ``run``) too: a broker that gates only
the immediate path lets anyone queue anything and then run it as the request's owner."""

from __future__ import annotations

import contextlib

from conformance.fakes.command_broker import (
    CallerOnlyBroker,
    ChattyErrorBroker,
    DeferredClearAuditBroker,
    FakeBroker,
    KeyNameRedactingBroker,
    KnownSecretsOnlyBroker,
    LoggingBroker,
    OkOnlyRedactingBroker,
    RefusedSubmitUnauditedBroker,
    RunAuditedTwiceBroker,
    RunChattyErrorBroker,
    SharedRequestsBroker,
    SilentForeignAccessBroker,
    SubmitKeepsCallerArgsBroker,
    SubmitSkipsAllowlistBroker,
    SubmitSkipsArgsBroker,
    UnauditedSubmitBroker,
)
from conformance.protocols.broker import ArgSpec, BrokerError, Denied, InvalidArguments
from homelabnext.conform.core import Mutant, Suite

from ._util import exc_text, raises, uniq

SUITE = Suite(
    "broker",
    "allowlisted command execution with argument validation, a redacted audit trail and caller-bound requests",
    "conformance.protocols.broker:Broker",
)

ARGS = {"name": ArgSpec("str"), "count": ArgSpec("int", required=False)}
SPEC_SECRET = ArgSpec("str", secret=True)

#: a secret value under an argument name that does not look secret: redaction must follow the
#: schema's ``secret`` flag, so a broker that guesses from names leaks it
SECRET = "zq7-opaque-4b1d-fake-DO-NOT-LOG"
INTERNAL = "internal-detail-7c2e"


def _setup(b, handler=None):
    calls = []
    cmd, caller = uniq("cmd"), uniq("caller")
    b.register(cmd, handler or (lambda **kw: calls.append(kw) or {"ok": kw["name"]}), ARGS)
    b.allow(caller, [cmd])
    return cmd, caller, calls


@SUITE.check("allowed-call-returns-result", "an allowlisted caller gets the handler's result")
def _(b):
    cmd, caller, calls = _setup(b)
    assert b.call(caller, cmd, {"name": "x"}) == {"ok": "x"}
    assert len(calls) == 1


def _ops(b):
    """The two ways in: run now (``call``) and run later (``submit``, then the owner's ``run``)."""
    return {"call": b.call, "submit": b.submit}


@SUITE.check("unknown-command-denied", "a command nobody registered is Denied, called or submitted")
def _(b):
    caller = uniq("caller")
    b.allow(caller, ["something-else"])
    for op, fn in _ops(b).items():
        raises(lambda f=fn: f(caller, uniq("nocmd"), {}), f"{op} of an unknown command", Denied)


@SUITE.check(
    "caller-outside-allowlist-denied",
    "a registered command is refused to a caller not allowed it, called or submitted",
)
def _(b):
    cmd, _, calls = _setup(b)
    for op, fn in _ops(b).items():
        raises(lambda f=fn: f(uniq("stranger"), cmd, {"name": "x"}), f"{op} by a stranger", Denied)
    assert calls == [], "handler ran for a denied caller"


@SUITE.check(
    "allowlist-is-per-command",
    "a caller allowed one command is denied another, called or submitted; that handler never runs",
)
def _(b):
    mine, caller, _ = _setup(b)
    ran = []
    other = uniq("cmd")
    b.register(other, lambda **kw: ran.append(kw) or "wiped", ARGS)
    b.allow(uniq("admin"), [other])
    for op, fn in _ops(b).items():
        for _attempt in range(2):
            raises(lambda f=fn: f(caller, other, {"name": "x"}), f"{op}: not allowed", Denied)
    assert ran == [], "the handler of a command the caller is not allowed ran"
    assert b.call(caller, mine, {"name": "x"}) == {"ok": "x"}, "the allowed command broke"


@SUITE.check(
    "invalid-args-never-reach-handler",
    "missing, unexpected and mistyped arguments are rejected first, called or submitted",
)
def _(b):
    cmd, caller, calls = _setup(b)
    for op, fn in _ops(b).items():
        for bad in (
            {},
            {"name": "x", "evil": "rm"},
            {"name": 5},
            {"name": "x", "count": "3"},
            {"name": "x", "count": True},
        ):
            raises(lambda f=fn, a=bad: f(caller, cmd, a), f"{op} args {bad}", InvalidArguments)
    assert calls == [], "handler ran with invalid arguments"


@SUITE.check(
    "handler-error-contained",
    "a failing handler surfaces as BrokerError carrying none of the handler's internal detail, "
    "called or run later",
)
def _(b):
    def boom(**kw):
        raise ZeroDivisionError(INTERNAL)

    cmd, caller, _ = _setup(b, boom)
    rid = b.submit(caller, cmd, {"name": "x"})
    for op, fn in (
        ("call", lambda: b.call(caller, cmd, {"name": "x"})),
        ("run", lambda: b.run(caller, rid)),
    ):
        exc = raises(fn, f"failing handler ({op})", BrokerError)
        assert isinstance(exc, BrokerError), f"{op}: raised {type(exc).__name__}"
        assert INTERNAL not in exc_text(exc), (
            f"{op}: the handler's internal detail reached the caller (message, cause or context)"
        )


@SUITE.check("every-call-audited", "ok, denied, invalid and error calls each leave one record")
def _(b):
    def boom(**kw):
        raise RuntimeError("x")

    ok_cmd, caller, _ = _setup(b)
    bad_cmd = uniq("cmd")
    b.register(bad_cmd, boom, ARGS)
    b.allow(caller, [bad_cmd])
    before = len(b.audit())
    b.call(caller, ok_cmd, {"name": "a"})
    for fn in (
        lambda: b.call(uniq("stranger"), ok_cmd, {"name": "a"}),
        lambda: b.call(caller, ok_cmd, {}),
        lambda: b.call(caller, bad_cmd, {"name": "a"}),
    ):
        with contextlib.suppress(BrokerError):
            fn()
    new = list(b.audit())[before:]
    assert [r.outcome for r in new] == ["ok", "denied", "invalid", "error"], [
        r.outcome for r in new
    ]
    assert new[0].caller == caller and new[0].command == ok_cmd


@SUITE.check(
    "every-submit-audited",
    "ok, denied and invalid submits each leave one submit record, as calls do",
)
def _(b):
    cmd, caller, _ = _setup(b)
    stranger = uniq("stranger")
    before = len(b.audit())
    rid = b.submit(caller, cmd, {"name": "a"})
    for fn in (
        lambda: b.submit(stranger, cmd, {"name": "a"}),
        lambda: b.submit(caller, cmd, {}),
        lambda: b.submit(caller, uniq("nocmd"), {"name": "a"}),
    ):
        with contextlib.suppress(BrokerError):
            fn()
    new = list(b.audit())[before:]
    got = [(r.operation, r.outcome, r.caller) for r in new]
    want = [
        ("submit", "ok", caller),
        ("submit", "denied", stranger),
        ("submit", "invalid", caller),
        ("submit", "denied", caller),
    ]
    assert got == want, f"four submits (ok, stranger, invalid, unknown command) left {got}"
    assert new[0].request_id == rid, f"the accepted submit's record names {new[0].request_id!r}"


@SUITE.check(
    "submit-keeps-its-own-copy",
    "changing the mapping given to submit afterwards changes nothing that runs",
)
def _(b):
    cmd, caller, calls = _setup(b)
    given = {"name": "x"}
    rid = b.submit(caller, cmd, given)
    given["name"] = 5  # what was validated is a str: a later int must never reach the handler
    given["evil"] = "--force"
    assert b.run(caller, rid) == {"ok": "x"}, "the request ran with the caller's later changes"
    assert calls == [{"name": "x"}], f"the handler got {calls}, not the arguments submitted"


@SUITE.check(
    "audit-redacts-secret-args",
    "arguments the schema marks secret never appear in the audit trail or an error, any outcome, "
    "called or deferred",
)
def _(b):
    cmd, caller = uniq("cmd"), uniq("caller")
    spec = {"user": ArgSpec("str"), "label": ArgSpec("str", secret=True)}

    def handler(**kw):
        if kw["user"] == "fail":
            raise RuntimeError(f"cannot use {kw['label']}")
        return "done"

    b.register(cmd, handler, spec)
    b.allow(caller, [cmd])
    before = len(b.audit())
    raised = []

    def attempt(fn):
        # only what is written and raised is judged here: whether each attempt succeeds, and how
        # many records it leaves, are other checks' business
        try:
            return fn()
        except BrokerError as exc:
            raised.append(exc_text(exc))
            return None

    for who, args in (
        (caller, {"user": "svc", "label": SECRET}),  # ok
        (uniq("stranger"), {"user": "svc", "label": SECRET}),  # denied
        (caller, {"user": 7, "label": SECRET}),  # invalid
        (caller, {"user": "fail", "label": SECRET}),  # error
    ):
        attempt(lambda w=who, a=args: b.call(w, cmd, a))
    # the same outcomes on the deferred path: submit, status, run, cancel
    for args in ({"user": "svc", "label": SECRET}, {"user": "fail", "label": SECRET}):
        rid = attempt(lambda a=args: b.submit(caller, cmd, a))
        if rid is not None:
            attempt(lambda r=rid: b.status(caller, r))
            attempt(lambda r=rid: b.run(caller, r))
    attempt(lambda: b.submit(uniq("stranger"), cmd, {"user": "svc", "label": SECRET}))
    attempt(lambda: b.submit(caller, cmd, {"user": 7, "label": SECRET}))
    rid = attempt(lambda: b.submit(caller, cmd, {"user": "svc", "label": SECRET}))
    if rid is not None:
        attempt(lambda: b.cancel(caller, rid))
    records = list(b.audit())[before:]
    for rec in records:
        assert SECRET not in repr(rec) and SECRET not in repr(dict(rec.args)), (
            f"a secret argument was written to the audit trail on a {rec.outcome!r} "
            f"{rec.operation!r} record"
        )
    assert not any(SECRET in t for t in raised), "a secret argument appeared in an error"
    shown = [r for r in records if r.outcome == "ok" and r.operation == "call"]
    assert shown and all(r.args.get("user") == "svc" for r in shown), (
        "non-secret arguments should stay visible (redaction is per argument, not per record)"
    )


@SUITE.check(
    "unknown-arguments-redacted",
    "an argument the schema does not name - misspelt, or of an unknown command - is audited "
    "without its value, called or submitted",
)
def _(b):
    cmd, caller = uniq("cmd"), uniq("caller")
    b.register(cmd, lambda **kw: "rotated", {"user": ArgSpec("str"), "password": SPEC_SECRET})
    b.allow(caller, [cmd])
    before = len(b.audit())
    for fn in _ops(b).values():
        for command, args in (
            (cmd, {"user": "svc", "pasword": SECRET}),  # a typo of a secret argument's name
            (uniq("nocmd"), {"password": SECRET}),  # a command nobody registered
        ):
            with contextlib.suppress(BrokerError):
                fn(caller, command, args)
    new = list(b.audit())[before:]
    assert new, "four refused attempts left no audit record to judge (see every-call-audited)"
    for rec in new:
        assert SECRET not in repr(rec) and SECRET not in repr(dict(rec.args)), (
            f"the value of an argument the schema does not name was audited on a "
            f"{rec.outcome!r} {rec.operation!r} record"
        )


@SUITE.check(
    "run-audited-once",
    "running a request leaves exactly one record of its outcome, operation run, with its id",
)
def _(b):
    cmd, caller = uniq("cmd"), uniq("caller")
    spec = {"user": ArgSpec("str"), "label": ArgSpec("str", secret=True)}

    def handler(**kw):
        if kw["user"] == "fail":
            raise RuntimeError("handler failed")
        return "done"

    b.register(cmd, handler, spec)
    b.allow(caller, [cmd])
    for user, outcome in (("svc", "ok"), ("fail", "error")):
        rid = b.submit(caller, cmd, {"user": user, "label": SECRET})
        before = len(b.audit())
        with contextlib.suppress(BrokerError):
            b.run(caller, rid)
        new = list(b.audit())[before:]
        got = [(r.operation, r.outcome, r.request_id, r.caller, r.command) for r in new]
        assert got == [("run", outcome, rid, caller, cmd)], (
            f"a run whose handler {'failed' if user == 'fail' else 'succeeded'} left {got}"
        )
        assert new[0].args.get("user") == user, "non-secret arguments should stay visible"


@SUITE.check(
    "audit-trail-is-append-only",
    "editing the returned audit list does not change the trail",
    severity="should",
)
def _(b):
    cmd, caller, _ = _setup(b)
    b.call(caller, cmd, {"name": "x"})
    n = len(b.audit())
    got = b.audit()
    with contextlib.suppress(Exception):  # an immutable sequence is fine too
        got.clear()
    assert len(b.audit()) == n, "the trail was altered through the returned list"


@SUITE.check(
    "results-are-isolated",
    "mutating a returned result does not change later results",
    severity="should",
)
def _(b):
    cmd, caller, _ = _setup(b, lambda **kw: {"items": [1, 2]})
    first = b.call(caller, cmd, {"name": "x"})
    first["items"].append(99)
    assert b.call(caller, cmd, {"name": "x"}) == {"items": [1, 2]}


# ---- deferred requests (P-07: one caller cannot read, run or cancel another's request)
NOT_OWNER = "not-request-owner"
OWNED = {"name": ArgSpec("str"), "label": ArgSpec("str", secret=True)}


def _owned_request(b):
    """A pending request of ``owner``; ``intruder`` is allowed the very same command."""
    calls = []
    cmd, owner, intruder = uniq("cmd"), uniq("owner"), uniq("intruder")
    b.register(cmd, lambda **kw: calls.append(kw) or {"ran": kw["name"]}, OWNED)
    b.allow(owner, [cmd])
    b.allow(intruder, [cmd])
    rid = b.submit(owner, cmd, {"name": "mine", "label": SECRET})
    return cmd, owner, intruder, rid, calls


def _foreign_attempts(b, intruder, rid):
    return {
        "status": lambda: b.status(intruder, rid),
        "run": lambda: b.run(intruder, rid),
        "cancel": lambda: b.cancel(intruder, rid),
    }


@SUITE.check(
    "submitted-request-runs-for-its-owner",
    "submit defers; the owner reads it pending, runs it once, and reads it done",
)
def _(b):
    cmd, owner, _, rid, calls = _owned_request(b)
    assert calls == [], "submit ran the handler"
    st = b.status(owner, rid)
    assert (st.request_id, st.caller, st.command, st.state) == (rid, owner, cmd, "pending"), st
    assert b.run(owner, rid) == {"ran": "mine"}
    assert len(calls) == 1 and b.status(owner, rid).state == "done"
    raises(lambda: b.run(owner, rid), "running a finished request again", BrokerError)
    assert len(calls) == 1, "a finished request ran twice"


@SUITE.check(
    "requests-bound-to-caller",
    "another caller - even one allowed the same command - cannot read, run or cancel a request",
)
def _(b):
    _, owner, intruder, rid, calls = _owned_request(b)
    for who in (intruder, uniq("stranger")):
        for op, fn in _foreign_attempts(b, who, rid).items():
            exc = raises(fn, f"{op} of another caller's request", Denied)
            assert getattr(exc, "reason", None) == NOT_OWNER, (
                f"{op}: expected reason {NOT_OWNER!r}, got {getattr(exc, 'reason', None)!r}"
            )
            text = exc_text(exc)
            assert SECRET not in text and "mine" not in text, (
                f"{op}: the refusal disclosed the owner's request arguments"
            )
    assert calls == [], "another caller ran the owner's request"
    assert b.status(owner, rid).state == "pending", "another caller changed the owner's request"
    assert b.run(owner, rid) == {"ran": "mine"}, "the owner lost its own request"


@SUITE.check(
    "foreign-request-access-audited",
    "each refused read, run or cancel of another's request leaves one denied record with a reason",
)
def _(b):
    _, _, intruder, rid, _ = _owned_request(b)
    for op, fn in _foreign_attempts(b, intruder, rid).items():
        before = len(b.audit())
        with contextlib.suppress(BrokerError):
            fn()
        new = list(b.audit())[before:]
        assert len(new) == 1, f"{op}: expected one audit record for the refusal, got {len(new)}"
        rec = new[0]
        got = (rec.caller, rec.outcome, rec.reason, rec.operation, rec.request_id)
        assert got == (intruder, "denied", NOT_OWNER, op, rid), f"{op}: audit record {got}"
        assert SECRET not in repr(rec), f"{op}: the owner's secret argument reached the audit trail"


@SUITE.check(
    "cancelled-request-never-runs",
    "the owner's cancel stops a pending request for good",
)
def _(b):
    _, owner, _, rid, calls = _owned_request(b)
    b.cancel(owner, rid)
    assert b.status(owner, rid).state == "cancelled"
    raises(lambda: b.run(owner, rid), "running a cancelled request", BrokerError)
    assert calls == [], "a cancelled request ran"


@SUITE.check(
    "foreign-request-looks-unknown",
    "refusing another caller's request answers exactly as for an id that does not exist",
    severity="should",
)
def _(b):
    _, _, intruder, rid, _ = _owned_request(b)
    for op in ("status", "run", "cancel"):
        foreign = raises(_foreign_attempts(b, intruder, rid)[op], op, BrokerError)
        unknown = raises(_foreign_attempts(b, intruder, uniq("req"))[op], op, BrokerError)
        assert type(foreign) is type(unknown), f"{op}: {type(foreign)} vs {type(unknown)}"
        assert getattr(foreign, "reason", None) == getattr(unknown, "reason", None), (
            f"{op}: the reason tells a foreign request from a missing one"
        )


def make_fake():
    return FakeBroker()


MUTANTS = {
    "audit-logs-secrets": Mutant(
        LoggingBroker, "audit-redacts-secret-args", "secret arguments are audited in the clear"
    ),
    "allowlist-per-caller-only": Mutant(
        CallerOnlyBroker,
        "allowlist-is-per-command",
        "any allowlisted caller may run any registered command",
    ),
    "redacts-by-key-name": Mutant(
        KeyNameRedactingBroker,
        "audit-redacts-secret-args",
        "redaction guesses from argument names instead of the schema's secret flag",
    ),
    "redacts-ok-calls-only": Mutant(
        OkOnlyRedactingBroker,
        "audit-redacts-secret-args",
        "denied, invalid and failed calls are audited with secrets in the clear",
    ),
    "handler-error-passed-through": Mutant(
        ChattyErrorBroker,
        "handler-error-contained",
        "the handler's exception message and cause reach the caller",
    ),
    "run-error-passed-through": Mutant(
        RunChattyErrorBroker,
        "handler-error-contained",
        "run (not call) passes the handler's exception message and cause to the caller",
    ),
    "requests-shared-between-callers": Mutant(
        SharedRequestsBroker,
        "requests-bound-to-caller",
        "any caller may read, run or cancel a request another caller submitted",
    ),
    "submit-skips-allowlist": Mutant(
        SubmitSkipsAllowlistBroker,
        "caller-outside-allowlist-denied",
        "submit checks the arguments but not the allowlist, so anyone can queue any command",
    ),
    "submit-skips-arg-validation": Mutant(
        SubmitSkipsArgsBroker,
        "invalid-args-never-reach-handler",
        "submit checks the allowlist but not the arguments",
    ),
    "deferred-audit-in-clear": Mutant(
        DeferredClearAuditBroker,
        "audit-redacts-secret-args",
        "submit and run audit records carry secret arguments in the clear",
    ),
    "run-audited-twice": Mutant(
        RunAuditedTwiceBroker,
        "run-audited-once",
        "running a request leaves a started record and then its outcome",
    ),
    "submit-keeps-caller-args": Mutant(
        SubmitKeepsCallerArgsBroker,
        "submit-keeps-its-own-copy",
        "submit validates the arguments, then runs whatever the caller's mapping holds later",
    ),
    "refused-submit-unaudited": Mutant(
        RefusedSubmitUnauditedBroker,
        "every-submit-audited",
        "a denied or invalid submit leaves no audit record",
    ),
    "submit-unaudited": Mutant(
        UnauditedSubmitBroker,
        "every-submit-audited",
        "no submit leaves an audit record",
    ),
    "redacts-known-secrets-only": Mutant(
        KnownSecretsOnlyBroker,
        "unknown-arguments-redacted",
        "a misspelt secret argument, or any argument of an unknown command, is audited in clear",
    ),
    "foreign-access-not-audited": Mutant(
        SilentForeignAccessBroker,
        "foreign-request-access-audited",
        "a refused access to another caller's request leaves no audit record",
    ),
}
