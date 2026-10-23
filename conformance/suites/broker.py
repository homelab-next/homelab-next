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
    LoggingBroker,
    OkOnlyRedactingBroker,
    SharedRequestsBroker,
    SilentForeignAccessBroker,
    SubmitSkipsAllowlistBroker,
    SubmitSkipsArgsBroker,
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
    assert b.run(caller, b.submit(caller, mine, {"name": "x"})) == {"ok": "x"}, (
        "the allowed submit broke"
    )


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
    "a failing handler surfaces as BrokerError carrying none of the handler's internal detail",
)
def _(b):
    def boom(**kw):
        raise ZeroDivisionError(INTERNAL)

    cmd, caller, _ = _setup(b, boom)
    exc = raises(lambda: b.call(caller, cmd, {"name": "x"}), "failing handler", BrokerError)
    assert isinstance(exc, BrokerError)
    assert INTERNAL not in exc_text(exc), (
        "the handler's internal detail reached the caller (message, cause or context)"
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
    called = list(b.audit())[before:]
    assert [r.outcome for r in called] == ["ok", "denied", "invalid", "error"], [
        r.outcome for r in called
    ]
    assert called[0].args.get("user") == "svc", "non-secret arguments should stay visible"
    # the same four outcomes on the deferred path: submit, status, run, cancel
    mid = len(b.audit())
    ok = b.submit(caller, cmd, {"user": "svc", "label": SECRET})
    b.status(caller, ok)
    assert b.run(caller, ok) == "done", "the deferred request did not run"
    attempt(lambda: b.run(caller, b.submit(caller, cmd, {"user": "fail", "label": SECRET})))
    attempt(lambda: b.submit(uniq("stranger"), cmd, {"user": "svc", "label": SECRET}))
    attempt(lambda: b.submit(caller, cmd, {"user": 7, "label": SECRET}))
    b.cancel(caller, b.submit(caller, cmd, {"user": "svc", "label": SECRET}))
    deferred = list(b.audit())[mid:]
    for rec in called + deferred:
        assert SECRET not in repr(rec) and SECRET not in repr(dict(rec.args)), (
            f"a secret argument was written to the audit trail on a {rec.outcome!r} "
            f"{getattr(rec, 'operation', 'call')!r} record"
        )
    assert len(raised) == 6 and not any(SECRET in t for t in raised), (
        f"{len(raised)} of 6 refusals raised, or a secret argument appeared in an error"
    )
    runs = [r for r in deferred if r.operation == "run" and r.request_id == ok]
    assert [r.outcome for r in runs] == ["ok"], f"the deferred run's audit records: {runs}"
    assert runs[0].args.get("user") == "svc", "non-secret arguments should stay visible"


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
    "foreign-access-not-audited": Mutant(
        SilentForeignAccessBroker,
        "foreign-request-access-audited",
        "a refused access to another caller's request leaves no audit record",
    ),
}
