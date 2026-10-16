# SPDX-License-Identifier: Apache-2.0
"""``broker``: allowlisted commands, validated arguments, one audit record per call."""

from __future__ import annotations

import contextlib

from conformance.fakes.command_broker import FakeBroker, LoggingBroker
from conformance.protocols.broker import ArgSpec, BrokerError, Denied, InvalidArguments
from homelabnext.conform.core import Mutant, Suite

from ._util import raises, uniq

SUITE = Suite(
    "broker",
    "allowlisted command execution with argument validation and a redacted audit trail",
    "conformance.protocols.broker:Broker",
)

ARGS = {"name": ArgSpec("str"), "count": ArgSpec("int", required=False)}


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


@SUITE.check("unknown-command-denied", "a command nobody registered is Denied")
def _(b):
    caller = uniq("caller")
    b.allow(caller, ["something-else"])
    raises(lambda: b.call(caller, uniq("nocmd"), {}), "unknown command", Denied)


@SUITE.check(
    "caller-outside-allowlist-denied", "a registered command is refused to a caller not allowed it"
)
def _(b):
    cmd, _, calls = _setup(b)
    raises(lambda: b.call(uniq("stranger"), cmd, {"name": "x"}), "stranger", Denied)
    assert calls == [], "handler ran for a denied caller"


@SUITE.check(
    "invalid-args-never-reach-handler",
    "missing, unexpected and mistyped arguments are rejected first",
)
def _(b):
    cmd, caller, calls = _setup(b)
    for bad in (
        {},
        {"name": "x", "evil": "rm"},
        {"name": 5},
        {"name": "x", "count": "3"},
        {"name": "x", "count": True},
    ):
        raises(lambda a=bad: b.call(caller, cmd, a), f"args {bad}", InvalidArguments)
    assert calls == [], "handler ran with invalid arguments"


@SUITE.check(
    "handler-error-contained", "a failing handler surfaces as BrokerError, not a raw exception"
)
def _(b):
    def boom(**kw):
        raise ZeroDivisionError("internal detail")

    cmd, caller, _ = _setup(b, boom)
    exc = raises(lambda: b.call(caller, cmd, {"name": "x"}), "failing handler", BrokerError)
    assert isinstance(exc, BrokerError)


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


@SUITE.check("audit-redacts-secret-args", "arguments marked secret never appear in the audit trail")
def _(b):
    cmd, caller = uniq("cmd"), uniq("caller")
    b.register(
        cmd, lambda **kw: "done", {"user": ArgSpec("str"), "token": ArgSpec("str", secret=True)}
    )
    b.allow(caller, [cmd])
    b.call(caller, cmd, {"user": "svc", "token": "tok-SECRET-123"})
    dump = " ".join(repr(r) for r in b.audit())
    assert "tok-SECRET-123" not in dump, "a secret argument was written to the audit trail"
    rec = [r for r in b.audit() if r.command == cmd][-1]
    assert rec.args.get("user") == "svc", "non-secret arguments should stay visible"


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


def make_fake():
    return FakeBroker()


MUTANTS = {
    "audit-logs-secrets": Mutant(
        LoggingBroker, "audit-redacts-secret-args", "secret arguments are audited in the clear"
    ),
}
