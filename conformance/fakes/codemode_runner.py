# SPDX-License-Identifier: Apache-2.0
"""Subjects for the ``codemode-runner`` suite: the reference runner over a broker, and mutants.

The runner itself is the product's (:class:`homelabnext.codemode.runner.Runner`); what is fake
here is what it runs against: the in-memory broker (:class:`conformance.fakes.command_broker.
FakeBroker`) or the reference broker service in process (``broker="reference"``), and the
test-only forking executor (:class:`conformance.fakes.code_executor.ForkingExecutor`, **not an
isolation boundary**).  Each subject has a private journal directory, removed by ``close``.  The
mutants change one thing each, and the suite must catch each with its own check.
"""

from __future__ import annotations

import contextlib
import shutil
import tempfile
from typing import Any

from conformance.fakes.code_executor import ForkingExecutor
from conformance.fakes.command_broker import FakeBroker
from homelabnext.codemode.runner import Runner

__all__ = [
    "CapHiddenRunner",
    "DenialAsErrorRunner",
    "HiddenPauseRunner",
    "RawLogsRunner",
    "ReferenceRunner",
    "ResendingRunner",
    "UnjournalledRefusalRunner",
    "make",
]


def _granted(broker: Any):
    """What a token may list for an actor, asked of the broker the runner serves."""
    actions_for = getattr(broker, "actions_for", None)
    if callable(actions_for):  # the reference service: decide()'s own view
        return lambda actor: [row["action"] for row in actions_for(actor)]
    return lambda actor: sorted(broker._allow.get(actor, ()))  # the fake's allowlist


class ReferenceRunner(Runner):
    """The runner over ``broker`` and a forking executor, registered as ``codemode.execute``'s
    handler; ``features`` are the broker's (its test hooks)."""

    def __init__(self, broker: Any = None) -> None:
        broker = FakeBroker() if broker is None else broker
        self._tmp = tempfile.mkdtemp(prefix="hnx-codemode-runner-")
        super().__init__(broker, ForkingExecutor(), self._tmp, actions_for=_granted(broker))
        self.features = frozenset(getattr(broker, "features", ()))
        broker.register_runner(self.runner_id, self.handle)

    def close(self) -> None:
        self.executor.close()
        shutil.rmtree(self._tmp, ignore_errors=True)
        close = getattr(self.broker, "close", None)
        if callable(close):
            close()


def make(**config: Any) -> ReferenceRunner:
    """Conformance factory: ``broker: fake`` (the default) or ``reference`` (the reference
    broker service over a private temporary state directory, ``homelabnext.broker.service:
    make``)."""
    which = config.get("broker", "fake")
    if which == "fake":
        return ReferenceRunner()
    if which == "reference":
        from homelabnext.broker.service import make as make_service

        return ReferenceRunner(make_service())
    raise ValueError(f"broker is fake or reference, not {which!r}")


class RawLogsRunner(ReferenceRunner):
    """Mutant: program output reaches ``logs`` as printed, control characters and all, and the
    result is returned without being held to its schema."""

    def _log_lines(self, output):
        return [line for line in output.split("\n") if line]

    def _check_result(self, out):
        return None


class DenialAsErrorRunner(ReferenceRunner):
    """Mutant: a broker refusal reaches the program as ``broker.Error``, not ``broker.Denied``
    (the record still says denied)."""

    def _refusal(self, run, step, action, target, exc, fp):
        reply = super()._refusal(run, step, action, target, exc, fp)
        return _as_error(reply)

    def _refused(self, run, step, action, target, outcome, reason):
        return _as_error(super()._refused(run, step, action, target, outcome, reason))


def _as_error(reply):
    if reply.get("denied"):
        return {"ok": False, "error": True, "reason": reply["reason"]}
    return reply


class UnjournalledRefusalRunner(ReferenceRunner):
    """Mutant: a refusal the broker answered with a request id is not journalled."""

    def _journal(self, run, rec, fp):
        if rec["outcome"] in ("denied", "error"):
            return
        super()._journal(run, rec, fp)


class HiddenPauseRunner(ReferenceRunner):
    """Mutant: a pending answer is journalled and recorded, but the program is told ``ok`` and
    runs on past the pause."""

    def _answered(self, run, step, action, target, answer, fp):
        reply = super()._answered(run, step, action, target, answer, fp)
        return {"ok": True, "value": None} if reply.get("pending") else reply


class ResendingRunner(ReferenceRunner):
    """Mutant: a resume sends every journalled step to the broker again (and then answers it
    from the journal, marked replayed, as if it had not)."""

    def _replay(self, run, step, entry, action, fp):
        rec = entry["record"]
        if rec["outcome"] != "pending":
            args = getattr(run, "_last_args", {})
            with contextlib.suppress(Exception):
                self.sandbox_broker.token_call(run.secret, action, args)
        return super()._replay(run, step, entry, action, fp)

    def serve_call(self, run, msg):
        if isinstance(msg, dict):
            run._last_args = dict(msg.get("args") or {})
        return super().serve_call(run, msg)


class CapHiddenRunner(ReferenceRunner):
    """Mutant: a call the broker refuses ``call-cap-reached`` is recorded, but the run ends with
    the program's own status (``ok`` when it caught the refusal)."""

    def _refused(self, run, step, action, target, outcome, reason):
        reply = super()._refused(run, step, action, target, outcome, reason)
        run.capped = False
        return reply
