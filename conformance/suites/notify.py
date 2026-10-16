# SPDX-License-Identifier: Apache-2.0
"""``notify``: a delivery channel that is exact, plus the state-diffed paging rules on top."""

from __future__ import annotations

from conformance.fakes.notify_target import DoubleSendNotifyTarget, FakeNotifyTarget
from homelabnext.conform.core import Mutant, Suite
from homelabnext.notify import Message, Notifier, SendError, UnregisteredProblem

from ._util import raises, uniq

SUITE = Suite(
    "notify",
    "exactly-once delivery of faithful messages; one page per state change, one recovery",
    "conformance.protocols.notify:NotifyTarget",
)


class _Mem:
    def __init__(self):
        self.d = {}

    def get(self, key, default=None):
        return self.d.get(key, default)

    def put(self, key, value):
        self.d[key] = value


def _notifier(t):
    n = Notifier(t.sender, _Mem(), clock=lambda: 1_000.0)
    title = uniq("Disk")
    n.register_pair(title, "Recovered: " + title)
    return n, title


def _msg(key, title, body="body", level="crit"):
    return Message(key=key, title=title, body=body, level=level)


def _for(t, key):
    return [m for m in t.received() if m.key == key]


@SUITE.check("first-report-delivers-once", "a new problem reaches the far side exactly once")
def _(t):
    n, title = _notifier(t)
    key = uniq("k")
    assert n.report(key, "crit", _msg(key, title)) is True
    got = _for(t, key)
    assert len(got) == 1, f"expected 1 delivery, got {len(got)}"


@SUITE.check("same-state-sends-once", "the same (key, state) reported again sends nothing")
def _(t):
    n, title = _notifier(t)
    key = uniq("k")
    n.report(key, "crit", _msg(key, title))
    assert n.report(key, "crit", _msg(key, title)) is False
    assert len(_for(t, key)) == 1, "repeat of an unchanged state was delivered again"


@SUITE.check("state-change-sends-again", "a different problem state is a new page")
def _(t):
    n, title = _notifier(t)
    key = uniq("k")
    n.report(key, "warn", _msg(key, title, level="warn"))
    n.report(key, "crit", _msg(key, title))
    assert len(_for(t, key)) == 2


@SUITE.check("recovery-sent-once", "returning to ok sends one recovery, then silence")
def _(t):
    n, title = _notifier(t)
    key = uniq("k")
    n.report(key, "crit", _msg(key, title))
    assert n.report(key, "ok", _msg(key, title, level="info")) is True
    assert n.report(key, "ok", _msg(key, title, level="info")) is False
    got = _for(t, key)
    assert [m.title for m in got] == [title, "Recovered: " + title], (
        f"titles {[m.title for m in got]}"
    )


@SUITE.check("ok-without-problem-is-silent", "reporting ok for a healthy key sends nothing")
def _(t):
    n, title = _notifier(t)
    key = uniq("k")
    assert n.report(key, "ok", _msg(key, title, level="info")) is False
    assert _for(t, key) == []


@SUITE.check("unregistered-problem-refused", "a problem with no recovery pair is refused unsent")
def _(t):
    n, _ = _notifier(t)
    key = uniq("k")
    raises(
        lambda: n.report(key, "crit", _msg(key, uniq("Unpaired"))),
        "unregistered problem",
        UnregisteredProblem,
    )
    assert _for(t, key) == [], "an unregistered problem was delivered"


@SUITE.check("message-fidelity", "title, body and level arrive unchanged (unicode, newlines)")
def _(t):
    n, title = _notifier(t)
    key = uniq("k")
    body = "line one\nline two — café ✓"
    n.report(key, "warn", _msg(key, title, body=body, level="warn"))
    (m,) = _for(t, key)
    assert (m.title, m.body, m.level) == (title, body, "warn"), f"arrived as {m!r}"


@SUITE.check("keys-are-independent", "two keys page independently")
def _(t):
    n, title = _notifier(t)
    a, b = uniq("k"), uniq("k")
    n.report(a, "crit", _msg(a, title))
    n.report(b, "crit", _msg(b, title))
    assert len(_for(t, a)) == 1 and len(_for(t, b)) == 1


@SUITE.check(
    "failed-send-raises-and-is-retried",
    "SendError propagates and the next report retries",
    requires=["fault-injection"],
)
def _(t):
    n, title = _notifier(t)
    key = uniq("k")
    t.fail_next(1)
    raises(lambda: n.report(key, "crit", _msg(key, title)), "failing sender", SendError)
    assert n.state_of(key) == "ok", "a failed send was recorded as sent"
    assert n.report(key, "crit", _msg(key, title)) is True
    assert len(_for(t, key)) == 1


def make_fake():
    return FakeNotifyTarget()


MUTANTS = {
    "double-send": Mutant(
        DoubleSendNotifyTarget, "first-report-delivers-once", "every message is delivered twice"
    ),
}
