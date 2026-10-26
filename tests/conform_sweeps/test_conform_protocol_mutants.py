# SPDX-License-Identifier: Apache-2.0
"""The record of the protocol violators that review found passing their suites.

Each name below is a deliberately broken fake that breaks one clause of its Protocol docstring
and used to pass its whole suite: the suites pinned only the defects their own mutants modelled.
Every one is registered in its suite's ``MUTANTS``, which is the single table of what each fake
breaks and which check must fail it; ``tests/conform_sweeps/test_conform_mutants.py`` (and ``hnx conform
mutants``) prove each is caught by that check.  This file only keeps the record: a mutant dropped
from ``MUTANTS`` - and with it the proof - fails here by name.
"""

import threading

import pytest

from homelabnext.conform.core import run_checks
from homelabnext.conform.registry import load_module

#: capability -> the mutants each review round found (by their ``MUTANTS`` name)
REVIEWED = {
    "broker": {
        # first round
        "allowlist-per-caller-only",
        "redacts-by-key-name",
        "redacts-ok-calls-only",
        "handler-error-passed-through",
        "submit-skips-allowlist",
        "submit-skips-arg-validation",
        "deferred-audit-in-clear",
        # second round
        "run-audited-twice",
        "run-error-passed-through",
        "submit-keeps-caller-args",
        "refused-submit-unaudited",
        "submit-unaudited",
        "redacts-known-secrets-only",
        # third round (verify)
        "redacts-unknown-by-name-guess",
        "refusal-echoes-unexpected-values",
    },
    "events": {
        "loses-unsettled-on-restart",
        "restart-at-tail",
        "double-settle",
        "stale-delivery-settles",
        "new-consumer-replays-history",
        "stale-term-dead-letters-live",
        "stale-nack-requeues-acked",
        "settled-nack-requeues",
        "work-queue-retention",
        "dead-letters-in-client-memory",
        "crash-loop-never-dead-letters",
    },
    "records": {
        "completes-inbox-notes",
        "completes-denied-notes",
        "partial-completion",
        "decide-follows-traversal",
        "read-follows-traversal",
        "approve-overturns-denial",
        "deny-withdraws-approval",
        "namesake-overwrites-decision",
    },
    "secrets": {
        "error-cause-leaks-value",
        "lease-never-expires",
        "unknown-lease-valid",
        "negative-ttl-accepted",
        "version-zero-is-latest",
        "negative-version-indexes-from-end",
        "version-error-leaks-value",
        "delete-drops-latest-only",
        "stores-caller-mapping",
        "version-coerced",
        "put-after-delete-revives-history",
        "deleted-path-listed-under-parent",
        "lease-shares-stored-mapping",
        "non-finite-lease-ttl-accepted",
        "versioned-get-shares-stored-mapping",
        "lease-cached-per-path",
    },
    "idp": {
        "alg-none-accepted",
        "empty-signature-accepted",
        "exp-not-enforced",
        "scope-matched-as-substring",
        "revocation-skipped-when-scoped",
        "non-finite-ttl-accepted",
        "empty-scope-is-no-scope",
        "scope-case-insensitive",
        "space-delimited-scopes",
        "bare-string-scopes-split-into-characters",
        "bare-string-scopes-split-on-spaces",
        "scope-checked-before-signature",
    },
    "lake-query": {"interpolated-params"},
    "object-store": {
        "keys-resolved-as-paths",
        "head-missing-is-empty",
        "delete-missing-bucket-succeeds",
        "delete-reaches-every-bucket",
        "flat-keyspace",
        "key-segments-collapsed",
        "deleted-key-listed",
        "keys-form-decoded",
        "keys-case-folded",
        "dotted-flat-keyspace",
    },
    # the CM-4 design review (PR #66): clauses added to match schemas/codemode
    "codemode-executor": {"no-call-cap", "pause-catchable"},
}


@pytest.mark.parametrize("cap", sorted(REVIEWED))
def test_every_reviewed_violator_is_a_registered_mutant(cap):
    mutants = load_module(cap).MUTANTS
    missing = sorted(REVIEWED[cap] - set(mutants))
    assert not missing, f"{cap}: no longer registered (and so no longer proved): {missing}"
    factories = [mutants[n].factory for n in REVIEWED[cap]]
    assert len(set(factories)) == len(factories), f"{cap}: two names share one broken fake"


def _check(cap, check, factory):
    (result,) = run_checks(load_module(cap).SUITE, factory, only=[check])
    return result


def test_a_redaction_failure_means_redaction():
    """``audit-redacts-secret-args`` once also asserted the deferred run's success, its audit
    shape and the refusal count, so a broker whose run was merely audited twice, or whose submit
    skipped validation, failed a check named for redaction.  Those are their own checks now."""
    from conformance.fakes.command_broker import RunAuditedTwiceBroker, SubmitSkipsArgsBroker

    for broken in (RunAuditedTwiceBroker, SubmitSkipsArgsBroker):
        assert _check("broker", "audit-redacts-secret-args", broken).status == "pass", broken
    assert _check("broker", "run-audited-once", RunAuditedTwiceBroker).status == "fail"


def test_a_stale_delivery_never_settles_the_live_one_in_the_reference_bus():
    """The reference fake used to key in-flight state by message: an old process's late ack
    settled the new process's redelivery, and the new process's nack was then dropped."""
    from conformance.fakes.event_bus import FakeEventBus

    bus = FakeEventBus()
    c = bus.consumer("c", "s.x")
    bus.publish("s.x", b"m")
    (old,) = c.fetch(1)
    c = bus.consumer("c", "s.x")
    (live,) = c.fetch(1)
    old.ack()
    live.nack()
    assert [d.data for d in c.fetch(5)] == [b"m"]


def test_the_reference_bus_dead_letters_a_message_its_consumer_keeps_crashing_on():
    """The reference fake counted only nacks against ``max_deliver``: a poison message whose
    consumer died before settling it came back at attempts 1, 2, 3, 4, ... for ever, while
    JetStream counts every delivery and dead-letters it."""
    from conformance.fakes.event_bus import FakeEventBus

    bus = FakeEventBus()
    c = bus.consumer("c", "s.x", max_deliver=3)
    bus.publish("s.x", b"poison")
    seen = []
    for _ in range(5):
        got = c.fetch(1)
        if not got:
            break
        seen.append(got[0].attempt)
        c = bus.consumer("c", "s.x", max_deliver=3)
    assert seen == [1, 2, 3] and [d.data for d in c.dead_letters()] == [b"poison"]


def test_the_reference_idp_refuses_a_ttl_that_never_ends():
    """The reference fake accepted ``ttl=nan`` (``nan <= 0`` is False): the token still verified
    after a billion seconds."""
    from conformance.fakes.identity import FakeIdentityProvider

    p = FakeIdentityProvider()
    for ttl in (float("nan"), float("inf")):
        with pytest.raises(ValueError):
            p.issue("user", ["read"], ttl)


def test_the_reference_idp_refuses_a_bare_string_for_the_scope_list():
    """``issue("u", "read", ttl)`` granted the scopes ``('r', 'e', 'a', 'd')``, so a check for
    ``r`` passed; a bare string is now refused."""
    from conformance.fakes.identity import FakeIdentityProvider

    with pytest.raises(TypeError):
        FakeIdentityProvider().issue("user", "read", 60)


def test_the_reference_secret_store_refuses_a_lease_that_never_ends():
    """``lease(p, inf)`` was still valid after ``tick(1e12)``, and ``lease(p, nan)`` was accepted
    and born expired."""
    from conformance.fakes.secret_store import FakeSecretStore
    from conformance.protocols.secrets import LeaseError

    s = FakeSecretStore()
    s.put("a/b", {"k": "v"})
    for ttl in (float("inf"), float("nan")):
        with pytest.raises(LeaseError):
            s.lease("a/b", ttl)


def test_the_reference_broker_redacts_what_its_schema_does_not_name():
    """The reference fake redacted by known key only: a misspelt secret argument, and any
    argument of an unregistered command, were audited in the clear."""
    from conformance.fakes.command_broker import FakeBroker
    from conformance.protocols.broker import ArgSpec, BrokerError

    b = FakeBroker()
    b.register("rotate", lambda **kw: "ok", {"password": ArgSpec("str", secret=True)})
    b.allow("u", ["rotate"])
    for command, args in (("rotate", {"pasword": "typo-value"}), ("rotat", {"password": "x-1"})):
        with pytest.raises(BrokerError):
            b.call("u", command, args)
    assert [dict(r.args) for r in b.audit()] == [
        {"pasword": "<redacted>"},
        {"password": "<redacted>"},
    ]


# ---- the interleaving harness behind records' decide-is-atomic (a SHOULD) -----------------------


class _Counter:
    """A read-modify-write on two lines, with or without a lock around it."""

    def __init__(self, lock: bool) -> None:
        self.n = 0
        self.lock = threading.Lock() if lock else None

    def bump(self) -> int:
        if self.lock is None:
            seen = self.n
            self.n = seen + 1
            return self.n
        with self.lock:
            seen = self.n
            self.n = seen + 1
            return self.n


def _race(counter):
    from conformance.suites._util import interleavings

    def setup():
        start = counter.n

        def judge(out1, out2):
            assert out1[0] and out2[0], (out1, out2)
            assert counter.n == start + 2, f"lost update: {start} -> {counter.n}"

        return counter.bump, counter.bump, judge

    return interleavings(counter, setup, blocked_after=0.05)


def test_the_interleaving_finds_a_lost_update_every_time():
    """Deterministic, not timing: the first bump is stopped between its read and its write on
    every run, so the lost update is found on every run, at the same schedule."""
    for _ in range(3):
        with pytest.raises(AssertionError, match="lost update"):
            _race(_Counter(lock=False))


def test_a_subject_that_serialises_on_a_lock_passes_at_every_point():
    """Paused inside the lock, the second bump blocks: the first is resumed and the pair passes.
    A blocked point no longer ends exploration (the window after a lock is still tried)."""
    assert _race(_Counter(lock=True)) >= 5


def _atomic(factory):
    (result,) = run_checks(load_module("records").SUITE, factory, only=["decide-is-atomic"])
    return result


def test_decide_is_atomic_fails_a_copy_then_unlink_decider():
    """The second review's racy decider (check, copy, unlink): an approve and a deny raced on one
    note both succeed.  The check is a SHOULD (it explores single-preemption schedules only), so
    the decider is pinned here rather than as a MUST mutant."""
    from conformance.fakes.records_target import CheckThenCopyRecordsTarget

    result = _atomic(CheckThenCopyRecordsTarget)
    assert result.status == "fail" and "both succeeded" in result.evidence, result


def test_decide_is_atomic_tries_the_window_after_a_lock():
    """A decider that locks only its existence check, then copies and unlinks outside the lock,
    passed: the first paused point inside the lock blocked the other decision, and a blocked
    schedule ended the exploration before the window after the lock was tried."""
    from conformance.fakes.records_target import FakeRecordsTarget

    class LockedCheckOnly(FakeRecordsTarget):
        def __init__(self) -> None:
            super().__init__()
            self._lock = threading.Lock()

        def _decide(self, name, lane):
            with self._lock:
                self._decider._load("inbox", name)
            src = self._dir / "inbox" / name
            data = src.read_bytes()
            (self._dir / lane / name).write_bytes(data)
            src.unlink(missing_ok=True)

        def approve(self, name):
            self._decide(name, "decided/approved")

        def deny(self, name, reason=None):
            self._decide(name, "decided/denied")

    assert _atomic(LockedCheckOnly).status == "fail"


def test_decide_is_atomic_never_fails_a_correct_decider_whose_lock_times_out():
    """A correct decider that waits at most 0.1s for its lock used to fail: the harness held the
    lock paused for a second, and the loser's TimeoutError was judged.  A loser may fail any
    way; only both succeeding, or the note leaving the inbox for the wrong lane, is wrong."""
    from conformance.fakes.records_target import FakeRecordsTarget

    class LockTimeoutRecords(FakeRecordsTarget):
        def __init__(self) -> None:
            super().__init__()
            self._lock = threading.Lock()

        def _decide(self, decide, *args):
            if not self._lock.acquire(timeout=0.1):
                raise TimeoutError("decision lock busy")
            try:
                decide(*args)
            finally:
                self._lock.release()

        def approve(self, name):
            self._decide(super().approve, name)

        def deny(self, name, reason=None):
            self._decide(super().deny, name, reason)

    assert _atomic(LockTimeoutRecords).status == "pass"


def test_a_subject_with_nothing_to_pause_at_is_not_judged():
    from conformance.suites._util import Inconclusive, interleavings

    class Opaque:
        pass

    with pytest.raises(Inconclusive):
        interleavings(Opaque(), lambda: (int, int, lambda *_: None))
