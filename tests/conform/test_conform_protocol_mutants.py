# SPDX-License-Identifier: Apache-2.0
"""The record of the protocol violators that review found passing their suites.

Each name below is a deliberately broken fake that breaks one clause of its Protocol docstring
and used to pass its whole suite: the suites pinned only the defects their own mutants modelled.
Every one is registered in its suite's ``MUTANTS``, which is the single table of what each fake
breaks and which check must fail it; ``tests/conform/test_conform_mutants.py`` (and ``hnx conform
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
        "decide-check-then-copy",
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
    },
    "idp": {
        "alg-none-accepted",
        "empty-signature-accepted",
        "exp-not-enforced",
        "scope-matched-as-substring",
        "revocation-skipped-when-scoped",
        "non-finite-ttl-accepted",
    },
    "lake-query": {"interpolated-params"},
    "object-store": {
        "keys-resolved-as-paths",
        "head-missing-is-empty",
        "delete-missing-bucket-succeeds",
        "delete-reaches-every-bucket",
    },
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


def test_the_reference_idp_refuses_a_ttl_that_never_ends():
    """The reference fake accepted ``ttl=nan`` (``nan <= 0`` is False): the token still verified
    after a billion seconds."""
    from conformance.fakes.identity import FakeIdentityProvider

    p = FakeIdentityProvider()
    for ttl in (float("nan"), float("inf")):
        with pytest.raises(ValueError):
            p.issue("user", ["read"], ttl)


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


# ---- the interleaving harness behind records' decide-is-atomic ----------------------------------


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

    return interleavings(counter, setup, blocked_after=0.2)


def test_the_interleaving_finds_a_lost_update_every_time():
    """Deterministic, not timing: the first bump is stopped between its read and its write on
    every run, so the lost update is found on every run, at the same schedule."""
    for _ in range(3):
        with pytest.raises(AssertionError, match="lost update"):
            _race(_Counter(lock=False))


def test_a_subject_that_serialises_on_a_lock_passes_and_ends_early():
    """Paused inside the lock, the second bump blocks: the first is resumed, the pair passes, and
    no later point is tried (the unpaused run, then lines 1-2 before the lock, then line 3)."""
    assert _race(_Counter(lock=True)) == 4
