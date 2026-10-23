# SPDX-License-Identifier: Apache-2.0
"""The record of the protocol violators that review found passing their suites.

Each name below is a deliberately broken fake that breaks one clause of its Protocol docstring
and used to pass its whole suite: the suites pinned only the defects their own mutants modelled.
Every one is registered in its suite's ``MUTANTS``, which is the single table of what each fake
breaks and which check must fail it; ``tests/conform/test_conform_mutants.py`` (and ``hnx conform
mutants``) prove each is caught by that check.  This file only keeps the record: a mutant dropped
from ``MUTANTS`` - and with it the proof - fails here by name.
"""

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
    },
    "events": {
        "loses-unsettled-on-restart",
        "restart-at-tail",
        "double-settle",
        "stale-delivery-settles",
        "new-consumer-replays-history",
    },
    "records": {
        "completes-inbox-notes",
        "completes-denied-notes",
        "partial-completion",
        "decide-follows-traversal",
        "read-follows-traversal",
        "approve-overturns-denial",
        "deny-withdraws-approval",
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
