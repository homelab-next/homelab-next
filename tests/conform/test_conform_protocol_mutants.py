# SPDX-License-Identifier: Apache-2.0
"""Each suite fails a subject that breaks a clause its Protocol states.

Every fake named here breaks one stated clause and used to pass its whole suite: the suites
pinned only the defects their own mutants modelled.  The table is the regression record: a
suite that loses one of these checks (or weakens it) lets the fake through again, and the test
says which.  Each fake is also registered as a mutant, so ``hnx conform mutants`` keeps proving
it.
"""

import importlib

import pytest

from homelabnext.conform.core import run_checks
from homelabnext.conform.registry import load_module

#: (capability, fakes module, broken fake, the check that must fail it)
CASES = [
    ("broker", "command_broker", "SubmitSkipsAllowlistBroker", "caller-outside-allowlist-denied"),
    ("broker", "command_broker", "SubmitSkipsArgsBroker", "invalid-args-never-reach-handler"),
    ("broker", "command_broker", "DeferredClearAuditBroker", "audit-redacts-secret-args"),
    ("events", "event_bus", "StaleSettleEventBus", "stale-delivery-settles-nothing"),
    ("events", "event_bus", "ReplayingEventBus", "new-consumer-starts-at-creation"),
]


def _factory(module, name):
    return getattr(importlib.import_module(f"conformance.fakes.{module}"), name)


@pytest.mark.parametrize(("cap", "module", "name", "check"), CASES)
def test_the_suite_fails_the_protocol_violating_fake(cap, module, name, check):
    results = run_checks(load_module(cap).SUITE, _factory(module, name))
    failed = [r.check for r in results if r.status == "fail"]
    assert failed, f"{cap}: {name} passed every check (the suite cannot see the defect)"
    assert check in failed, f"{cap}: {name} failed {failed}, not {check!r}"


@pytest.mark.parametrize(("cap", "module", "name", "check"), CASES)
def test_the_fake_is_registered_as_a_mutant_of_that_check(cap, module, name, check):
    factory = _factory(module, name)
    named = [m.fails for m in load_module(cap).MUTANTS.values() if m.factory is factory]
    assert named == [check], f"{cap}: {name} registered for {named}, expected [{check!r}]"


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
