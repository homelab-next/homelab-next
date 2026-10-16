# SPDX-License-Identifier: Apache-2.0
"""``orchestration``: idempotent submission, bounded retries, cancellation, isolation."""

from __future__ import annotations

from conformance.fakes.orchestrator import FakeOrchestrator, NoDedupeOrchestrator
from conformance.protocols.orchestration import UnknownJob
from homelabnext.conform.core import Mutant, Suite

from ._util import raises, uniq

SUITE = Suite(
    "orchestration",
    "named jobs: run once per idempotency key, retry a bounded number of times, cancel, isolate",
    "conformance.protocols.orchestration:Orchestrator",
)


@SUITE.check("runs-job-and-returns-result", "a submitted job runs and its result is reported")
def _(o):
    name = uniq("job")
    o.define(name, lambda p: {"echo": p["x"] * 2})
    st = o.wait(o.submit(name, {"x": 21}, idempotency_key=uniq("k")))
    assert st.state == "succeeded" and st.result == {"echo": 42}, f"status {st}"
    assert st.attempts == 1


@SUITE.check("idempotency-key-runs-once", "the same key twice gives one run and one execution")
def _(o):
    name, key, calls = uniq("job"), uniq("k"), []
    o.define(name, lambda p: calls.append(1) or "done")
    r1 = o.submit(name, {}, idempotency_key=key)
    r2 = o.submit(name, {}, idempotency_key=key)
    o.wait(r1)
    o.wait(r2)
    assert r1 == r2, f"run ids differ: {r1} vs {r2}"
    assert len(calls) == 1, f"job body ran {len(calls)} times"


@SUITE.check("distinct-keys-distinct-runs", "different keys are different runs")
def _(o):
    name, calls = uniq("job"), []
    o.define(name, lambda p: calls.append(1))
    a = o.submit(name, {}, idempotency_key=uniq("k"))
    b = o.submit(name, {}, idempotency_key=uniq("k"))
    o.wait(a)
    o.wait(b)
    assert a != b and len(calls) == 2


@SUITE.check("failure-is-recorded", "a raising job ends failed with its error text and one attempt")
def _(o):
    name = uniq("job")

    def boom(p):
        raise RuntimeError("kaboom")

    o.define(name, boom)
    st = o.wait(o.submit(name, {}, idempotency_key=uniq("k")))
    assert st.state == "failed" and st.attempts == 1, f"status {st}"
    assert "kaboom" in (st.error or ""), f"error text {st.error!r}"


@SUITE.check(
    "retries-until-success", "a job that fails twice succeeds on the third attempt with retries=2"
)
def _(o):
    name, n = uniq("job"), []

    def flaky(p):
        n.append(1)
        if len(n) < 3:
            raise RuntimeError("transient")
        return "ok"

    o.define(name, flaky, retries=2)
    st = o.wait(o.submit(name, {}, idempotency_key=uniq("k")))
    assert (st.state, st.attempts, st.result) == ("succeeded", 3, "ok"), f"status {st}"


@SUITE.check("retries-are-bounded", "a job that always fails stops after retries + 1 attempts")
def _(o):
    name, n = uniq("job"), []

    def always(p):
        n.append(1)
        raise RuntimeError("no")

    o.define(name, always, retries=1)
    st = o.wait(o.submit(name, {}, idempotency_key=uniq("k")))
    assert st.state == "failed" and st.attempts == 2 and len(n) == 2, f"status {st}, calls {len(n)}"


@SUITE.check("unknown-job-raises", "submitting an undefined job raises UnknownJob")
def _(o):
    raises(
        lambda: o.submit(uniq("nojob"), {}, idempotency_key=uniq("k")), "unknown job", UnknownJob
    )


@SUITE.check("cancel-before-start-never-runs", "a cancelled queued run does not execute")
def _(o):
    name, calls = uniq("job"), []
    o.define(name, lambda p: calls.append(1))
    rid = o.submit(name, {}, idempotency_key=uniq("k"))
    assert o.cancel(rid).state == "cancelled"
    assert o.wait(rid).state == "cancelled"
    assert calls == [], "a cancelled run executed"


@SUITE.check("cancel-finished-run-is-noop", "cancelling a finished run leaves it as it was")
def _(o):
    name = uniq("job")
    o.define(name, lambda p: 1)
    rid = o.submit(name, {}, idempotency_key=uniq("k"))
    o.wait(rid)
    assert o.cancel(rid).state == "succeeded"


@SUITE.check("params-arrive-unchanged", "nested parameters reach the handler as submitted")
def _(o):
    name, seen = uniq("job"), []
    o.define(name, lambda p: seen.append(p))
    params = {"a": [1, 2, {"b": None}], "c": "café", "d": 1.5}
    o.wait(o.submit(name, params, idempotency_key=uniq("k")))
    assert seen == [params], f"handler saw {seen}"


@SUITE.check("failing-run-does-not-affect-others", "one failed run leaves another run unharmed")
def _(o):
    bad, good = uniq("job"), uniq("job")

    def boom(p):
        raise RuntimeError("x")

    o.define(bad, boom)
    o.define(good, lambda p: "fine")
    rb = o.submit(bad, {}, idempotency_key=uniq("k"))
    rg = o.submit(good, {}, idempotency_key=uniq("k"))
    assert o.wait(rb).state == "failed"
    assert o.wait(rg).state == "succeeded"


def make_fake():
    return FakeOrchestrator()


MUTANTS = {
    "idempotency-ignored": Mutant(
        NoDedupeOrchestrator,
        "idempotency-key-runs-once",
        "a repeated key starts a second run",
    ),
}
