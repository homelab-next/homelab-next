# SPDX-License-Identifier: Apache-2.0
import json

import lakes
import pytest

from homelabnext.lake import FakeLake, LakeError
from homelabnext.swap import DualWriter


class Flaky:
    """Wraps a lake; fails the next N write_batch calls."""

    def __init__(self, inner, fail=0, exc=None):
        self.inner, self.fail = inner, fail
        self.exc = exc or LakeError("secondary down")

    def write_batch(self, *a, **kw):
        if self.fail:
            self.fail -= 1
            raise self.exc
        return self.inner.write_batch(*a, **kw)

    def __getattr__(self, n):
        return getattr(self.inner, n)


def rows(n=5):
    return lakes.rows_for("dns_activity")[:n]


def test_both_sides_receive_the_batch_with_the_same_key():
    a, b = FakeLake(), FakeLake()
    w = DualWriter(a, b)
    res = w.write_batch("dns_activity", rows(), idempotency_key="k1")
    assert res.rows_written == 5 and not w.divergences
    assert b.describe("dns_activity").row_count == 5
    assert w.write_batch("dns_activity", rows(), idempotency_key="k1").replayed  # idempotent
    assert b.describe("dns_activity").row_count == 5


def test_secondary_failure_never_blocks_the_primary(tmp_path):
    a, b = FakeLake(), Flaky(FakeLake(), fail=1)
    log = tmp_path / "div.jsonl"
    w = DualWriter(a, b, divergence_log=log)
    res = w.write_batch("dns_activity", rows(), idempotency_key="k1")
    assert res.rows_written == 5  # the primary result is returned untouched
    assert a.describe("dns_activity").row_count == 5
    assert [d.kind for d in w.divergences] == ["secondary_error"]
    assert w.status()["unresolved"] == 1
    line = json.loads(log.read_text().splitlines()[0])
    assert line["kind"] == "secondary_error" and line["table"] == "dns_activity"
    assert w.replay_pending() == 1 and w.status()["unresolved"] == 0
    assert b.inner.describe("dns_activity").row_count == 5


def test_replay_is_safe_when_secondary_actually_wrote():
    a, inner = FakeLake(), FakeLake()
    b = Flaky(inner)
    w = DualWriter(a, b)
    w.write_batch("dns_activity", rows(), idempotency_key="k1")
    w.pending.append(_pending(rows()))  # force a duplicate replay
    w.replay_pending()
    assert inner.describe("dns_activity").row_count == 5


def _pending(r):
    from homelabnext.swap.dualwrite import _Pending

    return _Pending("dns_activity", r, "k1", None, None)


def test_primary_failure_propagates_and_secondary_is_untouched():
    class Boom:
        def write_batch(self, *a, **kw):
            raise LakeError("primary down")

    b = FakeLake()
    w = DualWriter(Boom(), b)
    with pytest.raises(LakeError, match="primary down"):
        w.write_batch("dns_activity", rows(), idempotency_key="k1")
    assert b.describe("dns_activity").row_count == 0 and not w.divergences


def test_bad_rows_are_rejected_by_primary_before_anything_is_mirrored():
    a, b = FakeLake(), FakeLake()
    w = DualWriter(a, b)
    with pytest.raises(LakeError):
        w.write_batch("dns_activity", [{"nope": 1}], idempotency_key="k1")
    assert b.describe("dns_activity").row_count == 0


def test_count_mismatch_is_a_divergence():
    a, b = FakeLake(), FakeLake()
    b.write_batch("dns_activity", rows(2), idempotency_key="pre")  # secondary already has 2 rows
    w = DualWriter(a, b)
    w.write_batch("dns_activity", rows(5), idempotency_key="k1")
    assert [d.kind for d in w.divergences] == ["count_mismatch"]
    assert w.status()["count_mismatches"] == 1


def test_unexpected_secondary_exception_types_are_contained():
    a = FakeLake()
    b = Flaky(FakeLake(), fail=1, exc=RuntimeError("socket reset"))
    w = DualWriter(a, b)
    w.write_batch("dns_activity", rows(), idempotency_key="k1")
    assert "RuntimeError" in w.divergences[0].detail


def test_writer_alias_and_unwritable_log_do_not_break_writes(tmp_path):
    a, b = FakeLake(), Flaky(FakeLake(), fail=1)
    w = DualWriter(a, b, divergence_log=tmp_path / "missing-dir" / "x.jsonl")
    assert w.write("dns_activity", rows(3), batch_id="k") == 3
    assert len(w.divergences) == 1
