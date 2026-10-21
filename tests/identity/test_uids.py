# SPDX-License-Identifier: Apache-2.0
"""UUIDv7 generation and validation (homelabnext.identity.uid): format, order, monotonicity."""

from __future__ import annotations

import datetime as dt
import random
import uuid

import pytest

from homelabnext.identity.uid import UidGenerator, is_uid, uid_ms, uid_time, uuid7

T0 = 1_792_500_000_000  # 2026-10-20, in Unix milliseconds


def gen(clock, seed=7):
    rng = random.Random(seed)
    return UidGenerator(clock_ms=clock, randbytes=rng.randbytes)


def test_a_generated_uid_is_a_canonical_uuid_version_7():
    u = gen(lambda: T0)()
    parsed = uuid.UUID(u)
    assert parsed.version == 7 and parsed.variant == uuid.RFC_4122
    assert str(parsed) == u  # lowercase, hyphenated 8-4-4-4-12
    assert is_uid(u)
    assert uid_ms(u) == T0
    assert uid_time(u) == dt.datetime.fromtimestamp(T0 / 1000, dt.UTC)


def test_the_module_generator_makes_valid_distinct_uids():
    a, b = uuid7(), uuid7()
    assert is_uid(a) and is_uid(b) and a != b and a < b


@pytest.mark.parametrize(
    "value",
    [
        "0199F3A2-7C3E-7A1B-8000-0123456789AB",  # upper case is refused, never normalized
        "0f6b1c2e-3d4a-4b5c-8d6e-7f8091a2b3c4",  # version 4
        "0199f3a2-7c3e-7a1b-c000-0123456789ab",  # variant 110, not 10
        "{0199f3a2-7c3e-7a1b-8000-0123456789ab}",
        "0199f3a27c3e7a1b80000123456789ab",
        "0199f3a2-7c3e-7a1b-8000-0123456789ab\n",
        "LL-001",
        None,
        42,
    ],
)
def test_only_the_canonical_form_validates(value):
    assert not is_uid(value)


def test_uids_sort_in_creation_order_across_milliseconds():
    times = iter([T0, T0 + 1, T0 + 5, T0 + 1000])
    g = gen(lambda: next(times))
    made = [g() for _ in range(4)]
    assert made == sorted(made)
    assert [uid_ms(u) for u in made] == [T0, T0 + 1, T0 + 5, T0 + 1000]


def test_many_uids_in_one_millisecond_stay_ordered_and_distinct():
    g = gen(lambda: T0)
    made = [g() for _ in range(5000)]  # more than the 12-bit counter holds: borrows ms
    assert made == sorted(made)
    assert len(set(made)) == len(made)
    assert uid_ms(made[-1]) > T0  # the counter ran out and borrowed the next millisecond


def test_a_clock_that_steps_back_never_reorders():
    times = iter([T0 + 10, T0 + 3, T0 + 3, T0 + 11])
    g = gen(lambda: next(times))
    made = [g() for _ in range(4)]
    assert made == sorted(made) and len(set(made)) == 4


def test_a_clock_outside_48_bits_is_refused():
    with pytest.raises(ValueError, match="48-bit"):
        gen(lambda: 1 << 48)()
    with pytest.raises(ValueError, match="UUIDv7"):
        uid_ms("LL-001")
