# SPDX-License-Identifier: Apache-2.0
"""UUIDv7: the one identity of a record (RFC 9562, section 5.7), standard library only.

A record's ``uid`` is created once, with the record, and never changes: links, references,
sync keys, event sidecars and graph nodes use it.  Version 7 puts the creation time (Unix
milliseconds) in the first 48 bits, so uids sort in creation order -- the default order of
siblings when a computed display number is drawn (:mod:`homelabnext.identity.numbers`).

Layout (128 bits)::

    unix_ts_ms (48) | ver = 7 (4) | rand_a (12) | var = 0b10 (2) | rand_b (62)

``rand_a`` is a monotonic counter within one millisecond (the RFC's "fixed bit-length dedicated
counter", method 1): seeded randomly with its top bit clear at each new millisecond and
incremented for every further uid in it, so one generator never emits two uids out of order
even when the clock stands still or steps back.  ``rand_b`` is fresh randomness every time.

Only the canonical form is valid: lowercase hex, hyphenated 8-4-4-4-12, version 7, variant
``10`` (:func:`is_uid`).  An upper-case or braced spelling is refused rather than normalized, so
two spellings of one uid can never coexist in the files.
"""

from __future__ import annotations

import datetime as dt
import os
import re
import threading
import time
from collections.abc import Callable

__all__ = ["UID_PATTERN", "UID_RE", "UidGenerator", "is_uid", "uid_ms", "uid_time", "uuid7"]

#: the canonical text form, as a regular expression fragment (no anchors)
UID_PATTERN = r"[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"
UID_RE = re.compile(UID_PATTERN)
_MAX_MS = (1 << 48) - 1


def is_uid(value: object) -> bool:
    """True for a canonical UUIDv7 string (and nothing else: no other version, no upper case)."""
    return isinstance(value, str) and UID_RE.fullmatch(value) is not None


def uid_ms(uid: str) -> int:
    """The creation time a uid carries, in Unix milliseconds."""
    if not is_uid(uid):
        raise ValueError(f"{uid!r} is not a UUIDv7")
    return int(uid[:8] + uid[9:13], 16)


def uid_time(uid: str) -> dt.datetime:
    """The creation time a uid carries, as an aware UTC datetime."""
    return dt.datetime.fromtimestamp(uid_ms(uid) / 1000, dt.UTC)


def _format(ms: int, rand_a: int, rand_b: int) -> str:
    value = (ms << 80) | (0x7 << 76) | (rand_a << 64) | (0b10 << 62) | rand_b
    h = f"{value:032x}"
    return f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:]}"


class UidGenerator:
    """A monotonic UUIDv7 source.  ``clock_ms`` and ``randbytes`` are injectable (tests, the
    migration's deterministic mode); the defaults are the wall clock and ``os.urandom``."""

    def __init__(
        self,
        clock_ms: Callable[[], int] | None = None,
        randbytes: Callable[[int], bytes] | None = None,
    ):
        self._clock = clock_ms or (lambda: time.time_ns() // 1_000_000)
        self._rand = randbytes or os.urandom
        self._lock = threading.Lock()
        self._ms = -1
        self._seq = 0

    def __call__(self) -> str:
        with self._lock:
            ms = int(self._clock())
            if not 0 <= ms <= _MAX_MS:
                raise ValueError(f"clock {ms} ms is outside the 48-bit UUIDv7 range")
            if ms > self._ms:
                self._ms, self._seq = ms, int.from_bytes(self._rand(2), "big") & 0x7FF
            else:  # same millisecond, or the clock stepped back: count on from the last one
                self._seq += 1
                if self._seq > 0xFFF:  # counter exhausted: borrow the next millisecond
                    self._ms += 1
                    self._seq = int.from_bytes(self._rand(2), "big") & 0x7FF
            rand_b = int.from_bytes(self._rand(8), "big") & ((1 << 62) - 1)
            return _format(self._ms, self._seq, rand_b)


_DEFAULT = UidGenerator()


def uuid7() -> str:
    """A new uid from the process-wide monotonic generator."""
    return _DEFAULT()
