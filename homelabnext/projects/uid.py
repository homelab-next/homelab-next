# SPDX-License-Identifier: Apache-2.0
"""UUIDv7 identities (RFC 9562), stdlib only.

A project or work item is identified by a ``uid``: a UUIDv7 (48-bit Unix milliseconds, version 7,
variant 10, then random bits), written in the canonical lower-case 8-4-4-4-12 form.  Display
numbers are computed, never stored.  :class:`UidGenerator` is monotonic within one process: two
uids minted in the same millisecond differ in the 12-bit ``rand_a`` counter (RFC 9562 section
6.2, method 1), so sorting uids sorts them by creation.

:func:`derived_uid` is the one deterministic form: a UUIDv7 whose time is a given date and whose
random bits are a SHA-256 of a namespace and a key.  It names the strategy records that do not
carry a ``uid`` yet (:mod:`homelabnext.projects.strategy`), so a repeated sync keys them the same.

Note for later de-duplication: the uid work of ADR-0019 adds the same kind of helper for
strategy and register records; when it lands, this module should become an import of it.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import os
import re
import threading
from collections.abc import Callable

__all__ = ["UID_RE", "UidGenerator", "derived_uid", "is_uid", "uid_time"]

UID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")


def is_uid(value: object) -> bool:
    """True for a canonical lower-case UUIDv7 string."""
    return isinstance(value, str) and bool(UID_RE.match(value))


def _format(ms: int, rand_a: int, rand_b: int) -> str:
    n = (ms & ((1 << 48) - 1)) << 80
    n |= 0x7 << 76
    n |= (rand_a & 0xFFF) << 64
    n |= 0b10 << 62
    n |= rand_b & ((1 << 62) - 1)
    h = f"{n:032x}"
    return f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:]}"


def uid_time(uid: str) -> dt.datetime:
    """The creation time a uid carries (millisecond precision, UTC)."""
    if not is_uid(uid):
        raise ValueError(f"not a UUIDv7: {uid!r}")
    ms = int(uid.replace("-", "")[:12], 16)
    return dt.datetime.fromtimestamp(ms / 1000, dt.UTC)


def _utcnow() -> dt.datetime:
    return dt.datetime.now(dt.UTC)


class UidGenerator:
    """Mint UUIDv7 uids from an injectable clock and random source; monotonic per instance."""

    def __init__(
        self,
        clock: Callable[[], dt.datetime] = _utcnow,
        randbytes: Callable[[int], bytes] = os.urandom,
    ) -> None:
        self._clock = clock
        self._rand = randbytes
        self._last = (-1, 0)
        self._lock = threading.Lock()

    def __call__(self) -> str:
        with self._lock:
            ms = int(self._clock().timestamp() * 1000)
            last_ms, last_a = self._last
            if ms <= last_ms:  # same millisecond (or a clock step back): count up
                ms, rand_a = (last_ms, last_a + 1) if last_a < 0xFFF else (last_ms + 1, 0)
            else:
                rand_a = int.from_bytes(self._rand(2), "big") & 0x7FF  # room to count up
            self._last = (ms, rand_a)
            rand_b = int.from_bytes(self._rand(8), "big")
            return _format(ms, rand_a, rand_b)


def derived_uid(namespace: str, key: str, when: dt.date | dt.datetime) -> str:
    """A deterministic UUIDv7: time ``when`` (a date is midnight UTC), bits from the key's hash."""
    if not isinstance(when, dt.datetime):
        when = dt.datetime(when.year, when.month, when.day, tzinfo=dt.UTC)
    elif when.tzinfo is None:
        raise ValueError("derived_uid needs a timezone-aware time")
    ms = int(when.timestamp() * 1000)
    digest = hashlib.sha256(f"{namespace}\0{key}".encode()).digest()
    return _format(ms, int.from_bytes(digest[:2], "big"), int.from_bytes(digest[2:10], "big"))
