# SPDX-License-Identifier: Apache-2.0
"""Helpers shared by the suites."""

from __future__ import annotations

import contextlib
import itertools
import os
from collections.abc import Callable
from typing import Any

_COUNTER = itertools.count(1)


def nonce() -> str:
    """Run-scoped token that namespaces what checks create.  Set ``HNX_CONFORM_NONCE`` when
    several runs share one real service; the default keeps fake runs deterministic."""
    return os.environ.get("HNX_CONFORM_NONCE", "r0")


def uniq(prefix: str) -> str:
    return f"{prefix}-{nonce()}-{next(_COUNTER)}"


_DOC_NETS = ("192.0.2", "198.51.100", "203.0.113")  # RFC 5737 documentation ranges


def ip(host: int, net: int = 0) -> str:
    """An RFC 5737 documentation address: ``net`` 0 = 192.0.2/24, 1 = 198.51.100/24, 2 = 203.0.113/24."""
    return f"{_DOC_NETS[net]}.{host}"


def raises(fn: Callable[[], Any], what: str, *types: type[BaseException]) -> BaseException:
    """Call ``fn`` and return the exception it raises; fail the check if it does not raise."""
    catch = types or (Exception,)
    try:
        out = fn()
    except catch as exc:
        return exc
    raise AssertionError(f"{what}: expected an error, got {out!r}")


def exc_text(exc: BaseException) -> str:
    """Everything a caller can read off an exception: the formatted traceback, and for every
    exception on the chain (``__cause__`` and ``__context__``, suppressed or not) its ``str``,
    ``repr``, ``args`` and attributes.  Leak checks search this, not just ``str(exc)``."""
    import traceback

    parts = ["".join(traceback.format_exception(exc))]
    seen: set[int] = set()
    todo: list[BaseException | None] = [exc]
    while todo:
        e = todo.pop()
        if e is None or id(e) in seen:
            continue
        seen.add(id(e))
        parts += [str(e), repr(e), repr(e.args)]
        with contextlib.suppress(TypeError):
            parts.append(repr(vars(e)))
        parts += [repr(n) for n in getattr(e, "__notes__", ())]
        todo += [e.__cause__, e.__context__]
    return "\n".join(parts)


def expires(subject: Any, still_valid: Callable[[], bool], ttl: float) -> bool:
    """Let ``ttl`` seconds pass and report whether ``still_valid()`` turned False.

    With the ``clock-control`` hook (a ``tick(seconds)`` method) the clock is advanced; without
    it the check waits in real time (keep ``ttl`` to a second), polling so a precise
    implementation returns quickly and a whole-second one gets one second of grace.  Expiry is a
    MUST either way: not offering the hook only makes the check slower.
    """
    import time

    tick = getattr(subject, "tick", None)
    if callable(tick):
        tick(ttl + 1)
        return not still_valid()
    deadline = time.monotonic() + ttl + 1.5
    time.sleep(ttl)
    while time.monotonic() < deadline:
        if not still_valid():
            return True
        time.sleep(0.05)
    return not still_valid()
