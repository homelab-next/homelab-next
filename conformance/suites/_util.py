# SPDX-License-Identifier: Apache-2.0
"""Helpers shared by the suites."""

from __future__ import annotations

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
