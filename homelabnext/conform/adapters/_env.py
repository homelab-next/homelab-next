# SPDX-License-Identifier: Apache-2.0
"""Endpoint and credential lookup shared by the real-product adapters.

Endpoints come from the registry resolver: the ``HNX_ENDPOINT_<CAPABILITY>`` override (what the
lab-in-a-box smoke test exports) or the capability alias under ``domain``.  There is no literal
default.  Credentials are read from named environment variables at the moment they are needed and
are never stored on the adapter object.
"""

from __future__ import annotations

import os
import secrets
from collections.abc import Callable
from typing import Any

from homelabnext.registry import Endpoint, ResolutionError, Resolver

__all__ = ["env_reader", "resolve", "run_token"]

_RUN_TOKEN: str | None = None


def resolve(capability: str, *, resolver: Any = None, domain: str | None = None) -> Endpoint:
    """The capability's endpoint, or a ``LookupError`` naming the override to set."""
    try:
        if resolver is None:
            if not domain:
                raise LookupError(
                    f"no endpoint for {capability!r}: pass a resolver or a domain (and set "
                    "the HNX_ENDPOINT_* override); there is no default"
                )
            resolver = Resolver(domain=domain)
        return resolver.resolve(capability)
    except ResolutionError as exc:
        raise LookupError(str(exc)) from exc


def env_reader(*names: str) -> Callable[[], tuple[str, ...]]:
    """A callable returning the values of ``names`` from the environment, checked once now.

    The values are read again at every call, so the adapter never holds them.  A missing or
    empty variable raises ``LookupError`` naming the variable (never its value).
    """

    def read() -> tuple[str, ...]:
        out = []
        for n in names:
            v = os.environ.get(n, "")
            if not v:
                raise LookupError(f"environment variable {n} is not set")
            out.append(v)
        return tuple(out)

    read()
    return read


def run_token() -> str:
    """Six hex digits shared by every subject of this process: one namespace per run, so two runs
    against the same long-lived service never see each other's objects."""
    global _RUN_TOKEN
    if _RUN_TOKEN is None:
        _RUN_TOKEN = secrets.token_hex(3)
    return _RUN_TOKEN
