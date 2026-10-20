# SPDX-License-Identifier: Apache-2.0
"""Endpoint and credential lookup shared by every real-product adapter (s3, lake, openbao, ntfy,
nats).

Endpoints come from the registry resolver, never a literal default:

* with a ``resolver`` or a ``domain``: the ``HNX_ENDPOINT_<CAPABILITY>`` override (what the
  lab-in-a-box smoke test exports), else the capability alias under ``domain``;
* with ``env_only=True`` (adapters whose factory takes no domain): the override alone.

Credentials are read from named environment variables when the adapter is built (so a missing
one fails at once) and again at every use, so no adapter object ever holds the value.  Every
missing or malformed setting is one error type, :class:`AdapterConfigError`, naming the variable
and never its value.
"""

from __future__ import annotations

import os
import secrets
from collections.abc import Callable, Iterable
from typing import Any

from homelabnext.registry import Endpoint, ResolutionError, Resolver

__all__ = ["AdapterConfigError", "env_reader", "env_secret", "resolve", "run_token"]

_RUN_TOKEN: str | None = None


class AdapterConfigError(LookupError, ValueError):
    """The adapter is missing an endpoint or credential it needs (never a product failure)."""


def resolve(
    capability: str,
    *,
    resolver: Any = None,
    domain: str | None = None,
    env_only: bool = False,
    schemes: Iterable[str] | None = None,
) -> Endpoint:
    """The capability's endpoint (see the module doc); ``schemes`` limits its scheme."""
    from homelabnext.registry import env_var_name
    from homelabnext.registry.resolver import parse_override

    var = env_var_name(capability)
    try:
        if env_only:
            value = os.environ.get(var)
            if not value:
                raise AdapterConfigError(
                    f"{capability}: {var} is not set (the lab smoke exports it; set it to "
                    "scheme://host:port)"
                )
            ep = parse_override(capability, var, value)
        else:
            if resolver is None:
                if not domain:
                    raise AdapterConfigError(
                        f"no endpoint for {capability!r}: pass a resolver or a domain (and set "
                        "the HNX_ENDPOINT_* override); there is no default"
                    )
                resolver = Resolver(domain=domain)
            ep = resolver.resolve(capability)
    except ResolutionError as exc:
        raise AdapterConfigError(str(exc)) from exc
    allowed = tuple(schemes or ())
    if allowed and ep.scheme not in allowed:
        raise AdapterConfigError(f"{capability}: {var} must use {' or '.join(allowed)}")
    return ep


def env_reader(*names: str) -> Callable[[], tuple[str, ...]]:
    """A callable returning the values of credential variables ``names``, checked once now.

    The values are read again at every call, so the adapter never holds them.  A missing or
    empty variable raises :class:`AdapterConfigError` naming the variable (never its value).
    """
    if not names or not all(n and isinstance(n, str) for n in names):
        raise AdapterConfigError("a credential variable name is required")

    def read() -> tuple[str, ...]:
        out = []
        for n in names:
            v = os.environ.get(n, "")
            if not v:
                raise AdapterConfigError(f"credential variable {n} is not set")
            out.append(v)
        return tuple(out)

    read()
    return read


def env_secret(var: str) -> Callable[[], str]:
    """:func:`env_reader` for one variable: a callable returning its value."""
    read = env_reader(var)
    return lambda: read()[0]


def run_token() -> str:
    """Six hex digits shared by every subject of this process: one namespace per run, so two runs
    against the same long-lived service never see each other's objects."""
    global _RUN_TOKEN
    if _RUN_TOKEN is None:
        _RUN_TOKEN = secrets.token_hex(3)
    return _RUN_TOKEN
