# SPDX-License-Identifier: Apache-2.0
"""Shared plumbing for the real-product adapters: endpoints and credentials come from the env.

The lab smoke (``compose/lab-in-a-box/smoke.sh``) exports ``HNX_ENDPOINT_<CAPABILITY>`` for every
capability and the ``.env.example`` settings (throwaway credentials) into the environment of
``hnx conform run``.  Adapters read both at construction time through these helpers; nothing is
defaulted, so a missing variable is a clear configuration error, never a silent localhost.
"""

from __future__ import annotations

import os
from collections.abc import Callable, Iterable

__all__ = ["AdapterConfigError", "endpoint_url", "env_secret"]


class AdapterConfigError(ValueError):
    """The adapter is missing an endpoint or credential it needs (never a product failure)."""


def endpoint_url(capability: str, schemes: Iterable[str]) -> str:
    """``scheme://host:port`` for ``capability`` from its ``HNX_ENDPOINT_*`` override."""
    from homelabnext.registry import env_var_name
    from homelabnext.registry.resolver import parse_override

    var = env_var_name(capability)
    value = os.environ.get(var)
    if not value:
        raise AdapterConfigError(
            f"{capability}: {var} is not set (the lab smoke exports it; set it to scheme://host:port)"
        )
    ep = parse_override(capability, var, value)
    allowed = tuple(schemes)
    if ep.scheme not in allowed:
        raise AdapterConfigError(f"{capability}: {var} must use {' or '.join(allowed)}")
    return ep.url


def env_secret(var: str) -> Callable[[], str]:
    """A callable reading credential ``var`` at use time, so no object ever holds the value."""
    if not var or not isinstance(var, str):
        raise AdapterConfigError("a credential variable name is required")

    def read() -> str:
        value = os.environ.get(var)
        if not value:
            raise AdapterConfigError(f"credential variable {var} is not set")
        return value

    return read
