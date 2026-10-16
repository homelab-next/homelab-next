# SPDX-License-Identifier: Apache-2.0
"""Endpoint lookup for the networked adapters.

Every address comes from :mod:`homelabnext.registry` (env override, registry shape, DNS alias).
There is no literal default anywhere in this package: an unset endpoint raises
:class:`EndpointNotConfigured` (ADR-0002, enforced in CI by ``tools/no_raw_endpoints.py``).
"""

from __future__ import annotations

from collections.abc import Mapping

from homelabnext.registry import Endpoint, Registry, ResolutionError, Resolver

from .errors import EndpointNotConfigured


def endpoint_for(
    capability: str,
    *,
    resolver: Resolver | None = None,
    registry: Registry | None = None,
    environ: Mapping[str, str] | None = None,
) -> Endpoint:
    """Resolve ``capability`` (``lake-query`` or ``lake-catalog``) or raise."""
    try:
        if resolver is None:
            if registry is None:
                raise EndpointNotConfigured(
                    f"no endpoint for {capability!r}: pass a resolver or a registry "
                    "(or set the HNX_ENDPOINT_* override and load a registry); there is no default"
                )
            resolver = Resolver(registry, environ=environ)
        return resolver.resolve(capability)
    except ResolutionError as e:
        raise EndpointNotConfigured(f"no endpoint for {capability!r}: {e}") from e
