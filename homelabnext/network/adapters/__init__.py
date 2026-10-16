# SPDX-License-Identifier: Apache-2.0
"""Adapter registry: name -> adapter.  Unknown names are rejected, deferred names say so."""

from __future__ import annotations

from .base import Adapter, AdapterDeferred, AdapterError, Rendered, ServerOnly, UnknownAdapter
from .dnsmasq import DnsmasqAdapter
from .linux import LinuxAdapter
from .opnsense import OpnsenseAdapter
from .unifi import UnifiAdapter
from .zonefile import ZonefileAdapter

_ADAPTERS: dict[str, Adapter] = {
    a.name: a
    for a in (
        LinuxAdapter(),
        DnsmasqAdapter(),
        ZonefileAdapter(),
        UnifiAdapter(),
        OpnsenseAdapter(),
    )
}


def known_names() -> set[str]:
    """Every adapter name a document may select, ready or deferred."""
    return set(_ADAPTERS)


def get(name: str) -> Adapter:
    """Return the adapter ``name`` or raise :class:`UnknownAdapter`."""
    try:
        return _ADAPTERS[name]
    except KeyError:
        raise UnknownAdapter(name, sorted(_ADAPTERS)) from None


def listing() -> list[tuple[str, str, str]]:
    return [(a.name, a.status, a.summary) for a in (_ADAPTERS[n] for n in sorted(_ADAPTERS))]


__all__ = [
    "Adapter",
    "AdapterDeferred",
    "AdapterError",
    "Rendered",
    "ServerOnly",
    "UnknownAdapter",
    "get",
    "known_names",
    "listing",
]
