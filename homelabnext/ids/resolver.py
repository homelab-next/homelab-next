# SPDX-License-Identifier: Apache-2.0
"""Resolver interface: ``resolve(id) -> adapter-specific locator``.

Locators (URIs, hosts, rule numbers) live only in adapter maps.  The in-memory
:class:`MappingResolver` is the fake used by tests and by examples; the
registry resolver that reads a service registry is built on this protocol
elsewhere.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Protocol, runtime_checkable

from .grammar import LogicalId, parse


class UnresolvedId(LookupError):
    """The id is valid but the adapter has no locator for it."""


@runtime_checkable
class Resolver(Protocol):
    def resolve(self, logical_id: str | LogicalId) -> str: ...


class MappingResolver:
    """Resolve ids from ``{id: locator}`` for one named adapter."""

    def __init__(self, adapter: str, mapping: Mapping[str, str]) -> None:
        self.adapter = adapter
        self._map = {str(parse(k)): v for k, v in mapping.items()}

    def resolve(self, logical_id: str | LogicalId) -> str:
        key = str(logical_id if isinstance(logical_id, LogicalId) else parse(logical_id))
        try:
            return self._map[key]
        except KeyError:
            raise UnresolvedId(f"{key} has no locator in adapter {self.adapter!r}") from None
