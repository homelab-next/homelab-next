# SPDX-License-Identifier: Apache-2.0
"""Contract for ``dns`` (extended suite): an authoritative zone the registry publishes aliases to.

Names are case-insensitive and stored without a trailing dot.  ``lookup`` distinguishes
NXDOMAIN (``NoSuchName``: the name does not exist at all) from NODATA (the name exists but has
no record of that type: an empty list).  A CNAME is followed when another type is asked for,
with a hop limit; a CNAME may not coexist with other data at the same name.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable

__all__ = ["CnameLoop", "ConflictingRecord", "DnsError", "DnsZone", "NoSuchName", "Record"]


class DnsError(Exception):
    pass


class NoSuchName(DnsError):
    pass


class CnameLoop(DnsError):
    pass


class ConflictingRecord(DnsError):
    pass


@dataclass(frozen=True)
class Record:
    name: str
    rtype: str  # A | AAAA | CNAME | TXT
    value: str
    ttl: int


@runtime_checkable
class DnsZone(Protocol):
    def add(self, name: str, rtype: str, value: str, ttl: int = 300) -> Record:
        """Idempotent for an identical record.  ValueError for a bad type, value or ttl;
        ConflictingRecord for a CNAME next to other data."""

    def lookup(self, name: str, rtype: str) -> list[Record]:
        """Sorted by value.  NoSuchName for NXDOMAIN, ``[]`` for NODATA, CnameLoop on a cycle."""

    def remove(self, name: str, rtype: str, value: str | None = None) -> int:
        """Removes matching records (all of the type when ``value`` is None); returns the count."""
