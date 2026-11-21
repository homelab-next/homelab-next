# SPDX-License-Identifier: Apache-2.0
"""Contract for ``dns`` (extended suite): an authoritative zone the registry publishes aliases to.

Names are case-insensitive and stored without a trailing dot.  ``lookup`` distinguishes
NXDOMAIN (``NoSuchName``: the name does not exist at all) from NODATA (the name exists but has
no record of that type: an empty list).  A CNAME is followed when another type is asked for,
with a hop limit; a CNAME may not coexist with other data at the same name.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

__all__ = [
    "MAX_HOPS",
    "TYPES",
    "CnameLoop",
    "ConflictingRecord",
    "DnsError",
    "DnsZone",
    "NoSuchName",
    "Record",
    "check_record",
    "follow",
    "norm",
]

TYPES = ("A", "AAAA", "CNAME", "TXT")
MAX_HOPS = 8


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


def norm(name: str) -> str:
    """A name as the contract stores it: no trailing dot, lower case."""
    return name.rstrip(".").lower()


def check_record(rtype: str, value: str, ttl: int) -> str:
    """The record type in upper case, after the contract's own input checks (ValueError for an
    unsupported type, a ttl that is not a positive integer, a malformed address or an empty value)."""
    rtype = rtype.upper()
    if rtype not in TYPES:
        raise ValueError(f"unsupported type {rtype!r}")
    if not isinstance(ttl, int) or isinstance(ttl, bool) or not 1 <= ttl <= 2_147_483_647:
        raise ValueError("ttl must be a positive integer")
    if rtype == "A":
        ipaddress.IPv4Address(value)
    elif rtype == "AAAA":
        ipaddress.IPv6Address(value)
    elif not value:
        raise ValueError("value is required")
    return rtype


def follow(stored_at: Callable[[str], Iterable[Record]], name: str, rtype: str) -> list[Record]:
    """``DnsZone.lookup`` over a store: ``stored_at(key)`` is every record held at a normalised
    name (empty when there is none). NoSuchName when the name holds nothing, the records of the
    type when it has any, else the CNAME's target is followed (CnameLoop on a cycle or past
    ``MAX_HOPS`` hops); a name with other records only answers ``[]`` (NODATA)."""
    rtype = rtype.upper()
    key = norm(name)
    seen: list[str] = []
    for _ in range(MAX_HOPS + 1):
        have = list(stored_at(key))
        if not have:
            raise NoSuchName(key)
        direct = sorted((r for r in have if r.rtype == rtype), key=lambda r: r.value)
        if direct:
            return direct
        cname = next((r for r in have if r.rtype == "CNAME"), None)
        if cname is None or rtype == "CNAME":
            return []
        if cname.value in seen or cname.value == key:
            raise CnameLoop(" -> ".join([*seen, key, cname.value]))
        seen.append(key)
        key = cname.value
    raise CnameLoop(f"more than {MAX_HOPS} CNAME hops from {name}")
