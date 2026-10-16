# SPDX-License-Identifier: Apache-2.0
"""In-memory authoritative zone (``dns`` fake) and a case-sensitive defect."""

from __future__ import annotations

import ipaddress

from conformance.protocols.dns import CnameLoop, ConflictingRecord, NoSuchName, Record

_TYPES = ("A", "AAAA", "CNAME", "TXT")
MAX_HOPS = 8


class FakeDnsZone:
    features = frozenset()

    def __init__(self) -> None:
        self._r: dict[str, set[Record]] = {}

    def _norm(self, name: str) -> str:
        return name.rstrip(".").lower()

    def add(self, name: str, rtype: str, value: str, ttl: int = 300) -> Record:
        rtype = rtype.upper()
        if rtype not in _TYPES:
            raise ValueError(f"unsupported type {rtype!r}")
        if not isinstance(ttl, int) or isinstance(ttl, bool) or not 1 <= ttl <= 2_147_483_647:
            raise ValueError("ttl must be a positive integer")
        if rtype == "A":
            ipaddress.IPv4Address(value)
        elif rtype == "AAAA":
            ipaddress.IPv6Address(value)
        elif not value:
            raise ValueError("value is required")
        key = self._norm(name)
        have = self._r.setdefault(key, set())
        types = {r.rtype for r in have}
        if (rtype == "CNAME" and types - {"CNAME"}) or (rtype != "CNAME" and "CNAME" in types):
            raise ConflictingRecord(f"{key}: a CNAME cannot coexist with other records")
        if rtype == "CNAME":
            have.clear()
        rec = Record(key, rtype, value if rtype == "TXT" else self._norm(value), ttl)
        have.discard(next((r for r in have if (r.rtype, r.value) == (rec.rtype, rec.value)), None))
        have.add(rec)
        return rec

    def lookup(self, name: str, rtype: str) -> list[Record]:
        rtype = rtype.upper()
        key = self._norm(name)
        seen = []
        for _ in range(MAX_HOPS + 1):
            have = self._r.get(key)
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

    def remove(self, name: str, rtype: str, value: str | None = None) -> int:
        have = self._r.get(self._norm(name), set())
        doomed = [r for r in have if r.rtype == rtype.upper() and value in (None, r.value)]
        for r in doomed:
            have.discard(r)
        if not have:
            self._r.pop(self._norm(name), None)
        return len(doomed)


class CaseSensitiveDnsZone(FakeDnsZone):
    """Defect: names are compared exactly, so ``Host`` and ``host`` are different names."""

    def _norm(self, name: str) -> str:
        return name.rstrip(".")
