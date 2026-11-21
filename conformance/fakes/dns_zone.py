# SPDX-License-Identifier: Apache-2.0
"""In-memory authoritative zone (``dns`` fake) and a case-sensitive defect."""

from __future__ import annotations

from conformance.protocols.dns import (
    ConflictingRecord,
    Record,
    check_record,
    follow,
    norm,
)


class FakeDnsZone:
    features = frozenset()

    def __init__(self) -> None:
        self._r: dict[str, set[Record]] = {}

    def _norm(self, name: str) -> str:
        return norm(name)

    def add(self, name: str, rtype: str, value: str, ttl: int = 300) -> Record:
        rtype = check_record(rtype, value, ttl)
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
        return follow(lambda key: self._r.get(key, ()), name, rtype)

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
