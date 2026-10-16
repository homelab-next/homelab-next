# SPDX-License-Identifier: Apache-2.0
"""The one report shape every parity tool returns.

A :class:`ParityReport` is a list of named :class:`Check` results plus metadata. It serialises to
canonical JSON (sorted keys, no clock, no host data), so it can be stored as swap evidence and
compared byte-for-byte between runs.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class Check:
    name: str
    ok: bool
    summary: str
    detail: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "ok": self.ok, "summary": self.summary, "detail": self.detail}


@dataclass
class ParityReport:
    kind: str  # query | tables | events | notifications | combined
    checks: list[Check] = field(default_factory=list)
    sampled: bool = False  # True when any check compared a sample, not the full data
    meta: dict[str, Any] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return bool(self.checks) and all(c.ok for c in self.checks)

    def failures(self) -> list[Check]:
        return [c for c in self.checks if not c.ok]

    def add(self, check: Check) -> None:
        self.checks.append(check)

    def merge(self, other: ParityReport) -> None:
        self.checks.extend(other.checks)
        self.sampled = self.sampled or other.sampled

    def summary(self) -> str:
        bad = self.failures()
        head = f"parity[{self.kind}] {'OK' if self.ok else 'FAILED'}: {len(self.checks)} checks"
        if self.sampled:
            head += " (sampled)"
        return head + "".join(f"\n  - {c.name}: {c.summary}" for c in bad)

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "ok": self.ok,
            "sampled": self.sampled,
            "meta": self.meta,
            "checks": [c.to_dict() for c in self.checks],
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, indent=2, default=str) + "\n"

    def digest(self) -> str:
        return hashlib.sha256(self.to_json().encode("utf-8")).hexdigest()
