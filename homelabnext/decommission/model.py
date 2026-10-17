# SPDX-License-Identifier: Apache-2.0
"""Result model for the per-guest decommission audit.

A *plane* is one place a guest leaves traces (inventory, IaC, hypervisor, SIEM roster ...).
Each plane is a read-only probe returning a :class:`Result`.  The one rule that makes the audit
trustworthy: a plane that could not be measured is ``SKIP``, never ``CLEAN``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import StrEnum


class Status(StrEnum):
    CLEAN = "CLEAN"  # measured, nothing left behind
    REMNANT = "REMNANT"  # measured, something is still there: the guest is not fully gone
    INFO = "INFO"  # worth knowing, not a failure (e.g. the vmid now belongs to another resource)
    REVIEW = "REVIEW"  # a human should look (narrative mention, comment, unparseable file)
    SKIP = "SKIP"  # could not be measured; not a pass


class Unreachable(Exception):
    """An adapter could not answer.  The plane reports SKIP with this message."""


@dataclass(frozen=True)
class Target:
    """The retired guest.  Only ``name`` is required; the rest widens the net."""

    name: str
    vmid: int | None = None
    node: str | None = None
    ips: tuple[str, ...] = ()
    aliases: tuple[str, ...] = ()

    def terms(self) -> list[str]:
        return [t for t in (self.name, *self.ips, *self.aliases) if t]

    def patterns(self) -> list[re.Pattern[str]]:
        return [term_pattern(t) for t in self.terms()]

    def matches(self, text: str) -> str | None:
        """The first term found in ``text`` (word-bounded), else None."""
        for t, p in zip(self.terms(), self.patterns(), strict=True):
            if p.search(text):
                return t
        return None


def term_pattern(term: str) -> re.Pattern[str]:
    """Word-bounded, case-insensitive: ``app-core`` must not match ``app-core-2`` or ``x.app-core``."""
    return re.compile(r"(?<![\w.-])" + re.escape(term) + r"(?![\w-]|\.\d)", re.IGNORECASE)


@dataclass
class Result:
    plane: str
    status: Status
    detail: str = ""
    items: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "plane": self.plane,
            "status": self.status.value,
            "detail": self.detail,
            "items": list(self.items),
        }


@dataclass
class Report:
    target: Target
    results: list[Result]

    @property
    def remnants(self) -> list[Result]:
        return [r for r in self.results if r.status is Status.REMNANT]

    @property
    def measured(self) -> int:
        return sum(1 for r in self.results if r.status in (Status.CLEAN, Status.REMNANT))

    def verdict(self, strict: bool = False) -> str:
        if self.remnants:
            return "REMNANTS"
        if self.measured == 0:
            return "UNMEASURED"  # nothing could be checked; that is not a pass
        if strict and any(r.status in (Status.REVIEW, Status.SKIP) for r in self.results):
            return "UNRESOLVED"
        return "CLEAN"

    def exit_code(self, strict: bool = False) -> int:
        return 0 if self.verdict(strict) == "CLEAN" else 1

    def to_dict(self, strict: bool = False) -> dict:
        return {
            "target": self.target.name,
            "verdict": self.verdict(strict),
            "results": [r.to_dict() for r in self.results],
        }
