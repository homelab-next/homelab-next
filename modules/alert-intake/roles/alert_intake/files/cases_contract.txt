# SPDX-License-Identifier: Apache-2.0
"""Contract for ``cases``: alerts become cases; every disposition has a reason.

Lifecycle: an *alert* is ``new`` -> ``promoted`` (a case exists) or ``dismissed`` (needs a
reason).  A *case* is ``open`` -> ``in_progress`` -> ``closed`` (needs a resolution); a closed
case accepts no new notes until reopened.  Alerts with the same ``dedup_key`` while one is still
``new`` collapse into one alert whose ``count`` grows.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

__all__ = [
    "SEVERITIES",
    "Alert",
    "Case",
    "CaseClosed",
    "CaseStore",
    "CasesError",
    "InvalidTransition",
    "NotFound",
]

SEVERITIES = ("low", "medium", "high", "critical")


class CasesError(Exception):
    pass


class NotFound(CasesError):
    pass


class InvalidTransition(CasesError):
    pass


class CaseClosed(CasesError):
    pass


@dataclass(frozen=True)
class Alert:
    id: str
    source: str
    title: str
    severity: str
    status: str  # new | promoted | dismissed
    count: int = 1
    case_id: str | None = None
    reason: str | None = None


@dataclass(frozen=True)
class Case:
    id: str
    title: str
    status: str  # open | in_progress | closed
    alert_ids: tuple[str, ...] = ()
    notes: tuple[tuple[str, str], ...] = ()  # (author, text), oldest first
    resolution: str | None = None
    extra: dict = field(default_factory=dict)


@runtime_checkable
class CaseStore(Protocol):
    def create_alert(
        self, source: str, title: str, severity: str, *, dedup_key: str | None = None
    ) -> Alert: ...

    def get_alert(self, alert_id: str) -> Alert: ...

    def list_alerts(self, status: str | None = None) -> Sequence[Alert]: ...

    def promote(self, alert_id: str, title: str | None = None) -> Case:
        """Idempotent: promoting a promoted alert returns its existing case."""

    def dismiss(self, alert_id: str, reason: str) -> Alert:
        """Raises ValueError for an empty reason."""

    def get_case(self, case_id: str) -> Case: ...

    def add_note(self, case_id: str, author: str, text: str) -> Case: ...

    def set_status(self, case_id: str, status: str, *, resolution: str | None = None) -> Case: ...
