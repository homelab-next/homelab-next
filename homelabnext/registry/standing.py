# SPDX-License-Identifier: Apache-2.0
"""Standing expires loudly (ADR-0039 decision 8): ``hnx registry standing``.

Every non-primary row (``eval``, ``retiring``, ``legacy``) carries an ``until`` date.  Validation
never reads the clock, so a row past its date is still a valid row; this report is where it turns
red.  ``--overdue`` exits 1 when any row is past its ``until`` (the day after it, not on it), so an
``eval`` that never ends or a ``retiring`` row nobody removed fails checklist row X-12 instead of
lingering.

The date judged against is ``--today``, else ``HNX_TODAY`` (YYYY-MM-DD), else the local date.
"""

from __future__ import annotations

import datetime as dt
import json
import os
from dataclasses import dataclass
from typing import Any

from homelabnext.registry.model import Registry


@dataclass(frozen=True)
class Standing:
    """One non-primary row and how its date stands against ``today``."""

    row: str
    capability: str
    tier: str
    until: str
    why: str
    #: days from today to ``until``: negative once the row is overdue
    days_left: int

    @property
    def overdue(self) -> bool:
        return self.days_left < 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "row": self.row,
            "capability": self.capability,
            "tier": self.tier,
            "until": self.until,
            "why": self.why,
            "days_left": self.days_left,
            "overdue": self.overdue,
        }


def today(now: dt.date | None = None) -> dt.date:
    """``now`` when given, else ``HNX_TODAY`` when set (a test or a replay is deterministic),
    else the local date.  A malformed ``HNX_TODAY`` is a ``ValueError``, never ignored."""
    raw = os.environ.get("HNX_TODAY")
    if now is None and raw:
        try:
            now = dt.date.fromisoformat(raw)
        except ValueError:
            raise ValueError(f"HNX_TODAY={raw!r} is not a YYYY-MM-DD date") from None
    return now or dt.date.today()


def standings(reg: Registry, on: dt.date) -> list[Standing]:
    """Every non-primary row of ``reg``, by row name, judged against ``on``.  A row the schema
    let through without a usable ``until`` cannot happen (2.9 requires one); it would read as
    overdue rather than be skipped."""
    out = []
    for s in reg.rows("eval", "retiring", "legacy"):
        try:
            left = (dt.date.fromisoformat(s.until or "") - on).days
        except ValueError:
            left = -1
        out.append(Standing(s.name, s.capability, s.standing, s.until or "", s.why, left))
    return out


def text(rows: list[Standing]) -> str:
    lines = []
    for r in rows:
        when = f"overdue by {-r.days_left} day(s)" if r.overdue else f"{r.days_left} day(s) left"
        lines.append(f"{r.row}: {r.tier} {r.capability} until {r.until} ({when}): {r.why}")
    return "".join(f"{ln}\n" for ln in lines)


def run(reg: Registry, on: dt.date, *, overdue_only: bool, as_json: bool, out, err) -> int:
    """The command body: 1 when ``overdue_only`` and a row is past its date, else 0."""
    rows = standings(reg, on)
    shown = [r for r in rows if r.overdue] if overdue_only else rows
    if as_json:
        print(
            json.dumps(
                {"today": on.isoformat(), "rows": [r.to_dict() for r in shown]},
                indent=2,
                sort_keys=True,
            ),
            file=out,
        )
    else:
        print(text(shown), end="", file=out)
    if overdue_only and shown:
        print(
            f"hnx: {len(shown)} non-primary row(s) past their until on {on.isoformat()}: "
            "promote them, remove them, or give a new until and why in a reviewed change",
            file=err,
        )
        return 1
    if overdue_only and not as_json:
        print(f"ok: no non-primary row past its until ({len(rows)} non-primary)", file=out)
    return 0
