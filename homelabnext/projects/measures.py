# SPDX-License-Identifier: Apache-2.0
"""Work completion as a measure reading -- for a MOP only, never a MOE.

How much of the work linked to an objective is done is *activity*: it says whether we are doing
the work (a measure of performance), not whether the objective is being achieved (a measure of
effectiveness).  The doctrine rule ``activity_never_moe`` (``docs/strategy.md``) forbids feeding
activity into a MOE, so :func:`completion_reading` refuses one.  It never changes an objective
either: achievement stays a reviewed transition in the strategy repository.
"""

from __future__ import annotations

import datetime as dt
from collections.abc import Iterable
from typing import Any

from .model import WorkItem
from .strategy import StrategyRecord

__all__ = ["completion_reading"]


def completion_reading(
    items: Iterable[WorkItem], measure: StrategyRecord, *, now: dt.datetime
) -> dict[str, Any]:
    """A reading for ``measure`` (a MOP): the share, in percent, of the steps and tasks linked to
    the objective it measures that are done (cancelled ones do not count).  The result has the
    shape of a ``value`` event's payload: ``value`` (or a ``finding``), ``observed_at``,
    ``sample``, ``evidence``."""
    if measure.type != "MOP":
        raise ValueError(
            f"{measure.label or measure.uid} is a {measure.type}: work completion is activity and "
            "feeds a MOP only, never a MOE (doctrine rule activity_never_moe)"
        )
    target = measure.parent_uid  # a measure's parent is the objective it measures
    if not target:
        raise ValueError(f"{measure.label or measure.uid} measures no objective")
    work = [
        i
        for i in items
        if i.kind in ("step", "task") and target in i.linked() and i.status != "cancelled"
    ]
    out: dict[str, Any] = {
        "observed_at": now.astimezone(dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "sample": len(work),
        "evidence": f"projects: {len(work)} linked step(s)/task(s) of objective {target}",
    }
    if not work:
        out["finding"] = "no work is linked to the objective"
    else:
        done = sum(1 for i in work if i.status == "done")
        out["value"] = round(100.0 * done / len(work), 1)
    return out
