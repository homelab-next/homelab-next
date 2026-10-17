# SPDX-License-Identifier: Apache-2.0
"""Run the planes and render a report.  The engine never mutates anything."""

from __future__ import annotations

from collections.abc import Iterable

from .adapters import Adapters
from .model import Report, Result, Status, Target
from .planes import ACTIONS, PLANES


def run(target: Target, adapters: Adapters, only: Iterable[str] | None = None) -> Report:
    names = list(only) if only else list(PLANES)
    unknown = [n for n in names if n not in PLANES]
    if unknown:
        raise KeyError(f"unknown plane(s): {', '.join(unknown)}")
    adapters.claimed.clear()
    results: list[Result] = []
    for n in names:
        try:
            results.append(PLANES[n](target, adapters))
        except Exception as exc:
            results.append(Result(n, Status.SKIP, f"probe error: {type(exc).__name__}: {exc}"))
    return Report(target, results)


def positive_control(live: Target, adapters: Adapters, only: Iterable[str] | None = None) -> Report:
    """Run the audit against a guest known to be LIVE.  A clean answer means the audit is broken."""
    return run(live, adapters, only)


def render(report: Report, strict: bool = False) -> str:
    lines = [f"decommission check: {report.target.name}"]
    for r in report.results:
        lines.append(f"  [{r.status.value:<7}] {r.plane}: {r.detail}")
        lines += [f"             - {i}" for i in r.items]
    lines.append(f"verdict: {report.verdict(strict)}")
    return "\n".join(lines)


def plan(report: Report) -> str:
    lines = [f"decommission plan: {report.target.name} (read-only; nothing is executed)"]
    n = 0
    for r in report.results:
        if r.status in (Status.REMNANT, Status.REVIEW):
            n += 1
            lines.append(f"{n}. {r.plane}: {ACTIONS.get(r.plane, 'review')}")
            lines += [f"     {i}" for i in r.items]
        elif r.status is Status.INFO:
            lines.append(f"-  {r.plane}: note: {r.detail}")
        elif r.status is Status.SKIP:
            lines.append(f"?  {r.plane}: NOT MEASURED ({r.detail}); check by hand")
    if n == 0:
        lines.append("nothing to do on the planes that could be measured")
    lines.append("then re-run: hnx decommission check " + report.target.name)
    return "\n".join(lines)
