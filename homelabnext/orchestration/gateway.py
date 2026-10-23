# SPDX-License-Identifier: Apache-2.0
"""Per-turn records from the gateway, joined to jobs by tag.

The gateway's per-call log is read through a **turn source**
(:class:`conformance.protocols.inference.TurnSource`, the ``inference`` capability's
``turn-records`` feature): ``turns(start, end, tags)`` yields the neutral turn records
(:data:`~conformance.protocols.inference.TURN_FIELDS`) of the calls started in a window that carry
one of the tags.  Which product's log that is, and how its rows map to the record, is the
adapter's (the adapters are listed in ``docs/orchestration-telemetry.md``); the CLI picks one by
``--turn-source``, and ``none`` reads nothing (per-job data only, "no gateway data" on the page).

:func:`sync_turns` decides what to read (:func:`_windows`), joins the turns to jobs by tag, and
settles the jobs whose turns are final.  The store refuses a record outside the turn shape
(:func:`conformance.protocols.inference.turn_problems`), so no adapter can widen what is kept.
"""

from __future__ import annotations

import math
from collections import Counter
from collections.abc import Iterable, Mapping
from typing import Any

from conformance.protocols.inference import TurnSource
from homelabnext.status.model import parse_iso

from .store import TelemetryStore

#: a job's turns are re-read until it has been finished this long (a gateway may write its
#: per-call log in batches)
SETTLE_S = 600.0
#: read this much before a job was queued and after it finished (clock skew, a slow last write)
SLACK_S = 120.0
#: jobs whose read windows are closer than this are read in one window
MERGE_GAP_S = 3600.0
#: but a window is never longer than this, so one window is never all of a backlog's traffic
MAX_WINDOW_S = 3600.0


def _windows(
    jobs: Iterable[Mapping[str, Any]], floor: float
) -> list[tuple[float, float, list[Mapping[str, Any]]]]:
    """Read windows covering every job, oldest first, each with the jobs whose span it overlaps.
    Spans closer than :data:`MERGE_GAP_S` are read together, but no window is longer than
    :data:`MAX_WINDOW_S`: a run of jobs less than an hour apart (a week of first replay, a backlog
    after a gateway outage) is cut into windows a page budget can finish, rather than one window
    over all of the gateway's traffic that fails every run."""
    spans = sorted((*_span(j, floor), i, j) for i, j in enumerate(jobs))
    merged: list[tuple[float, float, list[tuple[float, float, Mapping[str, Any]]]]] = []
    for lo, hi, _, job in spans:
        if merged and lo <= merged[-1][1] + MERGE_GAP_S:
            plo, phi, members = merged[-1]
            merged[-1] = (plo, max(phi, hi), [*members, (lo, hi, job)])
        else:
            merged.append((lo, hi, [(lo, hi, job)]))
    out: list[tuple[float, float, list[Mapping[str, Any]]]] = []
    for lo, hi, members in merged:
        n = max(1, math.ceil((hi - lo) / MAX_WINDOW_S))
        step = (hi - lo) / n
        for k in range(n):
            a, b = lo + k * step, hi if k == n - 1 else lo + (k + 1) * step
            inside = [job for jlo, jhi, job in members if jlo <= b and jhi >= a]
            if inside:
                out.append((a, b, inside))
    return out


def _span(job: Mapping[str, Any], floor: float) -> tuple[float, float]:
    """The time a job's turns can lie in, with :data:`SLACK_S` either side: from its start (no
    turn happens while it is queued, however long it waited; a job that never started is read
    around its finish only) to its finish.  Ordered even when the record's times are not (the
    store refuses those): a reversed span overlaps no window, so its job would never be read or
    settled.  Never earlier than ``floor``, the retention cutoff (turns before it are purged
    anyway): a start of 0001-01-01 would otherwise be read as some seventeen million one-hour
    windows, and no pass would ever reach the next job."""
    f = parse_iso(job["finished_at"])
    s = parse_iso(job["started_at"]) if job.get("started_at") else f
    return max(min(s, f), floor) - SLACK_S, max(s, f) + SLACK_S


def sync_turns(
    store: TelemetryStore,
    source: TurnSource,
    *,
    now: float,
    settle_s: float = SETTLE_S,
) -> dict[str, int]:
    """Read the turns of every unsettled job from ``source`` into the store, window by window
    (:func:`_windows`), oldest first.  Each window's turns are stored as soon as it is read (a
    turn carrying a tag no job of the window asked for is dropped), and a job finished more than
    ``settle_s`` before ``now`` is settled as soon as the last window it overlaps is read.  A
    failed read raises (:class:`~conformance.protocols.inference.TurnSourceError`), and a record
    outside the turn shape is refused by the store (:class:`ValueError`); what was read and
    settled before either stays, and the next run reads the jobs still unsettled."""
    pending = store.unsettled()
    windows = _windows(pending, now - store.retention_s)
    left = Counter(j["run_id"] for _, _, inside in windows for j in inside)
    seen: set[str] = set()  # a turn read by two adjacent windows is one turn
    settled = 0
    for lo, hi, inside in windows:
        if lo <= now:
            tags = sorted({j["gateway_tag"] for j in inside})
            asked = set(tags)
            found = [
                t
                for t in source.turns(lo, min(hi, now), tags)
                if isinstance(t, Mapping) and t.get("gateway_tag") in asked
            ]
            store.add_turns(found)
            seen.update(t["turn_id"] for t in found)
        done = []
        for j in inside:
            left[j["run_id"]] -= 1
            if not left[j["run_id"]] and parse_iso(j["finished_at"]) <= now - settle_s:
                done.append(j["run_id"])
        store.settle(done, now)
        settled += len(done)
    return {"jobs": len(pending), "turns": len(seen), "settled": settled}


__all__ = ["MAX_WINDOW_S", "SETTLE_S", "SLACK_S", "sync_turns"]
