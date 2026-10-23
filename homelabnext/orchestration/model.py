# SPDX-License-Identifier: Apache-2.0
"""The rollup of orchestration telemetry: per profile, backend and lane, and per day.

:func:`rollup` is a pure function of stored job records (the ``data`` of
``homelabnext.agent.job.finished``) and the gateway turns joined to them; the Orchestration page
renders it and ``hnx orchestration report --json`` prints it as the recommendation engine's input
(``homelabnext.orchestration.rollup/1``; evolve additively once released).  Shape::

    schema, generated_at, window {since, until, days}
    groups  [{profile, backend, lane, jobs, outcomes {completed, failed, cancelled, timeout},
              failure_classes {class: n}, wall_s {p50, p95, n}, queue_wait_s {p50, p95, n},
              tokens {input, output, reasoning, cache_read,
                      jobs_unknown {input, output, reasoning, cache_read}},
              tokens_per_job {input {p50, p95, n}, output {p50, p95, n}},
              api_calls_per_job {p50, p95, n}, cache_read_share, cost_usd {total, jobs_unknown},
              retries {of_earlier_run, auto_scheduled}, cloud_fallbacks, local_attempts,
              bytes {input {p50, total}, output {p50, total, n}},
              turns {jobs_with_turns, count, per_job {p50, p95, n}, input_tokens, output_tokens,
                     cache_read_tokens, cost_usd,
                     turns_unknown {input_tokens, output_tokens, cache_read_tokens, cost_usd},
                     failures, ttft_ms {p50, p95, n}, duration_ms {p50, p95, n}}}]
    days    [{day, profile, jobs, completed, not_completed, wall_s_p50, input_tokens,
              output_tokens, cost_usd, jobs_unknown {input_tokens, output_tokens, cost_usd}}]

Percentiles are nearest-rank over the known values (``n`` of them); ``None`` when none is known.
A token count, cost or size that was not reported is *unknown*, never 0: every sum is over the
known values, has its own count of the values left out beside it (``jobs_unknown.<sum>``,
``turns_unknown.<sum>``, ``bytes.output.n`` known), and is ``None`` when no value is known, so a
sum or a share is never diluted by missing data.  The turn sums are ``None`` too when no job has
gateway turns.  A day is the UTC day the job finished.
"""

from __future__ import annotations

import math
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from typing import Any

from homelabnext.status.model import iso, parse_iso

FINISHED_EVENT = "homelabnext.agent.job.finished"
#: the default publisher of job records: the orchestration controller's service id in the example
#: lab.  Which service fills the orchestration slot is site configuration
#: (``TelemetryStore(sources=...)``, ``hnx orchestration --source``); this is only the default
CONTROLLER_SOURCE = "svc:llm-orchestrator"
ROLLUP_SCHEMA = "homelabnext.orchestration.rollup/1"
OUTCOMES = ("completed", "failed", "cancelled", "timeout")
LANES = ("real", "shadow")
#: the group key of a job without a backend (it never reached one)
NO_BACKEND = "-"
_TOKEN_KEYS = ("input_tokens", "output_tokens", "reasoning_tokens", "cache_read_tokens")
_TURN_SUMS = ("input_tokens", "output_tokens", "cache_read_tokens", "cost_usd")
_DAY_SUMS = ("input_tokens", "output_tokens", "cost_usd")


def percentile(values: Iterable[float | int | None], p: float) -> float | int | None:
    """Nearest-rank percentile of the known values (``None`` ignored); ``None`` if there are none."""
    vals = sorted(v for v in values if v is not None)
    if not vals:
        return None
    k = max(1, math.ceil(p / 100 * len(vals)))
    return vals[k - 1]


def _dist(values: Iterable[float | int | None]) -> dict[str, Any]:
    vals = [v for v in values if v is not None]
    return {"p50": percentile(vals, 50), "p95": percentile(vals, 95), "n": len(vals)}


def _total(values: Iterable[float | int | None]) -> tuple[float | int | None, int]:
    """(the sum of the known values or None when there is none, how many were unknown)."""
    vals = list(values)
    known = [v for v in vals if v is not None]
    return (sum(known) if known else None), len(vals) - len(known)


def _round(v: float | int | None) -> float | int | None:
    return None if v is None else round(v, 6)


def _usage(job: Mapping[str, Any], key: str) -> Any:
    usage = job.get("usage")
    return usage.get(key) if isinstance(usage, Mapping) else None


def group_key(job: Mapping[str, Any]) -> tuple[str, str, str]:
    return (job["profile"], job.get("backend") or NO_BACKEND, job["lane"])


def _turns_block(jobs: Sequence[Mapping[str, Any]], turns: Mapping[str, Sequence[Mapping]]):
    """The gateway's view of the jobs.  Only jobs routed through a gateway whose turn source is read
    have turns (not a direct backend or a cloud provider): with none, the sums are None (no gateway
    data), never 0."""
    mine = [list(turns.get(j["gateway_tag"], ())) for j in jobs]
    flat = [t for ts in mine for t in ts]
    sums = {k: _total(t.get(k) for t in flat) for k in _TURN_SUMS}
    return {
        "jobs_with_turns": sum(1 for ts in mine if ts),
        "count": len(flat),
        "per_job": _dist(len(ts) for ts in mine if ts),
        **{k: _round(v) if k == "cost_usd" else v for k, (v, _) in sums.items()},
        "turns_unknown": {k: n for k, (_, n) in sums.items()},
        "failures": sum(1 for t in flat if t.get("status") == "failure"),
        "ttft_ms": _dist(t.get("ttft_ms") for t in flat),
        "duration_ms": _dist(t.get("duration_ms") for t in flat),
    }


def _group(
    key: tuple[str, str, str],
    jobs: Sequence[Mapping[str, Any]],
    turns: Mapping[str, Sequence[Mapping]],
) -> dict[str, Any]:
    with_usage = [j for j in jobs if isinstance(j.get("usage"), Mapping)]
    share_pairs = [
        (_usage(j, "cache_read_tokens"), _usage(j, "input_tokens"))
        for j in with_usage
        if _usage(j, "cache_read_tokens") is not None and _usage(j, "input_tokens")
    ]
    share_in = sum(i for _, i in share_pairs)
    tokens = {k: _total(_usage(j, k) for j in jobs) for k in _TOKEN_KEYS}
    cost, cost_unknown = _total(_usage(j, "cost_usd") for j in jobs)
    out_bytes = [j.get("output_bytes") for j in jobs]
    return {
        "profile": key[0],
        "backend": key[1],
        "lane": key[2],
        "jobs": len(jobs),
        "outcomes": {o: sum(1 for j in jobs if j["outcome"] == o) for o in OUTCOMES},
        "failure_classes": dict(
            sorted(Counter(j["failure_class"] for j in jobs if j.get("failure_class")).items())
        ),
        "wall_s": _dist(j.get("wall_s") for j in jobs),
        "queue_wait_s": _dist(j.get("queue_wait_s") for j in jobs),
        "tokens": {
            **{k.removesuffix("_tokens"): v for k, (v, _) in tokens.items()},
            "jobs_unknown": {k.removesuffix("_tokens"): n for k, (_, n) in tokens.items()},
        },
        "tokens_per_job": {
            "input": _dist(_usage(j, "input_tokens") for j in jobs),
            "output": _dist(_usage(j, "output_tokens") for j in jobs),
        },
        "api_calls_per_job": _dist(_usage(j, "api_calls") for j in jobs),
        "cache_read_share": round(sum(c for c, _ in share_pairs) / share_in, 4)
        if share_in
        else None,
        "cost_usd": {"total": _round(cost), "jobs_unknown": cost_unknown},
        "retries": {
            "of_earlier_run": sum(1 for j in jobs if j.get("retry_of_run_id")),
            "auto_scheduled": sum(1 for j in jobs if j.get("auto_retry_scheduled")),
        },
        "cloud_fallbacks": sum(1 for j in jobs if j.get("cloud_fallback_used")),
        "local_attempts": sum(int(j.get("local_attempts") or 0) for j in jobs),
        "bytes": {
            "input": {
                "p50": percentile((j["input_bytes"] for j in jobs), 50),
                "total": sum(j["input_bytes"] for j in jobs),
            },
            "output": {
                "p50": percentile(out_bytes, 50),
                "total": _total(out_bytes)[0],
                "n": sum(1 for b in out_bytes if b is not None),
            },
        },
        "turns": _turns_block(jobs, turns),
    }


def _days(jobs: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    by: dict[tuple[str, str], list[Mapping[str, Any]]] = {}
    for j in jobs:
        day = iso(parse_iso(j["finished_at"]))[:10]  # the UTC day, whatever offset was sent
        by.setdefault((day, j["profile"]), []).append(j)
    rows = []
    for (day, profile), js in sorted(by.items(), key=lambda kv: (kv[0][0], kv[0][1])):
        done = sum(1 for j in js if j["outcome"] == "completed")
        sums = {k: _total(_usage(j, k) for j in js) for k in _DAY_SUMS}
        rows.append(
            {
                "day": day,
                "profile": profile,
                "jobs": len(js),
                "completed": done,
                "not_completed": len(js) - done,
                "wall_s_p50": percentile((j.get("wall_s") for j in js), 50),
                **{k: _round(v) if k == "cost_usd" else v for k, (v, _) in sums.items()},
                "jobs_unknown": {k: n for k, (_, n) in sums.items()},
            }
        )
    return rows


def rollup(
    jobs: Iterable[Mapping[str, Any]],
    turns: Mapping[str, Sequence[Mapping[str, Any]]],
    *,
    now: float,
    days: int,
) -> dict[str, Any]:
    """The rollup of ``jobs`` finished in the ``days`` before ``now`` (see the module docstring);
    ``turns`` maps a gateway tag to the gateway turns joined to it."""
    since = now - days * 86400
    window = [j for j in jobs if since <= parse_iso(j["finished_at"]) <= now]
    groups: dict[tuple[str, str, str], list[Mapping[str, Any]]] = {}
    for j in window:
        groups.setdefault(group_key(j), []).append(j)
    return {
        "schema": ROLLUP_SCHEMA,
        "generated_at": iso(now),
        "window": {"since": iso(since), "until": iso(now), "days": days},
        "groups": [_group(k, groups[k], turns) for k in sorted(groups)],
        "days": _days(window),
    }


__all__ = [
    "CONTROLLER_SOURCE",
    "FINISHED_EVENT",
    "LANES",
    "NO_BACKEND",
    "OUTCOMES",
    "ROLLUP_SCHEMA",
    "group_key",
    "percentile",
    "rollup",
]
