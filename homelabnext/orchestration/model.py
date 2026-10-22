# SPDX-License-Identifier: Apache-2.0
"""The rollup of orchestration telemetry: per profile, backend and lane, and per day.

:func:`rollup` is a pure function of stored job records (the ``data`` of
``homelabnext.agent.job.finished``) and the gateway turns joined to them; the Orchestration page
renders it and ``hnx orchestration report --json`` prints it as the recommendation engine's input
(``homelabnext.orchestration.rollup/1``; evolve additively).  Shape::

    schema, generated_at, window {since, until, days}
    groups  [{profile, backend, lane, jobs, outcomes {completed, failed, cancelled, timeout},
              failure_classes {class: n}, wall_s {p50, p95, n}, queue_wait_s {p50, p95, n},
              tokens {input, output, reasoning, cache_read, jobs_unknown},
              tokens_per_job {input {p50, p95, n}, output {p50, p95, n}},
              api_calls_per_job {p50, p95, n}, cache_read_share, cost_usd {total, jobs_unknown},
              retries {of_earlier_run, auto_scheduled}, cloud_fallbacks, local_attempts,
              bytes {input {p50, total}, output {p50, total, n}},
              turns {jobs_with_turns, count, per_job {p50, p95, n}, input_tokens, output_tokens,
                     cache_read_tokens, cost_usd, failures, ttft_ms {p50, p95, n},
                     duration_ms {p50, p95, n}}}]   (the sums None when no job has gateway turns)
    days    [{day, profile, jobs, completed, not_completed, wall_s_p50, input_tokens,
              output_tokens, cost_usd}]

Percentiles are nearest-rank over the known values (``n`` of them); ``None`` when none is known.
A token count or cost the usage file did not report is *unknown*, never 0: sums are over the
known values and ``jobs_unknown`` counts the rest, so a share is never diluted by missing data.
"""

from __future__ import annotations

import math
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from typing import Any

from homelabnext.status.model import iso, parse_iso

FINISHED_EVENT = "homelabnext.agent.job.finished"
#: the only publisher of job records: the orchestration controller
CONTROLLER_SOURCE = "svc:llm-orchestrator"
ROLLUP_SCHEMA = "homelabnext.orchestration.rollup/1"
OUTCOMES = ("completed", "failed", "cancelled", "timeout")
LANES = ("real", "shadow")
#: the group key of a job without a backend (it never reached one)
NO_BACKEND = "-"
_TOKEN_KEYS = ("input_tokens", "output_tokens", "reasoning_tokens", "cache_read_tokens")


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


def _known_sum(values: Iterable[float | int | None]) -> float | int:
    return sum(v for v in values if v is not None)


def _usage(job: Mapping[str, Any], key: str) -> Any:
    usage = job.get("usage")
    return usage.get(key) if isinstance(usage, Mapping) else None


def group_key(job: Mapping[str, Any]) -> tuple[str, str, str]:
    return (job["profile"], job.get("backend") or NO_BACKEND, job["lane"])


def _turns_block(jobs: Sequence[Mapping[str, Any]], turns: Mapping[str, Sequence[Mapping]]):
    """The gateway's view of the jobs.  Only jobs routed through the LiteLLM gateway have turns
    (not a direct vLLM backend or a cloud provider): with none, the sums are None (no gateway
    data), never 0."""
    mine = [list(turns.get(j["gateway_tag"], ())) for j in jobs]
    flat = [t for ts in mine for t in ts]

    def total(key: str) -> Any:
        return _known_sum(t.get(key) for t in flat) if flat else None

    cost = total("cost_usd")
    return {
        "jobs_with_turns": sum(1 for ts in mine if ts),
        "count": len(flat),
        "per_job": _dist(len(ts) for ts in mine if ts),
        "input_tokens": total("input_tokens"),
        "output_tokens": total("output_tokens"),
        "cache_read_tokens": total("cache_read_tokens"),
        "cost_usd": None if cost is None else round(cost, 6),
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
    costs = [_usage(j, "cost_usd") for j in jobs]
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
            **{
                k.removesuffix("_tokens"): _known_sum(_usage(j, k) for j in jobs)
                for k in _TOKEN_KEYS
            },
            "jobs_unknown": sum(1 for j in jobs if _usage(j, "input_tokens") is None),
        },
        "tokens_per_job": {
            "input": _dist(_usage(j, "input_tokens") for j in jobs),
            "output": _dist(_usage(j, "output_tokens") for j in jobs),
        },
        "api_calls_per_job": _dist(_usage(j, "api_calls") for j in jobs),
        "cache_read_share": round(sum(c for c, _ in share_pairs) / share_in, 4)
        if share_in
        else None,
        "cost_usd": {
            "total": round(_known_sum(costs), 6),
            "jobs_unknown": sum(1 for c in costs if c is None),
        },
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
                "total": _known_sum(out_bytes),
                "n": sum(1 for b in out_bytes if b is not None),
            },
        },
        "turns": _turns_block(jobs, turns),
    }


def _days(jobs: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    by: dict[tuple[str, str], list[Mapping[str, Any]]] = {}
    for j in jobs:
        by.setdefault((j["finished_at"][:10], j["profile"]), []).append(j)
    rows = []
    for (day, profile), js in sorted(by.items(), key=lambda kv: (kv[0][0], kv[0][1])):
        done = sum(1 for j in js if j["outcome"] == "completed")
        rows.append(
            {
                "day": day,
                "profile": profile,
                "jobs": len(js),
                "completed": done,
                "not_completed": len(js) - done,
                "wall_s_p50": percentile((j.get("wall_s") for j in js), 50),
                "input_tokens": _known_sum(_usage(j, "input_tokens") for j in js),
                "output_tokens": _known_sum(_usage(j, "output_tokens") for j in js),
                "cost_usd": round(_known_sum(_usage(j, "cost_usd") for j in js), 6),
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
