# SPDX-License-Identifier: Apache-2.0
"""The Orchestration page of the status hub: server-rendered, no script, the hub's stylesheet.

``hnx status serve --orchestration DB`` (menu panel ``orchestration``, views schema 1.9):

======================== ========================================================================
``/orchestration``         per profile, backend and lane over the last ``days`` (``?days=``, 1..90,
                           default 7): jobs, outcomes, p50/p95 wall time and queue wait, tokens in
                           and out, cache-read share, cost, retries and cloud fallbacks, input vs
                           output size, the gateway turns joined to the jobs; the trend by day and
                           profile; the latest jobs.  Filter chips by profile, backend, lane and
                           outcome narrow all three.
``/orchestration/job``     one job (``?run=``): its record and the gateway turns joined to it.
======================== ========================================================================

Names and numbers only: the store holds no text to show (:mod:`.store`, :mod:`.gateway`), and
every value is escaped anyway.  Each request reads the store; it never writes.
"""

from __future__ import annotations

import re
import urllib.parse
from collections.abc import Callable, Mapping, Sequence
from typing import Any

from homelabnext.status.agents.pages import _chips, _href, _n, _table
from homelabnext.status.render import _e, nav_html, shell_html

from .model import NO_BACKEND, OUTCOMES, _total, group_key, rollup
from .store import TelemetryStore

__all__ = ["ROUTES", "OrchestrationSite"]

Response = tuple[int, str, bytes]
HTML = "text/html; charset=utf-8"
ROUTES = ("/orchestration", "/orchestration/job")
DEFAULT_DAYS = 7
MAX_DAYS = 90
RECENT = 50
_CLASS = {"completed": "ok", "failed": "fail", "timeout": "fail", "cancelled": "unknown"}
_FILTERS = ("profile", "backend", "lane", "outcome")
#: a job without gateway turns (a direct vLLM backend, a cloud provider): not zero, unknown
NO_GATEWAY = '<span class="muted">no gateway data</span>'
#: a query value: the characters of the job record's run_id and backend (agent.job.finished 1.0),
#: which may start with a dot or a digit, so also the literal ``-`` (NO_BACKEND); profile ids,
#: lanes, outcomes and ``days`` are inside it too
_VALUE = re.compile(r"[A-Za-z0-9._:-]{1,128}")


def _q(query: str) -> dict[str, str]:
    """Single-valued, shape-checked query parameters (anything else is ignored).  Not the agent
    pages' validator: theirs requires a letter or digit first, which refused ``backend=-`` and
    every dotted backend or run id, so such a filter or link silently showed everything or no
    job."""
    out = {}
    for k, vals in urllib.parse.parse_qs(query, keep_blank_values=False).items():
        if len(vals) == 1 and _VALUE.fullmatch(vals[0]):
            out[k] = vals[0]
    return out


def _badge(outcome: str) -> str:
    return f'<span class="s {_CLASS.get(outcome, "unknown")}">{_e(outcome)}</span>'


def _num(v: Any, unit: str = "") -> str:
    if v is None:
        return '<span class="muted">?</span>'
    if isinstance(v, float):
        v = f"{v:.1f}" if abs(v) >= 1 or v == 0 else f"{v:.3g}"
    return _e(f"{v}{unit}")


def _pair(d: Mapping[str, Any], unit: str = "s") -> str:
    return f"{_num(d['p50'], unit)} / {_num(d['p95'], unit)}"


def _usd(v: Any) -> str:
    return '<span class="muted">?</span>' if v is None else _e(f"${v:.4f}")


def _size(n: Any) -> str:
    if n is None:
        return '<span class="muted">?</span>'
    for unit in ("B", "KiB", "MiB"):
        if n < 1024 or unit == "MiB":
            return _e(f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}")
        n /= 1024
    return ""  # pragma: no cover


def _partial(total: Any, unknown: int, show: Callable[[Any], str] = _num) -> str:
    """A sum over the known values (the rollup's): ``?`` when none is known (``total`` None),
    else the sum and, when some were left out, how many."""
    if total is None:
        return '<span class="muted">?</span>'
    return show(total) + (f' <span class="muted">({unknown} unknown)</span>' if unknown else "")


def _in_out(sums: Mapping[str, Any], unknown: Mapping[str, int], keys: tuple[str, str]) -> str:
    return "/".join(_partial(sums[k], unknown[k]) for k in keys)


def _usage(j: Mapping[str, Any], key: str) -> Any:
    return (j.get("usage") or {}).get(key)


class OrchestrationSite:
    """The orchestration routes of ``hnx status serve`` over one :class:`TelemetryStore`."""

    def __init__(self, store: TelemetryStore, *, clock: Callable[[], float]):
        self.store, self.clock = store, clock

    def handle(self, route: str, query: str, doc: Mapping[str, Any]) -> Response | None:
        if route not in ROUTES:
            return None
        q = _q(query)
        if route == "/orchestration/job":
            title, main = self._job(q)
        else:
            title, main = "Orchestration", self._overview(q)
        html = shell_html(doc, title, main, nav=nav_html(doc, live=True))
        return 200, HTML, html.encode("utf-8")

    # ---------------------------------------------------------------- overview
    def _overview(self, q: Mapping[str, str]) -> str:
        days = int(q["days"]) if q.get("days", "").isdigit() else DEFAULT_DAYS
        days = min(max(days, 1), MAX_DAYS)
        now = self.clock()
        since = now - days * 86400
        all_jobs = self.store.jobs(since=since)
        jobs = [
            j
            for j in all_jobs
            if all(
                str(j.get(k) or (NO_BACKEND if k == "backend" else "")) == q[k]
                for k in _FILTERS
                if k in q
            )
        ]
        turns = self.store.turns((j["gateway_tag"] for j in jobs), since=since)
        roll = rollup(jobs, turns, now=now, days=days)
        cur = {k: v for k, v in q.items() if k in (*_FILTERS, "days")}
        chips = "".join(
            _chips("/orchestration", cur, k, sorted({str(group_key(j)[i]) for j in all_jobs}))
            for i, k in enumerate(("profile", "backend", "lane"))
        ) + _chips("/orchestration", cur, "outcome", [o for o in OUTCOMES if any(
            j["outcome"] == o for j in all_jobs)])  # fmt: skip
        counts = " ".join(
            f"{_badge(o)} {sum(1 for j in jobs if j['outcome'] == o)}" for o in OUTCOMES
        )
        return (
            "<h2>Orchestration</h2>"
            f'<p class="muted">Agent jobs of the orchestration controller finished in the last '
            f"{days} day(s), {_e(roll['window']['since'])} to {_e(roll['window']['until'])}; "
            "per-turn figures are the gateway's, joined by tag. Names and numbers only.</p>"
            f"<p>{len(jobs)} jobs &middot; {counts}</p>{chips}"
            "<h3>By profile and backend</h3>" + self._groups(roll["groups"]) +
            "<h3>Trend by day</h3>" + self._trend(roll["days"]) +
            "<h3>Latest jobs</h3>" + self._recent(jobs[:RECENT], turns)
        )  # fmt: skip

    @staticmethod
    def _groups(groups: Sequence[Mapping[str, Any]]) -> str:
        rows = []
        for g in groups:
            o, t, tr = g["outcomes"], g["tokens"], g["turns"]
            share = g["cache_read_share"]
            rows.append(
                (
                    _e(g["profile"]), _e(g["backend"]), _e(g["lane"]), _e(g["jobs"]),
                    " ".join(f"{_badge(k)}&nbsp;{o[k]}" for k in OUTCOMES if o[k]),
                    _pair(g["wall_s"]), _pair(g["queue_wait_s"]),
                    _in_out(t, t["jobs_unknown"], ("input", "output")),
                    _num(None if share is None else round(100 * share, 1), "%"),
                    _partial(g["cost_usd"]["total"], g["cost_usd"]["jobs_unknown"], _usd),
                    _e(f"{g['retries']['of_earlier_run']}/{g['retries']['auto_scheduled']}"),
                    _e(g["cloud_fallbacks"]),
                    f"{_size(g['bytes']['input']['p50'])} / {_size(g['bytes']['output']['p50'])}",
                    _e(f"{tr['count']} in {tr['jobs_with_turns']} of {g['jobs']} jobs")
                    if tr["count"]
                    else NO_GATEWAY,
                )
            )  # fmt: skip
        return _table(
            ("Profile", "Backend", "Lane", "Jobs", "Outcomes", "Wall p50/p95", "Queue p50/p95",
             "Tokens in/out", "Cache read", "Cost", "Retries/auto", "Cloud fallbacks",
             "Input/output p50", "Gateway turns"),
            rows,
        )  # fmt: skip

    @staticmethod
    def _trend(days: Sequence[Mapping[str, Any]]) -> str:
        rows = [
            (
                _e(d["day"]), _e(d["profile"]), _e(d["jobs"]), _e(d["completed"]),
                _e(d["not_completed"]), _num(d["wall_s_p50"], "s"),
                _in_out(d, d["jobs_unknown"], ("input_tokens", "output_tokens")),
                _partial(d["cost_usd"], d["jobs_unknown"]["cost_usd"], _usd),
            )
            for d in sorted(days, key=lambda d: (d["day"], d["profile"]), reverse=True)
        ]  # fmt: skip
        return _table(
            ("Day", "Profile", "Jobs", "Completed", "Not completed", "Wall p50", "Tokens in/out",
             "Cost"),
            rows,
        )  # fmt: skip

    @staticmethod
    def _recent(jobs: Sequence[Mapping[str, Any]], turns: Mapping[str, Sequence]) -> str:
        rows = [
            (
                _e(j["finished_at"]),
                f'<a href="{_e(_href("/orchestration/job", run=j["run_id"]))}"><code>'
                f"{_e(j['run_id'])}</code></a>",
                _e(j["profile"]), _n(j.get("backend")), _e(j["lane"]), _badge(j["outcome"]),
                _n(j.get("failure_class")), _num(j.get("wall_s"), "s"),
                _num(j.get("queue_wait_s"), "s"),
                f"{_num(_usage(j, 'input_tokens'))}/{_num(_usage(j, 'output_tokens'))}",
                _usd(_usage(j, "cost_usd")), _e(len(turns[j["gateway_tag"]])) if turns.get(j["gateway_tag"]) else NO_GATEWAY,
            )
            for j in jobs
        ]  # fmt: skip
        return _table(
            ("Finished", "Run", "Profile", "Backend", "Lane", "Outcome", "Failure class", "Wall",
             "Queue", "Tokens in/out", "Cost", "Turns"),
            rows,
        )  # fmt: skip

    # ---------------------------------------------------------------- one job
    def _job(self, q: Mapping[str, str]) -> tuple[str, str]:
        run = q.get("run")
        job = self.store.job(run) if run else None
        if job is None:
            return "Orchestration job", (
                '<h2>Orchestration job</h2><p class="muted">no such job '
                f'<code>{_e(run or "")}</code></p><p><a href="/orchestration">all jobs</a></p>'
            )
        turns = self.store.job_turns(job["gateway_tag"])
        usage = job.get("usage") or {}
        facts = [
            ("Run", f"<code>{_e(job['run_id'])}</code>"),
            ("Profile", f"{_e(job['profile'])} {_n(job.get('profile_revision'))}"),
            ("Lane", _e(job["lane"])),
            ("Outcome", _badge(job["outcome"]) + f" {_n(job.get('failure_class'))}"),
            ("Retry of", _n(job.get("retry_of_run_id"))),
            ("Auto-retry scheduled", _e("yes" if job.get("auto_retry_scheduled") else "no")),
            ("Local attempts", _e(job["local_attempts"])),
            ("Cloud fallback", _e("yes" if job.get("cloud_fallback_used") else "no")),
            ("Backend / model", f"{_n(job.get('backend'))} / {_n(job.get('model'))}"),
            ("Queued / started / finished",
             f"{_e(job['queued_at'])} / {_n(job.get('started_at'))} / {_e(job['finished_at'])}"),
            ("Queue wait / wall", f"{_num(job.get('queue_wait_s'), 's')} / {_num(job.get('wall_s'), 's')}"),
            ("Input / output", f"{_size(job['input_bytes'])} / {_size(job.get('output_bytes'))}"),
            ("Usage file", "none" if not job.get("usage") else " &middot; ".join(
                f"{_e(k.removesuffix('_tokens').replace('_', ' '))} {_num(usage.get(k))}"
                for k in ("input_tokens", "output_tokens", "reasoning_tokens",
                          "cache_read_tokens", "api_calls")
            ) + f" &middot; cost {_usd(usage.get('cost_usd'))}"),
            ("Turn exit", _n(job.get("turn_exit_reason"))),
            ("Gateway tag", f"<code>{_e(job['gateway_tag'])}</code>"),
        ]  # fmt: skip
        tools = _table(
            ("Tool", "Calls"), [(_e(t["name"]), _e(t["calls"])) for t in job.get("tools") or ()]
        )
        if turns:
            # each sum over the turns that report that value, the others counted
            seen_in = _partial(*_total(t.get("input_tokens") for t in turns))
            seen_out = _partial(*_total(t.get("output_tokens") for t in turns))
            recon = (
                f"<p>The gateway saw {len(turns)} turn(s): {seen_in} tokens in, {seen_out} out; "
                "the usage file reports "
                f"{_num(usage.get('input_tokens'))} in, {_num(usage.get('output_tokens'))} out "
                f"over {_num(usage.get('api_calls'))} call(s).</p>"
            )
        else:
            recon = (
                f"<p>{NO_GATEWAY}: none of this job's requests went through the LLM gateway with "
                "its tag (a direct backend, a cloud provider, or the gateway's spend log is not "
                "read yet).</p>"
            )
        rows = [
            (
                _e(t["started_at"]), f"<code>{_e(t['turn_id'])}</code>", _n(t.get("model_group")),
                _n(t.get("model")), _n(t.get("call_type")), _n(t.get("status")),
                _n(t.get("error_code")), _num(t.get("input_tokens")), _num(t.get("output_tokens")),
                _num(t.get("cache_read_tokens")),
                _e({True: "hit", False: "miss"}.get(t.get("cache_hit"), "")),
                _num(t.get("ttft_ms"), "ms"), _num(t.get("duration_ms"), "ms"),
                _usd(t.get("cost_usd")),
            )
            for t in turns
        ]  # fmt: skip
        main = (
            f"<h2>Job <code>{_e(job['run_id'])}</code></h2>"
            '<p><a href="/orchestration">all jobs</a></p>'
            + _table(("Field", "Value"), [(_e(k), v) for k, v in facts])
            + "<h3>Tools</h3>" + tools
            + "<h3>Gateway turns</h3>" + recon
            + _table(
                ("Started", "Request", "Model group", "Model", "Call", "Status", "Error",
                 "In", "Out", "Cache read", "Cache", "TTFT", "Duration", "Cost"),
                rows,
            )
        )  # fmt: skip
        return f"Orchestration job {job['run_id']}", main
