# SPDX-License-Identifier: Apache-2.0
"""The ``cti-watch`` checks: is the threat-intelligence product fresh, and is it leaning on the fallback?

Three checks, each a pure function of values the caller read (no network here, so each is tested
without one), joined into the rows of ``table:cti.watch`` that the ``cti-watch-*`` packs look up
(``workflows/packs/cti-watch-*.yml``) and page or post on:

``site``      LL-134: the published page's own top-level ``generated_at`` is older than ``max_age_h``
              (3 h).  Liveness is not freshness: a static site keeps serving the last good build
              while every render fails, so only the page's own timestamp tells.  Fetch it through
              the public edge, never LAN DNS (LL-107), and treat a fetch that fails as stale.
``lake``      LL-542: pipeline health is judged by what it produced, not whether timers ran.  Stale
              when the reporting table gained no rows in ``dead_air_h`` (LL-134's 2 h dead air),
              or far fewer rows in the last ``window_h`` (3 h) than its trailing median for the
              same window, or the last ``failed_runs`` (3) extract runs each reported ``failed`` > 0
              (the "extracted 0, failed 5, exit 0" shape).  ``LAKE_ROWS_SQL`` is the query that
              yields the counts.
``fallback``  Operator decision D1: a request no local backend can hold falls back to the
              Max-plan CLI, and every fallback is counted and alerted, never silent.  Counts the
              app's ``llm-route-fallback:`` WARNING lines (text) or the ``LLM_ROUTE_LOG`` JSONL
              records (``event == "llm-route-fallback"`` or ``fallback`` true, with a ``ts``) inside
              ``window_h`` and alerts above ``threshold``.  The fallback is expected to go unused
              once the reasoner's context is raised, so the default threshold is small.

A row is ``{check, stale, summary, value, threshold}``; ``stale`` is a real boolean, and a check that
cannot measure (no input) is stale with that as its summary, never silently fresh: an unrecognised
or empty input is an error to page on, not a pass.
"""

from __future__ import annotations

import json
import re
import statistics
import sys
from datetime import UTC, datetime, timedelta
from typing import Any

SITE_MAX_AGE_H = 3.0
LAKE_WINDOW_H = 3.0
LAKE_DEAD_AIR_H = 2.0
LAKE_RATIO = 0.2
LAKE_FAILED_RUNS = 3
FALLBACK_WINDOW_H = 3.0
FALLBACK_THRESHOLD = 5

# Rows of the reporting table per hour for the last 8 days (the caller turns them into the
# `hourly` list of lake_check, newest first); the table's schema is the lake's, set by the site.
LAKE_ROWS_SQL = (
    "SELECT date_trunc('hour', ingested_at) AS hour, count(*) AS rows "
    "FROM {schema}.reporting WHERE ingested_at > current_timestamp - INTERVAL '8' DAY "
    "GROUP BY 1 ORDER BY 1 DESC"
)

_GENERATED_AT = re.compile(r'"generated_at"\s*:\s*"([^"]+)"')


def parse_ts(value: Any) -> datetime | None:
    """An ISO-8601 timestamp (``Z`` or an offset; naive means UTC) or epoch seconds, else None."""
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        try:
            return datetime.fromtimestamp(float(value), UTC)
        except (OverflowError, OSError, ValueError):
            return None
    if not isinstance(value, str):
        return None
    text = value.strip().replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def _row(check: str, stale: bool, summary: str, value: Any, threshold: Any) -> dict[str, Any]:
    return {
        "check": check,
        "stale": bool(stale),
        "summary": summary,
        "value": value,
        "threshold": threshold,
    }


def site_check(
    page: str | None, now: datetime, max_age_h: float = SITE_MAX_AGE_H
) -> dict[str, Any]:
    """LL-134: age of the page's own ``generated_at``.  No page, or none readable, is stale."""
    if not page:
        return _row(
            "site", True, "cti site: the page could not be fetched or was empty", None, max_age_h
        )
    m = _GENERATED_AT.search(page)
    ts = parse_ts(m.group(1)) if m else None
    if ts is None:
        return _row("site", True, "cti site: no readable generated_at on the page", None, max_age_h)
    age = round((now - ts).total_seconds() / 3600, 2)
    if age < -1:  # a timestamp from the future is a broken clock or a broken page, never fresh
        return _row(
            "site", True, f"cti site: generated_at is {-age:.1f} h in the future", age, max_age_h
        )
    stale = age > max_age_h
    return _row(
        "site",
        stale,
        f"cti site: generated_at {age:.1f} h old (limit {max_age_h:g} h)",
        age,
        max_age_h,
    )


def lake_check(
    hourly: list[tuple[datetime, int]] | None,
    extract_failed: list[int] | None,
    now: datetime,
    window_h: float = LAKE_WINDOW_H,
    dead_air_h: float = LAKE_DEAD_AIR_H,
    ratio: float = LAKE_RATIO,
    failed_runs: int = LAKE_FAILED_RUNS,
) -> dict[str, Any]:
    """LL-542 (and LL-134's dead air): rows written to the reporting table, and extract failures.

    ``hourly`` is (hour start, rows) for hours that had rows; an hour absent had none.
    ``extract_failed`` is the ``failed`` count of the latest extract runs, newest first.
    """
    if hourly is None or len(hourly) == 0:
        return _row(
            "lake",
            True,
            "cti lake: no reporting row counts were read (empty or unreadable)",
            None,
            ratio,
        )
    counts = {h.replace(minute=0, second=0, microsecond=0): n for h, n in hourly}
    top = now.replace(minute=0, second=0, microsecond=0)

    def rows_in(hours: int, end: datetime) -> int:
        return sum(counts.get(end - timedelta(hours=i), 0) for i in range(hours))

    win = max(1, round(window_h))
    last = rows_in(win, top + timedelta(hours=1))  # this (partial) hour and the previous win-1
    recent_dead = round(dead_air_h)
    dead = rows_in(max(1, recent_dead), top + timedelta(hours=1)) == 0
    # the same window at every offset over the previous 7 days, whole windows only
    trail = [rows_in(win, top - timedelta(hours=win * k)) for k in range(1, (7 * 24) // win + 1)]
    median = statistics.median(trail) if trail else 0
    reasons: list[str] = []
    if dead:
        reasons.append(f"no new rows in {dead_air_h:g} h")
    if median > 0 and last < ratio * median:
        reasons.append(f"{last} rows in {window_h:g} h against a trailing median of {median:g}")
    if (
        extract_failed is not None
        and len(extract_failed) >= failed_runs
        and all(f > 0 for f in extract_failed[:failed_runs])
    ):
        reasons.append(f"extract reported failed > 0 in each of the last {failed_runs} runs")
    if reasons:
        return _row("lake", True, "cti lake: " + "; ".join(reasons), last, ratio)
    return _row(
        "lake",
        False,
        f"cti lake: {last} rows in {window_h:g} h (trailing median {median:g})",
        last,
        ratio,
    )


def fallback_check(
    log_text: str | None,
    now: datetime,
    window_h: float = FALLBACK_WINDOW_H,
    threshold: int = FALLBACK_THRESHOLD,
) -> dict[str, Any]:
    """D1: count fallbacks to the Max-plan CLI inside the window, from text lines or JSONL.

    A line counts when it is a JSON object with ``event`` ``llm-route-fallback`` (or ``fallback``
    true) and a ``ts`` in the window, or a text line holding ``llm-route-fallback:`` with a leading
    ISO timestamp in the window.  A line with no readable timestamp is counted (it cannot be proven
    old, and the log is the window's own), so a log that lost its timestamps is loud, not silent.
    ``None`` (no log read) is stale: a counter that cannot read its log has not shown zero.
    """
    if log_text is None:
        return _row(
            "fallback", True, "cti fallback: the route log could not be read", None, threshold
        )
    since = now - timedelta(hours=window_h)
    n = 0
    for line in log_text.splitlines():
        line = line.strip()
        if not line:
            continue
        ts = None
        hit = False
        if line.startswith("{"):
            try:
                rec = json.loads(line)
            except ValueError:
                rec = None
            if isinstance(rec, dict):
                hit = rec.get("event") == "llm-route-fallback" or rec.get("fallback") is True
                ts = parse_ts(rec.get("ts") or rec.get("time") or rec.get("timestamp"))
        elif "llm-route-fallback:" in line:
            hit = True
            ts = parse_ts(line.split(None, 1)[0])
        if hit and (ts is None or since <= ts <= now + timedelta(minutes=5)):
            n += 1
    return _row(
        "fallback",
        n > threshold,
        f"cti fallback: {n} claude-cli fallbacks in {window_h:g} h (alert above {threshold})",
        n,
        threshold,
    )


def build_table(rows: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """The ``table:cti.watch`` rows, keyed ``cti-watch-<check>``: each pack looks up its own schedule id."""
    return {f"cti-watch-{r['check']}": r for r in rows}


def main(argv: list[str] | None = None, clock=datetime.now) -> int:
    """Read the inputs the caller already fetched and print the table as JSON; exit 1 if any is stale."""
    import argparse
    from pathlib import Path

    ap = argparse.ArgumentParser(prog="cti_watch", description=__doc__.splitlines()[0])
    ap.add_argument("--site-file", help="the fetched page (through the public edge)")
    ap.add_argument(
        "--lake-json", help='{"hourly": [["<hour ISO>", rows], ...], "extract_failed": [n, ...]}'
    )
    ap.add_argument(
        "--route-log", help="the cti-agent LLM_ROUTE_LOG JSONL or the journal's WARNING lines"
    )
    ap.add_argument("--now", help="ISO time (tests)")
    ap.add_argument("--fallback-threshold", type=int, default=FALLBACK_THRESHOLD)
    args = ap.parse_args(argv)
    now = parse_ts(args.now) if args.now else clock(UTC)
    if now is None:
        ap.error("--now is not a timestamp")

    def read(path: str | None) -> str | None:
        try:
            return Path(path).read_text() if path else None
        except OSError:
            return None

    hourly = extract_failed = None
    raw = read(args.lake_json)
    if raw:
        try:
            doc = json.loads(raw)
            hourly = [(t, int(n)) for h, n in doc["hourly"] if (t := parse_ts(h)) is not None]
            extract_failed = [int(x) for x in doc.get("extract_failed", [])]
        except (ValueError, KeyError, TypeError):
            hourly = None
    table = build_table(
        [
            site_check(read(args.site_file), now),
            lake_check(hourly, extract_failed, now),
            fallback_check(read(args.route_log), now, threshold=args.fallback_threshold),
        ]
    )
    json.dump(table, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 1 if any(r["stale"] for r in table.values()) else 0


if __name__ == "__main__":
    raise SystemExit(main())
