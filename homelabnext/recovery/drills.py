# SPDX-License-Identifier: Apache-2.0
"""``hnx recovery drills check``: are the restore drills recent, verified and covering what they must.

The records file is the drill command's (``drills.json``): ``guests`` maps a guest id to its
last verified drill (``last_verified``, ``snapshot``) and its last failure (``last_failure``,
``failure``); ``services`` maps an application to its last verified export restore.  A row is

* **fail** when its last failure is newer than its last verified drill, or it was never verified,
  or its last verified drill is older than ``--max-age``;
* **warn** when it is older than ``--interval`` but within ``--max-age`` (overdue, not yet stale);
* **ok** otherwise.

``--require`` lists guest ids that must have a record (a guest never drilled is a fail, not an
absence), and ``--require-export N`` asks for at least N applications whose export restore
verified within ``--max-age`` (X-07: an export hook was exercised, not only an image).  Exit 0
when no row fails, 1 when one does, 2 on a usage error or an unreadable file; warnings alone
exit 0 (``--strict`` makes them fail).  Nothing here reads dumped content: a record carries none.
"""

from __future__ import annotations

import argparse
import datetime
import json
import re
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

_FMT = "%Y-%m-%dT%H:%M:%SZ"
_DURATION = re.compile(r"^(\d+)([dh])\Z")


def parse_duration(text: str) -> datetime.timedelta:
    m = _DURATION.match(text)
    if not m:
        raise ValueError(f"{text!r}: a duration is <n>d or <n>h")
    n = int(m.group(1))
    return datetime.timedelta(days=n) if m.group(2) == "d" else datetime.timedelta(hours=n)


def _ts(value: Any) -> datetime.datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return datetime.datetime.strptime(value, _FMT).replace(tzinfo=datetime.timezone.utc)  # noqa: UP017
    except ValueError:
        return None


def judge(
    row: Any, now: datetime.datetime, interval: datetime.timedelta, max_age: datetime.timedelta
) -> tuple[str, str]:
    """``(state, why)`` of one record."""
    if not isinstance(row, dict):
        return "fail", "the record is not a mapping"
    ok, bad = _ts(row.get("last_verified")), _ts(row.get("last_failure"))
    if ok is None:
        return "fail", "never verified" + (f"; last failure {row['last_failure']}" if bad else "")
    if bad is not None and bad >= ok:
        return "fail", f"the last drill failed ({str(row.get('failure', ''))[:120]})"
    age = now - ok
    days = age.total_seconds() / 86400
    if age > max_age:
        return "fail", f"last verified {days:.0f} d ago (limit {max_age.days} d)"
    if age > interval:
        return "warn", f"last verified {days:.0f} d ago (due every {interval.days} d)"
    return "ok", f"verified {days:.0f} d ago"


def check(
    doc: Any,
    now: datetime.datetime,
    interval: datetime.timedelta,
    max_age: datetime.timedelta,
    require: list[str] | None = None,
    require_export: int = 0,
) -> list[tuple[str, str, str]]:
    """``[(item, state, why)]`` for every guest, every required guest and the export requirement."""
    if not isinstance(doc, dict) or not isinstance(doc.get("guests"), dict):
        raise ValueError("the records hold no 'guests' mapping")
    out: list[tuple[str, str, str]] = []
    guests = doc["guests"]
    for gid in sorted(set(guests) | set(require or [])):
        if gid not in guests:
            out.append((gid, "fail", "required and never drilled"))
            continue
        state, why = judge(guests[gid], now, interval, max_age)
        out.append((gid, state, why))
    services = doc.get("services") if isinstance(doc.get("services"), dict) else {}
    fresh = 0
    for app in sorted(services):
        state, why = judge(services[app], now, interval, max_age)
        out.append(
            (f"export:{app}", state if state != "fail" else "warn", why + " (export restore)")
        )
        fresh += state in ("ok", "warn")
    if require_export and fresh < require_export:
        out.append(
            (
                "export-restores",
                "fail",
                f"{fresh} application export restore(s) verified, {require_export} required",
            )
        )
    return out


def _utcnow() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)  # noqa: UP017


def main(
    argv: list[str] | None = None,
    clock: Callable[[], datetime.datetime] = _utcnow,
) -> int:
    ap = argparse.ArgumentParser(prog="hnx recovery drills", description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("check", help="judge the drill records")
    c.add_argument("--records", required=True, type=Path)
    c.add_argument("--max-age", default="90d")
    c.add_argument("--interval", default="30d")
    c.add_argument(
        "--require", default="", help="comma-separated guest ids that must have a record"
    )
    c.add_argument(
        "--require-export", type=int, default=0, help="at least this many export restores verified"
    )
    c.add_argument("--strict", action="store_true", help="an overdue row fails too")
    c.add_argument("--now", help="the evaluation time (YYYY-MM-DDTHH:MM:SSZ), for a replay")
    args = ap.parse_args(argv)
    try:
        interval, max_age = parse_duration(args.interval), parse_duration(args.max_age)
        now = _ts(args.now) if args.now else clock()
        if now is None:
            raise ValueError("--now is YYYY-MM-DDTHH:MM:SSZ")
        doc = json.loads(args.records.read_text(encoding="utf-8"))
        rows = check(
            doc,
            now,
            interval,
            max_age,
            [g for g in args.require.split(",") if g],
            args.require_export,
        )
    except (OSError, ValueError) as exc:
        print(f"hnx recovery drills: {exc}", file=sys.stderr)
        return 2
    for item, state, why in rows:
        print(f"{state.upper():4}  {item}: {why}")
    failed = [r for r in rows if r[1] == "fail" or (args.strict and r[1] == "warn")]
    print(
        f"recovery drills: {'FAIL' if failed else 'ok'} ({len(rows)} rows, {len(failed)} failing)"
    )
    return 1 if failed else 0
