# SPDX-License-Identifier: Apache-2.0
"""Calendar expressions in plain words, and their next run (the Schedule page).

Two dialects are read: a systemd ``OnCalendar=`` value (the roles' timers and the fleet units)
and a five-field cron line (a GitHub Actions ``on: schedule``, always UTC).  Both are turned into
one :class:`Calendar` -- the sets of minutes, hours, days of the month, months and weekdays it
fires on -- which gives the words (``daily at 05:20 UTC``) and the next run after a time.

Only what can be read exactly is read: an expression in another time zone (or none, which is the
host's local zone), a shorthand (``daily``, which is local too) or a construct outside the subset
below keeps its raw text, is described as such and has no computed next run.  A wrong next run
is worse than none.

Subset: values, ``*``, comma lists, ranges (``a-b`` in cron, ``a..b`` in systemd) and steps
(``*/n``, ``a/n``); systemd weekdays by name (``Mon``, ``Mon..Fri``), dates ``*-*-*``,
``*-MM-DD``, ``*-*-DD``, times ``HH:MM`` or ``HH:MM:SS`` and the trailing ``UTC`` token.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

__all__ = ["Calendar", "from_cron", "from_oncalendar", "interval_words", "next_run"]

DAYS = ("Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday")
_SD_DAYS = {d[:3].lower(): i for i, d in enumerate(DAYS)}
_SHORTHANDS = {
    "minutely",
    "hourly",
    "daily",
    "weekly",
    "monthly",
    "yearly",
    "annually",
    "quarterly",
    "semiannually",
}
#: how far ahead a next run is searched (a calendar that fires less often reads "not computed")
HORIZON_DAYS = 400


@dataclass(frozen=True)
class Calendar:
    """When an expression fires, as sets (weekdays 0 = Monday).  ``either``: cron's rule that
    a restricted day-of-month and a restricted weekday fire on either (systemd: both)."""

    minutes: tuple[int, ...]
    hours: tuple[int, ...]
    days: tuple[int, ...]
    months: tuple[int, ...]
    weekdays: tuple[int, ...]
    second: int = 0
    either: bool = False

    def fires_on(self, d: datetime) -> bool:
        if d.month not in self.months:
            return False
        dom, dow = d.day in self.days, d.weekday() in self.weekdays
        if self.either and len(self.days) < 31 and len(self.weekdays) < 7:
            return dom or dow
        return dom and dow


def _field(text: str, lo: int, hi: int, *, rng: str = "-") -> tuple[int, ...] | None:
    """The values of one field (a comma list of values, ranges and steps), or None."""
    out: set[int] = set()
    for part in text.split(","):
        base, _, step = part.partition("/")
        if step and not step.isdigit():
            return None
        if base == "*":
            a, b = lo, hi
        elif rng in base:
            x, _, y = base.partition(rng)
            if not (x.isdigit() and y.isdigit()):
                return None
            a, b = int(x), int(y)
        elif base.isdigit():
            a = int(base)
            b = hi if step else a
        else:
            return None
        if not (lo <= a <= b <= hi) or (step and int(step) < 1):
            return None
        out.update(range(a, b + 1, int(step) if step else 1))
    return tuple(sorted(out)) if out else None


def from_cron(expr: str) -> Calendar | None:
    """A five-field cron line (UTC, as GitHub Actions reads it), or None outside the subset."""
    f = expr.split()
    if len(f) != 5:
        return None
    vals = (
        _field(f[0], 0, 59),
        _field(f[1], 0, 23),
        _field(f[2], 1, 31),
        _field(f[3], 1, 12),
        _field(f[4], 0, 7),
    )
    if any(v is None for v in vals):
        return None
    minutes, hours, days, months, sun0 = vals
    weekdays = tuple(sorted({(d - 1) % 7 for d in sun0}))  # cron 0 and 7: Sunday; ours 0: Monday
    return Calendar(minutes, hours, days, months, weekdays, either=True)


def _sd_weekdays(text: str) -> tuple[int, ...] | None:
    out: set[int] = set()
    for part in text.lower().split(","):
        a, _, b = part.partition("..")
        if a[:3] not in _SD_DAYS or (b and b[:3] not in _SD_DAYS):
            return None
        x, y = _SD_DAYS[a[:3]], _SD_DAYS[(b or a)[:3]]
        out.update(range(x, y + 1) if x <= y else [*range(x, 7), *range(0, y + 1)])
    return tuple(sorted(out))


def from_oncalendar(expr: str) -> Calendar | None:
    """A systemd ``OnCalendar=`` value ending in ``UTC``, or None (another or no time zone, a
    shorthand, or outside the subset)."""
    tokens = expr.split()
    if not tokens or tokens[-1] != "UTC":
        return None
    tokens = tokens[:-1]
    weekdays: tuple[int, ...] | None = tuple(range(7))
    if tokens and re.match(r"^[A-Za-z]", tokens[0]):
        weekdays = _sd_weekdays(tokens.pop(0))
    if len(tokens) != 2 or weekdays is None:
        return None
    date, time = tokens
    d = date.split("-")
    t = time.split(":")
    if len(d) != 3 or d[0] != "*" or len(t) not in (2, 3):
        return None
    months, days = _field(d[1], 1, 12, rng=".."), _field(d[2], 1, 31, rng="..")
    hours, minutes = _field(t[0], 0, 23, rng=".."), _field(t[1], 0, 59, rng="..")
    second = t[2] if len(t) == 3 else "0"
    if None in (months, days, hours, minutes) or not re.fullmatch(r"\d{1,2}", second):
        return None
    return Calendar(minutes, hours, days, months, weekdays, second=int(second))


def _list(names: list[str]) -> str:
    return names[0] if len(names) == 1 else ", ".join(names[:-1]) + " and " + names[-1]


def words(cal: Calendar) -> str:
    """The calendar in plain words (UTC)."""
    every_day = len(cal.days) == 31 and len(cal.months) == 12
    if len(cal.hours) == 1 and len(cal.minutes) == 1:
        at = f"at {cal.hours[0]:02d}:{cal.minutes[0]:02d}"
        at += f":{cal.second:02d} UTC" if cal.second else " UTC"
    elif len(cal.hours) == 24 and len(cal.minutes) == 1:
        at = f"every hour at minute {cal.minutes[0]:02d}"
    elif len(cal.hours) == 24 and _step(cal.minutes, 60):
        at = f"every {_step(cal.minutes, 60)} minutes"
    else:
        hrs = ", ".join(f"{h:02d}" for h in cal.hours)
        mins = ", ".join(f"{m:02d}" for m in cal.minutes)
        at = f"at hours {hrs} UTC, minutes {mins}"
    if every_day and len(cal.weekdays) == 7:
        return ("daily " + at) if at.startswith("at ") else at
    day_names = [DAYS[d] for d in cal.weekdays]
    if every_day:
        if cal.weekdays == (0, 1, 2, 3, 4):
            return f"weekdays {at}"
        return f"weekly on {_list(day_names)} {at}"
    if len(cal.months) == 12 and len(cal.weekdays) == 7:
        return f"monthly on day {_list([str(d) for d in cal.days])} {at}"
    return f"on a calendar ({at})"


def _step(values: tuple[int, ...], span: int) -> int | None:
    """n when ``values`` is 0, n, 2n, ... covering ``span``."""
    if len(values) < 2 or values[0] != 0:
        return None
    n = values[1]
    return n if values == tuple(range(0, span, n)) else None


def next_run(cal: Calendar, after: datetime) -> datetime | None:
    """The first firing strictly after ``after`` (UTC), or None within :data:`HORIZON_DAYS`."""
    after = after.astimezone(UTC)
    day = after.replace(hour=0, minute=0, second=0, microsecond=0)
    for _ in range(HORIZON_DAYS):
        if cal.fires_on(day):
            for h in cal.hours:
                for m in cal.minutes:
                    t = day.replace(hour=h, minute=m, second=cal.second)
                    if t > after:
                        return t
        day += timedelta(days=1)
    return None


def interval_words(seconds: int) -> str:
    """``60`` -> ``every minute``, ``300`` -> ``every 5 minutes``, ``3600`` -> ``every hour``."""
    for unit, size in (("day", 86400), ("hour", 3600), ("minute", 60), ("second", 1)):
        if seconds % size == 0:
            n = seconds // size
            return f"every {unit}" if n == 1 else f"every {n} {unit}s"
    return f"every {seconds} seconds"


def describe(expr: str, dialect: str) -> tuple[str, Calendar | None]:
    """(plain words, calendar or None) for an expression of ``dialect`` (``cron`` or
    ``systemd``)."""
    if dialect == "cron":
        cal = from_cron(expr)
        return (
            words(cal) if cal else f"cron {expr} (UTC), outside the subset this page reads"
        ), cal
    if expr.strip().lower() in _SHORTHANDS:
        return f"{expr.strip().lower()}, in the host's local time zone", None
    cal = from_oncalendar(expr)
    if cal is not None:
        return words(cal), cal
    if not expr.strip().endswith("UTC"):
        return f"{expr} (no UTC token: the host's local time zone)", None
    return f"{expr} (outside the subset this page reads)", None
