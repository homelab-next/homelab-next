# SPDX-License-Identifier: Apache-2.0
"""The telemetry store: job records and gateway turns in one SQLite file, purged by age.

**Jobs** come only through :meth:`TelemetryStore.consume`, the consumer of
``homelabnext.agent.job.finished``: the body is decoded and validated against the envelope and
the type's schema (:func:`homelabnext.events.consumer.decode_event`), its ``source`` must be the
controller's (:data:`.model.CONTROLLER_SOURCE`), and it is idempotent the way
:class:`homelabnext.events.consumer.Consumer` is, but durably (the seen ids are the table):

* the same event id with the same body is a ``duplicate`` (acknowledged, nothing written);
* the same event id with a different body, or a second event for a run already recorded under
  another id, is refused (:class:`homelabnext.events.envelope.EventError`): one run, one record;
* a value the schema's pattern accepts but that is not real (a timestamp of 2026-02-30, an hour
  24, an offset of 99 hours) is refused the same way: everything :meth:`consume` derives from a
  record is computed before the database is touched, so the only other exceptions it raises are
  the store's own (:mod:`sqlite3`, the disk), which a caller may retry.

**Turns** come from the gateway's spend log (:mod:`.gateway`), already reduced to the allow-listed
names and numbers; a turn is keyed by the gateway's request id, so reading a window twice
rewrites the same rows.  A job's turns are re-read until it has been finished for ``settle_s``
(the gateway writes its spend log in batches), then the job is marked settled.

**Retention**: jobs finished, and turns started, more than ``retention_days`` ago are deleted
when the store opens and on every write (with the injected clock).
"""

from __future__ import annotations

import functools
import json
import sqlite3
import time
from collections.abc import Callable, Iterable, Mapping
from pathlib import Path
from typing import Any

from homelabnext._sqlite import transaction
from homelabnext.events.consumer import Delivery, decode_event
from homelabnext.events.envelope import EventError, body_digest
from homelabnext.status.model import iso, parse_iso

from .model import CONTROLLER_SOURCE, FINISHED_EVENT, rollup

_SCHEMA = """
CREATE TABLE IF NOT EXISTS jobs(
  run_id TEXT PRIMARY KEY, event_id TEXT NOT NULL UNIQUE, digest TEXT NOT NULL,
  profile TEXT NOT NULL, backend TEXT, lane TEXT NOT NULL, outcome TEXT NOT NULL,
  finished REAL NOT NULL, gateway_tag TEXT NOT NULL, received REAL NOT NULL,
  turns_settled REAL, doc TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS jobs_finished ON jobs(finished);
CREATE INDEX IF NOT EXISTS jobs_tag ON jobs(gateway_tag);
CREATE TABLE IF NOT EXISTS turns(
  turn_id TEXT PRIMARY KEY, gateway_tag TEXT NOT NULL, started REAL NOT NULL, doc TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS turns_tag ON turns(gateway_tag);
CREATE INDEX IF NOT EXISTS turns_started ON turns(started);
"""
DEFAULT_RETENTION_DAYS = 90
#: the store's own failures (the database, the disk): a caller retries these, never a record's
STORE_ERRORS = (sqlite3.Error, OSError)
#: (table, the time column retention is measured on)
_RETAINED = (("jobs", "finished"), ("turns", "started"))


class TelemetryStore:
    """Job records and gateway turns in one SQLite file (``path``)."""

    def __init__(
        self,
        path: str | Path,
        *,
        clock: Callable[[], float] = time.time,
        retention_days: float = DEFAULT_RETENTION_DAYS,
    ):
        self.path, self.clock = Path(path), clock
        self.retention_s = retention_days * 86400.0
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._db = functools.partial(transaction, self.path)
        with self._db() as db:
            db.executescript(_SCHEMA)
            self._purge(db, None)

    # ---------------------------------------------------------------- writes
    def purge(self, now: float | None = None) -> int:
        """Delete the jobs and turns past retention; returns how many rows went."""
        with self._db() as db:
            return self._purge(db, now)

    def _purge(self, db: sqlite3.Connection, now: float | None) -> int:
        cutoff = (self.clock() if now is None else now) - self.retention_s
        return sum(
            db.execute(f"DELETE FROM {table} WHERE {col} < ?", (cutoff,)).rowcount
            for table, col in _RETAINED
        )

    def consume(self, body: bytes | str | Mapping[str, Any]) -> Delivery:
        """Store one ``homelabnext.agent.job.finished`` event (see the module docstring); raises
        :class:`EventError` for a body that must never be retried (poison)."""
        event = decode_event(body, types=[FINISHED_EVENT])
        if event["source"] != CONTROLLER_SOURCE:
            raise EventError(
                "not the controller's job record",
                [f"source {event['source']!r}: only {CONTROLLER_SOURCE} reports jobs"],
            )
        eid, digest, data = event["id"], body_digest(event), event["data"]
        finished = _instants(data)["finished_at"]
        now = self.clock()
        with self._db() as db:
            row = db.execute(
                "SELECT event_id, digest FROM jobs WHERE event_id = ? OR run_id = ?",
                (eid, data["run_id"]),
            ).fetchone()
            if row is not None:
                if row[0] == eid and row[1] == digest:
                    return Delivery(eid, "duplicate")
                why = (
                    f"id {eid!r} was already consumed with another body"
                    if row[0] == eid
                    else f"run {data['run_id']!r} is already recorded under event {row[0]!r}"
                )
                raise EventError("job record conflicts with a stored one", [why])
            db.execute(
                "INSERT INTO jobs VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    data["run_id"], eid, digest, data["profile"], data.get("backend"),
                    data["lane"], data["outcome"], finished,
                    data["gateway_tag"], now, None, json.dumps(data, sort_keys=True),
                ),
            )  # fmt: skip
            self._purge(db, now)
        return Delivery(eid, "processed")

    def add_turns(self, turns: Iterable[Mapping[str, Any]]) -> int:
        """Insert or rewrite gateway turns (keyed by ``turn_id``); returns how many were written."""
        rows = [
            (
                t["turn_id"],
                t["gateway_tag"],
                parse_iso(t["started_at"]),
                json.dumps(t, sort_keys=True),
            )
            for t in turns
        ]
        with self._db() as db:
            db.executemany("INSERT OR REPLACE INTO turns VALUES (?,?,?,?)", rows)
            self._purge(db, None)
        return len(rows)

    def unsettled(self) -> list[dict[str, Any]]:
        """The jobs whose turns are still to be (re)read from the gateway."""
        with self._db() as db:
            rows = db.execute("SELECT doc FROM jobs WHERE turns_settled IS NULL ORDER BY finished")
            return [json.loads(r[0]) for r in rows]

    def settle(self, run_ids: Iterable[str], now: float) -> None:
        ids = [(now, r) for r in run_ids]
        with self._db() as db:
            db.executemany("UPDATE jobs SET turns_settled = ? WHERE run_id = ?", ids)

    # ---------------------------------------------------------------- reads
    def jobs(self, *, since: float | None = None, limit: int | None = None) -> list[dict[str, Any]]:
        """Job records (the event's ``data``), most recently finished first."""
        sql, args = "SELECT doc FROM jobs", []
        if since is not None:
            sql += " WHERE finished >= ?"
            args.append(since)
        sql += " ORDER BY finished DESC, run_id"
        if limit:
            sql += f" LIMIT {int(limit)}"
        with self._db() as db:
            return [json.loads(r[0]) for r in db.execute(sql, args)]

    def job(self, run_id: str) -> dict[str, Any] | None:
        with self._db() as db:
            row = db.execute("SELECT doc FROM jobs WHERE run_id = ?", (run_id,)).fetchone()
            return json.loads(row[0]) if row else None

    def turns(self, tags: Iterable[str] | None = None) -> dict[str, list[dict[str, Any]]]:
        """gateway tag -> its turns, oldest first (every stored turn when ``tags`` is None)."""
        sql, args = "SELECT gateway_tag, doc FROM turns", []
        if tags is not None:
            wanted = sorted(set(tags))
            if not wanted:
                return {}
            sql += f" WHERE gateway_tag IN ({','.join('?' * len(wanted))})"
            args = wanted
        sql += " ORDER BY started, turn_id"
        out: dict[str, list[dict[str, Any]]] = {}
        with self._db() as db:
            for tag, doc in db.execute(sql, args):
                out.setdefault(tag, []).append(json.loads(doc))
        return out

    def rollup(self, *, days: int = 7, now: float | None = None) -> dict[str, Any]:
        """:func:`.model.rollup` over the stored jobs of the last ``days`` and their turns."""
        now = self.clock() if now is None else now
        jobs = self.jobs(since=now - days * 86400)
        return rollup(jobs, self.turns(j["gateway_tag"] for j in jobs), now=now, days=days)


#: the record's timestamps; each must name a real instant that UTC can represent
_TIMES = ("queued_at", "started_at", "finished_at")


def _instants(data: Mapping[str, Any]) -> dict[str, float]:
    """The record's timestamps as epoch seconds; :class:`EventError` (poison) for one that matches
    the schema's pattern but is no real date and time, or falls outside what UTC can express."""
    out: dict[str, float] = {}
    for key in _TIMES:
        value = data.get(key)
        if value is None:
            continue
        try:
            out[key] = parse_iso(value)
            iso(out[key])  # the rollup buckets by the UTC day: it must be representable
        except (ValueError, OverflowError, OSError) as exc:
            raise EventError(
                "invalid event", [f"data.{key}: {value!r} is not a real date and time ({exc})"]
            ) from None
    return out


__all__ = ["DEFAULT_RETENTION_DAYS", "STORE_ERRORS", "TelemetryStore"]
