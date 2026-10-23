# SPDX-License-Identifier: Apache-2.0
"""The telemetry store: job records and gateway turns in one SQLite file, purged by age.

**Jobs** come only through :meth:`TelemetryStore.consume`, the consumer of
``homelabnext.agent.job.finished``: the body is decoded and validated against the envelope and
the type's schema (:func:`homelabnext.events.consumer.decode_event`), its ``source`` must be one
of the controller's service ids the store is configured with (``sources``, default
:data:`.model.CONTROLLER_SOURCE`), and it is idempotent the way
:class:`homelabnext.events.consumer.Consumer` is, but durably (the seen ids are the table):

* the same event id with the same body is a ``duplicate`` (acknowledged, nothing written);
* a record that finished more than ``retention_days`` ago is ``expired``: valid, acknowledged and
  not stored, since retention would delete it in the same write (a late replay, a backfill of an
  old outbox); it is neither ``processed`` nor poison;
* the same event id with a different body, a second event for a run already recorded under
  another id, or a record whose ``gateway_tag`` another run already holds, is refused
  (:class:`homelabnext.events.envelope.EventError`): one run, one record, and one tag per run, so
  the turns joined by a tag belong to exactly one job (a unique index enforces it too; a store
  an earlier release left with two jobs on one tag is refused when it opens, :class:`ValueError`
  naming the count and how to fix it, since the index cannot be built over them);
* an envelope attribute the envelope schema does not declare (a CloudEvents extension, which
  would be free text beside the closed ``data``: :data:`ENVELOPE_ATTRIBUTES`) is refused the same
  way, so the stored and exported envelope is names and numbers only;
* a ``subject`` other than the record's run id, or a time more than :data:`FUTURE_S` ahead of
  the store's clock, is refused the same way;
* a value the schema's pattern accepts but that is not real (a timestamp of 2026-02-30, an hour
  24, an offset of 99 hours), or timestamps out of order (queued after started or finished,
  started after finished, by more than :data:`ORDER_SLACK_S`), a time before :data:`EARLIEST`
  (a zero time), or queued more than ``retention_days`` before it finished, is refused the same
  way (the controller bounds neither queue wait nor run time, so a long job is not refused): everything
  :meth:`consume` derives from a record is computed before the database is touched, so the only other exceptions it raises are
  the store's own (:mod:`sqlite3`, the disk), which a caller may retry.

**Turns** come from the gateway's per-call log through a turn source (:mod:`.gateway`), as
neutral turn records (:data:`conformance.protocols.inference.TURN_FIELDS`): a record outside that
shape (another field, a value of the wrong kind) is refused with :class:`ValueError` before
anything is written, so no adapter can widen what is stored.  A turn is keyed by the gateway's
id of the call, so reading a window twice rewrites the same rows.  A job's turns are re-read
until it has been finished for ``settle_s`` (a gateway may write its log in batches), then the
job is marked settled.

**Retention**: jobs finished, and turns started, more than ``retention_days`` ago are deleted
when the store opens and on every write (with the injected clock).

**Files**: the database alone.  Writers use a rollback journal (``journal_mode=DELETE``, set on
every open, so a database a WAL writer left is converted), not WAL: ``<db>-journal`` exists only
while a write is in flight (or after a crash, until the next write rolls it back), and there is
never a ``-wal`` or ``-shm``.  That is what lets the hub read the store as another user: a WAL
reader must create ``-shm`` and ``-wal`` (it fails without write access to the directory, and
with it leaves files the writer cannot open), a rollback-journal reader creates nothing.  The
writers are one-shot timer passes with short transactions, so a reader that meets one waits for
its lock (SQLite's busy timeout) instead of reading beside it, and loses nothing it needs.

**Read-only** (``read_only=True``, the status hub's open): the file must already be a telemetry
store; it is opened with SQLite's ``mode=ro``, so nothing is created (no directory, no file, no
table, no journal), nothing is purged, the journal mode is not touched, and every write is
refused.  It needs read access to the file and nothing else.  A file that is no SQLite database
or holds no store is :class:`ValueError` (not a telemetry store); a store SQLite cannot open (a
database still in WAL mode, a lock held past the timeout, a crash's journal only a writer can roll
back) is :class:`ValueError` carrying SQLite's own message.
"""

from __future__ import annotations

import functools
import itertools
import json
import math
import re
import shlex
import sqlite3
import time
from collections.abc import Callable, Iterable, Iterator, Mapping
from pathlib import Path
from typing import Any

from conformance.protocols.inference import turn_problems
from homelabnext._sqlite import transaction
from homelabnext.events.consumer import Delivery, decode_event
from homelabnext.events.envelope import EventError, body_digest
from homelabnext.status.model import iso, parse_iso

from .model import CONTROLLER_SOURCE, FINISHED_EVENT, rollup

_TABLES = """
CREATE TABLE IF NOT EXISTS jobs(
  run_id TEXT PRIMARY KEY, event_id TEXT NOT NULL UNIQUE, digest TEXT NOT NULL,
  profile TEXT NOT NULL, backend TEXT, lane TEXT NOT NULL, outcome TEXT NOT NULL,
  finished REAL NOT NULL, gateway_tag TEXT NOT NULL, received REAL NOT NULL,
  turns_settled REAL, doc TEXT NOT NULL, event TEXT);
CREATE TABLE IF NOT EXISTS turns(
  turn_id TEXT PRIMARY KEY, gateway_tag TEXT NOT NULL, started REAL NOT NULL, doc TEXT NOT NULL);
"""
_INDEXES = """
CREATE INDEX IF NOT EXISTS jobs_finished ON jobs(finished);
DROP INDEX IF EXISTS jobs_tag;
CREATE UNIQUE INDEX IF NOT EXISTS jobs_gateway_tag ON jobs(gateway_tag);
CREATE INDEX IF NOT EXISTS turns_tag ON turns(gateway_tag);
CREATE INDEX IF NOT EXISTS turns_started ON turns(started);
"""


def dedupe_sql(cutoff: float) -> str:
    """What to run on a store whose jobs share a tag: keep, of each tag's jobs that finished at or
    after ``cutoff`` (the retention cutoff), the one received first (then the least run id), and
    delete the rest, the expired ones too.  Never by rowid, and never an expired job: the next
    open would purge it and leave the tag with no job at all, its live jobs already deleted."""
    c = repr(float(cutoff))
    return (
        f"DELETE FROM jobs WHERE finished < {c} OR EXISTS (SELECT 1 FROM jobs AS k"
        f" WHERE k.gateway_tag = jobs.gateway_tag AND k.finished >= {c} AND (k.received <"
        " jobs.received OR (k.received = jobs.received AND k.run_id < jobs.run_id)))"
    )


DEFAULT_RETENTION_DAYS = 90
#: the retention a store takes: every read window is bounded by it (a 10,000-day retention let a
#: job started in 2001 be read as 225,697 one-hour windows), and nan, inf or 0 would make every
#: age comparison meaningless
MIN_RETENTION_DAYS, MAX_RETENTION_DAYS = 1, 3650
#: a configured job source: a service id (``schemas/ids/logical-id.schema.json``'s ``svc_id``)
_SOURCE = re.compile(r"svc:[a-z][a-z0-9]*(?:-[a-z0-9]+)*")
#: the writers' journal: no -wal or -shm, so a reader as another user needs no write access
JOURNAL_MODE = "DELETE"
#: how long the write probe waits for its lock (ms); see :meth:`TelemetryStore.check_writable`
PROBE_BUSY_MS = 1000
#: the store's own failures (the database, the disk): a caller retries these, never a record's
STORE_ERRORS = (sqlite3.Error, OSError)
#: the envelope attributes a job record may carry: those ``schemas/events/envelope.schema.json``
#: declares, each a constant, an id or a pattern.  The envelope is open to CloudEvents
#: extensions, and an extension is free text this store would keep and export, so for this type
#: any other attribute is refused (poison), as ``data`` refuses any field its schema does not name
ENVELOPE_ATTRIBUTES = frozenset(
    {
        "specversion", "id", "source", "type", "time", "subject", "severity", "datacontenttype",
        "dataschema", "correlationid", "assetid", "assetowner", "assetcriticality", "data",
    }
)  # fmt: skip
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
        read_only: bool = False,
        sources: Iterable[str] = (CONTROLLER_SOURCE,),
    ):
        self.path, self.clock = Path(path), clock
        self.sources = tuple(sources)
        if not self.sources or not all(
            isinstance(s, str) and _SOURCE.fullmatch(s) for s in self.sources
        ):
            raise ValueError("sources: one or more service ids (svc:<name>), the controller's")
        if (
            isinstance(retention_days, bool)
            or not isinstance(retention_days, int | float)
            or not math.isfinite(retention_days)
            or not MIN_RETENTION_DAYS <= retention_days <= MAX_RETENTION_DAYS
        ):
            raise ValueError(
                f"retention_days {retention_days!r:.40}: a number of days, "
                f"{MIN_RETENTION_DAYS} to {MAX_RETENTION_DAYS}"
            )
        self.retention_s = retention_days * 86400.0
        if read_only:
            if not self.path.is_file():
                raise FileNotFoundError(f"no telemetry store at {self.path}")
            self._db = functools.partial(transaction, self.path, read_only=True)
            try:
                with self._db() as db:
                    names = {r[0] for r in db.execute("SELECT name FROM sqlite_master")}
            except sqlite3.OperationalError as exc:  # a store SQLite cannot open: say why
                raise ValueError(f"cannot read the telemetry store {self.path}: {exc}") from None
            except sqlite3.DatabaseError as exc:  # not a database at all
                raise ValueError(f"{self.path} is not a telemetry store ({exc})") from None
            if not {"jobs", "turns"} <= names:
                raise ValueError(f"{self.path} is not a telemetry store (no jobs or turns table)")
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._db = functools.partial(transaction, self.path, journal_mode=JOURNAL_MODE)
        with self._db() as db:  # committed on its own: a refusal below must not roll it back
            db.executescript(_TABLES)
            if "event" not in {r[1] for r in db.execute("PRAGMA table_info(jobs)")}:
                db.execute("ALTER TABLE jobs ADD COLUMN event TEXT")  # a store before export
            self._purge(db, None)
        with self._db() as db:
            _refuse_shared_tags(db, self.path, self.clock() - self.retention_s)
            db.executescript(_INDEXES)

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

    def check_writable(self) -> None:
        """Raise the store's own error (:data:`STORE_ERRORS`) unless a write could commit now:
        the lock a commit needs is taken (``BEGIN EXCLUSIVE``, waiting out SQLite's busy timeout:
        unlike ``IMMEDIATE`` it waits for readers too, so a reader stuck in a transaction fails
        the probe instead of every commit after it; held for microseconds) and a row is written,
        so the journal is created and written, then everything is rolled back.  The probe waits
        :data:`PROBE_BUSY_MS` at most, not the store's busy timeout: while ``BEGIN EXCLUSIVE``
        waits it holds a pending lock that every new reader (the hub) waits behind, so a reader
        stuck in a transaction would otherwise stall the hub for the whole timeout every pass.
        A consumer runs this before it fetches (:func:`.bus.drain`): a delivery fetched into a
        store that cannot take it costs an attempt, and the bus dead-letters a record after
        ``max_deliver`` of them however valid it is."""
        with self._db() as db:
            current = db.execute("PRAGMA busy_timeout").fetchone()[0]
            db.execute(f"PRAGMA busy_timeout={min(int(current), PROBE_BUSY_MS)}")
            db.execute("BEGIN EXCLUSIVE")
            try:
                db.execute("INSERT OR REPLACE INTO turns VALUES ('', '', 0, '')")
            finally:
                db.rollback()

    def consume(self, body: bytes | str | Mapping[str, Any]) -> Delivery:
        """Store one ``homelabnext.agent.job.finished`` event (see the module docstring); raises
        :class:`EventError` for a body that must never be retried (poison)."""
        event = decode_event(body, types=[FINISHED_EVENT])
        extra = sorted(set(event) - ENVELOPE_ATTRIBUTES)
        if extra:
            raise EventError(
                "invalid event",
                [f"envelope attribute {k!r:.40}: not one the envelope declares" for k in extra],
            )
        if event.get("subject", event["data"]["run_id"]) != event["data"]["run_id"]:
            raise EventError("invalid event", ["subject: not the record's run id (data.run_id)"])
        if event["source"] not in self.sources:
            raise EventError(
                "not the controller's job record",
                [f"source {event['source']!r}: only {', '.join(self.sources)} reports jobs"],
            )
        eid, digest, data = event["id"], body_digest(event), event["data"]
        now = self.clock()
        finished = _instants(data, self.retention_s, now + FUTURE_S)["finished_at"]
        if finished < now - self.retention_s:
            return Delivery(eid, "expired")
        with self._db() as db:
            rows = db.execute(
                "SELECT event_id, digest, run_id FROM jobs"
                " WHERE event_id = ? OR run_id = ? OR gateway_tag = ?",
                (eid, data["run_id"], data["gateway_tag"]),
            ).fetchall()
            if rows:
                if len(rows) == 1 and rows[0][:2] == (eid, digest):
                    return Delivery(eid, "duplicate")
                raise EventError(
                    "job record conflicts with a stored one",
                    [_conflict(r, eid, data) for r in rows],
                )
            db.execute(
                "INSERT INTO jobs (run_id, event_id, digest, profile, backend, lane, outcome,"
                " finished, gateway_tag, received, turns_settled, doc, event)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    data["run_id"], eid, digest, data["profile"], data.get("backend"),
                    data["lane"], data["outcome"], finished,
                    data["gateway_tag"], now, None, json.dumps(data, sort_keys=True),
                    json.dumps(event, sort_keys=True),
                ),
            )  # fmt: skip
            self._purge(db, now)
        return Delivery(eid, "processed")

    def add_turns(self, turns: Iterable[Mapping[str, Any]]) -> int:
        """Insert or rewrite gateway turns (keyed by ``turn_id``); returns how many were written.
        :class:`ValueError` and nothing written when any is not a neutral turn record."""
        turns = list(turns)
        for t in turns:
            probs = turn_problems(t)
            if probs:
                tid = t.get("turn_id") if isinstance(t, Mapping) else None
                raise ValueError(f"not a turn record ({tid!r:.80}): {'; '.join(probs)}")
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

    def dump(self) -> Iterator[tuple[str, Any]]:
        """Everything the store holds, for an export (:mod:`.export`): ``("job", (event,
        turns_settled))`` per job, oldest finish first, then ``("turn", turn)`` per turn, oldest
        start first.  ``event`` is the envelope as consumed (``None`` for a job a store before
        exports kept without it)."""
        with self._db() as db:
            has_event = "event" in {r[1] for r in db.execute("PRAGMA table_info(jobs)")}
            sql = f"SELECT {'event' if has_event else 'NULL'}, turns_settled FROM jobs"
            jobs = db.execute(sql + " ORDER BY finished, run_id").fetchall()
            turns = db.execute("SELECT doc FROM turns ORDER BY started, turn_id").fetchall()
        for event, settled in jobs:
            yield "job", (json.loads(event) if event else None, settled)
        for (doc,) in turns:
            yield "turn", json.loads(doc)

    def holds_tag(self, tag: str) -> bool:
        """Whether a stored job carries gateway tag ``tag`` (its turns join to it)."""
        with self._db() as db:
            sql = "SELECT 1 FROM jobs WHERE gateway_tag = ?"
            return db.execute(sql, (tag,)).fetchone() is not None

    def turn(self, turn_id: str) -> dict[str, Any] | None:
        with self._db() as db:
            row = db.execute("SELECT doc FROM turns WHERE turn_id = ?", (turn_id,)).fetchone()
            return json.loads(row[0]) if row else None

    def job(self, run_id: str) -> dict[str, Any] | None:
        with self._db() as db:
            row = db.execute("SELECT doc FROM jobs WHERE run_id = ?", (run_id,)).fetchone()
            return json.loads(row[0]) if row else None

    def turns(
        self, tags: Iterable[str] | None = None, *, since: float | None = None
    ) -> dict[str, list[dict[str, Any]]]:
        """gateway tag -> its turns, oldest first: the turns of the jobs finished at or after
        ``since`` (joined in SQL), narrowed to ``tags`` when given; every stored turn when neither
        is.  The tags are never bound one SQL variable each: a 90-day page of jobs would pass
        SQLite's variable limit (999 on an old build, 32766 on a current one)."""
        sql, args = "SELECT gateway_tag, doc FROM turns", []
        if since is not None:
            sql += " WHERE gateway_tag IN (SELECT gateway_tag FROM jobs WHERE finished >= ?)"
            args.append(since)
        sql += " ORDER BY started, turn_id"
        wanted = None if tags is None else set(tags)
        if wanted is not None and not wanted:
            return {}
        out: dict[str, list[dict[str, Any]]] = {}
        with self._db() as db:
            for tag, doc in db.execute(sql, args):
                if wanted is None or tag in wanted:
                    out.setdefault(tag, []).append(json.loads(doc))
        return out

    def job_turns(self, tag: str) -> list[dict[str, Any]]:
        """One job's turns (by its gateway tag), oldest first."""
        sql = "SELECT doc FROM turns WHERE gateway_tag = ? ORDER BY started, turn_id"
        with self._db() as db:
            return [json.loads(r[0]) for r in db.execute(sql, (tag,))]

    def rollup(self, *, days: int = 7, now: float | None = None) -> dict[str, Any]:
        """:func:`.model.rollup` over the stored jobs of the last ``days`` and their turns."""
        now = self.clock() if now is None else now
        since = now - days * 86400
        return rollup(self.jobs(since=since), self.turns(since=since), now=now, days=days)


def _refuse_shared_tags(db: sqlite3.Connection, path: Path, cutoff: float) -> None:
    """A store an earlier release wrote (a plain index on the tag) may hold two jobs with one
    tag, and the unique index cannot be built over them: refuse to open it (:class:`ValueError`)
    and say how to fix it (:func:`dedupe_sql` at the retention ``cutoff``), rather than fail on
    the index, or pick which job to drop.  The purge before it is already committed, so the count
    is of the jobs the table holds."""
    if db.execute("SELECT 1 FROM sqlite_master WHERE name = 'jobs_gateway_tag'").fetchone():
        return  # the unique index already holds
    tags, jobs = db.execute(
        "SELECT count(*), coalesce(sum(n), 0) FROM"
        " (SELECT count(*) AS n FROM jobs GROUP BY gateway_tag HAVING n > 1)"
    ).fetchone()
    if tags:
        raise ValueError(
            f"{path}: {tags} gateway tag(s) are each held by more than one job ({jobs} jobs), so "
            "their turns cannot be told apart and the store will not open; keep one job per tag "
            "and run again (to keep the one received first: "
            f"sqlite3 {shlex.quote(str(path))} {shlex.quote(dedupe_sql(cutoff))})"
        )


def _conflict(row: tuple[str, str, str], eid: str, data: Mapping[str, Any]) -> str:
    if row[0] == eid:
        return f"id {eid!r} was already consumed with another body"
    if row[2] == data["run_id"]:
        return f"run {data['run_id']!r} is already recorded under event {row[0]!r}"
    return (
        f"gateway tag {data['gateway_tag']!r} already joins run {row[2]!r}: "
        "its turns cannot be told apart"
    )


#: the record's timestamps; each must name a real instant that UTC can represent
_TIMES = ("queued_at", "started_at", "finished_at")
#: how far the timestamps may be out of order (queued <= started <= finished).  The controller
#: stamps all three from one clock at nanosecond precision, so they invert only when that wall
#: clock is stepped between two stamps (an NTP correction); a second absorbs such a step, and more
#: is a record whose span no read window covers as it stands
ORDER_SLACK_S = 1.0
#: no job time is earlier than this: an earlier one is a zero time (Go's 0001-01-01 behind a parse
#: error the controller ignored), not a job.  The controller bounds neither queue wait nor run
#: time, so the span between the times is not bounded here; only an instant no job has is refused
EARLIEST = parse_iso("2000-01-01T00:00:00Z")
#: how far ahead of the store's clock a job's time, or an imported time, may be: clock skew
#: between hosts, not a record (a job finished in 2099 would never be purged and hold its tag)
FUTURE_S = 86400.0


def _instants(data: Mapping[str, Any], retention_s: float, latest: float) -> dict[str, float]:
    """The record's timestamps as epoch seconds; :class:`EventError` (poison) for one that matches
    the schema's pattern but is no real date and time, falls outside what UTC can express, is
    before :data:`EARLIEST`, after ``latest`` (the store's clock plus :data:`FUTURE_S`), or is
    more than ``retention_s`` before the finish (older than anything the store keeps)."""
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
        if out[key] > latest:
            raise EventError(
                "invalid event",
                [f"data.{key}: {value!r} is in the future (more than a day ahead of the store)"],
            )
        if out[key] < EARLIEST:
            raise EventError(
                "invalid event", [f"data.{key}: {value!r} is before 2000: a zero time, not a job's"]
            )
    order = [k for k in _TIMES if k in out]
    for early, late in itertools.pairwise(order):
        if out[early] > out[late] + ORDER_SLACK_S:
            raise EventError(
                "invalid event",
                [f"data.{early}: {data[early]!r} is after data.{late} {data[late]!r}"],
            )
    first, last = out[order[0]], out[order[-1]]
    if first < last - retention_s:
        raise EventError(
            "invalid event",
            [
                f"data.{order[0]}: {data[order[0]]!r} is more than {retention_s / 86400:g} days "
                f"before data.{order[-1]} {data[order[-1]]!r}: older than the store keeps"
            ],
        )
    return out


__all__ = [
    "DEFAULT_RETENTION_DAYS",
    "EARLIEST",
    "ENVELOPE_ATTRIBUTES",
    "FUTURE_S",
    "JOURNAL_MODE",
    "MAX_RETENTION_DAYS",
    "MIN_RETENTION_DAYS",
    "PROBE_BUSY_MS",
    "STORE_ERRORS",
    "TelemetryStore",
    "dedupe_sql",
]
