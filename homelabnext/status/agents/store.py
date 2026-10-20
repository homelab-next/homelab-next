# SPDX-License-Identifier: Apache-2.0
"""The activity store: both tiers in one SQLite file, redacted and capped before anything is
written, purged by age.

**Order on the way in, for every record, always** (``add``):

1. validate against its schema (``summary_problems`` / ``detail_problems``) -- refused otherwise;
2. **redact**: every private text field goes through the shared screener
   (:class:`homelabnext.agent.screen.Screener`) with the secret types always on (private keys,
   JWTs, vendor tokens and ``Authorization: Bearer`` credentials, secret-key values) and the
   personal-data types (e-mail, phone, card, national id, addresses) when
   ``redact_personal_data`` is set.  Replacements are typed labels (``[REDACTED:token:1]``); the
   counts are kept in ``redactions``, never the values.  The summary tier's few names (host,
   project, model, agent, tool) are screened too: one that holds a secret becomes ``redacted``;
3. **cap**: each field is cut to its configured size *after* redaction (cutting first could
   leave half a secret the screener no longer recognises) and listed in ``truncated``;
4. validate again, then write.

So a secret in a command never reaches the disk, not even in the WAL.  **Retention**: rows older
than ``retention_days`` -- by event time or by arrival, whichever is older -- are deleted when the
store opens and on every write batch (:meth:`ActivityStore.purge`, with the injected clock).
"""

from __future__ import annotations

import json
import sqlite3
import time
from collections.abc import Callable, Iterable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from homelabnext.agent.screen import Screener

from ..model import parse_iso
from .model import (
    DETAIL_TEXT,
    Thresholds,
    derive_sessions,
    detail_problems,
    summary_problems,
)

SECRET_TYPES = ("private-key", "jwt", "token", "secret")
PERSONAL_TYPES = ("card", "email", "national-id", "ip", "phone")
DEFAULT_CAPS = {
    "prompt": 4000,
    "command": 2000,
    "tool_input": 4000,
    "tool_output": 8000,
    "error": 2000,
    "approval_payload": 4000,
}
_SUMMARY_NAMES = ("host", "project", "model", "agent", "tool")
_SCHEMA = """
CREATE TABLE IF NOT EXISTS summary(
  event_id TEXT PRIMARY KEY, session_id TEXT NOT NULL, time REAL NOT NULL, received REAL NOT NULL,
  runtime TEXT NOT NULL, kind TEXT NOT NULL, outcome TEXT, tool TEXT, model TEXT, project TEXT,
  via TEXT NOT NULL, doc TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS summary_session ON summary(session_id);
CREATE INDEX IF NOT EXISTS summary_time ON summary(time);
CREATE TABLE IF NOT EXISTS detail(
  event_id TEXT PRIMARY KEY, session_id TEXT NOT NULL, time REAL NOT NULL, received REAL NOT NULL,
  via TEXT NOT NULL, doc TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS detail_session ON detail(session_id);
CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
"""


class ActivityError(ValueError):
    """A record the store refuses (schema problems)."""

    def __init__(self, message: str, problems: list[str] | None = None):
        self.problems = list(problems or [])
        super().__init__(message + "".join(f"\n  - {p}" for p in self.problems))


@dataclass
class AddResult:
    added: int = 0
    duplicates: int = 0
    details: int = 0
    redactions: dict[str, int] = field(default_factory=dict)


class Redactor:
    """The screener settings of one store: secrets always, personal data on request."""

    def __init__(self, *, personal: bool = False, caps: Mapping[str, int] | None = None):
        self.types = SECRET_TYPES + (PERSONAL_TYPES if personal else ())
        self.caps = {**DEFAULT_CAPS, **dict(caps or {})}

    def _screen(self, screener: Screener, text: str) -> str:
        return screener.screen(text)[0]

    def detail(self, doc: Mapping[str, Any]) -> dict[str, Any]:
        """Redact, then cap, one (schema-valid) detail record."""
        screener = Screener(types=self.types, redact_private_ips=True)
        out = {k: v for k, v in doc.items() if k not in ("truncated", "redactions")}
        truncated: list[str] = []

        def clean(value: str, cap_key: str, name: str) -> str:
            text = self._screen(screener, value)
            cap = self.caps[cap_key]
            if len(text) > cap:
                truncated.append(name)
                text = text[:cap]
            return text

        for k in DETAIL_TEXT:
            if isinstance(out.get(k), str):
                out[k] = clean(out[k], k, k)
        if isinstance(out.get("approval"), Mapping):
            appr = dict(out["approval"])
            if isinstance(appr.get("payload"), str):
                appr["payload"] = clean(appr["payload"], "approval_payload", "approval.payload")
            out["approval"] = appr
        if truncated:
            out["truncated"] = truncated
        out["redactions"] = dict(sorted(screener.redactions.items()))
        return out

    def summary(self, doc: Mapping[str, Any]) -> dict[str, Any]:
        """A summary event with any name that holds a secret replaced by ``redacted``."""
        screener = Screener(types=SECRET_TYPES)
        out = dict(doc)
        for k in _SUMMARY_NAMES:
            if isinstance(out.get(k), str) and screener.find(out[k]):
                out[k] = "redacted"
        return out


class ActivityStore:
    """Both tiers of agent activity in one SQLite file (``path``)."""

    def __init__(
        self,
        path: str | Path,
        *,
        clock: Callable[[], float] = time.time,
        retention_days: float = 14,
        redactor: Redactor | None = None,
        keep_detail: bool = True,
        thresholds: Thresholds | None = None,
    ):
        self.path = Path(path)
        self.clock = clock
        self.retention_s = float(retention_days) * 86400
        self.redactor = redactor or Redactor()
        self.keep_detail = keep_detail
        self.thresholds = thresholds or Thresholds()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._db() as db:
            db.executescript(_SCHEMA)
        self.purge()

    @contextmanager
    def _db(self) -> Iterator[sqlite3.Connection]:
        db = sqlite3.connect(self.path, timeout=10)
        try:
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("PRAGMA secure_delete=ON")  # a purged row is overwritten, not left in a page
            with db:
                yield db
        finally:
            db.close()

    # ---------------------------------------------------------------- writes
    def purge(self, now: float | None = None) -> int:
        """Delete every row past retention (by event time or arrival); returns rows deleted."""
        cutoff = (self.clock() if now is None else now) - self.retention_s
        with self._db() as db:
            n = db.execute("DELETE FROM summary WHERE time < ? OR received < ?", (cutoff, cutoff))
            m = db.execute("DELETE FROM detail WHERE time < ? OR received < ?", (cutoff, cutoff))
            return n.rowcount + m.rowcount

    def add(
        self,
        summaries: Iterable[Mapping[str, Any]],
        details: Iterable[Mapping[str, Any]] = (),
        *,
        via: str,
    ) -> AddResult:
        """Validate, redact, cap and store a batch (atomically); duplicates are counted, not
        rewritten.  Raises :class:`ActivityError` if any record is invalid (nothing is stored)."""
        now = self.clock()
        s_rows, d_rows, problems = [], [], []
        for i, s in enumerate(summaries):
            problems += [f"summary[{i}] {p}" for p in summary_problems(s)]
            if not problems:
                clean = self.redactor.summary(s)
                s_rows.append(clean)
        details = list(details) if self.keep_detail else []
        result = AddResult()
        for i, d in enumerate(details):
            errs = detail_problems(d)
            problems += [f"detail[{i}] {p}" for p in errs]
            if errs:
                continue
            clean = self.redactor.detail(d)
            again = detail_problems(clean)
            problems += [f"detail[{i}] after redaction: {p}" for p in again]
            d_rows.append(clean)
            for t, n in clean["redactions"].items():
                result.redactions[t] = result.redactions.get(t, 0) + n
        if problems:
            raise ActivityError("invalid agent activity", problems)
        with self._db() as db:
            for s in s_rows:
                cur = db.execute(
                    "INSERT OR IGNORE INTO summary VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        s["event_id"], s["session_id"], parse_iso(s["time"]), now, s["runtime"],
                        s["kind"], s.get("outcome"), s.get("tool"), s.get("model"),
                        s.get("project"), via, json.dumps(s, sort_keys=True),
                    ),
                )  # fmt: skip
                if cur.rowcount:
                    result.added += 1
                else:
                    result.duplicates += 1
            for d in d_rows:
                cur = db.execute(
                    "INSERT OR IGNORE INTO detail VALUES (?,?,?,?,?,?)",
                    (
                        d["event_id"], d["session_id"], parse_iso(d["time"]), now, via,
                        json.dumps(d, sort_keys=True),
                    ),
                )  # fmt: skip
                result.details += cur.rowcount
        self.purge(now)
        return result

    def get_meta(self, key: str) -> str | None:
        with self._db() as db:
            row = db.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
            return row[0] if row else None

    def set_meta(self, key: str, value: str) -> None:
        with self._db() as db:
            db.execute("INSERT OR REPLACE INTO meta VALUES (?, ?)", (key, value))

    # ---------------------------------------------------------------- reads (summary tier)
    def events(
        self,
        *,
        session: str | None = None,
        runtime: str | None = None,
        outcome: str | None = None,
        kind: str | None = None,
        via: str | None = None,
        limit: int | None = 200,
        oldest_first: bool = False,
    ) -> list[dict[str, Any]]:
        """Summary events, newest first (``oldest_first`` for a timeline), filtered."""
        where, args = [], []
        for col, val in (
            ("session_id", session),
            ("runtime", runtime),
            ("outcome", outcome),
            ("kind", kind),
        ):
            if val:
                where.append(f"{col} = ?")
                args.append(val)
        if via:
            where.append("(via = ? OR via LIKE ?)")
            args += [via, f"{via}:%"]
        sql = "SELECT doc FROM summary"
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY time " + ("ASC" if oldest_first else "DESC") + ", event_id"
        if limit:
            sql += f" LIMIT {int(limit)}"
        with self._db() as db:
            return [json.loads(r[0]) for r in db.execute(sql, args)]

    def event(self, event_id: str) -> dict[str, Any] | None:
        with self._db() as db:
            row = db.execute("SELECT doc FROM summary WHERE event_id = ?", (event_id,)).fetchone()
            return json.loads(row[0]) if row else None

    def owners(self, session_ids: Iterable[str]) -> dict[str, set[str]]:
        """session_id -> every ``via`` that has written to it (who owns a session)."""
        ids = sorted(set(session_ids))
        if not ids:
            return {}
        marks = ",".join("?" * len(ids))
        with self._db() as db:
            rows = db.execute(
                f"SELECT session_id, via FROM summary WHERE session_id IN ({marks})", ids
            ).fetchall()
        out: dict[str, set[str]] = {}
        for sid, via in rows:
            out.setdefault(sid, set()).add(via)
        return out

    def has_event(self, event_id: str) -> bool:
        return self.event(event_id) is not None

    def sessions(self, now: float | None = None, *, via: str | None = None) -> list[dict[str, Any]]:
        """Derived sessions (``homelabnext.status.agents.model.derive_sessions``)."""
        now = self.clock() if now is None else now
        return derive_sessions(self.events(via=via, limit=None), now, self.thresholds)

    # ---------------------------------------------------------------- reads (detail tier)
    def detail(self, event_id: str) -> dict[str, Any] | None:
        """The private detail of one event (callers: the authorized private view only)."""
        with self._db() as db:
            row = db.execute("SELECT doc FROM detail WHERE event_id = ?", (event_id,)).fetchone()
            return json.loads(row[0]) if row else None

    def details(self, session: str) -> dict[str, dict[str, Any]]:
        """event_id -> detail for one session (callers: the authorized private view only)."""
        with self._db() as db:
            rows = db.execute("SELECT event_id, doc FROM detail WHERE session_id = ?", (session,))
            return {r[0]: json.loads(r[1]) for r in rows}
