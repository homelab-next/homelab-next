# SPDX-License-Identifier: Apache-2.0
"""Dual-write helper: write to the incumbent and the candidate, never hurt the incumbent.

Rules (each is a test):

* The **primary** write happens first and its result (or its exception) is what the caller sees.
  If the primary fails, nothing is sent to the secondary, so the candidate can never hold data
  the incumbent lacks.
* The **secondary** write uses the *same* idempotency key. A secondary failure is caught,
  recorded as a :class:`Divergence` and parked in ``pending``; it never raises into the caller.
  :meth:`DualWriter.replay_pending` retries parked batches; the key makes replay safe.
  Each parked batch remembers the component it was meant for, so a writer re-pointed with
  :meth:`DualWriter.rerouted` (a route flip or a rollback) still replays it into that component.
* **Order per component.** While batches are parked for the secondary, a new batch is not sent
  past them: they are replayed first, and if any is still refused the new batch is parked behind
  them (``queued``).  Replays go oldest first and stop at a component's first failure.  So a
  component takes its batches in write order, and the lake's per-source mark never moves to an
  older batch.  As a second line of defence, a replay into a component that has already taken a
  newer batch of the same source is sent without its source mark.
* :meth:`DualWriter.discard_pending` drops parked batches on purpose, with a reason, and returns
  them (rows included) for the caller to keep as evidence; nothing else ever drops one.
* A secondary that "succeeds" but wrote a different number of rows than the primary is a
  divergence too (``count_mismatch``), because that is how silent loss starts.
* Divergences go to an optional JSON Lines file (one object per line) as well as memory.
  The clock is injected; nothing here reads the wall clock or the network.

``DualWriter`` is itself a ``LakeWriter`` (``write``) and exposes ``write_batch`` with the
``LakeClient`` signature, so it can stand in for the incumbent client in a writer.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from homelabnext.lake.protocol import WriteResult


@dataclass(frozen=True)
class Divergence:
    at: str
    kind: str  # secondary_error | queued | count_mismatch | replay_failed | discarded
    table: str
    idempotency_key: str
    detail: str
    rows: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "at": self.at,
            "kind": self.kind,
            "table": self.table,
            "idempotency_key": self.idempotency_key,
            "detail": self.detail,
            "rows": self.rows,
        }


@dataclass
class _Pending:
    table: str
    rows: list[dict[str, Any]]
    idempotency_key: str
    source: str | None
    high_water: str | None
    target: Any = None  # the component the batch is owed to; None means the current secondary
    order: int = 0  # the write order of the batch (shared by every rerouted writer)

    def to_dict(self) -> dict[str, Any]:
        return {
            "table": self.table,
            "idempotency_key": self.idempotency_key,
            "source": self.source,
            "high_water": self.high_water,
            "order": self.order,
            "rows": self.rows,
        }


@dataclass
class MirrorStats:
    batches: int = 0
    rows: int = 0
    secondary_failures: int = 0
    count_mismatches: int = 0
    replayed_ok: int = 0


def _utcnow() -> datetime:
    return datetime.now(UTC)


class DualWriter:
    def __init__(
        self,
        primary: Any,
        secondary: Any,
        *,
        clock: Callable[[], datetime] = _utcnow,
        divergence_log: str | Path | None = None,
    ):
        self.primary = primary
        self.secondary = secondary
        self._clock = clock
        self._log = Path(divergence_log) if divergence_log else None
        self.divergences: list[Divergence] = []
        self.pending: list[_Pending] = []
        self.stats = MirrorStats()
        #: write order counter and, per (component, table, source), the order of the newest
        #: batch that component took with that source's mark (shared by rerouted writers)
        self._order: dict[str, Any] = {"n": 0, "marked": {}}
        #: an optional journal (``park(p)``, ``settled(order)``, ``mark(component, table, source,
        #: order)``) told of each change as it happens, so a backend can persist the queue at a
        #: cost of one record per change rather than one rewrite of the whole queue
        self.journal: Any = None

    def rerouted(self, primary: Any, secondary: Any) -> DualWriter:
        """A writer for a new direction that keeps this one's parked batches, divergences and stats.

        A parked batch is still owed to the component it was parked for, whichever role that
        component has now, so a rollback replays writes made while the old component was stopped.
        """
        new = DualWriter(primary, secondary, clock=self._clock, divergence_log=self._log)
        new.pending = self.pending
        new.divergences = self.divergences
        new.stats = self.stats
        new._order = self._order
        new.journal = self.journal
        return new

    def _park(self, p: _Pending) -> None:
        self.pending.append(p)
        if self.journal is not None:
            self.journal.park(p)

    def _settled(self, p: _Pending) -> None:
        if self.journal is not None:
            self.journal.settled(p.order)

    def _mark(self, component: Any, table: str, source: str | None, order: int) -> None:
        if source is not None:
            k = (id(component), table, source)
            marked = self._order["marked"]
            if order > marked.get(k, 0):
                marked[k] = order
                # the guard matters only while something is owed to the component: journal the
                # mark then (and so it survives a restart), not on every write
                if self.journal is not None and self.owed_to(component):
                    self.journal.mark(component, table, source, order)

    # ------------------------------------------------------------ writes
    def write_batch(
        self,
        table: str,
        rows: Sequence[Mapping[str, Any]],
        *,
        idempotency_key: str,
        source: str | None = None,
        high_water: str | None = None,
    ) -> WriteResult:
        result = self.primary.write_batch(
            table, rows, idempotency_key=idempotency_key, source=source, high_water=high_water
        )  # an exception here is the caller's, and the secondary is not touched
        self._order["n"] += 1
        order = self._order["n"]
        self._mark(self.primary, table, source, order)
        self.stats.batches += 1
        self.stats.rows += len(rows)
        self._mirror(
            table, [dict(r) for r in rows], idempotency_key, source, high_water, result, order
        )
        return result

    def write(self, table: str, rows: Sequence[Mapping[str, Any]], *, batch_id: str) -> int:
        return self.write_batch(table, rows, idempotency_key=batch_id).rows_written

    def _mirror(
        self,
        table: str,
        rows: list[dict[str, Any]],
        key: str,
        source: str | None,
        high_water: str | None,
        primary_result: WriteResult,
        order: int = 0,
    ) -> None:
        parked = _Pending(table, rows, key, source, high_water, self.secondary, order)
        if self.owed_to(self.secondary):  # never send a batch past older ones still parked
            self.replay_pending(owed_to=self.secondary)
            if self.owed_to(self.secondary):
                self._park(parked)
                self._record("queued", table, key, "parked behind earlier batches", len(rows))
                return
        try:
            res = self.secondary.write_batch(
                table, rows, idempotency_key=key, source=source, high_water=high_water
            )
        except Exception as exc:  # the secondary must never break the primary
            self.stats.secondary_failures += 1
            self._park(parked)
            self._record("secondary_error", table, key, f"{type(exc).__name__}: {exc}", len(rows))
            return
        self._mark(self.secondary, table, source, order)
        if res.rows_written != primary_result.rows_written:
            self.stats.count_mismatches += 1
            self._record(
                "count_mismatch",
                table,
                key,
                f"primary wrote {primary_result.rows_written}, secondary wrote {res.rows_written}",
                len(rows),
            )

    def owed_to(self, component: Any) -> int:
        """How many parked batches are owed to ``component``."""
        return sum(1 for p in self.pending if self._target(p) is component)

    def _target(self, p: _Pending) -> Any:
        return self.secondary if p.target is None else p.target

    def replay_pending(self, owed_to: Any = None) -> int:
        """Retry parked batches (only those owed to ``owed_to``, when given); returns how many
        now succeeded.  Batches are retried oldest first and stop at the first failure for each
        component.  A batch older than one the component already took with the same source's
        mark is replayed without the mark, so the mark never moves back."""
        still: list[_Pending] = []
        ok = 0
        failed: list[Any] = []
        for p in self.pending:
            target = self._target(p)
            if (owed_to is not None and target is not owed_to) or any(target is f for f in failed):
                still.append(p)
                continue
            newer = self._order["marked"].get((id(target), p.table, p.source), 0) > p.order
            try:
                target.write_batch(
                    p.table,
                    p.rows,
                    idempotency_key=p.idempotency_key,
                    source=None if newer else p.source,
                    high_water=None if newer else p.high_water,
                )
                ok += 1
                self._settled(p)
                if not newer:
                    self._mark(target, p.table, p.source, p.order)
            except Exception as exc:
                still.append(p)
                failed.append(target)
                self._record(
                    "replay_failed",
                    p.table,
                    p.idempotency_key,
                    f"{type(exc).__name__}: {exc}",
                    len(p.rows),
                )
        self.pending[:] = still  # in place: rerouted writers share the queue
        self.stats.replayed_ok += ok
        return ok

    def first_owed(self, component: Any) -> _Pending | None:
        """The oldest batch parked for ``component`` (the one a replay stops at), or None."""
        return next((p for p in self.pending if self._target(p) is component), None)

    def discard_pending(
        self, reason: str, *, keys: Sequence[str] | None = None, owed_to: Any = None
    ) -> list[dict[str, Any]]:
        """Drop parked batches on purpose (those with ``keys``, and owed to ``owed_to``, when
        given; else all) and return them, rows included, for the caller's evidence.  Each drop is
        a ``discarded`` divergence naming ``reason``."""
        reason = (reason or "").strip()
        if not reason:
            raise ValueError("discarding parked batches needs a reason")
        want = None if keys is None else set(keys)
        gone, still = [], []
        for p in self.pending:
            hit = (want is None or p.idempotency_key in want) and (
                owed_to is None or self._target(p) is owed_to
            )
            (gone if hit else still).append(p)
        self.pending[:] = still
        for p in gone:
            self._record("discarded", p.table, p.idempotency_key, reason, len(p.rows))
            self._settled(p)
        return [p.to_dict() for p in gone]

    # ------------------------------------------------------------ reporting
    def _record(self, kind: str, table: str, key: str, detail: str, rows: int) -> None:
        d = Divergence(self._clock().astimezone(UTC).isoformat(), kind, table, key, detail, rows)
        self.divergences.append(d)
        if self._log is not None:
            try:
                with self._log.open("a", encoding="utf-8") as fh:
                    fh.write(json.dumps(d.to_dict(), sort_keys=True) + "\n")
            except OSError:
                pass  # a broken log must not break the write path; the in-memory list remains

    @property
    def unresolved(self) -> int:
        """Divergences that still matter: parked batches plus count mismatches."""
        return len(self.pending) + self.stats.count_mismatches

    def status(self) -> dict[str, Any]:
        return {
            "batches": self.stats.batches,
            "rows": self.stats.rows,
            "divergences": len(self.divergences),
            "unresolved": self.unresolved,
            "pending": len(self.pending),
            "secondary_failures": self.stats.secondary_failures,
            "count_mismatches": self.stats.count_mismatches,
            "replayed_ok": self.stats.replayed_ok,
        }


__all__ = ["Divergence", "DualWriter", "MirrorStats"]
