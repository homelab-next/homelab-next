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
    kind: str  # secondary_error | count_mismatch | replay_failed
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

    def rerouted(self, primary: Any, secondary: Any) -> DualWriter:
        """A writer for a new direction that keeps this one's parked batches, divergences and stats.

        A parked batch is still owed to the component it was parked for, whichever role that
        component has now, so a rollback replays writes made while the old component was stopped.
        """
        new = DualWriter(primary, secondary, clock=self._clock, divergence_log=self._log)
        new.pending = self.pending
        new.divergences = self.divergences
        new.stats = self.stats
        return new

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
        self.stats.batches += 1
        self.stats.rows += len(rows)
        self._mirror(table, [dict(r) for r in rows], idempotency_key, source, high_water, result)
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
    ) -> None:
        try:
            res = self.secondary.write_batch(
                table, rows, idempotency_key=key, source=source, high_water=high_water
            )
        except Exception as exc:  # the secondary must never break the primary
            self.stats.secondary_failures += 1
            self.pending.append(_Pending(table, rows, key, source, high_water, self.secondary))
            self._record("secondary_error", table, key, f"{type(exc).__name__}: {exc}", len(rows))
            return
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
        component, so a component never takes an older batch after a newer one."""
        still: list[_Pending] = []
        ok = 0
        failed: list[Any] = []
        for p in self.pending:
            target = self._target(p)
            if (owed_to is not None and target is not owed_to) or any(target is f for f in failed):
                still.append(p)
                continue
            try:
                target.write_batch(
                    p.table,
                    p.rows,
                    idempotency_key=p.idempotency_key,
                    source=p.source,
                    high_water=p.high_water,
                )
                ok += 1
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
        self.pending = still
        self.stats.replayed_ok += ok
        return ok

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
