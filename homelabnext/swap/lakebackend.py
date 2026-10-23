# SPDX-License-Identifier: Apache-2.0
"""Reference backend: swap between two :class:`~homelabnext.lake.LakeClient` implementations.

Used by the end-to-end tests and the worked example in ``docs/swap.md`` (two ``FakeLake`` objects),
and a template for a real backend (replace the clients with ``TrinoLake`` / ``DuckDBLake`` and the
"component" start/stop with your deployment tooling, which is SERVER work).

Behaviour worth knowing:

* ``shadow_start`` backfills the candidate from the incumbent with fixed idempotency keys, so it
  can be re-run safely.
* ``writer`` is the :class:`DualWriter` production code should write through. After the route is
  flipped the direction reverses (candidate primary, old component secondary), so a rollback
  loses no data; while the old component is stopped its writes are parked and replayed on restart.
  A batch parked for a component is replayed into it before a route change makes it primary, and
  the route is not changed while one cannot be; ``start_old`` fails while any stays parked.
* ``mirror_status`` retries the batches parked for the candidate, so a transient failure clears
  the ``divergences-within-budget`` gates once the candidate takes them.
* At start the direction and the old component's state follow the registry (flipped: the
  candidate is primary and the old component stopped).
* Parked batches live in memory unless ``pending_path`` is given: then each change is appended
  to that journal (:mod:`.journal`; one record per change, compacted at start) and read back at
  start, with the write-order marks and the old component's state; an unreadable journal, or one
  another backend holds, refuses to start.  ``close()`` releases it.
* ``discard_parked`` drops, on purpose, only the batches the old component refuses (``rollback
  (abandon_parked=True)``) and returns them as evidence.
* ``stop_old`` makes the old client refuse requests (it is stopped, not destroyed).
"""

from __future__ import annotations

import json
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

from homelabnext.lake.errors import LakeError
from homelabnext.lake.sqlparams import quote_table
from homelabnext.parity import ParityQuery, ParityReport, Sample, compare_queries, compare_tables

from .backend import Backend, Outcome
from .decommission import Retired, scan
from .dualwrite import DualWriter, _Pending
from .flip import flip_text, load_doc, plan_flip
from .journal import ParkedJournal, json_value


class SwitchableClient:
    """Wraps a client so it can be "stopped": every call then raises ``LakeError``."""

    def __init__(self, inner: Any):
        self._inner = inner
        self.down = False

    def __getattr__(self, name: str) -> Any:
        attr = getattr(self._inner, name)
        if not callable(attr):
            return attr

        def call(*a: Any, **kw: Any) -> Any:
            if self.down:
                raise LakeError("component is stopped")
            return attr(*a, **kw)

        return call


class LakeBackend(Backend):
    def __init__(
        self,
        old: Any,
        new: Any,
        *,
        tables: Sequence[str],
        registry_path: str | Path,
        service: str,
        new_host: str,
        queries: Sequence[ParityQuery] = (),
        sample: Sample | None = None,
        scan_roots: Sequence[str | Path] = (),
        retired: Retired | None = None,
        allow: Sequence[str] = (),
        smoke: Callable[[Any, str], Outcome] | None = None,
        pending_path: str | Path | None = None,
    ):
        self.old = SwitchableClient(old)
        self.new = new
        for t in tables:
            quote_table(t)  # refuse a name that is not a plain identifier before anything runs
        self.tables = list(tables)
        self.queries = list(queries)
        self.sample = sample
        self.registry_path = Path(registry_path)
        self.service = service
        self.new_host = new_host
        self.scan_roots = list(scan_roots)
        self.retired = retired
        self.allow = list(allow)
        self._smoke = smoke
        self.mirroring = False
        self.last_report: ParityReport | None = None
        # the direction and the old component's state follow the registry: after a restart in
        # the flipped state the candidate is primary and the old component is stopped
        flipped = self._current_host() == self.new_host
        self.writer = (  # production writes go through this
            DualWriter(self.new, self.old) if flipped else DualWriter(self.old, self.new)
        )
        self.old.down = flipped
        self.journal: ParkedJournal | None = None
        if pending_path:
            self._open_journal(Path(pending_path))

    def _current_host(self) -> str | None:
        try:
            doc = load_doc(self.registry_path.read_text(encoding="utf-8"))
            return str(doc["services"][self.service]["host"])
        except (OSError, ValueError, KeyError, TypeError):
            return None  # no readable registry yet: the plan step reports it

    # ------------------------------------------------------------ the parked queue on disk
    def _role(self, component: Any) -> str:
        return "old" if component is self.old else "new"

    def _open_journal(self, path: Path) -> None:
        """Read the parked batches, the marks and the old component's state back from the
        journal (refusing to start on an unreadable one or one in use), then journal changes."""
        j = ParkedJournal(path)
        comp = {"old": self.old, "new": self.new}
        try:
            st = j.state
            for it in st.parked:
                self.writer.pending.append(
                    _Pending(
                        it["table"], list(it["rows"]), it["idempotency_key"], it.get("source"),
                        it.get("high_water"), comp[it["owed_to"]], int(it["order"]),
                    )
                )  # fmt: skip
            for (on, table, source), order in st.marks.items():
                self.writer._order["marked"][(id(comp[on]), table, source)] = order
        except (KeyError, TypeError, ValueError) as exc:
            j.close()
            raise LakeError(f"parked batches in {path} are unreadable: {exc}") from exc
        self.writer._order["n"] = max(self.writer._order["n"], st.last_order)
        if st.old_down is not None:
            self.old.down = st.old_down
        self.journal = j
        self.writer.journal = _WriterJournal(self)

    def close(self) -> None:
        """Release the parked-batch journal (and its lock).  The writer keeps the closed journal,
        so a batch parked after this raises rather than living in memory only."""
        if self.journal is not None:
            self.journal.close()

    def __enter__(self) -> LakeBackend:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # ------------------------------------------------------------ conformance / shadow / mirror
    def conformance(self, role: str) -> Outcome:
        client = self.old if role == "old" else self.new
        try:
            have = set(client.list_tables())
            missing = [t for t in self.tables if t not in have]
            if missing:
                return Outcome(False, f"missing tables {missing}")
            for t in self.tables:
                client.describe(t)
            if self._smoke is not None:
                return self._smoke(client, role)
        except LakeError as exc:
            return Outcome(False, f"{role} client failed its smoke test: {exc}")
        return Outcome(
            True, f"{role}: {len(self.tables)} tables described", {"tables": self.tables}
        )

    def shadow_start(self) -> Outcome:
        counts: dict[str, int] = {}
        try:
            for t in self.tables:
                rows = self.old.query(f"SELECT * FROM {quote_table(t)}")
                res = self.new.write_batch(t, rows, idempotency_key=f"backfill-{t}")
                counts[t] = len(rows)
                if res.rows_written + res.rows_skipped != len(rows):
                    return Outcome(False, f"backfill of {t} wrote an unexpected row count")
        except LakeError as exc:
            return Outcome(False, f"backfill failed: {exc}")
        return Outcome(True, f"backfilled {sum(counts.values())} rows", {"backfilled": counts})

    def start_mirror(self) -> Outcome:
        self.mirroring = True
        return Outcome(True, "dual-write active", {"direction": "old->new"})

    def mirror_status(self) -> Outcome:
        if self.mirroring:  # a batch parked for the candidate is retried at every status check
            self.writer.replay_pending(owed_to=self.writer.secondary)
        s = self.writer.status()
        return Outcome(self.mirroring, f"{s['unresolved']} unresolved", {**s})

    def stop_mirror(self) -> Outcome:
        self.mirroring = False
        return Outcome(True, "dual-write stopped (forward-only)", self.writer.status())

    # ------------------------------------------------------------ parity
    def parity(self) -> Outcome:
        report = compare_tables(self.old, self.new, self.tables, sample=self.sample, min_rows=0)
        if self.queries:
            report.merge(compare_queries(self.old, self.new, self.queries))
        report.kind = "combined"
        self.last_report = report
        rows = sum(c.detail.get("left_count", 0) for c in report.checks if c.name.endswith(":rows"))
        return Outcome(
            report.ok,
            report.summary(),
            {"rows_compared": rows, "report": report.to_dict(), "report_sha256": report.digest()},
        )

    # ------------------------------------------------------------ route
    def _plan(self, target: dict[str, Any]):
        doc = load_doc(self.registry_path.read_text(encoding="utf-8"))
        return plan_flip(
            doc,
            self.service,
            host=target.get("host"),
            port=target.get("port"),
            impl=target.get("impl"),
            version=target.get("version"),
        )

    def preview_route(self, target: dict[str, Any]) -> Outcome:
        plan = self._plan(target)
        return Outcome(True, plan.diff(), {"diff": plan.diff(), "plan": plan.to_dict()})

    def apply_route(self, target: dict[str, Any]) -> Outcome:
        plan = self._plan(target)
        incoming = self.new if target.get("host") == self.new_host else self.old
        # a batch parked for the component that becomes primary is replayed into it first: once
        # it is primary nothing else replays it, and replayed later it would land after newer
        # batches (moving the lake's source mark backwards).  While one stays parked, no flip.
        if self.writer.owed_to(incoming):
            self.writer.replay_pending(owed_to=incoming)
            left = self.writer.owed_to(incoming)
            if left:
                why = (
                    f"route not changed: {left} parked batches owed to the incoming primary "
                    "could not be replayed into it"
                )
                return Outcome(False, why, {"pending": left})
        if not plan.empty:
            text = self.registry_path.read_text(encoding="utf-8")
            self.registry_path.write_text(flip_text(text, plan), encoding="utf-8")
        # one writer state across flips: batches parked for a stopped component survive the
        # flip and a rollback, and are replayed into that component when it starts again
        if target.get("host") == self.new_host:
            self.writer = self.writer.rerouted(self.new, self.old)  # candidate is primary
        else:
            self.writer = self.writer.rerouted(self.old, self.new)
        return Outcome(True, plan.diff(), {"diff": plan.diff(), "plan": plan.to_dict()})

    def verify_route(self, target: dict[str, Any]) -> Outcome:
        plan = self._plan(target)
        if not plan.empty:
            return Outcome(
                False, "the alias does not point at the target yet", {"pending": plan.diff()}
            )
        return Outcome(True, f"alias {plan.alias} -> {plan.new_target}", {"alias": plan.alias})

    # ------------------------------------------------------------ old component
    def stop_old(self) -> Outcome:
        self.old.down = True
        if self.journal is not None:
            self.journal.old_down(True)
        return Outcome(True, "old component stopped (kept, not destroyed)")

    def start_old(self) -> Outcome:
        self.old.down = False
        if self.journal is not None:
            self.journal.old_down(False)
        replayed = self.writer.replay_pending(owed_to=self.old)
        left = self.writer.owed_to(self.old)
        detail = f"old component running; replayed {replayed} parked batches"
        if left:
            return Outcome(
                False, f"{detail}; {left} still parked (replay failed)", {"pending": left}
            )
        return Outcome(True, detail)

    #: errors that mean the old component could not be reached, not that it refused a batch: an
    #: abandon stops on them and drops nothing more (a backend may widen this)
    UNAVAILABLE: tuple[type[BaseException], ...] = (ConnectionError, TimeoutError)

    def discard_parked(self, reason: str) -> Outcome:
        """Drop only what the old component refuses: replay, drop the batch the replay stopped
        at, and repeat until nothing more is owed.  A batch behind a refused one is replayed, not
        dropped.  When the old component cannot be reached at all (:attr:`UNAVAILABLE`) the loop
        stops and nothing more is dropped: an unreachable component refuses nothing."""
        gone: list[dict[str, Any]] = []
        unreachable: BaseException | None = None
        while True:
            self.writer.replay_pending(owed_to=self.old)
            head = self.writer.first_owed(self.old)
            if head is None:
                break
            err = self.writer.last_failure.get(id(self.old))
            if isinstance(err, self.UNAVAILABLE):
                unreachable = err
                break
            gone += self.writer.discard_pending(
                reason, keys=[head.idempotency_key], owed_to=self.old
            )
        gone = json.loads(json.dumps(gone, default=json_value))  # plain JSON, for the evidence
        keys = ", ".join(g["idempotency_key"] for g in gone) or "none"
        if unreachable is not None:
            left = self.writer.owed_to(self.old)
            why = (
                f"old unreachable ({type(unreachable).__name__}: {unreachable}); "
                f"{left} parked batches kept"
            )
            if gone:
                why += f"; discarded before that: {keys}"
            return Outcome(False, why, {"discarded": gone, "unreachable": True, "pending": left})
        return Outcome(True, f"discarded {len(gone)} parked batches: {keys}", {"discarded": gone})

    def restore_parked(self, batches: list[dict[str, Any]]) -> Outcome:
        back = [
            _Pending(
                b["table"], list(b["rows"]), b["idempotency_key"], b.get("source"),
                b.get("high_water"), self.old, int(b["order"]),
            )
            for b in batches
        ]  # fmt: skip
        self.writer.pending[:] = sorted([*self.writer.pending, *back], key=lambda p: p.order)
        if self.journal is not None:
            for p in back:
                self.journal.park("old", p)
        return Outcome(True, f"parked {len(back)} batches again", {"pending": len(back)})

    def old_state(self) -> Outcome:
        return Outcome(True, "", {"state": "stopped" if self.old.down else "running"})

    def decommission_scan(self) -> Outcome:
        if self.retired is None:
            return Outcome(False, "no retired names configured")
        found = scan(self.scan_roots, self.retired, registry=self.registry_path, allow=self.allow)
        return Outcome(
            not found,
            "no references remain" if not found else f"{len(found)} references remain",
            {"findings": [f.to_dict() for f in found]},
        )


class _WriterJournal:
    """The writer's journal hooks, in the backend's roles (``old``/``new``)."""

    def __init__(self, backend: LakeBackend):
        self.b = backend

    def park(self, p: Any) -> None:
        assert self.b.journal is not None
        self.b.journal.park(self.b._role(self.b.writer._target(p)), p)

    def settled(self, order: int) -> None:
        assert self.b.journal is not None
        self.b.journal.settled(order)

    def mark(self, component: Any, table: str, source: str, order: int) -> None:
        assert self.b.journal is not None
        self.b.journal.mark(self.b._role(component), table, source, order)
