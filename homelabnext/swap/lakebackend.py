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
* ``stop_old`` makes the old client refuse requests (it is stopped, not destroyed).
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

from homelabnext.lake.errors import LakeError
from homelabnext.lake.sqlparams import quote_table
from homelabnext.parity import ParityQuery, ParityReport, Sample, compare_queries, compare_tables

from .backend import Backend, Outcome
from .decommission import Retired, scan
from .dualwrite import DualWriter
from .flip import flip_text, load_doc, plan_flip


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
        self.writer = DualWriter(self.old, self.new)  # production writes go through this
        self.last_report: ParityReport | None = None

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
        return Outcome(True, "old component stopped (kept, not destroyed)")

    def start_old(self) -> Outcome:
        self.old.down = False
        replayed = self.writer.replay_pending(owed_to=self.old)
        left = self.writer.owed_to(self.old)
        detail = f"old component running; replayed {replayed} parked batches"
        if left:
            return Outcome(
                False, f"{detail}; {left} still parked (replay failed)", {"pending": left}
            )
        return Outcome(True, detail)

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
