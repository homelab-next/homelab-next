# SPDX-License-Identifier: Apache-2.0
"""The worked example: swap the lake-query implementation between two fake lakes."""

from __future__ import annotations

from pathlib import Path

import lakes  # tests/parity/lakes.py is added to sys.path by conftest
from support import FakeClock, registry_text

from homelabnext.lake import FakeLake
from homelabnext.parity import ParityQuery, RowRules
from homelabnext.swap import LakeBackend, Retired, SwapRunner

BEFORE = {"host": "lake-core", "port": 8443, "impl": "trino", "version": "450.0"}
AFTER = {"host": "lake-core-2", "port": 8443, "impl": "duckdb", "version": "1.5"}
RETIRED = Retired(
    "trino-lake",
    impls=("trino",),
    aliases=("lake-query-old.svc.example.internal",),
    env_vars=("OLD_LAKE_ENDPOINT",),
    units=("trino-sync",),
)
QUERIES = [
    ParityQuery(
        "auth-by-user",
        sql="SELECT user_name, count(*) AS n FROM authentication GROUP BY user_name",
        rules=RowRules(key=("user_name",)),
        min_rows=1,
    )
]


class Scenario:
    def __init__(self, tmp: Path, swap_id: str = "swap-lake-query-0001"):
        self.tmp = tmp
        self.clock = FakeClock()
        self.old: FakeLake = lakes.seeded()
        self.new: FakeLake = FakeLake()
        self.registry = tmp / "services.yml"
        self.registry.write_text(registry_text(), encoding="utf-8")
        self.original_registry = self.registry.read_text(encoding="utf-8")
        self.tree = tmp / "tree"
        self.tree.mkdir()
        self.backend = LakeBackend(
            self.old,
            self.new,
            tables=list(lakes.TABLES),
            registry_path=self.registry,
            service="lake-query",
            new_host="lake-core-2",
            queries=QUERIES,
            scan_roots=[self.tree],
            retired=RETIRED,
        )
        self.runner = SwapRunner.create(
            tmp / f"{swap_id}.swap.json",
            self.backend,
            swap_id=swap_id,
            capability="cap:lake-query",
            from_adapter="trino-lake",
            to_adapter="duckdb-lake",
            service="lake-query",
            before=BEFORE,
            after=AFTER,
            plan={
                "soak_hours": 48,
                "rollback_window_hours": 72,
                "max_divergences": 0,
                "min_parity_rows": 50,
            },
            registry="services.yml",
            clock=self.clock,
            actor="platform-team",
        )

    def leave_stale_references(self) -> None:
        (self.tree / "ops").mkdir()
        (self.tree / "ops" / "trino-sync.service").write_text("[Service]\nExecStart=/bin/true\n")
        (self.tree / "ops" / "lake.env").write_text(
            "OLD_LAKE_ENDPOINT=https://lake-query-old.svc.example.internal\n"
        )
        (self.tree / "README.md").write_text("Queries run on Trino.\n")

    def clean_references(self) -> None:
        for p in sorted(self.tree.rglob("*"), reverse=True):
            p.unlink() if p.is_file() else p.rmdir()

    def run_to_cutover(self, *, app_writes: bool = True) -> None:
        r = self.runner
        r.advance()  # declare
        r.advance()  # shadow-start (backfill)
        r.advance()  # dual-write
        if app_writes:
            # production keeps writing through the mirror while the candidate shadows
            extra = lakes.rows_for("dns_activity")[:3]
            for i, row in enumerate(extra):
                row = dict(row, uid=f"live-{i}")
                self.backend.writer.write_batch("dns_activity", [row], idempotency_key=f"live-{i}")
        r.advance()  # parity-compare
        self.clock.advance(hours=49)
        r.advance()  # soak
        r.advance()  # cutover
