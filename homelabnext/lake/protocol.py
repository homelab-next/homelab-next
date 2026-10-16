# SPDX-License-Identifier: Apache-2.0
"""The lake capability interface.

``LakeQuery`` / ``LakeWriter`` are the signatures fixed in ``docs/interfaces.md``. ``LakeClient``
is the full contract that the in-memory fake, the DuckDB/Iceberg adapter, the Trino adapter and
the cassette all implement; consumers and the swap kit are written against it only.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

from .tables import Column


@dataclass(frozen=True)
class Mark:
    """What the lake itself remembers about the last batch committed for a source."""

    batch_id: str
    high_water: str | None
    snapshot_id: str | None


@dataclass(frozen=True)
class TableInfo:
    name: str
    schema_id: str
    columns: tuple[Column, ...]
    key: tuple[str, ...]
    row_count: int | None = None
    snapshot_id: str | None = None
    committed: Mapping[str, Mark] = field(default_factory=dict)  # source -> last committed mark


@dataclass(frozen=True)
class WriteResult:
    rows_in: int
    rows_written: int
    rows_skipped: int  # already present (content key) or repeated inside the batch
    replayed: bool  # the idempotency key had already been committed: nothing was touched
    snapshot_id: str | None = None


@runtime_checkable
class LakeQuery(Protocol):
    def query(self, sql: str, params: Mapping[str, Any] | None = None) -> list[dict[str, Any]]: ...

    def named(self, name: str, params: Mapping[str, Any] | None = None) -> list[dict[str, Any]]: ...


@runtime_checkable
class LakeWriter(Protocol):
    def write(self, table: str, rows: Sequence[Mapping[str, Any]], *, batch_id: str) -> int: ...


@runtime_checkable
class LakeClient(LakeQuery, LakeWriter, Protocol):
    """query, describe, write_batch (idempotency key), list_tables."""

    def describe(self, table: str) -> TableInfo: ...

    def write_batch(
        self,
        table: str,
        rows: Sequence[Mapping[str, Any]],
        *,
        idempotency_key: str,
        source: str | None = None,
        high_water: str | None = None,
    ) -> WriteResult:
        """Commit ``rows`` atomically, at most once per ``idempotency_key``.

        A key that was already committed returns ``replayed=True`` and writes nothing. Rows whose
        content key (the table's ``key`` columns) is already present are skipped, so a replay under
        a different batching is also safe. ``source``/``high_water`` are stored with the commit
        itself and come back in ``describe(table).committed``.
        """
        ...

    def list_tables(self) -> list[str]: ...
