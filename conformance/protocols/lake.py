# SPDX-License-Identifier: Apache-2.0
"""Contract for ``lake-query`` and ``lake-catalog``: the ``LakeClient`` of ``homelabnext.lake``.

Subject = any object implementing ``homelabnext.lake.LakeClient``:

    query(sql, params) -> list[dict]        portable SQL subset, ``:name`` parameters only
    named(name, params) -> list[dict]       registered queries
    describe(table) -> TableInfo            columns, key, row count, last committed mark per source
    list_tables() -> list[str]
    write_batch(table, rows, *, idempotency_key, source=None, high_water=None) -> WriteResult

Seeding goes through ``write_batch``, so a read-only deployment either points the adapter at a
scratch namespace or declares a seeded copy.  Adapters raise ``homelabnext.lake.LakeError``
subclasses (``RowRejected``, ``UnknownTable``, ...); a suite accepts any ``Exception`` for
"rejected" but pins the observable effect (nothing written).
"""

from __future__ import annotations

from homelabnext.lake import LakeClient, LakeError, TableInfo, WriteResult

__all__ = ["LakeClient", "LakeError", "TableInfo", "WriteResult"]
