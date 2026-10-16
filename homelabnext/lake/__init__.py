# SPDX-License-Identifier: Apache-2.0
"""Lake library: query, catalog, idempotent write.

Importing this package needs only the standard library. ``IcebergLake``, ``DuckDBLake`` and the
generators of Arrow/Iceberg schemas import their heavy dependencies lazily and raise
:class:`MissingExtra` naming the extra (``pip install 'homelabnext[lake]'``).
"""

from __future__ import annotations

from typing import Any

from .base import normalize_rows as normalize_result_rows
from .base import normalize_value
from .cassette import CassetteLake, compare, record
from .checkpoint import Checkpoint, Ingestor, SourceState
from .errors import (
    CassetteMiss,
    CheckpointError,
    EndpointNotConfigured,
    LakeError,
    MissingExtra,
    RowRejected,
    SchemaMismatch,
    UnknownTable,
    WriteNotSupported,
)
from .fake import FakeLake
from .protocol import LakeClient, LakeQuery, LakeWriter, Mark, TableInfo, WriteResult
from .tables import Column, TableSchema, get_schema, load_schemas

__all__ = [
    "CassetteLake",
    "CassetteMiss",
    "Checkpoint",
    "CheckpointError",
    "Column",
    "DuckDBLake",
    "EndpointNotConfigured",
    "FakeLake",
    "IcebergLake",
    "Ingestor",
    "LakeClient",
    "LakeError",
    "LakeQuery",
    "LakeWriter",
    "Mark",
    "MissingExtra",
    "RowRejected",
    "SchemaMismatch",
    "SourceState",
    "TableInfo",
    "TableSchema",
    "TrinoLake",
    "UnknownTable",
    "WriteNotSupported",
    "WriteResult",
    "compare",
    "get_schema",
    "load_schemas",
    "normalize_result_rows",
    "normalize_value",
    "record",
]


def __getattr__(name: str) -> Any:  # lazy: keep `import homelabnext.lake` dependency-free
    if name == "DuckDBLake":
        from .duck import DuckDBLake

        return DuckDBLake
    if name == "IcebergLake":
        from .iceberg import IcebergLake

        return IcebergLake
    if name == "TrinoLake":
        from .trino import TrinoLake

        return TrinoLake
    raise AttributeError(name)
