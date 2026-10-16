# SPDX-License-Identifier: Apache-2.0
"""A second lake implementation for the lake suites: Iceberg over a local SQLite catalog.

Needs the ``lake`` extra.  It is not a fake: it is the real adapter running on a temporary
directory, which is exactly what makes it a good *replacement* target for the same suites that
prove the in-memory ``FakeLake``.  Target file: ``conformance/targets/lake-iceberg.yml``.
"""

from __future__ import annotations

import shutil
import tempfile


class TempIcebergLake:
    """Wraps ``IcebergLake`` and removes its warehouse on ``close``."""

    features: frozenset[str] = frozenset()

    def __init__(self) -> None:
        from homelabnext.lake import IcebergLake
        from homelabnext.lake.iceberg import open_sql_catalog
        from homelabnext.lake.tables import load_schemas

        self._dir = tempfile.mkdtemp(prefix="hnx-conform-iceberg-")
        catalog = open_sql_catalog(
            "conform", uri=f"sqlite:///{self._dir}/catalog.db", warehouse=f"file://{self._dir}"
        )
        self._lake = IcebergLake(catalog, load_schemas())
        self._lake.ensure_tables()

    def __getattr__(self, name):
        return getattr(self._lake, name)

    def close(self) -> None:
        shutil.rmtree(self._dir, ignore_errors=True)


def make() -> TempIcebergLake:
    return TempIcebergLake()
