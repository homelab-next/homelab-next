# SPDX-License-Identifier: Apache-2.0
"""A duckdb error raised while fetching (duckdb >= 2.0 streams results) is still a LakeError."""

import pytest

duckdb = pytest.importorskip("duckdb")

from homelabnext.lake import duck
from homelabnext.lake.errors import LakeError


class _Cursor:
    description = (("n",),)

    def fetchall(self):
        raise duckdb.Error("late row failed")


class _Con:
    def execute(self, sql, params=None):
        return _Cursor()

    def register(self, name, tbl):
        pass

    def close(self):
        pass


def test_fetch_time_error_becomes_lake_error(monkeypatch):
    monkeypatch.setattr(duckdb, "connect", lambda *a, **k: _Con())
    with pytest.raises(LakeError, match="query failed: late row failed"):
        duck.run_duckdb("SELECT 1 AS n", None, {})
