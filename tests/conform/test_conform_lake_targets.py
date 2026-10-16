# SPDX-License-Identifier: Apache-2.0
"""The same lake suites prove the in-memory fake AND the real Iceberg adapter (lake extra)."""

import pytest

from homelabnext.conform import run_capability


@pytest.mark.parametrize("cap", ["lake-query", "lake-catalog"])
def test_iceberg_adapter_passes_the_same_suite(cap):
    for mod in ("duckdb", "pyiceberg", "pyarrow", "sqlalchemy"):
        pytest.importorskip(mod)
    run = run_capability(cap, "lake-iceberg")
    assert run.error is None, run.error
    bad = [(r.check, r.evidence) for r in run.results if r.status != "pass"]
    assert not bad, bad


def test_without_the_extra_the_target_is_could_not_measure_not_a_failure(monkeypatch):
    import sys

    monkeypatch.setitem(sys.modules, "duckdb", None)
    monkeypatch.setitem(sys.modules, "pyiceberg", None)
    run = run_capability("lake-query", "lake-iceberg")
    assert run.error and "homelabnext[lake]" in run.error
    assert not run.ok and not run.passing
