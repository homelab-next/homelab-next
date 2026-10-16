# SPDX-License-Identifier: Apache-2.0
"""pytest glue for ``conformance/<capability>/test_*.py``.

Each capability folder has a tiny test module that parametrises over the suite's check ids and
asserts one at a time.  The target comes from ``HNX_CONFORM_TARGET`` (default ``fake``), so the
very same files prove a real service::

    HNX_CONFORM_TARGET=staging python -m pytest conformance/object-store
"""

from __future__ import annotations

import os

from .registry import load_suite
from .runner import run_capability

__all__ = ["assert_check", "check_ids", "target_name"]


def target_name() -> str:
    return os.environ.get("HNX_CONFORM_TARGET", "fake")


def check_ids(capability: str) -> list[str]:
    return load_suite(capability).ids()


def assert_check(capability: str, check_id: str) -> None:
    import pytest

    run = run_capability(capability, target_name(), only=[check_id])
    if run.error:
        pytest.fail(run.error)
    (res,) = run.results
    if res.status in ("skip", "waived"):
        pytest.skip(res.evidence)
    if not res.ok and res.severity == "should":
        pytest.xfail(f"SHOULD check failed: {res.evidence}")
    assert res.ok, f"{capability}/{res.check}: {res.evidence}"
