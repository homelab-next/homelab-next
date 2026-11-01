# SPDX-License-Identifier: Apache-2.0
"""``BASE`` is an opt-in for ``make schemas`` and ``make ids-check`` (an append-only and a
no-record-vanishes comparison), while the review-tier and swap targets always need a base and
default it to ``origin/main``.  Make variables are global, so a ``BASE ?= origin/main`` written
for the second group turned the first group's comparison on for every run, and failed it on a
clone without ``origin/main``."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

from tests.suite_policy import require_tool

ROOT = Path(__file__).resolve().parents[2]


def _dry_run(*args: str) -> str:
    require_tool("make")
    r = subprocess.run(
        [shutil.which("make") or "make", "-n", "-C", str(ROOT), "PY=python3", *args],
        capture_output=True,
        text=True,
        check=True,
    )
    return r.stdout


def test_schemas_and_ids_check_compare_with_no_base_unless_one_is_given():
    out = _dry_run("schemas", "ids-check")
    assert "--base" not in out, out
    given = _dry_run("schemas", "ids-check", "BASE=deadbeef")
    assert "schema_check.py --strict --base deadbeef" in given
    assert "check-lost --base deadbeef" in given


def test_the_review_and_swap_targets_default_their_base():
    out = _dry_run("modules-review-tier", "swap-gate")
    assert out.count('--base "origin/main"') == 2, out
    given = _dry_run("modules-review-tier", "swap-gate", "BASE=deadbeef")
    assert given.count('--base "deadbeef"') == 2, given
