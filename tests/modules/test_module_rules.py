# SPDX-License-Identifier: Apache-2.0
"""Unit tests of the loader rules' name helpers (homelabnext.modules.rules).  The contract tests
(tests/schemas/test_module_1_0.py) apply the full rule set to the fictional examples."""

from __future__ import annotations

from pathlib import Path

from homelabnext.modules import rules as mr

ROOT = Path(__file__).resolve().parents[2]


def test_a_bound_name_needs_the_id_and_a_separator():
    assert mr._named("external-collector", "external-collector")
    assert mr._named("external-collector-analyst", "external-collector")
    assert not mr._named("external-collectorx", "external-collector")
    assert mr._named("external_collector_edge", "external-collector", "_")
    assert not mr._named("external-collector-edge", "external-collector", "_")


def test_lane_writes_are_bound_to_their_lane():
    assert mr._own_write_prefix("findings/m/", "m", "real")
    assert not mr._own_write_prefix("findings/m-shadow/", "m", "real")
    assert mr._own_write_prefix("findings/m-shadow/", "m", "shadow")
    assert not mr._own_write_prefix("findings/m/", "m", "shadow")
    assert mr._own_write_prefix("state/m-shadow/", "m")
    assert not mr._own_write_prefix("cases/m/", "m")
    assert not mr._own_write_prefix("findings/", "m")


def test_the_default_in_tree_root_is_the_public_modules_tree_only():
    assert mr.PUBLIC_MODULE_ROOTS == (ROOT / "modules",)
    assert mr.EXAMPLE_ROOTS == (ROOT / "examples" / "modules",)


def test_a_name_belongs_to_the_longest_module_id():
    ids = {"external", "external-collector"}
    assert mr._owner("external_collector_edge", ids, "_") == "external-collector"
    assert mr._owner("external_edge", ids, "_") == "external"
    assert mr._owner("other_edge", ids, "_") is None
