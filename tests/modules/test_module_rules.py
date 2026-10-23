# SPDX-License-Identifier: Apache-2.0
"""Unit tests of the loader rules' name helpers (homelabnext.modules.rules).  The contract tests
(tests/schemas/test_module_1_0.py) apply the full rule set to the fictional examples."""

from __future__ import annotations

from pathlib import Path

import pytest

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


def test_the_default_in_tree_root_is_the_checkouts_public_modules_tree_only():
    assert mr.public_module_roots() == (ROOT / "modules",)
    assert not hasattr(mr, "EXAMPLE_ROOTS"), "the examples' root is the tests' fixture"


def test_outside_a_checkout_there_is_no_default_root(monkeypatch, tmp_path):
    """Negative: an installed package has no public tree to trust, so the default refuses
    (NotACheckout) instead of guessing site-packages/modules."""
    monkeypatch.setattr(mr.paths, "checkout_root", lambda: None)
    with pytest.raises(mr.paths.NotACheckout):
        mr.public_module_roots()
    doc = {"id": "m", "kind": "feature", "origin": {"kind": "in-tree"}, "requires": {}}
    with pytest.raises(mr.paths.NotACheckout):
        mr.module_problems(doc, tmp_path / "m", {}, lambda p: {})
    assert "origin in-tree: the module is not in the public modules/ tree" in mr.module_problems(
        doc, tmp_path / "m", {}, lambda p: {}, (tmp_path / "modules",)
    )


def test_a_name_belongs_to_the_longest_module_id():
    ids = {"external", "external-collector"}
    assert mr._owner("external_collector_edge", ids, "_") == "external-collector"
    assert mr._owner("external_edge", ids, "_") == "external"
    assert mr._owner("other_edge", ids, "_") is None


def test_a_scope_reader_returns_the_parts_networks():
    site = {"scope": {"trusted": {"wan": ["203.0.113.7/32", "2001:db8:1::/48"]}}}
    nets = mr.scope_networks(site, "trusted.wan")
    assert [str(n) for n in nets] == ["203.0.113.7/32", "2001:db8:1::/48"]
    assert all(mr.is_documentation(n) for n in nets)


@pytest.mark.parametrize(
    ("site", "part", "why"),
    [
        ({}, "trusted.wan", "missing or empty"),
        ({"scope": {"trusted": {}}}, "trusted.wan", "missing or empty"),
        ({"scope": {"trusted": {"wan": []}}}, "trusted.wan", "missing or empty"),
        ({"scope": {"trusted": "203.0.113.7"}}, "trusted.wan", "missing or empty"),
        ({"scope": {"target": ["198.51.100.0/33"]}}, "target", "not an address or network"),
        ({"scope": {"target": ["198.51.100.1/24"]}}, "target", "host bits set"),
        ({"scope": {"target": [3325256704]}}, "target", "not a string"),
        ({"scope": {"target": ["198.51.100.0/24"]}}, "trusted.wans", "no such scope part"),
    ],
)
def test_a_scope_reader_fails_closed(site, part, why):
    """Negative: an absent, empty or malformed part never reads as "no addresses"."""
    with pytest.raises(mr.ScopeMissing, match=why):
        mr.scope_networks(site, part)


def test_documentation_means_every_address_of_the_network():
    import ipaddress

    assert mr.is_documentation(ipaddress.ip_network("192.0.2.128/25"))
    assert not mr.is_documentation(ipaddress.ip_network("192.0.0.0/16"))
    assert not mr.is_documentation(ipaddress.ip_network("0.0.0.0/0"))
    assert not mr.is_documentation(ipaddress.ip_network("::/0"))


def test_scope_problems_check_only_the_parts_present():
    assert mr.scope_problems({}) == []
    assert mr.scope_problems({"scope": {"target": ["198.51.100.0/24"]}}) == []
    probs = mr.scope_problems({"scope": {"target": ["198.51.100.0/24", "198.51.100.0/24"]}})
    assert probs == ["scope.target: a network is listed twice"]
