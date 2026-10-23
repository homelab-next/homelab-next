# SPDX-License-Identifier: Apache-2.0
"""Unit tests of the site's network scope (homelabnext.modules.scope): the strict reader and the
rules over a selection's scope block.  The contract tests (tests/schemas/test_module_1_0.py) apply
them to the fictional site profiles."""

from __future__ import annotations

import pytest

from homelabnext.modules import scope as ms


def test_a_scope_reader_returns_the_parts_networks():
    site = {"scope": {"trusted": {"wan": ["203.0.113.7/32", "2001:db8:1::/48"]}}}
    nets = ms.scope_networks(site, "trusted.wan")
    assert [str(n) for n in nets] == ["203.0.113.7/32", "2001:db8:1::/48"]
    assert all(ms.is_documentation(n) for n in nets)


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
    with pytest.raises(ms.ScopeMissing, match=why):
        ms.scope_networks(site, part)


def test_documentation_means_every_address_of_the_network():
    import ipaddress

    assert ms.is_documentation(ipaddress.ip_network("192.0.2.128/25"))
    assert not ms.is_documentation(ipaddress.ip_network("192.0.0.0/16"))
    assert not ms.is_documentation(ipaddress.ip_network("0.0.0.0/0"))
    assert not ms.is_documentation(ipaddress.ip_network("::/0"))


def test_scope_problems_check_only_the_parts_present():
    assert ms.scope_problems({}) == []
    assert ms.scope_problems({"scope": {"target": ["198.51.100.0/24"]}}) == []
    probs = ms.scope_problems({"scope": {"target": ["198.51.100.0/24", "198.51.100.0/24"]}})
    assert probs == ["scope.target: a network is listed twice"]
