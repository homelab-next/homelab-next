# SPDX-License-Identifier: Apache-2.0
"""Site 1.5 ``delegated_prefixes6``: the global-unicast IPv6 prefixes a site declares its own, inside
which a zone's global ``subnet6`` is the lab's (``homelabnext.compute.validate``).  ``hnx site
validate`` requires each canonical, a /48 to a /64, global unicast outside the special and
documentation blocks, with a reason, and no two overlapping.

Prefixes outside the documentation range are built from integers, so no such literal is in the
tree."""

from __future__ import annotations

import copy
import ipaddress
from pathlib import Path

import pytest

from homelabnext.network import load_site, validate
from homelabnext.network.loader import load_registry
from homelabnext.network.validate import (
    delegated_prefix6_problem,
    delegated_prefixes6,
    schema_problems,
)

MINIMAL = Path(__file__).resolve().parents[2] / "examples" / "minimal"
WHY = "the upstream ISP delegated it with the circuit"


def _net(n: int, plen: int) -> str:
    return str(ipaddress.IPv6Network((n, plen)))


#: a global /48, a /56 inside it and a /64 inside that, never written as literals
G48 = _net(0x2600_0010_0005 << 80, 48)
G56 = _net(0x2600_0010_0005_0100 << 64, 56)
G64 = _net(0x2600_0010_0005_0182 << 64, 64)


@pytest.fixture
def doc() -> dict:
    return copy.deepcopy(load_site(MINIMAL / "site.yml"))


@pytest.fixture(scope="module")
def registry():
    return load_registry(MINIMAL / "services.yml")


@pytest.mark.parametrize("prefix", [G48, G56, G64])
def test_a_global_48_to_64_is_a_delegated_prefix(prefix):
    net, why = delegated_prefix6_problem(prefix)
    assert why is None and str(net) == prefix


@pytest.mark.parametrize(
    ("prefix", "why"),
    [
        ("2001:db8:5::/48", "documentation space"),
        (_net(0x3FFF_0000_0005 << 80, 48), "documentation space"),  # RFC 9637
        (_net(0xFD00_0000_0010 << 80, 48), "unique-local prefix needs no declaration"),
        (_net(0x2001_0001_0005 << 80, 48), "2001::/23"),  # an IETF protocol assignment
        (_net(0x3FFE_0000_0005 << 80, 48), "3ffe::/16"),  # the retired 6bone
        (_net(0x2000_0000_0005 << 80, 48), "2000::/16"),  # reserved, never allocated
        (_net(0x2002_0000_0005 << 80, 48), "embeds IPv4"),  # 6to4
        (_net(0x2001_0000_0005 << 80, 48), "embeds IPv4"),  # Teredo
        # an ISP's own allocation, or anything wider than one site's /48, holds third-party space
        ("2001:db8::/32", "is a /32"),
        (_net(0x2600_0010 << 96, 32), "is a /32"),
        (_net(0x2600_0010 << 96, 40), "is a /40"),
        (_net(0x2600_0010 << 96, 47), "is a /47"),
        (_net(0x2600 << 112, 16), "is a /16"),
        (_net(0x2600_0010_0005_0082 << 64, 96), "is a /96"),
        (G48.replace("::", ":0::"), "canonical form"),
        (ipaddress.IPv6Network(G48).exploded, "canonical form"),
        (_net(0x2A0B_00CD_0005 << 80, 48).upper(), "canonical form"),
        (_net(0x2A0B_00CD_0005_00EF << 64, 64).upper(), "canonical form"),
        (_net(0x2600_0010_0005 << 80 | 1, 128).replace("/128", "/48"), "host bits"),
        (G48.replace("::/", "::%eth0/"), "zone id"),
        ("192.0.2.0/24", "is not an IPv6 prefix"),  # no-raw-endpoint: allow an IPv4 prefix, refused
        (48, "not an IPv6 prefix written as text"),
        (None, "not an IPv6 prefix written as text"),
    ],
)
def test_a_prefix_the_site_cannot_hold_is_refused(prefix, why):
    net, bad = delegated_prefix6_problem(prefix)
    assert net is None and why in bad


def test_absent_is_no_declaration():
    assert delegated_prefixes6(None) == ((), [])


@pytest.mark.parametrize(
    ("raw", "why"),
    [
        ("x", "not a list"),
        ({"prefix": G48, "why": WHY}, "not a list"),
        (["x"], "not a {prefix, why} mapping"),
        ([{"prefix": G48}], "gives no reason"),
        ([{"prefix": G48, "why": "   "}], "gives no reason"),
        ([{"prefix": G48, "why": WHY}, {"prefix": G56, "why": WHY}], f"overlaps {G48}"),
        ([{"prefix": G56, "why": WHY}, {"prefix": G48, "why": WHY}], f"overlaps {G56}"),
        ([{"prefix": G48, "why": WHY}, {"prefix": G48, "why": WHY}], f"overlaps {G48}"),
        # a wider prefix that would contain a declared one fails on its length first
        ([{"prefix": G48, "why": WHY}, {"prefix": _net(0x2600_0010 << 96, 32), "why": WHY}], "/32"),
    ],
)
def test_an_unusable_declaration_holds_nothing(raw, why):
    nets, problems = delegated_prefixes6(raw)
    assert nets == () and any(why in p for p in problems), problems


def test_the_site_validator_judges_the_declaration(doc, registry):
    doc["delegated_prefixes6"] = [{"prefix": G48, "why": WHY}]
    assert schema_problems(doc) == []
    assert validate(doc, registry).ok
    doc["delegated_prefixes6"].append({"prefix": G56, "why": WHY})
    rep = validate(doc, registry)
    assert any("overlaps" in e for e in rep.errors), rep.errors


def test_the_schema_requires_a_reason_and_the_prefix_shape(doc):
    doc["delegated_prefixes6"] = [{"prefix": G48, "why": " " * 12}]
    assert any("delegated_prefixes6" in p for p in schema_problems(doc))
    for wide in (_net(0x2600 << 112, 16), _net(0x2600_0010 << 96, 32), _net(0x2600_0010 << 96, 47)):
        doc["delegated_prefixes6"] = [{"prefix": wide, "why": WHY}]
        assert any("delegated_prefixes6" in p for p in schema_problems(doc)), wide
