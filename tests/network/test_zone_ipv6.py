# SPDX-License-Identifier: Apache-2.0
"""Site 1.4 ``subnet6``: a zone's IPv6 prefix, which a guest's IPv6 extra address is held against
(``homelabnext.compute.validate``).  ``hnx site validate`` requires one prefix that names its zone
only.

Prefixes outside the documentation range are built from integers, so no such literal is in the
tree."""

from __future__ import annotations

import copy
import ipaddress
from pathlib import Path

import pytest

from homelabnext.network import load_site, validate
from homelabnext.network.loader import load_registry
from homelabnext.network.validate import schema_problems, subnet6_problem

#: the example lab, whose zone compute has a subnet6, and the registry it resolves against
MINIMAL = Path(__file__).resolve().parents[2] / "examples" / "minimal"


def _net(n: int, plen: int) -> str:
    return str(ipaddress.IPv6Network((n, plen)))


@pytest.fixture
def zdoc() -> dict:
    return copy.deepcopy(load_site(MINIMAL / "site.yml"))


@pytest.fixture(scope="module")
def registry():
    return load_registry(MINIMAL / "services.yml")


def _zone(d: dict, zid: str) -> dict:
    return next(z for z in d["zones"] if z["id"] == zid)


def test_the_example_lab_is_clean(zdoc, registry):
    assert _zone(zdoc, "compute")["subnet6"] == "2001:db8:0:82::/64"
    assert schema_problems(zdoc) == []
    rep = validate(zdoc, registry)
    assert rep.ok, rep.errors


@pytest.mark.parametrize(
    "prefix",
    [
        "2001:db8:0:82::/64",
        "2001:db8:5::/48",
        _net(0x3FFF_0000_0005 << 80, 48),  # documentation (RFC 9637)
        _net(0x2600_0000_0000_0082 << 64, 64),  # global unicast
        _net(0xFD00_0000_0000_0082 << 64, 64),  # unique-local
    ],
)
def test_a_canonical_48_to_64_is_a_prefix(prefix):
    net, why = subnet6_problem(prefix)
    assert why is None and str(net) == prefix


@pytest.mark.parametrize(
    ("prefix", "why"),
    [
        ("2001:db8:0:82::1/64", "host bits"),
        ("2001:db8:0:82:0::/64", "canonical form; write 2001:db8:0:82::/64"),
        ("2001:db8::/32", "is a /32"),
        ("2001:db8:0:82::/96", "is a /96"),
        ("192.0.2.0/24", "is not an IPv6 prefix"),  # no-raw-endpoint: allow an IPv4 prefix, refused
        (_net(0xFE80 << 112, 64), "link-local"),
        (_net(0xFF02 << 112, 64), "multicast"),
        (_net(0, 64), "unspecified"),  # ::/64 holds :: and ::1
        (_net(0x64_FF9B << 96, 64), "embeds IPv4"),  # NAT64, well-known
        (_net(0x64_FF9B_0001 << 80, 48), "embeds IPv4"),  # NAT64, local use
        (_net(0x2002_C000_0200 << 80, 48), "embeds IPv4"),  # 6to4
        (_net(0x2001_0000_0001 << 80, 48), "embeds IPv4"),  # Teredo
        # special-purpose space no zone is numbered from
        (_net(0x0100 << 112, 64), "is not unique-local"),  # discard-only
        (_net(0xFEC0 << 112, 48), "is not unique-local"),  # deprecated site-local
        (_net(0x2001_0002 << 96, 48), "is not unique-local"),  # benchmarking
        (_net(0x2001_0010 << 96, 48), "is not unique-local"),  # ORCHID
        (_net(0x2001_0020 << 96, 48), "is not unique-local"),  # ORCHIDv2
        (_net(0x5F00 << 112, 48), "is not unique-local"),  # SRv6 SIDs
        (_net(0x4000 << 112, 48), "is not unique-local"),  # unassigned
    ],
)
def test_a_prefix_that_names_no_one_zone_is_refused(prefix, why):
    net, problem = subnet6_problem(prefix)
    assert net is None
    assert why in problem


def test_two_zones_with_overlapping_prefixes_are_refused(zdoc, registry):
    _zone(zdoc, "data")["subnet6"] = "2001:db8:0:82::/64"
    rep = validate(zdoc, registry)
    assert any(
        "zones data and compute: subnet6 2001:db8:0:82::/64 and 2001:db8:0:82::/64 overlap" in e
        for e in rep.errors
    ), rep.errors
    # a /48 that holds another zone's /64 overlaps it too
    _zone(zdoc, "data")["subnet6"] = "2001:db8::/48"
    assert any("overlap" in e for e in validate(zdoc, registry).errors)


def test_a_bad_prefix_is_an_error_naming_its_zone(zdoc, registry):
    """The schema checks the shape; these pass it and are refused for what they mean."""
    for bad, why in (
        ("2001:db8:0:82:0::/64", "is not in its canonical form"),
        (_net(0xFE80 << 112, 64), "is link-local"),
        (_net(0x64_FF9B << 96, 64), "embeds IPv4"),
    ):
        _zone(zdoc, "compute")["subnet6"] = bad
        rep = validate(zdoc, registry)
        assert any(e.startswith(f"zone compute: subnet6 {bad!r} {why}") for e in rep.errors), (
            rep.errors
        )


def test_the_schema_refuses_upper_case_and_a_prefix_outside_48_to_64(zdoc):
    for bad in ("2001:DB8:0:82::/64", "2001:db8::/32", "2001:db8:0:82::/65", "2001:db8:0:82::"):
        _zone(zdoc, "compute")["subnet6"] = bad
        assert any("subnet6" in p for p in schema_problems(zdoc)), bad
