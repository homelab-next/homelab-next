# SPDX-License-Identifier: Apache-2.0
"""The hnx_enroll_address_problems filter (ansible/plugins/filter/hnx_address.py): the address
checks a central role runs on its ``<role>_guests`` rows, called directly (no playbook).

Addresses outside the documentation ranges are built from integers, so no private, shared,
link-local or public literal sits in the tree (the leak scan)."""

from __future__ import annotations

import functools
import importlib.util
import ipaddress
from pathlib import Path

import pytest

PLUGIN = Path(__file__).resolve().parents[2] / "ansible/plugins/filter/hnx_address.py"


@functools.cache
def _plugin():
    """The plugin module, loaded on first use (so a missing plugin fails tests, not collection)."""
    spec = importlib.util.spec_from_file_location("hnx_address", PLUGIN)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def problems(rows):
    return _plugin().enroll_address_problems(rows)


def a(value: int, v6: bool = False) -> str:
    return str(ipaddress.IPv6Address(value) if v6 else ipaddress.IPv4Address(value))


PUBLIC = a(0x0808_0808)  # an internet address, outside every documentation range
PRIVATE = a(0x0A01_0203)  # RFC 1918
SHARED = a(0x6440_0005)  # RFC 6598, the overlay range a tailnet uses
MAPPED = a(0xFFFF_C633_6405, v6=True)  # IPv4-mapped 198.51.100.5
COMPATIBLE = "::" + "198.51.100.5"  # IPv4-compatible
NAT64 = a((0x0064_FF9B << 96) | 0xC633_6405, v6=True)
LINK_LOCAL6 = a(0xFE80 << 112 | 1, v6=True)
MULTICAST6 = a(0xFF02 << 112 | 1, v6=True)
ULA = a(0xFD00 << 112 | 5, v6=True)
GLOBAL6 = a(0x2600 << 112 | 5, v6=True)
METADATA = a(0xA9FE_A9FE)
SHARED_METADATA = a(0x6464_64C8)  # a metadata address inside the shared range

ROW = {"name": "bus-core", "ip": "198.51.100.50", "zone": "data"}
ZONED = {**ROW, "subnet": "198.51.100.0/24"}


def test_sound_rows_have_no_problems():
    assert problems([ROW]) == []
    assert problems([{**ROW, "extra_addresses": []}]) == []
    assert problems([{**ZONED, "extra_addresses": ["198.51.100.51", SHARED, ULA]}]) == []
    # without a subnet (a hand-written row): private, shared and documentation space only
    assert problems([{**ROW, "extra_addresses": [PRIVATE, SHARED, "2001:db8::5", ULA]}]) == []


@pytest.mark.parametrize(
    ("ip", "why"),
    [
        ("999.1.1.1", "is not an IP address"),
        ("198.51.100.050", "is not an IP address"),
        ("any", "is not an IP address"),
        ("198.51.100.50\nHOME_NET: any", "is not an IP address"),
        ("127.0.0.1", "loopback"),
        ("0.0.0.0", "unspecified"),
        (METADATA, "cloud metadata"),
        ("2001:db8::5", "is not IPv4"),
        ("2001:db8::5%eth0", "zone id"),
        (None, "is not a string"),
    ],
)
def test_the_ip_is_a_plain_ipv4_address(ip, why):
    (msg,) = problems([{**ROW, "ip": ip}])
    assert msg.startswith("guest bus-core: ip ") and why in msg


@pytest.mark.parametrize(
    ("extra", "why"),
    [
        ("::", "unspecified"),
        ("1:2:3", "is not an IP address"),
        ("1::2::3", "is not an IP address"),
        ("999.1.1.1", "is not an IP address"),
        ("127.0.0.1", "loopback"),
        ("::1", "loopback"),
        (LINK_LOCAL6, "link-local"),
        (MULTICAST6, "multicast"),
        (MAPPED, "writes an IPv4 address inside IPv6"),
        (COMPATIBLE, "writes an IPv4 address inside IPv6"),
        (NAT64, "writes an IPv4 address inside IPv6"),
        ("2001:DB8::5", "canonical form (2001:db8::5)"),
        ("2001:db8:0:0::5", "canonical form (2001:db8::5)"),
        (METADATA, "cloud metadata"),
        (SHARED_METADATA, "cloud metadata"),
        (GLOBAL6, "global or special-purpose IPv6"),
        (PUBLIC, "outside the zone subnet 198.51.100.0/24"),
        ("203.0.113.5", "outside the zone subnet 198.51.100.0/24"),  # another zone's
        ("198.51.100.0", "network or broadcast address"),
        ("198.51.100.255", "network or broadcast address"),
        (5, "is not a string"),
        # a zone id: Python parses it into the address and writes it back unchanged, and the
        # address with it compares unequal to the one without (one address named twice)
        (f"{ULA}%eth0", "zone id"),
        ("2001:db8::5%1", "zone id"),
    ],
)
def test_an_extra_address_is_the_guests_own(extra, why):
    (msg,) = problems([{**ZONED, "extra_addresses": [extra]}])
    assert msg.startswith(f"guest bus-core: extra address {extra!r} ") and why in msg, msg


def test_a_row_without_a_subnet_names_only_non_internet_space():
    (msg,) = problems([{**ROW, "extra_addresses": [PUBLIC]}])
    assert "outside private, shared and documentation space" in msg
    assert problems([{**ROW, "extra_addresses": [GLOBAL6]}])  # no IPv6 prefix to hold it to


@pytest.mark.parametrize(
    ("subnet", "why"),
    [
        ("198.51.100.5/24", "without host bits"),
        ("0.0.0.0/0", "not a /8 to /30"),
        ("198.51.100.48/31", "not a /8 to /30"),
        (a(0x0800_0000) + "/16", "wider than /24"),  # public space, wider than one zone
        ("203.0.113.0/24", "does not hold the guest's ip"),
        (["198.51.100.0/24"], "is not a string"),
    ],
)
def test_the_subnet_is_the_guests_zone(subnet, why):
    msgs = problems([{**ZONED, "subnet": subnet, "extra_addresses": ["198.51.100.51"]}])
    assert any(m.startswith("guest bus-core: subnet ") and why in m for m in msgs), msgs
    # an unusable subnet holds no extra address, rather than letting it through
    assert any("unusable subnet" in m for m in msgs), msgs


def test_a_public_zone_of_one_24_is_accepted():
    zone = a(0x0808_0800) + "/24"
    row = {**ROW, "ip": a(0x0808_0805), "subnet": zone, "extra_addresses": [a(0x0808_0806)]}
    assert problems([row]) == []


def test_every_problem_is_reported_once():
    rows = [
        {**ZONED, "extra_addresses": [PUBLIC, "::", MAPPED]},
        {"name": "edge-core", "ip": "1:2:3", "zone": "edge"},
        "not a row",
        {**ROW, "name": "other", "extra_addresses": "198.51.100.51"},
    ]
    msgs = problems(rows)
    assert len(msgs) == 6, msgs
    assert msgs[3].startswith("guest edge-core: ip ") and msgs[4] == "guest #2 is not a mapping"
    assert msgs[5] == "guest other: extra_addresses is not a list"
    assert problems("not a list") == ["the guests are not a list"]


PREFIX6 = a(0x2600 << 112, v6=True) + "/64"  # a global /64 a zone is numbered from
IN_PREFIX6 = a(0x2600 << 112 | 0xA, v6=True)
ZONED6 = {**ZONED, "subnet6": PREFIX6}


def test_a_zones_ipv6_prefix_holds_a_global_extra_address():
    assert problems([{**ZONED6, "extra_addresses": [IN_PREFIX6, "198.51.100.51"]}]) == []
    # the row gives the prefix, so a unique-local or documentation address outside it is not its
    (msg,) = problems([{**ZONED6, "extra_addresses": [ULA]}])
    assert f"outside the zone's IPv6 prefix {PREFIX6}" in msg
    (msg,) = problems([{**ZONED6, "extra_addresses": [a(0x2600_0000_0000_0001 << 64 | 5, True)]}])
    assert "outside the zone's IPv6 prefix" in msg  # another /64
    # without the prefix a global address has nothing to be held against
    (msg,) = problems([{**ZONED, "extra_addresses": [IN_PREFIX6]}])
    assert "gives no IPv6 prefix (subnet6)" in msg


@pytest.mark.parametrize(
    ("extra", "why"),
    [
        (a(0x2600 << 112, v6=True), "subnet-router anycast"),
        (a(0x2600 << 112 | 0xFDFF_FFFF_FFFF_FF80, v6=True), "RFC 2526"),
        (a(0x2600 << 112 | 0xFDFF_FFFF_FFFF_FFFF, v6=True), "RFC 2526"),
        (a(0x2600 << 112 | 0xFFFF_FFFF_FFFF_FFFE, v6=True), "RFC 2526"),
        (a(0xFD00 << 112, v6=True), "subnet-router anycast"),  # with no prefix too
    ],
)
def test_an_anycast_address_of_its_64_is_never_an_extra_address(extra, why):
    (msg,) = problems([{**ZONED6, "extra_addresses": [extra]}])
    assert why in msg, msg


@pytest.mark.parametrize(
    ("subnet6", "why"),
    [
        (a(0x2600 << 112 | 5, v6=True) + "/64", "without host bits"),
        ("2001:DB8:0:28::/64", "canonical form"),
        (a(0x2600 << 112, v6=True) + "/32", "not a /48 to /64"),
        (a(0x2600 << 112, v6=True) + "/96", "not a /48 to /64"),
        (a(0x2002 << 112, v6=True) + "/48", "writes IPv4 addresses inside IPv6"),  # 6to4
        (a(0x0064_FF9B << 96, v6=True) + "/64", "writes IPv4 addresses inside IPv6"),  # NAT64
        (a(0x2001_0002 << 96, v6=True) + "/48", "IETF protocol assignments"),  # benchmarking
        (a(0xFE80 << 112, v6=True) + "/64", "not unique-local or global unicast"),
        (a(0xFF00 << 112, v6=True) + "/64", "not unique-local or global unicast"),
        (PREFIX6.replace("/", "%eth0/"), "zone id"),
        ("2001:db8:0:28::%1/64", "zone id"),
        ("", "without host bits"),
        (64, "is not a string"),
        (None, "is not a string"),
        (True, "is not a string"),
        ([PREFIX6], "is not a string"),
    ],
)
def test_the_subnet6_is_a_zone_prefix(subnet6, why):
    msgs = problems([{**ZONED, "subnet6": subnet6, "extra_addresses": [ULA, "198.51.100.51"]}])
    assert any(m.startswith("guest bus-core: subnet6 ") and why in m for m in msgs), msgs
    # an unusable prefix holds no IPv6 extra address; the IPv4 one is still held to the subnet
    assert any(f"{ULA!r} cannot be held against the row's unusable subnet6" in m for m in msgs)
    assert not any("198.51.100.51" in m for m in msgs), msgs


@pytest.mark.parametrize(
    "extra", [IN_PREFIX6.upper(), str(ipaddress.IPv6Address(IN_PREFIX6).exploded)]
)
def test_an_extra_inside_the_prefix_must_still_be_written_canonically(extra):
    (msg,) = problems([{**ZONED6, "extra_addresses": [extra]}])
    assert f"canonical form ({IN_PREFIX6})" in msg, msg


def test_the_last_identifier_below_each_anycast_block_is_an_address():
    base = 0x2600 << 112
    for iid in (0xFDFF_FFFF_FFFF_FF7F, 0xFFFF_FFFF_FFFF_FF7F, 1):
        assert problems([{**ZONED6, "extra_addresses": [a(base | iid, v6=True)]}]) == []


@pytest.mark.parametrize(
    "prefix",
    [
        "2001:db8:0:28::/64",
        a(0x3FFF_0000_0028 << 80, v6=True) + "/48",  # 3fff::/20, documentation (RFC 9637)
        a(0xFD00_0000_0028 << 80, v6=True) + "/48",  # unique-local
    ],
)
def test_documentation_and_unique_local_prefixes_are_zone_prefixes(prefix):
    inside = a(int(ipaddress.IPv6Network(prefix).network_address) | 5, v6=True)
    assert problems([{**ZONED, "subnet6": prefix, "extra_addresses": [inside]}]) == []


def test_an_unusable_ipv4_subnet_holds_no_ipv6_extra_either():
    msgs = problems([{**ZONED6, "subnet": "198.51.100.5/24", "extra_addresses": [IN_PREFIX6]}])
    assert any("unusable subnet" in m and IN_PREFIX6 in m for m in msgs), msgs


def test_the_filter_is_registered():
    mod = _plugin()
    assert mod.FilterModule().filters() == {
        "hnx_enroll_address_problems": mod.enroll_address_problems,
        "hnx_rule_prefix6_problems": mod.rule_prefix6_problems,
    }


# ---------------------------------------------------------------- firewall-rule IPv6 addresses
@pytest.mark.parametrize(
    ("value", "why"),
    [
        ("2001:db8::/32", "is not a /48 to /64"),
        ("2001:DB8:0:10::/64", "canonical form"),
        ("2001:db8:0:10:0::/64", "canonical form"),
        ("fe80::/64", "unique-local or global unicast"),
        ("2001:db8:0:10::/64%eth0", "zone id"),
        (f"{a(0xFFFF_C000_0200, True)}/120", "is not a /48 to /64"),
        (5, "is not a string"),
        # neither any, an IPv4 CIDR nor an IPv6 prefix: judged as one, never skipped
        ("10/8", "not an IPv6 prefix"),
        ("abc/8", "not an IPv6 prefix"),
        ("ff/0", "not an IPv6 prefix"),
    ],
)
def test_an_ipv6_rule_address_is_a_zone_prefix(value, why):
    (msg,) = _plugin().rule_prefix6_problems(["any", "192.0.2.0/26", value])
    assert why in msg, msg


def test_a_zone_prefix_rule_address_has_no_problems():
    assert _plugin().rule_prefix6_problems(["any", "192.0.2.0/26", "2001:db8:0:10::/64"]) == []
    assert _plugin().rule_prefix6_problems("2001:db8:0:10::/64") == [
        "the rule addresses are not a list"
    ]
