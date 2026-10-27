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


def test_the_filter_is_registered():
    mod = _plugin()
    assert mod.FilterModule().filters() == {
        "hnx_enroll_address_problems": mod.enroll_address_problems
    }
