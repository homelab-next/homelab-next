# SPDX-License-Identifier: Apache-2.0
"""guest 1.6 ``network.extra_addresses``: the other addresses a guest sends from, which the log
pipeline's runtime table labels like ``network.ip`` (docs/log-pipeline.md).  Each must name this
guest and no other wherever a collector sees it, so validation refuses any address that does not.

Addresses outside the documentation ranges are built from integers, so no such literal is in
the tree."""

from __future__ import annotations

import ipaddress
import json
import re
import shutil
from pathlib import Path

import pytest
import yaml

from homelabnext.compute.loader import load_fleet
from homelabnext.compute.model import ComputeError
from homelabnext.compute.render import render
from homelabnext.compute.zones import open_site
from homelabnext.modules.egress import METADATA

REPO = Path(__file__).resolve().parents[2]
MINIMAL = REPO / "examples" / "minimal"
EXTRA = "2001:db8:0:82::8c"  # the example infer-core's extra address
PREFIX = "2001:db8:0:82::/64"  # the example zone compute's subnet6 (site 1.4)


def _v6(n: int) -> str:
    return str(ipaddress.IPv6Address(n))


def _v4(n: int) -> str:
    return str(ipaddress.IPv4Address(n))


def _site(tmp_path: Path, extras: list[str], guest: str = "infer-core") -> Path:
    site = tmp_path / "minimal"
    shutil.copytree(MINIMAL, site)
    path = site / "guests" / f"{guest}.yml"
    doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    doc["network"]["extra_addresses"] = [
        {"address": a, "why": "a second address it sends from"} for a in extras
    ]
    path.write_text(yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")
    return site


def _subnet6(site: Path, zone: str, prefix: str | None) -> None:
    """Set (or, with None, drop) a zone's ``subnet6`` in the copied site."""
    path = site / "site.yml"
    doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    z = next(z for z in doc["zones"] if z["id"] == zone)
    if prefix is None:
        z.pop("subnet6", None)
    else:
        z["subnet6"] = prefix
    path.write_text(yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")


def _load(site: Path):
    zones, domain = open_site(site / "site.yml")
    return load_fleet(site / "guests", zones, domain=domain or "example.internal")


def test_the_example_runtime_has_an_extra_address_and_loads():
    fleet = _load(MINIMAL)
    (g,) = [g for g in fleet.sorted() if g.id == "guest:infer-core"]
    assert g.extra_addresses == ("192.0.2.150", EXTRA)
    assert g.addresses == ("192.0.2.140", "192.0.2.150", EXTRA)


def test_every_address_of_a_guest_is_in_the_table_with_its_value(tmp_path):
    site = _site(tmp_path, [EXTRA, "192.0.2.150"])
    (text,) = render(_load(site), "runtime-labels").values()
    table = json.loads(text)["addresses"]
    for a in ("192.0.2.140", "192.0.2.150", EXTRA):
        assert table[a] == {
            "value": "model",
            "guest": "guest:infer-core",
            "capability": "cap:inference",
        }
    # a guest that runs no model labels its extra address none
    site = _site(tmp_path / "b", ["2001:db8:0:50::14"], guest="ops-core")
    (text,) = render(_load(site), "runtime-labels").values()
    assert json.loads(text)["addresses"]["2001:db8:0:50::14"]["value"] == "none"


@pytest.mark.parametrize(
    ("address", "why"),
    [
        ("2001:db8:0:82:0:0:0:8c", "canonical form; write 2001:db8:0:82::8c"),
        ("2001:db8:0:82:0000::8c", "canonical form"),
        # ::ffff:192.0.2.140 in hex groups (Python writes it dotted, which the schema refuses)
        (f"::ffff:{0xC000:x}:{0x028C:x}", "embeds an IPv4 address"),
        (_v6((0x64FF9B << 96) | 0xC000028C), "embeds an IPv4 address"),
        (_v6(1), "embeds an IPv4 address"),  # ::1 is in ::/96
        (_v6(0xFE80 << 112 | 1), "link-local"),
        (_v4(0xA9FE_0A01), "link-local"),
        (_v6(0xFF02 << 112 | 1), "multicast"),
        (str(METADATA[0]), "cloud metadata"),
        (str(METADATA[2]), "cloud metadata"),
        (str(METADATA[-1]), "cloud metadata"),
        (_v4(0x7F00_0001), "loopback"),
        (_v4(0xF000_0001), "reserved"),
        (_v4(0x0000_0001), "this-network"),
        (_v4(0x0B00_0001), "is outside zone compute's subnet"),
        (_v4(0xC0A8_0001), "is outside zone compute's subnet"),  # private, but in no zone
        # zone compute has an IPv6 prefix (subnet6): an IPv6 address is held against it
        (_v6(0x2600 << 112 | 1), f"is outside zone compute's IPv6 prefix {PREFIX}"),
        (_v6(0x2002 << 112 | 1), "is outside zone compute's IPv6 prefix"),  # 6to4
        (_v6(0x2001 << 112 | 1), "is outside zone compute's IPv6 prefix"),  # Teredo
        (_v6(0xFD00 << 112 | 0x8C), "is outside zone compute's IPv6 prefix"),  # unique-local
        ("2001:db8:0:83::1", "is outside zone compute's IPv6 prefix"),
        ("2001:db8:0:82::", "subnet-router anycast address"),
        ("192.0.2.129", "zone compute's gateway"),
        # another zone's address, whatever holds it (a router, a NAS, a VIP no guest file names)
        ("192.0.2.5", "inside zone mgmt's subnet, not zone compute's"),
        ("192.0.2.66", "inside zone data's subnet, not zone compute's"),
        ("198.51.100.1", "inside zone edge's subnet"),  # a zone no guest is in
        ("192.0.2.170", "zone compute's DHCP pool"),
        ("192.0.2.128", "network or broadcast"),
        ("192.0.2.191", "network or broadcast"),
        ("192.0.2.140", "repeats network.ip"),
    ],
    ids=lambda v: v if isinstance(v, str) and len(v) < 30 else None,
)
def test_an_address_that_names_no_one_guest_is_refused(tmp_path, address, why):
    site = _site(tmp_path, [address])
    with pytest.raises(ComputeError) as exc:
        _load(site)
    assert f"network.extra_addresses {address} " in str(exc.value)
    assert why in str(exc.value)


def test_an_address_named_twice_is_refused(tmp_path):
    with pytest.raises(ComputeError, match="is named twice"):
        _load(_site(tmp_path, [EXTRA, EXTRA]))


def test_one_extra_address_on_two_guests_is_refused(tmp_path):
    site = _site(tmp_path, [EXTRA])
    _into_compute(site, "ops-core", "192.0.2.152")  # in zone compute, whose prefix holds EXTRA
    ops = site / "guests" / "ops-core.yml"
    doc = yaml.safe_load(ops.read_text(encoding="utf-8"))
    doc["network"]["extra_addresses"] = [{"address": EXTRA, "why": "the same container NAT"}]
    ops.write_text(yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")
    with pytest.raises(ComputeError, match=f"extra_addresses {EXTRA} already used by"):
        _load(site)


def _into_compute(site: Path, guest: str, ip: str) -> None:
    """Move an example guest into zone compute (the only zone infer-core may claim in)."""
    path = site / "guests" / f"{guest}.yml"
    doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    doc["network"]["zone"], doc["network"]["ip"] = "compute", ip
    path.write_text(yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")


@pytest.mark.parametrize(
    ("address", "owner"), [("192.0.2.151", "guest:bus-core"), ("192.0.2.152", "guest:infer-core")]
)
def test_another_guests_network_ip_is_refused_whichever_comes_first(tmp_path, address, owner):
    """bus-core sorts before infer-core and ops-core after it: the address is refused either way,
    on whichever guest names it second, and the message names its first holder."""
    site = _site(tmp_path, [address])
    _into_compute(site, "bus-core", "192.0.2.151")
    _into_compute(site, "ops-core", "192.0.2.152")
    with pytest.raises(ComputeError, match=f"{address} already used by {owner}"):
        _load(site)


def test_a_third_claimant_of_an_address_names_its_first_holder(tmp_path):
    site = _site(tmp_path, [])
    _into_compute(site, "bus-core", "192.0.2.151")
    _into_compute(site, "ops-core", "192.0.2.151")
    path = site / "guests" / "infer-core.yml"
    doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    doc["network"]["ip"] = "192.0.2.151"
    path.write_text(yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")
    with pytest.raises(ComputeError) as exc:
        _load(site)
    text = str(exc.value)
    assert "guest:infer-core: ip 192.0.2.151 already used by guest:bus-core" in text
    assert "guest:ops-core: ip 192.0.2.151 already used by guest:bus-core" in text


def test_the_guests_own_gateway_override_is_refused(tmp_path):
    site = _site(tmp_path, ["192.0.2.150"])
    path = site / "guests" / "infer-core.yml"
    doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    doc["network"]["gateway"] = "192.0.2.150"
    path.write_text(yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")
    with pytest.raises(ComputeError, match=re.escape("192.0.2.150 is this guest's own gateway")):
        _load(site)


def test_another_guests_gateway_override_is_refused(tmp_path):
    site = _site(tmp_path, ["192.0.2.150"])
    _into_compute(site, "ops-core", "192.0.2.152")
    path = site / "guests" / "ops-core.yml"
    doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    doc["network"]["gateway"] = "192.0.2.150"
    path.write_text(yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")
    with pytest.raises(
        ComputeError, match=re.escape("192.0.2.150 is the gateway guest:ops-core names")
    ):
        _load(site)


def _dns_record(site: Path, fqdn: str, value: str) -> None:
    path = site / "site.yml"
    doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    doc["dns"]["records"]["static"].append({"fqdn": fqdn, "type": "A", "value": value})
    path.write_text(yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")


def _load_with_site_addresses(site: Path):
    from homelabnext.compute.zones import site_addresses

    zones, domain = open_site(site / "site.yml")
    return load_fleet(
        site / "guests",
        zones,
        domain=domain or "example.internal",
        site_addresses=site_addresses(site / "site.yml"),
    )


def test_an_address_the_site_names_for_something_else_is_refused(tmp_path):
    """A NAS or a service VIP in the guest's own zone that no guest file names: its static DNS
    name is the site model's record of who holds it."""
    site = _site(tmp_path, ["192.0.2.150"])
    _dns_record(site, "nas.example.internal", "192.0.2.150")
    with pytest.raises(ComputeError, match=re.escape("the site's DNS name nas.example.internal")):
        _load_with_site_addresses(site)
    # the guest's own name for the address is no conflict
    site = _site(tmp_path / "own", ["192.0.2.150"])
    _dns_record(site, "infer-core.example.internal", "192.0.2.150")
    assert (
        "192.0.2.150"
        in next(
            g for g in _load_with_site_addresses(site).sorted() if g.id == "guest:infer-core"
        ).addresses
    )


def test_the_cli_reads_the_sites_names(tmp_path, capsys):
    from homelabnext.compute.cli import main

    site = _site(tmp_path, ["192.0.2.150"])
    _dns_record(site, "nas.example.internal", "192.0.2.150")
    rc = main(["validate", str(site / "guests"), "--site", str(site / "site.yml")])
    assert rc == 1
    assert "nas.example.internal" in capsys.readouterr().err


@pytest.mark.parametrize(
    "address",
    [
        _v6(0xFD00 << 112 | 0x8C),  # unique-local: no zone prefix says whose, operator review
        "2001:db8:0:83::1",
        _v4(0x6440_0A8C),  # a tailnet's overlay address (zone-less)
    ],
)
def test_without_a_prefix_unique_local_documentation_and_overlay_are_accepted(tmp_path, address):
    site = _site(tmp_path, [address])
    _subnet6(site, "compute", None)
    g = next(g for g in _load(site).sorted() if g.id == "guest:infer-core")
    assert address in g.addresses


@pytest.mark.parametrize(
    ("address", "why"),
    [
        (_v6(0x2600 << 112 | 1), "zone compute gives no IPv6 prefix (subnet6, site 1.4)"),
        (_v6(0x2002 << 112 | 1), "special-purpose IPv6"),  # 6to4 writes an IPv4 address in it
        (_v6(0x2001 << 112 | 1), "special-purpose IPv6"),  # Teredo
        # documentation space, but inside another zone's prefix: that zone's
        ("2001:db8:0:10::5", "is inside zone mgmt's IPv6 prefix, not zone compute's"),
    ],
)
def test_without_a_prefix_global_special_and_another_zones_are_refused(tmp_path, address, why):
    site = _site(tmp_path, [address])
    _subnet6(site, "compute", None)
    _subnet6(site, "mgmt", "2001:db8:0:10::/64")
    with pytest.raises(ComputeError) as exc:
        _load(site)
    assert f"network.extra_addresses {address} " in str(exc.value)
    assert why in str(exc.value)


def test_a_global_address_inside_its_zones_prefix_is_accepted_and_labelled(tmp_path):
    """SLAAC: the address a runtime really sends from, once its zone says which prefix is its."""
    prefix = str(ipaddress.IPv6Network((0x2600_0000_0000_0082 << 64, 64)))
    address = _v6(0x2600_0000_0000_0082 << 64 | 0x8C)
    site = _site(tmp_path, [address])
    _subnet6(site, "compute", prefix)
    fleet = _load(site)
    assert address in next(g for g in fleet.sorted() if g.id == "guest:infer-core").addresses
    (text,) = render(fleet, "runtime-labels").values()
    assert json.loads(text)["addresses"][address]["value"] == "model"


def test_an_address_inside_another_zones_prefix_is_refused(tmp_path):
    site = _site(tmp_path, ["2001:db8:0:10::5"])
    _subnet6(site, "mgmt", "2001:db8:0:10::/64")
    with pytest.raises(ComputeError, match="is inside zone mgmt's IPv6 prefix, not zone compute's"):
        _load(site)


def test_an_unreadable_prefix_refuses_every_ipv6_extra_and_no_ipv4_one(tmp_path):
    """open_site does not run hnx site validate: a prefix it would refuse is read here with the
    same rule, and no IPv6 address is held against a zone list it cannot read."""
    site = _site(tmp_path, [EXTRA])
    _subnet6(site, "mgmt", "2001:db8:0:10:0::/64")
    with pytest.raises(ComputeError, match=r"cannot be held against zone mgmt: its subnet6"):
        _load(site)
    site = _site(tmp_path / "v4", ["192.0.2.150"])
    _subnet6(site, "mgmt", "2001:db8:0:10:0::/64")
    assert (
        "192.0.2.150"
        in next(g for g in _load(site).sorted() if g.id == "guest:infer-core").addresses
    )


def test_a_zone_reads_its_prefix():
    from homelabnext.compute.model import ZoneInfo
    from homelabnext.compute.zones import SiteAdapter, zone_from_mapping

    z = zone_from_mapping({"id": "c", "subnet": "192.0.2.128/26", "subnet6": PREFIX})
    assert z.network6 == ipaddress.IPv6Network(PREFIX)
    assert ZoneInfo(id="a", subnet="192.0.2.0/26").network6 is None
    with pytest.raises(ValueError, match="not an IPv6 prefix"):
        ZoneInfo(id="a", subnet="192.0.2.0/26", subnet6="192.0.2.0/26").network6  # noqa: B018
    listed = SiteAdapter(
        type("S", (), {"zones": [{"id": "c", "subnet": "192.0.2.128/26", "subnet6": PREFIX}]})()
    ).all()
    assert listed[0].subnet6 == PREFIX


def test_an_overlay_address_inside_a_zone_is_that_zones(tmp_path):
    """The overlay exception is for zone-less ranges: once a zone holds part of the range, an
    address in it is that zone's like any other."""
    overlay = _v4(0x6440_0A00)
    site = _site(tmp_path, [_v4(0x6440_0A8C)])
    path = site / "site.yml"
    doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    doc["zones"].append(
        {
            "id": "tailnet",
            "purpose": "overlay",
            "vlan_id": 60,
            "subnet": f"{overlay}/24",
            "gateway": _v4(0x6440_0A01),
        }
    )
    path.write_text(yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")
    with pytest.raises(ComputeError, match="inside zone tailnet's subnet, not zone compute's"):
        _load(site)


@pytest.mark.parametrize(
    "address",
    ["2001:db8::8c/64", _v6(0xFE80 << 112 | 1) + "%eth0", "2001:DB8::8C", "198.51.100.200:443"],
)
def test_a_shape_that_is_no_bare_address_is_refused_by_the_schema(tmp_path, address):
    with pytest.raises(ComputeError, match="extra_addresses"):
        _load(_site(tmp_path, [address]))


class _ByIdOnly:
    """A zone lookup that answers ``zone(id)`` and cannot list its zones."""

    def __init__(self, zones):
        self._zones = zones

    def zone(self, zone_id):
        return self._zones.zone(zone_id)


def test_a_lookup_that_cannot_list_its_zones_is_a_problem_only_for_extra_addresses(tmp_path):
    zones, domain = open_site(MINIMAL / "site.yml")
    with pytest.raises(ComputeError, match=r"does not list zone\(s\) .*ZoneLookup.all"):
        load_fleet(MINIMAL / "guests", _ByIdOnly(zones), domain=domain)
    site = _site(tmp_path, [])  # no guest names an extra address: nothing needs every zone
    assert load_fleet(site / "guests", _ByIdOnly(zones), domain=domain).guests


def test_the_zone_lookups_list_every_zone():
    from homelabnext.compute.model import ZoneInfo, ZoneLookup
    from homelabnext.compute.zones import MappingZones, SiteAdapter

    a = ZoneInfo(id="a", subnet="192.0.2.0/26", gateway="192.0.2.1")
    b = {"id": "b", "subnet": "192.0.2.64/26", "dhcp": {"range": ["192.0.2.100", "192.0.2.110"]}}
    assert [z.id for z in MappingZones([a]).all()] == ["a"]
    assert isinstance(MappingZones([a]), ZoneLookup)
    listed = SiteAdapter(type("S", (), {"zones": [a, b]})()).all()
    assert [z.id for z in listed] == ["a", "b"]
    assert listed[1].dhcp_range == ("192.0.2.100", "192.0.2.110")
    assert [z.id for z in SiteAdapter(type("S", (), {"zones": {"b": b}})()).all()] == ["b"]
    # a site that only answers zone(id) lists none, and validation says so (test above)
    only = SiteAdapter(type("S", (), {"zone": lambda self, i: a if i == "a" else None})())
    assert only.zone("a") == a and only.all() == []
    assert not isinstance(_ByIdOnly(MappingZones([a])), ZoneLookup)


def test_a_why_of_only_white_space_is_refused_at_load(tmp_path):
    site = _site(tmp_path, [])
    path = site / "guests" / "infer-core.yml"
    doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    doc["network"]["extra_addresses"] = [{"address": "192.0.2.150", "why": " " * 12}]
    path.write_text(yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")
    with pytest.raises(ComputeError, match="extra_addresses"):
        _load(site)
