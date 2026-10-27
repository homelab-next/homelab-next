# SPDX-License-Identifier: Apache-2.0
"""guest 1.6 ``network.extra_addresses``: the other addresses a guest sends from, which the log
pipeline's runtime table labels like ``network.ip`` (docs/log-pipeline.md).  Each must name this
guest and no other wherever a collector sees it, so validation refuses any address that does not.

Addresses outside the documentation ranges are built from integers, so no such literal is in
the tree."""

from __future__ import annotations

import ipaddress
import json
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


def _load(site: Path):
    zones, domain = open_site(site / "site.yml")
    return load_fleet(site / "guests", zones, domain=domain or "example.internal")


def test_the_example_runtime_has_an_extra_address_and_loads():
    fleet = _load(MINIMAL)
    (g,) = [g for g in fleet.sorted() if g.id == "guest:infer-core"]
    assert g.extra_addresses == (EXTRA,)
    assert g.addresses == ("192.0.2.140", EXTRA)


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
        (_v4(0x0B00_0001), "internet address outside zone compute"),
        (_v6(0x2600 << 112 | 1), "internet address outside zone compute"),
        ("192.0.2.129", "zone compute's gateway"),
        ("198.51.100.1", "zone edge's gateway"),  # a zone no guest is in
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
    ops = site / "guests" / "ops-core.yml"
    doc = yaml.safe_load(ops.read_text(encoding="utf-8"))
    doc["network"]["extra_addresses"] = [{"address": EXTRA, "why": "the same container NAT"}]
    ops.write_text(yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")
    with pytest.raises(ComputeError, match=f"extra_addresses {EXTRA} already used by"):
        _load(site)


@pytest.mark.parametrize(
    ("address", "owner"), [("192.0.2.80", "guest:bus-core"), ("192.0.2.20", "guest:infer-core")]
)
def test_another_guests_network_ip_is_refused_whichever_comes_first(tmp_path, address, owner):
    """bus-core sorts before infer-core and ops-core after it: the address is refused either way,
    on whichever guest names it second."""
    with pytest.raises(ComputeError, match=f"{address} already used by {owner}"):
        _load(_site(tmp_path, [address]))


@pytest.mark.parametrize(
    "address",
    ["2001:db8::8c/64", _v6(0xFE80 << 112 | 1) + "%eth0", "2001:DB8::8C", "198.51.100.200:443"],
)
def test_a_shape_that_is_no_bare_address_is_refused_by_the_schema(tmp_path, address):
    with pytest.raises(ComputeError, match="extra_addresses"):
        _load(_site(tmp_path, [address]))
