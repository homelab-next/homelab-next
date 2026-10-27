# SPDX-License-Identifier: Apache-2.0
"""The hnx_enroll_address_problems filter (ansible/plugins/filter/hnx_address.py) re-implements,
standard library only, the rules the guest model holds addresses to: a zone's IPv6 prefix
(``homelabnext.network.validate.subnet6_problem``) and an extra address
(``homelabnext.compute.validate._extra_address_problem``).  The two must not drift apart, so a
hand-written inventory row is never held to looser rules than the generator's.  One corpus runs
through both, for what one row can show: one zone, its IPv4 subnet and, or not, its prefix.

Addresses outside the documentation ranges are built from integers, so no such literal sits in
the tree (the leak scan)."""

from __future__ import annotations

import functools
import importlib.util
import ipaddress
from pathlib import Path
from types import SimpleNamespace

import pytest

from homelabnext.compute.model import ZoneInfo
from homelabnext.compute.validate import _extra_address_problem
from homelabnext.network.validate import subnet6_problem

PLUGIN = Path(__file__).resolve().parents[2] / "ansible/plugins/filter/hnx_address.py"


@functools.cache
def _plugin():
    spec = importlib.util.spec_from_file_location("hnx_address_parity", PLUGIN)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def v6(n: int) -> str:
    return str(ipaddress.IPv6Address(n))


def v4(n: int) -> str:
    return str(ipaddress.IPv4Address(n))


def net6(n: int, plen: int) -> str:
    return str(ipaddress.IPv6Network((n, plen)))


GLOBAL = 0x2600 << 112  # a global unicast /64 a zone could be numbered from
DOC = 0x2001_0DB8_0000_0028 << 64
ULA = 0xFD00_0000_0000_0028 << 64

PREFIXES = (
    net6(GLOBAL, 64),
    net6(GLOBAL, 48),
    net6(GLOBAL, 56),
    net6(DOC, 64),
    net6(0x3FFF_0000_0028 << 80, 48),  # 3fff::/20, documentation
    net6(ULA, 64),
    net6(GLOBAL, 47),
    net6(GLOBAL, 65),
    net6(0, 64),
    net6(0, 0),
    net6(0x2000 << 112, 3),
    net6(0x2001 << 112, 48),  # Teredo
    net6(0x2001_0002 << 96, 48),  # benchmarking, inside 2001::/23
    net6(0x2001_01FF << 96, 48),  # the last /48 inside 2001::/23
    net6(0x2001_0200 << 96, 48),  # the first /48 past it
    net6(0x2002 << 112, 48),  # 6to4
    net6(0x64_FF9B << 96, 64),  # NAT64, well-known
    net6(0x64_FF9B_0001 << 80, 48),  # NAT64, local use
    net6(0xFFFF << 32, 96),  # IPv4-mapped
    net6(0xFE80 << 112, 64),  # link-local
    net6(0xFF02 << 112, 64),  # multicast
    net6(0xFEC0 << 112, 48),  # deprecated site-local
    net6(0x0100 << 112, 64),  # discard-only
    net6(0x4000 << 112, 48),  # unassigned
    net6(GLOBAL, 64).upper(),
    ipaddress.IPv6Network((GLOBAL, 64)).exploded,
    v6(GLOBAL | 5) + "/64",  # host bits
    net6(GLOBAL, 64).replace("/", "%eth0/"),
    net6(DOC, 64).replace("/", "%1/"),
    net6(GLOBAL, 64) + " ",
    net6(GLOBAL, 64) + "\n",
    "198.51.100.0/24",  # an IPv4 prefix, refused as an IPv6 one
    "",
    "any",
)
NOT_TEXT = (None, 64, 6.4, True, [net6(GLOBAL, 64)], {"prefix": net6(GLOBAL, 64)})


@pytest.mark.parametrize("prefix", PREFIXES + NOT_TEXT, ids=repr)
def test_the_filter_and_the_site_model_agree_on_a_zone_prefix(prefix):
    filt, _ = _plugin()._subnet6(prefix)
    model, _ = subnet6_problem(prefix)
    assert (filt is None) == (model is None), (filt, model)


SUBNET = "198.51.100.0/24"  # the one zone's IPv4 subnet


def _extras(prefix: int) -> list:
    """Addresses around one /64: inside, at and either side of each anycast block."""
    out: list = []
    for iid in (
        0,
        1,
        0x5,
        0xFDFF_FFFF_FFFF_FF7F,
        0xFDFF_FFFF_FFFF_FF80,
        0xFDFF_FFFF_FFFF_FFFF,
        0xFE00_0000_0000_0000,
        0xFFFF_FFFF_FFFF_FF7F,
        0xFFFF_FFFF_FFFF_FF80,
        0xFFFF_FFFF_FFFF_FFFF,
    ):
        out.append(v6(prefix | iid))
    out.append(v6((prefix + (1 << 64)) | 5))  # the next /64
    return out


EXTRAS = (
    *_extras(GLOBAL),
    *_extras(DOC),
    *_extras(ULA),
    v6(0x2001_0200 << 96 | 5),
    v6(0x2001 << 112 | 5),  # Teredo
    v6(0x2002 << 112 | 5),  # 6to4
    v6(0x64_FF9B << 96 | 0xC633_6405),  # NAT64
    v6(0xFFFF_C633_6405),  # IPv4-mapped
    v6(0xC633_6405),  # IPv4-compatible
    v6(0xFFFF_0000_C633_6405),  # IPv4-translated
    v6(0xFE80 << 112 | 1),
    v6(0xFF02 << 112 | 1),
    v6(0xFD00_0EC2 << 96 | 0x254),  # a cloud metadata address
    v6(0x3FFF << 112 | 5),
    v6(0x4000 << 112 | 5),
    "::",
    "::1",
    v6(GLOBAL | 5).upper(),
    ipaddress.IPv6Address(GLOBAL | 5).exploded,
    v6(GLOBAL | 5) + "%eth0",
    v6(DOC | 5) + "%1",
    v6(GLOBAL | 5) + " ",
    "198.51.100.51",
    "198.51.100.0",
    "198.51.100.255",
    "198.51.100.051",
    "203.0.113.5",
    v4(0x6440_0005),  # the shared range a tailnet uses
    v4(0x6464_64C8),  # a cloud metadata address inside it
    v4(0xA9FE_A9FE),  # a cloud metadata address
    v4(0xA9FE_0001),  # link-local
    v4(0x7F00_0001),
    v4(0x0000_0001),
    v4(0xF000_0001),
    v4(0xE000_0001),
    v4(0x0808_0808),
    "",
    "any",
    None,
    5,
    int(ipaddress.IPv4Address("198.51.100.51")),
)
ZONE_PREFIXES = (None, net6(GLOBAL, 64), net6(DOC, 64), net6(0xFD00 << 112, 48), "not a prefix")


def _model_accepts(extra, prefix) -> bool:
    zone = ZoneInfo(id="data", subnet=SUBNET, subnet6=prefix)
    guest = SimpleNamespace(id="guest:bus-core", zone="data", network={"gateway": "inherit"})
    fleet = SimpleNamespace(site_addresses={}, fqdn=lambda g: "bus-core.example.internal")
    key, _ = _extra_address_problem(extra, guest, [zone], {}, fleet)
    return key is not None


def _filter_accepts(extra, prefix) -> bool:
    row = {"name": "bus-core", "ip": "198.51.100.50", "zone": "data", "subnet": SUBNET}
    if prefix is not None:
        row["subnet6"] = prefix
    row["extra_addresses"] = [extra]
    # an unusable prefix is a problem of its own; the verdict is the one on the extra address
    msgs = _plugin().enroll_address_problems([row])
    return not any(m.startswith(f"guest bus-core: extra address {extra!r} ") for m in msgs)


@pytest.mark.parametrize("prefix", ZONE_PREFIXES, ids=repr)
def test_the_filter_and_the_guest_model_agree_on_every_extra_address(prefix):
    differ = [
        (e, m) for e in EXTRAS if (m := _model_accepts(e, prefix)) != _filter_accepts(e, prefix)
    ]
    assert not differ, f"(extra, accepted by the guest model) where the filter disagrees: {differ}"


def test_the_corpus_has_both_verdicts():
    """A corpus every address of which both refuse (or both accept) would prove nothing."""
    verdicts = {_model_accepts(e, p) for e in EXTRAS for p in ZONE_PREFIXES}
    assert verdicts == {True, False}
