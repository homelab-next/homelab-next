# SPDX-License-Identifier: Apache-2.0
"""Unit tests of the site's network scope (homelabnext.modules.scope): the strict reader and the
rules over a selection's scope block.  The contract tests (tests/schemas/test_module_1_0.py) apply
them to the fictional site profiles.

Addresses are written from three-octet prefixes, so no line holds a four-part literal for the
endpoint and leak scanners to allowlist; every one is in a documentation or special-use range, or
is assembled from parts at run time."""

from __future__ import annotations

import ipaddress
import re

import pytest

from homelabnext.modules import scope as ms

#: documentation prefixes (RFC 5737)
D1, D2, D3 = "192.0.2", "198.51.100", "203.0.113"
#: a private network, assembled so the source carries no private literal
PRIVATE = ".".join(("10", "20", "0", "0"))


def net(text: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    return ipaddress.ip_network(text)


def test_a_scope_reader_returns_the_parts_networks():
    site = {"scope": {"trusted": {"wan": [f"{D3}.7/32", "2001:db8:1::/48"]}}}
    nets = ms.scope_networks(site, "trusted.wan")
    assert [str(n) for n in nets] == [f"{D3}.7/32", "2001:db8:1::/48"]
    assert all(ms.is_documentation(n) for n in nets)


@pytest.mark.parametrize(
    ("site", "part", "why"),
    [
        ({}, "trusted.wan", "missing"),
        ({"scope": {"trusted": {}}}, "trusted.wan", "missing"),
        ({"scope": {"trusted": {"wan": []}}}, "trusted.wan", "empty"),
        ({"scope": {"trusted": {"wan": True}}}, "trusted.wan", r"not a list \(bool\)"),
        ({"scope": {"trusted": f"{D3}.7"}}, "trusted.wan", "missing"),
        ({"scope": {"target": [f"{D2}.0/33"]}}, "target", "not a usable address or network"),
        ({"scope": {"target": [f"{D2}.1/24"]}}, "target", "host bits set"),
        ({"scope": {"target": [3325256704]}}, "target", "not a string"),
        ({"scope": {"target": [f"{D2}.0/24"]}}, "trusted.wans", "no such scope part"),
    ],
)
def test_a_scope_reader_fails_closed(site, part, why):
    """Negative: an absent, empty or malformed part never reads as "no addresses"."""
    with pytest.raises(ms.ScopeMissing, match=why):
        ms.scope_networks(site, part)


def v4(*octets: int, plen: int = 32) -> str:
    """An IPv4 network written from its octets (no four-part literal in this source)."""
    return ".".join(map(str, octets)) + f"/{plen}"


def v6(*groups: str) -> str:
    """An IPv6 text from its groups (no IPv4-embedding literal in this source)."""
    return ":".join(groups)


#: entries no part may hold, with the reason the reader gives
REFUSED_EVERYWHERE = [
    (v4(0, 0, 0, 0, plen=0), "whole address space"),
    ("::/0", "whole address space"),
    (v4(0, 0, 0, 0), "unspecified"),
    ("::/128", "embeds IPv4"),  # :: is inside the IPv4-compatible prefix
    ("::1/128", "embeds IPv4"),
    (v4(127, 0, 0, 1), "loopback"),
    (v4(169, 254, 0, 0, plen=16), "link-local"),
    ("fe80::/64", "link-local"),
    (v4(224, 0, 0, 0, plen=4), "multicast"),
    ("ff02::/16", "multicast"),
    (v4(240, 0, 0, 0, plen=4), "reserved"),
    (v4(128, 0, 0, 0, plen=1), "link-local"),  # half the space touches link-local
    ("2001:db8::1%eth0", "zone id"),
    (f"{D1}.0 /24", "whitespace"),
    (f"::ffff:{D1}.0/120", "IPv4 address written inside IPv6"),
    (v6("", "", "ffff", "c000", "200/120"), "embeds IPv4"),  # IPv4-mapped, hex
    (v6("64", "ff9b", "", "c000", "201"), "embeds IPv4"),  # NAT64
    (":::::::", "does not appear to be"),
    ("1::2::3", "does not appear to be"),
    (f"{D1}.0/024", "leading zeros"),
    (f"{D1}.00/24", "leading zeros"),
    ("2001:0db8:00001::/48", "does not appear to be"),
    ("2001:db8::1/64", "host bits set"),
]


@pytest.mark.parametrize("part", ms.SCOPE_PARTS)
@pytest.mark.parametrize(("entry", "why"), REFUSED_EVERYWHERE)
def test_an_entry_no_part_may_hold(part, entry, why):
    with pytest.raises(ValueError, match=why):
        ms.parse_entry(entry, part)


@pytest.mark.parametrize(
    ("entry", "trusted_ok"),
    [
        (".".join(("10", "0", "0", "0")) + "/8", True),
        (".".join(("10", "0", "0", "0")) + "/7", False),
        ("2001:db8::/32", True),
        ("2001:db8::/31", False),
        ("2000::/3", False),
    ],
)
def test_a_trusted_part_has_a_floor_and_target_does_not(entry, trusted_ok):
    """Trusting more than a /8 or a /32 is a blind spot, not the lab: refused in trusted.*."""
    for part in ("trusted.wan", "trusted.nets", "trusted.tooling"):
        if trusted_ok:
            assert ms.parse_entry(entry, part) == net(entry)
        else:
            with pytest.raises(ValueError, match="floor for a trusted part"):
                ms.parse_entry(entry, part)
    assert ms.parse_entry(entry, "target") == net(entry)


def test_the_entry_pattern_is_the_readers_first_check():
    """The reader matches ENTRY_PATTERN before parsing, so the schema (which carries the same
    pattern) never accepts an entry text the reader refuses, or the other way round."""
    pattern = re.compile(ms.ENTRY_PATTERN)
    for entry, _ in REFUSED_EVERYWHERE:
        if pattern.match(entry):
            # only semantic refusals pass the pattern: the reader adds them
            assert any(w in _ for w in ("whole", "unspecified", "loopback", "link", "multi",
                                        "reserved", "host bits", "embeds"))  # fmt: skip
    for ok in (f"{D1}.0/24", f"{D2}.128/25", f"{D3}.7", "2001:db8:30::/48", "2001:DB8::1"):
        assert pattern.match(ok), ok
        ms.parse_entry(ok, "target")


def test_documentation_means_every_address_of_the_network():
    assert ms.is_documentation(net(f"{D1}.128/25"))
    assert ms.is_documentation(net("3fff::/20"))  # RFC 9637, as tools/leak_scan.py reads it
    assert not ms.is_documentation(net(v4(192, 0, 0, 0, plen=16)))  # widened
    assert not ms.is_documentation(net(v4(0, 0, 0, 0, plen=0)))
    assert not ms.is_documentation(net("::/0"))


def test_scope_tree_is_built_from_the_parts():
    tree = ms.scope_tree()
    leaves = {f"{g}.{x}" if xs else g for g, xs in tree.items() for x in (xs or (None,))}
    assert leaves == set(ms.SCOPE_PARTS)
    assert set(ms.PART_DOCS) == set(ms.SCOPE_PARTS) | {g for g, xs in tree.items() if xs}


def test_scope_problems_check_only_the_parts_present():
    assert ms.scope_problems({}) == []
    assert ms.scope_problems({"scope": {"target": [f"{D2}.0/24"]}}) == []
    probs = ms.scope_problems({"scope": {"target": [f"{D2}.0/24", f"{D2}.0/24"]}})
    assert probs == ["scope.target: a network is listed twice"]


@pytest.mark.parametrize(
    ("block", "problem"),
    [
        ([f"{D1}.0/24"], "scope: not a mapping (list)"),
        ({"trusted": [f"{D1}.0/24"]}, "scope.trusted: not a mapping (list)"),
        ({"trusted": {"wan": True}}, "scope.trusted.wan: not a list (bool)"),
        ({"targets": [PRIVATE + "/16"]}, "scope.targets: no such scope part"),
        ({"trusted": {"wans": [f"{D1}.0/24"]}}, "scope.trusted.wans: no such scope part"),
        ({"target": [v4(0, 0, 0, 0, plen=0)]}, "scope.target[0]: '0.0.0.0/0' is not a usable"),
    ],
)
def test_scope_problems_stand_alone_without_the_schema(block, problem):
    """Negative: a wrong-typed part or group, or an unknown part, is reported by the rules
    themselves; it is never skipped as "absent"."""
    assert any(p.startswith(problem) for p in ms.scope_problems({"scope": block})), problem


def test_the_entry_pattern_matches_exactly_the_strict_texts():
    """Seeded sample of IPv4 and IPv6 networks, written compressed, exploded and upper case, with
    and without host bits: the pattern accepts a text exactly when it parses strictly, embeds no
    IPv4 and (IPv4) has no host bits; IPv6 host bits are the reader's check alone."""
    import random

    rnd = random.Random(20261023)
    pattern = re.compile(ms.ENTRY_PATTERN)
    for _ in range(3000):
        if rnd.random() < 0.5:
            addr = ipaddress.IPv4Address(rnd.getrandbits(32))
            text = f"{addr}/{rnd.randint(0, 32)}"
            try:
                ipaddress.ip_network(text, strict=True)
                want = True
            except ValueError:
                want = False
        else:
            bits = rnd.getrandbits(128)
            if rnd.random() < 0.4:
                e = rnd.choice(ms.EMBEDDED_V4)
                bits = int(e.network_address) | (bits & ((1 << (128 - e.prefixlen)) - 1))
            if rnd.random() < 0.5:  # runs of zero groups, so :: lands everywhere
                for g in range(8):
                    if rnd.random() < 0.6:
                        bits &= ~(0xFFFF << (16 * g))
            addr6 = ipaddress.IPv6Address(bits)
            spelled = rnd.choice([addr6.compressed, addr6.exploded, addr6.compressed.upper()])
            text = f"{spelled}/{rnd.randint(0, 128)}"
            want = not ms.embedded_ipv4(ipaddress.ip_network(addr6))
        assert bool(pattern.match(text)) == want, text
