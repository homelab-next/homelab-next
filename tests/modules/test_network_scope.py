# SPDX-License-Identifier: Apache-2.0
"""Unit tests of the site's network scope (homelabnext.modules.scope): the strict reader and the
rules over a selection's scope block.  The contract tests (tests/schemas/test_module_1_0.py) apply
them to the fictional site profiles.

Addresses are written from three-octet prefixes, so no line holds a four-part literal for the
endpoint and leak scanners to allowlist; every one is in a documentation or special-use range, or
is assembled from parts at run time."""

from __future__ import annotations

import ipaddress
import json
import re
from pathlib import Path

import pytest

from homelabnext.modules import scope as ms

ROOT = Path(__file__).resolve().parents[2]

#: documentation prefixes (RFC 5737)
D1, D2, D3 = "192.0.2", "198.51.100", "203.0.113"
#: a private network, assembled so the source carries no private literal
PRIVATE = ".".join(("10", "20", "0", "0"))


#: a module that declares every part (the reader refuses an undeclared one)
EVERY = {"id": "m", "requires": {"scope": [{"part": p} for p in ms.SCOPE_PARTS]}}


def net(text: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    return ipaddress.ip_network(text)


def test_a_scope_reader_returns_the_parts_networks():
    site = {"scope": {"trusted": {"wan": [f"{D3}.7/32", "2001:db8:1::/48"]}}}
    nets = ms.scope_networks(site, EVERY, "trusted.wan")
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
        ms.scope_networks(site, EVERY, part)


def v4(*octets: int, plen: int = 32) -> str:
    """An IPv4 network written from its octets (no four-part literal in this source)."""
    return ".".join(map(str, octets)) + f"/{plen}"


def v6(*groups: str) -> str:
    """An IPv6 text from its groups (no IPv4-embedding literal in this source)."""
    return ":".join(groups)


def test_an_exclusion_may_be_explicitly_empty_and_nothing_else_may():
    """S3: an explicit [] means "nothing excluded" for an exclusion only; an absent exclusion
    still fails closed, and an empty trusted part or target is still refused."""
    site = {"scope": {"exclude": {"offensive": [], "unattended_mutation": []}, "target": []}}
    assert ms.scope_networks(site, EVERY, "exclude.offensive") == []
    assert ms.scope_networks(site, EVERY, "exclude.unattended_mutation") == []
    with pytest.raises(ms.ScopeMissing, match="only an exclusion may be an explicit"):
        ms.scope_networks(site, EVERY, "target")
    with pytest.raises(ms.ScopeMissing, match="missing"):
        ms.scope_networks({"scope": {"target": [f"{D2}.0/24"]}}, EVERY, "exclude.offensive")


def test_a_dynamic_wan_source_is_specified_and_refused():
    site = {"scope": {"trusted": {"wan": [{"source": "wan-dhcp"}], "nets": [{"source": "x"}]}}}
    with pytest.raises(ms.ScopeMissing, match="dynamic WAN sources are specified, not implemented"):
        ms.scope_networks(site, EVERY, "trusted.wan")
    with pytest.raises(ms.ScopeMissing, match=r"not a string \(dict\)"):
        ms.scope_networks(site, EVERY, "trusted.nets")  # only trusted.wan has a dynamic form
    assert set(ms.SCOPE_PARTS) >= ms.DYNAMIC_PARTS
    assert set(ms.SCOPE_PARTS) >= ms.EMPTY_ALLOWED


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
        if part == "trusted.wan" and entry.startswith("10."):
            continue  # private space: trusted.wan refuses it for that reason (N8, below)
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
        (
            {"target": [v4(0, 0, 0, 0, plen=0)]},
            f"scope.target[0]: '{v4(0, 0, 0, 0, plen=0)}' is not",
        ),
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


def reader(*parts: str, unattended: bool = False) -> dict:
    m = {"id": "assess", "requires": {"scope": [{"part": p} for p in parts]}}
    if unattended:
        m["contributes"] = {"scheduler_jobs": [{"timer": "timer:assess/nightly"}]}
    return m


def test_a_module_reads_only_the_parts_it_declared():
    """S5: requires.scope is an access list.  Reading an undeclared part raises (a subclass of
    ScopeMissing, so a reader that fails closed on a missing part fails closed here too)."""
    site = {"scope": {"trusted": {"wan": [f"{D3}.7/32"]}, "target": [f"{D2}.0/24"]}}
    collector = reader("trusted.wan")
    assert ms.scope_networks(site, collector, "trusted.wan") == [net(f"{D3}.7/32")]
    with pytest.raises(ms.ScopeUndeclared, match=r"assess: reads scope\.target"):
        ms.scope_networks(site, collector, "target")
    assert issubclass(ms.ScopeUndeclared, ms.ScopeMissing)


SITE = {
    "scope": {
        "target": [f"{D1}.0/24", f"{D2}.0/24", "2001:db8:30::/48"],
        "exclude": {
            "offensive": [f"{D1}.0/28", f"{D2}.128/25", "2001:db8:30:1::/64"],
            "unattended_mutation": [f"{D1}.16/28"],
        },
    }
}


def test_effective_targets_subtract_the_exclusions():
    """S4: an exclusion inside target is subtracted, per IP version."""
    got = ms.effective_targets(SITE, reader("target", "exclude.offensive"))
    left = {str(n) for n in got}
    for excluded in (f"{D1}.1", f"{D1}.15", f"{D2}.128", f"{D2}.255", "2001:db8:30:1::1"):
        assert not any(ipaddress.ip_address(excluded) in n for n in got), excluded
    for kept in (f"{D1}.16", f"{D1}.255", f"{D2}.0", f"{D2}.127", "2001:db8:30:2::1"):
        assert any(ipaddress.ip_address(kept) in n for n in got), kept
    assert f"{D2}.0/25" in left


def test_an_unattended_module_also_subtracts_the_mutation_exclusion():
    assert any(
        ipaddress.ip_address(f"{D1}.17") in n
        for n in ms.effective_targets(SITE, reader("target", "exclude.offensive"))
    )
    got = ms.effective_targets(
        SITE, reader("target", "exclude.offensive", "exclude.unattended_mutation", unattended=True)
    )
    assert not any(ipaddress.ip_address(f"{D1}.17") in n for n in got)


@pytest.mark.parametrize(
    "module",
    [
        reader("target"),
        reader("exclude.offensive"),
        reader("target", "exclude.offensive", unattended=True),
    ],
)
def test_effective_targets_needs_every_part_it_subtracts_declared(module):
    with pytest.raises(ms.ScopeUndeclared):
        ms.effective_targets(SITE, module)


@pytest.mark.parametrize("excluded", [f"{D2}.0/24", f"{D2}.0/23"])
def test_effective_targets_never_returns_an_empty_list(excluded):
    """SF4: exclusions that cover every target leave nothing to act on: that raises (fails
    closed) instead of returning [], which a caller could read as "unrestricted"."""
    site = {"scope": {"target": [f"{D2}.0/24"], "exclude": {"offensive": [excluded]}}}
    with pytest.raises(ms.ScopeMissing, match="nothing left after the exclusions"):
        ms.effective_targets(site, reader("target", "exclude.offensive"))


def test_effective_targets_fails_closed_on_an_absent_exclusion_and_takes_an_empty_one():
    site = {"scope": {"target": [f"{D2}.0/24"]}}
    with pytest.raises(ms.ScopeMissing, match=r"exclude\.offensive: missing"):
        ms.effective_targets(site, reader("target", "exclude.offensive"))
    site["scope"]["exclude"] = {"offensive": []}
    assert ms.effective_targets(site, reader("target", "exclude.offensive")) == [net(f"{D2}.0/24")]


def test_an_ipv6_written_exclusion_of_an_ipv4_range_fails_closed():
    """S4: in ipaddress an IPv4 target is never inside an IPv6 network, so a mapped or NAT64
    exclusion would subtract nothing.  It is refused, never silently ignored."""
    for written in (v6("", "", "ffff", "c000", "200/120"), v6("64", "ff9b", "", "c000", "200/120")):
        site = {"scope": {"target": [f"{D1}.0/24"], "exclude": {"offensive": [written]}}}
        with pytest.raises(ms.ScopeMissing, match="embeds IPv4"):
            ms.effective_targets(site, reader("target", "exclude.offensive"))


@pytest.mark.parametrize(
    ("parts", "unattended", "missing"),
    [
        (("target",), False, ["exclude.offensive"]),
        (("target", "exclude.offensive"), False, []),
        (("target", "exclude.offensive"), True, ["exclude.unattended_mutation"]),
        (("target",), True, ["exclude.offensive", "exclude.unattended_mutation"]),
        # SF3: every address part, not target alone (the manifest cannot say "only filters")
        (("trusted.wan",), True, ["exclude.offensive", "exclude.unattended_mutation"]),
        (("trusted.nets",), True, ["exclude.offensive", "exclude.unattended_mutation"]),
        (("trusted.tooling",), False, ["exclude.offensive"]),
        (("exclude.offensive",), True, []),
    ],
)
def test_a_module_reading_addresses_must_declare_the_exclusions(parts, unattended, missing):
    problems = ms.manifest_scope_problems(reader(*parts, unattended=unattended))
    assert [p.split(" without ", 1)[1].split(" ", 1)[0] for p in problems] == missing


#: a module contributing one entry of a kind, for every kind platform/module 1.0 declares
CONTRIBUTION_KINDS = sorted(
    json.loads((ROOT / "schemas/platform/module.schema.json").read_text())["$defs"]["contributes"][
        "properties"
    ]
)


def test_every_contribution_kind_is_classified():
    """The inert set names real kinds only; every other kind (and any kind added later) counts as
    something that can run unattended."""
    assert set(CONTRIBUTION_KINDS) >= ms.INERT_CONTRIBUTIONS
    for kind in ("services", "workflow_packs", "mcp_servers", "invariants", "entry_points",
                 "preflight", "scheduler_jobs", "agents", "roles", "shared_config"):  # fmt: skip
        assert kind in CONTRIBUTION_KINDS and kind not in ms.INERT_CONTRIBUTIONS, kind


@pytest.mark.parametrize("kind", CONTRIBUTION_KINDS)
def test_a_module_runs_unattended_unless_it_contributes_only_inert_kinds(kind):
    """SF3: inverted, fail closed.  A service, a workflow pack, an MCP server, an invariant, an
    entry point, a preflight hook, a role and every agent can run with no human present."""
    module = {"contributes": {kind: [{"file": "x"}]}}
    assert ms.runs_unattended(module) is (kind not in ms.INERT_CONTRIBUTIONS)
    if kind not in ms.INERT_CONTRIBUTIONS:
        scanner = reader("target", "exclude.offensive") | module
        assert ms.manifest_scope_problems(scanner), kind  # needs exclude.unattended_mutation


def test_a_module_with_nothing_executable_is_attended():
    assert not ms.runs_unattended({})
    assert not ms.runs_unattended({"contributes": {}})
    assert not ms.runs_unattended({"contributes": {"docs": [{"file": "d.md"}], "services": []}})
    assert ms.runs_unattended({"contributes": "not a mapping"})  # malformed is not "attended"
    for not_a_list in (None, {}, "x", 0):  # only an explicit [] declares "nothing"
        assert ms.runs_unattended({"contributes": {"services": not_a_list}}), not_a_list
    agent = {"key": "assess-analyst"}
    assert ms.runs_unattended({"contributes": {"agents": [agent]}})


def test_a_part_less_scope_requirement_is_a_problem_not_a_crash():
    """N7: the rules stand alone without the schema (which requires part)."""
    module = {"id": "m", "requires": {"scope": [{"purpose": "x"}, "target", {"part": "target"}]}}
    assert ms.declared_parts(module) == {"target"}
    problems = ms.manifest_scope_problems(module)
    assert [p.split(":", 1)[0] for p in problems[:2]] == [
        "requires.scope[0]",
        "requires.scope[1]",
    ]
    assert ms.declared_parts({"requires": None}) == set()


#: a public resolver and a public host, assembled at run time
RESOLVER = ".".join(("9",) * 4)
LAB_HOST = ".".join(("10", "20", "0", "1"))
GLOBAL_V6 = ":".join(("2a00", "1450", "", "1"))


@pytest.mark.parametrize(
    "value",
    [
        v4(0, 0, 0, 0).removesuffix("/32"),  # bind all
        v4(127, 0, 0, 1).removesuffix("/32"),
        "::",
        "::1",
        "[::]:8080",
        v4(0, 0, 0, 0).removesuffix("/32") + ":8080",
        ".".join("2104"),  # a version: a bare global dotted quad is never refused
        ".".join("1234") + "-beta",
        "v" + ".".join("2104"),
        "cafe::beef",
        "a::b",
        "12:30:45",
        ":".join(("fe80", "", "1%eth0")),
        f"{D1}.10",  # documentation
        "2001:db8::1",
        RESOLVER,  # bare: indistinguishable from a version (documented)
        "1700000000",  # a number (a global address only as an integer)
        "0x1f",
        "eu-west",
        ":".join(("collector.example.internal", "443")),
    ],
)
def test_a_config_value_that_is_not_a_site_address_is_kept(value):
    """S7: bind and listen addresses, versions, labels and numbers are legitimate config."""
    assert ms.address_literals(value) == []


@pytest.mark.parametrize(
    "value",
    [
        LAB_HOST,
        f"{LAB_HOST}:8080",
        f"svc:{LAB_HOST}",
        f"udp://{RESOLVER}:53",  # an external endpoint is a hostname or a svc: reference
        f"{RESOLVER}:53",
        f"{RESOLVER}/32",
        "010.020.000.001",  # zero-padded (inet_aton reads octal)
        "0x0a000001",  # hex integer
        "0x0a.0.0.1",  # hex dotted
        "3232235777",  # an integer naming a private address
        ":".join(("fd00", "", "1")),  # unique local
        GLOBAL_V6,
        f"http://[{GLOBAL_V6}]:80/x",
    ],
)
def test_a_config_value_naming_a_site_address_is_refused(value):
    """S7: an address in any spelling, outside the special and documentation blocks."""
    assert ms.address_literals(value), value


#: inet_aton short forms of private addresses (the octets 10, 20, 0, 5; 10, 0, 0, 1; 172, 16, 0, 1)
SHORT3 = ".".join(("10", "20", "5"))
SHORT2 = ".".join(("10", "1"))
SHORT_SHARED = ".".join(("172", "16", "1"))


@pytest.mark.parametrize(
    "value",
    [
        f"http://{SHORT3}/",
        f"{SHORT3}:8080",
        f"http://{SHORT2}/",
        f"udp://{SHORT_SHARED}:53",
        f"{SHORT2}/8",
        f"https://user@{SHORT3}/x",
    ],
)
def test_an_inet_aton_short_form_in_an_address_context_is_refused(value):
    """SF5: glibc and curl read a three-part 10.20.5 as the octets 10, 20, 0, 5; with a URL, a port or a prefix length it is
    an address, never a version."""
    assert ms.address_literals(value), value


@pytest.mark.parametrize("value", ["1.2", "2.1.0", SHORT3, "v1.2:3", f"http://{D1}.7/"])
def test_a_plain_short_form_is_a_version(value):
    assert ms.address_literals(value) == []


@pytest.mark.parametrize(
    "parts",
    [("10", "0", "0", "0", "8"), ("172", "16", "0", "0", "12"), ("100", "64", "0", "0", "10")],
)
def test_trusted_wan_refuses_private_and_shared_space(parts):
    """N8: the WAN is what the internet sees; an internal network there belongs in trusted.nets."""
    entry = ".".join(parts[:4]) + "/" + parts[4]
    with pytest.raises(ValueError, match="private, shared or unique-local"):
        ms.parse_entry(entry, "trusted.wan")
    assert ms.parse_entry(entry, "trusted.nets") == net(entry)
    with pytest.raises(ValueError, match="private, shared or unique-local"):
        ms.parse_entry(":".join(("fd00", "1", "")) + ":/48", "trusted.wan")
    assert ms.parse_entry(f"{D3}.0/24", "trusted.wan") == net(f"{D3}.0/24")
