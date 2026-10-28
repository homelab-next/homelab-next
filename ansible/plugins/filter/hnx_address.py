# SPDX-License-Identifier: Apache-2.0
"""Address checks for roles that put guests' addresses into a product's configuration.

    {{ suricata_enroll_guests | hnx_enroll_address_problems }}

returns one message per problem (an empty list when the rows are sound), so a role's assert can
name every bad entry at once.  ``{{ addresses | hnx_rule_prefix6_problems }}`` does the same for
every firewall-rule address (``hnx_firewall``) that is neither ``any`` nor an IPv4 CIDR: it must
be a well-formed IPv6 prefix by the ``subnet6`` rule below (a unique-local or global-unicast /48 to
/64).  That is all a role can prove from one rule; that the prefix is a zone's is the generator's
doing (it resolves ``zone:`` to the zone's ``subnet6``, ``homelabnext/compute/gen/firewall_rules.py``),
so a hand-written rule names no wider or odder IPv6 network than a zone could have.

A row of guests is ``{name, ip, zone, extra_addresses?, subnet?, subnet6?}`` as the baseline
playbook writes it (``homelabnext/compute/gen/baseline_playbook.py``): ``subnet``
is the guest's zone's IPv4 subnet, carried in every row that names ``extra_addresses``, and
``subnet6`` its IPv6 prefix (site 1.4), carried too when the zone gives one.

The addresses are parsed, never pattern-matched, and held to the guest model's own rules
(``homelabnext/compute/validate.py``) so far as one row can show them, so a hand-written
inventory gets no further than the generator's rows on what follows.  A row carries one zone's
``subnet`` and ``subnet6`` and nothing else of the site, so three refusals of the guest model are
NOT made here, and a role's own assert must not be read as making them: an IPv4 extra address that
is the zone's gateway, or inside its DHCP pool (the row has neither), and an IPv6 one inside
another zone's prefix (the row names no other zone: a row without ``subnet6`` accepts any
unique-local or documentation address).  Those stay the generator's, which refuses them before a
row exists:

* every address is in its canonical form (IPv4 dotted quad without leading zeros, IPv6 lower case
  and compressed, with no zone id ``%scope``), and never loopback, unspecified, multicast, reserved, link-local, this-network
  (0.0.0.0/8) or a cloud metadata address;
* ``ip`` is IPv4, and inside ``subnet`` when the row gives one;
* ``subnet`` is a canonical IPv4 network of /8 to /30 that holds ``ip``; one that reaches beyond
  private, shared (CGNAT) and documentation space is no wider than /24;
* an IPv4 extra address is inside ``subnet`` (never its network or broadcast address) or in the
  shared range a zone-less overlay such as a tailnet uses; a row without ``subnet`` (hand-written)
  may name only private, shared or documentation addresses;
* ``subnet6`` is a canonical IPv6 prefix (no zone id) of /48 to /64 from the space zones are numbered from
  (unique-local, or global unicast less the IETF protocol assignments 2001::/23, the retired 6bone
  3ffe::/16 and the reserved 2000::/16), never one that
  writes IPv4 inside IPv6 (mapped, compatible, translated, NAT64, 6to4, Teredo);
* an IPv6 extra address never writes around an IPv4 one and is never an anycast address of its /64
  (the subnet-router one, with no host part, or one RFC 2526 reserves at its top); it is inside
  ``subnet6`` when the row gives one, and otherwise unique-local or documentation, since there is
  no prefix to hold a global one against.

Standard library only (the controller needs nothing beyond Ansible).
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable, Mapping
from typing import Any

Address = ipaddress.IPv4Address | ipaddress.IPv6Address


def _v4(value: int, plen: int) -> ipaddress.IPv4Network:
    return ipaddress.IPv4Network((value, plen))


def _v6(groups: Iterable[int], plen: int) -> ipaddress.IPv6Network:
    value = 0
    for i, g in enumerate(groups):
        value |= g << (16 * (7 - i))
    return ipaddress.IPv6Network((value, plen))


#: written as integers so no address literal sits in the tree (the leak scan)
PRIVATE_V4 = (_v4(0x0A00_0000, 8), _v4(0xAC10_0000, 12), _v4(0xC0A8_0000, 16))
SHARED_V4 = _v4(0x6440_0000, 10)  # RFC 6598: CGNAT, and the overlay range tailnets use
DOC_V4 = (_v4(0xC000_0200, 24), _v4(0xC633_6400, 24), _v4(0xCB00_7100, 24))
NOT_INTERNET_V4 = (*PRIVATE_V4, SHARED_V4, *DOC_V4)
OWNABLE_V6 = (
    _v6((0xFC00,), 7),  # unique-local
    _v6((0x2001, 0x0DB8), 32),  # documentation
    _v6((0x3FFF,), 20),  # documentation
)
EMBEDDED_V4 = (
    _v6((), 96),  # IPv4-compatible
    _v6((0, 0, 0, 0, 0, 0xFFFF), 96),  # IPv4-mapped
    _v6((0, 0, 0, 0, 0xFFFF), 96),  # IPv4-translated
    _v6((0x64, 0xFF9B), 96),  # NAT64, well-known
    _v6((0x64, 0xFF9B, 1), 48),  # NAT64, local use
)
#: the space a zone's IPv6 prefix is numbered from, less the IETF protocol assignments
ZONE_V6 = (_v6((0xFC00,), 7), _v6((0x2000,), 3))
SPECIAL_V6 = (_v6((0x2001,), 23), _v6((0x3FFE,), 16), _v6((0x2000,), 16))  # IETF, 6bone, reserved
PREFIX_EMBEDS_V4 = (*EMBEDDED_V4, _v6((0x2002,), 16), _v6((0x2001, 0), 32))  # ... 6to4, Teredo
#: RFC 2526's reserved subnet anycast interface identifiers, the top 128 of a /64: written in
#: EUI-64 form (the identifier starts 0xfdff) and in the form a non-EUI-64 identifier takes (all ones)
ANYCAST_EUI64 = 0xFDFF_FFFF_FFFF_FF80
ANYCAST_TOP = 0xFFFF_FFFF_FFFF_FF80
METADATA = frozenset(
    {
        ipaddress.IPv4Address(0xA9FE_A9FE),
        ipaddress.IPv4Address(0xA9FE_AA02),
        ipaddress.IPv4Address(0xC000_00C0),
        ipaddress.IPv4Address(0x6464_64C8),
        _v6((0xFD00, 0x0EC2, 0, 0, 0, 0, 0, 0x0254), 128).network_address,
    }
)


def _address(raw: Any) -> tuple[Address | None, str | None]:
    """The parsed address, or why ``raw`` is not one this module accepts anywhere."""
    if not isinstance(raw, str):
        return None, "is not a string"
    if "%" in raw:
        return None, "names an IPv6 zone id (%scope), which is a link, not part of an address"
    try:
        ip = ipaddress.ip_address(raw)
    except ValueError:
        return None, "is not an IP address"
    if ip in METADATA:
        return None, "is a cloud metadata address"
    if ip.is_loopback or ip.is_unspecified:
        return None, "is a loopback or unspecified address"
    if isinstance(ip, ipaddress.IPv6Address) and any(ip in n for n in EMBEDDED_V4):
        return None, "writes an IPv4 address inside IPv6; write the IPv4 address"
    if ip.is_multicast or ip.is_reserved:
        return None, "is a multicast or reserved address"
    if ip.is_link_local:
        return None, "is link-local"
    if str(ip) != raw:
        return None, f"is not in its canonical form ({ip})"
    if isinstance(ip, ipaddress.IPv4Address) and int(ip) >> 24 == 0:
        return None, "is in this-network (0.0.0.0/8)"
    return ip, None


def _subnet(raw: Any, ip: Address | None) -> tuple[ipaddress.IPv4Network | None, str | None]:
    if not isinstance(raw, str):
        return None, "is not a string"
    try:
        net = ipaddress.IPv4Network(raw)  # strict: no host bits
    except ValueError:
        return None, "is not an IPv4 network without host bits"
    if str(net) != raw:
        return None, f"is not in its canonical form ({net})"
    if not 8 <= net.prefixlen <= 30:
        return None, "is not a /8 to /30"
    if not any(net.subnet_of(n) for n in NOT_INTERNET_V4) and net.prefixlen < 24:
        return None, "reaches beyond private, shared and documentation space and is wider than /24"
    if ip is not None and ip not in net:
        return None, f"does not hold the guest's ip {ip}"
    return net, None


def _subnet6(raw: Any) -> tuple[ipaddress.IPv6Network | None, str | None]:
    if not isinstance(raw, str):
        return None, "is not a string"
    if "%" in raw:
        return None, "names an IPv6 zone id (%scope), which a prefix never carries"
    try:
        net = ipaddress.IPv6Network(raw)  # strict: no host bits
    except ValueError:
        return None, "is not an IPv6 prefix without host bits"
    if str(net) != raw:
        return None, f"is not in its canonical form ({net})"
    if not 48 <= net.prefixlen <= 64:
        return None, "is not a /48 to /64"
    if any(net.overlaps(n) for n in PREFIX_EMBEDS_V4):
        return None, "writes IPv4 addresses inside IPv6 (mapped, NAT64, 6to4, Teredo and the like)"
    if any(net.subnet_of(s) for s in SPECIAL_V6) or not any(net.subnet_of(n) for n in ZONE_V6):
        return None, (
            "is not unique-local or global unicast space (less the IETF protocol assignments "
            "2001::/23, the retired 6bone 3ffe::/16 and the reserved 2000::/16)"
        )
    return net, None


def _extra6(ip: ipaddress.IPv6Address, net6: ipaddress.IPv6Network | None) -> str | None:
    iid = int(ip) & (1 << 64) - 1  # the interface identifier: the low 64 bits
    if iid == 0:
        return "is the subnet-router anycast address of its /64 (no host part)"
    if iid >= ANYCAST_EUI64 and (iid <= ANYCAST_EUI64 | 0x7F or iid >= ANYCAST_TOP):
        return "is an anycast address RFC 2526 reserves at the top of its /64"
    if net6 is not None:
        if ip not in net6:
            return f"is outside the zone's IPv6 prefix {net6}"
        if ip == net6[1]:  # the router's address there (homelabnext.network.ir.router_address6)
            return f"is the router's address in the zone's IPv6 prefix {net6} (its ::1)"
        return None
    if any(ip in n for n in OWNABLE_V6):
        return None
    return (
        "is a global or special-purpose IPv6 address, not a unique-local or documentation one, "
        "and the row gives no IPv6 prefix (subnet6) to hold it against"
    )


def _extra(
    ip: Address, net: ipaddress.IPv4Network | None, net6: ipaddress.IPv6Network | None
) -> str | None:
    """Why an otherwise sound extra address is not this guest's to name, else None."""
    if isinstance(ip, ipaddress.IPv6Address):
        return _extra6(ip, net6)
    if net is not None:
        if ip in (net.network_address, net.broadcast_address):
            return f"is the network or broadcast address of the zone subnet {net}"
        if ip in net or ip in SHARED_V4:
            return None
        return f"is outside the zone subnet {net} (and outside the shared range)"
    if any(ip in n for n in NOT_INTERNET_V4):
        return None
    return "is outside private, shared and documentation space (the row gives no zone subnet)"


def enroll_address_problems(guests: Any) -> list[str]:
    """Every problem with the addresses of ``<role>_guests`` rows, one message each."""
    if not isinstance(guests, list):
        return ["the guests are not a list"]
    out: list[str] = []
    for n, row in enumerate(guests):
        if not isinstance(row, Mapping):
            out.append(f"guest #{n} is not a mapping")
            continue
        who = f"guest {row.get('name', '#' + str(n))}"
        ip, why = _address(row.get("ip"))
        if ip is not None and not isinstance(ip, ipaddress.IPv4Address):
            ip, why = None, "is not IPv4"
        if why:
            out.append(f"{who}: ip {row.get('ip')!r} {why}")
        net: ipaddress.IPv4Network | None = None
        if "subnet" in row:
            net, why = _subnet(row["subnet"], ip)
            if why:
                out.append(f"{who}: subnet {row['subnet']!r} {why}")
        net6: ipaddress.IPv6Network | None = None
        if "subnet6" in row:
            net6, why = _subnet6(row["subnet6"])
            if why:
                out.append(f"{who}: subnet6 {row['subnet6']!r} {why}")
        extras = row.get("extra_addresses", [])
        if not isinstance(extras, list):
            out.append(f"{who}: extra_addresses is not a list")
            continue
        for raw in extras:
            extra, why = _address(raw)
            if extra is not None:
                v6 = isinstance(extra, ipaddress.IPv6Address)
                if "subnet" in row and net is None:  # as validation: no address of a bad zone
                    why = "cannot be held against the row's unusable subnet"
                elif v6 and "subnet6" in row and net6 is None:
                    why = "cannot be held against the row's unusable subnet6"
                else:
                    why = _extra(extra, net, net6)
            if why:
                out.append(f"{who}: extra address {raw!r} {why}")
    return out


_V4_CIDR = re.compile(r"[0-9]{1,3}(?:\.[0-9]{1,3}){3}/[0-9]{1,2}\Z")


def rule_prefix6_problems(addresses: Any) -> list[str]:
    """One message per firewall-rule address that is neither ``any`` nor shaped as an IPv4 CIDR
    (the role's own pattern judges those) and is not a well-formed IPv6 prefix by the ``subnet6``
    rule; so ``10/8`` or ``abc/8`` is refused here as well as by the pattern."""
    if not isinstance(addresses, list):
        return ["the rule addresses are not a list"]
    out = []
    for raw in addresses:
        if isinstance(raw, str) and (raw == "any" or _V4_CIDR.match(raw)):
            continue
        _, why = _subnet6(raw)
        if why:
            out.append(f"rule address {raw!r} {why}")
    return out


class FilterModule:
    def filters(self) -> dict[str, Any]:
        return {
            "hnx_enroll_address_problems": enroll_address_problems,
            "hnx_rule_prefix6_problems": rule_prefix6_problems,
        }
