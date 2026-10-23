# SPDX-License-Identifier: Apache-2.0
"""The site's network scope (docs/modules.md, "The network scope"): its parts, the strict reader
and the rules over a selection's ``scope:`` block.

A neutral module: the schema generator (:mod:`homelabnext.schemas.module_manifest`), the loader
rules (:mod:`homelabnext.modules.rules`) and the public leak check (``tools/private_leak_check.py``)
all import it, and it imports nothing of theirs.

One source of truth.  :data:`SCOPE_PARTS` is the list of parts; the selection schema's ``scope``
object is generated from it (:func:`scope_tree`, :data:`PART_DOCS`), and a scope entry's text is
matched by one pattern (:data:`ENTRY_PATTERN`) in both the schema and :func:`parse_entry`, so the
two can never disagree on what an entry may look like.  The schema is the shape; the reader adds
what a pattern cannot say (IPv6 host bits, special-use and over-broad networks, duplicates).
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any

from homelabnext.ids.lint import DOCUMENTATION_NETS

Doc = dict[str, Any]

__all__ = [
    "DYNAMIC_PARTS",
    "EMBEDDED_V4",
    "EMPTY_ALLOWED",
    "ENTRY_PATTERN",
    "PART_DOCS",
    "SCOPE_PARTS",
    "TRUSTED_FLOOR",
    "Network",
    "ScopeMissing",
    "ScopeUndeclared",
    "declared_parts",
    "effective_targets",
    "embedded_ipv4",
    "is_documentation",
    "manifest_scope_problems",
    "parse_entry",
    "runs_unattended",
    "scope_networks",
    "scope_problems",
    "scope_tree",
]

#: the parts of a selection's scope block, as a module's requires.scope names them
SCOPE_PARTS = (
    "trusted.wan",
    "trusted.nets",
    "trusted.tooling",
    "target",
    "exclude.unattended_mutation",
    "exclude.offensive",
)
#: what each part (and each group of parts) means: the selection schema's descriptions
PART_DOCS = {
    "trusted": "Addresses that are the lab itself: never reported as an outsider.",
    "trusted.wan": "The lab's own public addresses: what the internet sees the lab as.",
    "trusted.nets": "The lab's own internal networks.",
    "trusted.tooling": "Where the operator's own tooling runs from (scanners, jump hosts, CI runners).",
    "target": "What the lab's assessment tooling may touch.",
    "exclude": "Carve-outs every reader honours, whatever else names the address.",
    "exclude.unattended_mutation": "Never changed by an unattended job: a human approves each change.",
    "exclude.offensive": "Never the target of offensive tooling, even inside target.",
}
#: parts an explicit empty list may fill, meaning "nothing excluded"; every other part is a
#: non-empty list, and an absent part is always refused when a module requires it
EMPTY_ALLOWED = frozenset({"exclude.unattended_mutation", "exclude.offensive"})
#: parts that may also name a dynamic source (``{source: <name>}``) instead of a literal network:
#: a WAN address from DHCP, CGNAT or a delegated IPv6 prefix that changes.  The shape is
#: specified so freezing the schema later is not a breaking change; no reader exists yet, so the
#: rules refuse it (docs/modules.md, "Specified, not implemented").
DYNAMIC_PARTS = frozenset({"trusted.wan"})
#: the broadest network a trusted part may hold, per IP version: trusting more than a /8 (IPv4)
#: or a /32 (IPv6, one regional allocation) is no longer "the lab itself", it is a blind spot
TRUSTED_FLOOR = {4: 8, 6: 32}
Network = ipaddress.IPv4Network | ipaddress.IPv6Network

#: networks no scope part may touch: unspecified and "this network", loopback, link-local,
#: multicast and the reserved block (broadcast included)
SPECIAL_NETS: tuple[tuple[str, Network], ...] = tuple(
    (why, ipaddress.ip_network(n))
    for why, n in (
        ("unspecified or 'this network'", (0x0000_0000, 8)),  # 0/8
        ("loopback", (0x7F00_0000, 8)),  # 127/8
        ("link-local", (0xA9FE_0000, 16)),  # 169.254/16
        ("multicast", (0xE000_0000, 4)),  # 224/4
        ("reserved", (0xF000_0000, 4)),  # 240/4, the broadcast address included
        ("link-local", "fe80::/10"),
        ("multicast", "ff00::/8"),
    )
)


def _v6(groups: tuple[int, ...], plen: int) -> ipaddress.IPv6Network:
    """An IPv6 network from its leading 16-bit groups (no address literal in the source)."""
    value = 0
    for g in (*groups, *(0,) * (8 - len(groups))):
        value = value << 16 | g
    return ipaddress.IPv6Network((value, plen))


#: IPv6 prefixes that embed an IPv4 address (IPv4-compatible, which holds :: and ::1 too,
#: IPv4-mapped, IPv4-translated, and both NAT64 prefixes).  An IPv4 target is never inside an
#: IPv6 network, so an exclusion written this way would silently exclude nothing: refused, write
#: the IPv4 network instead.
EMBEDDED_V4: tuple[Network, ...] = tuple(
    _v6(groups, plen)
    for groups, plen in (
        ((), 96),  # IPv4-compatible (:: and ::1 inside it)
        ((0, 0, 0, 0, 0, 0xFFFF), 96),  # IPv4-mapped
        ((0, 0, 0, 0, 0xFFFF), 96),  # IPv4-translated
        ((0x64, 0xFF9B), 96),  # NAT64, well-known
        ((0x64, 0xFF9B, 1), 48),  # NAT64, local use
    )
)


class ScopeMissing(ValueError):
    """A scope part a reader needs is absent, empty or malformed: the reader stops (fails closed)."""


class ScopeUndeclared(ScopeMissing):
    """A module read a scope part it did not declare in ``requires.scope``.  A subclass of
    :class:`ScopeMissing`, so every reader that fails closed on a missing part fails closed on
    an undeclared one too."""


def scope_tree() -> dict[str, tuple[str, ...] | None]:
    """The scope block's shape, from :data:`SCOPE_PARTS`: a group's parts, or None for a part
    that is a list itself (``{"trusted": ("wan", "nets", "tooling"), "target": None, ...}``)."""
    out: dict[str, Any] = {}
    for part in SCOPE_PARTS:
        group, _, leaf = part.partition(".")
        if leaf:
            out[group] = (*out.get(group, ()), leaf)
        else:
            out[group] = None
    return out


# ---- the one pattern an entry's text must match (schema and reader) ---------------------------

_OCTET = "(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])"
_H = "[0-9A-Fa-f]{1,4}"
_V6_PREFIX = "(?:12[0-8]|1[01][0-9]|[1-9]?[0-9])"
#: the guard every repository pattern ends with: Python's $ also matches before a final newline
_END = "$(?!\\n)"


def _alt(items: list[str]) -> str:
    return "(?:" + "|".join(items) + ")"


def _ipv4_networks() -> str:
    """Every IPv4 network with no host bits set: an address (optionally /32), or for /n < 32 the
    network octets, the one partial octet restricted to the multiples it can take, and zeros."""
    forms = [_OCTET + ("\\." + _OCTET) * 3 + "(?:/32)?"]
    for n in range(32):
        full, rem = divmod(n, 8)
        octets = [_OCTET] * full
        if rem:
            octets.append(_alt([str(k << (8 - rem)) for k in range(1 << rem)]))
        octets += ["0"] * (4 - len(octets))
        forms.append("\\.".join(octets) + f"/{n}")
    return _alt(forms)


def _ipv6_address() -> str:
    """An IPv6 address in hex groups (RFC 4291 text forms, no embedded dotted IPv4, no zone)."""
    h = _H
    return _alt(
        [
            f"(?:{h}:){{7}}{h}",
            f"(?:{h}:){{1,7}}:",
            f"(?:{h}:){{1,6}}:{h}",
            f"(?:{h}:){{1,5}}(?::{h}){{1,2}}",
            f"(?:{h}:){{1,4}}(?::{h}){{1,3}}",
            f"(?:{h}:){{1,3}}(?::{h}){{1,4}}",
            f"(?:{h}:){{1,2}}(?::{h}){{1,5}}",
            f"{h}:(?::{h}){{1,6}}",
            f":(?:(?::{h}){{1,7}}|:)",
        ]
    )


def _group(value: int | None) -> str:
    if value is None:
        return _H
    if value == 0:
        return "0{1,4}"
    hx = f"{value:x}"
    return f"0{{0,{4 - len(hx)}}}" + "".join(f"[{c}{c.upper()}]" if c.isalpha() else c for c in hx)


def _embedded_forms(net: ipaddress.IPv6Network) -> list[str]:
    """Every text form of an address inside ``net`` (groups fixed by the prefix, the rest free),
    with every place a ``::`` can compress a run of zero (or free, then zero) groups."""
    fixed = net.prefixlen // 16
    groups: list[int | None] = [int(g, 16) for g in net.exploded.split(":")[:fixed]]
    groups += [None] * (8 - fixed)
    zeroable = [g in (0, None) for g in groups]
    forms = [":".join(_group(g) for g in groups)]
    for i in range(8):
        for j in range(i + 1, 9):
            if not all(zeroable[i:j]):
                break
            left = ":".join(_group(g) for g in groups[:i])
            right = ":".join(_group(g) for g in groups[j:])
            forms.append(left + "::" + right)
    return forms


def _entry_pattern() -> str:
    embedded = _alt([f for net in EMBEDDED_V4 for f in _embedded_forms(net)])
    v6 = f"(?!{embedded}(?:/[0-9]{{1,3}})?{_END}){_ipv6_address()}(?:/{_V6_PREFIX})?"
    return f"^(?:{_ipv4_networks()}|{v6}){_END}"


#: an IPv4 network with no host bits set, or an IPv6 address or network in hex groups that does
#: not embed an IPv4 address; no zone id, no whitespace, no leading zeros, no dotted IPv4 inside
#: IPv6.  The selection schema and :func:`parse_entry` both match it.
ENTRY_PATTERN = _entry_pattern()
_ENTRY = re.compile(ENTRY_PATTERN)


def embedded_ipv4(net: Network) -> bool:
    """True when ``net`` is IPv6 and overlaps a prefix that embeds an IPv4 address."""
    return net.version == 6 and any(net.overlaps(e) for e in EMBEDDED_V4)


def is_documentation(net: Network) -> bool:
    """True when every address of ``net`` is in a documentation range."""
    return any(net.version == d.version and net.subnet_of(d) for d in DOCUMENTATION_NETS)


def _why_not(value: str) -> str:
    if "%" in value:
        return "a zone id (an interface name is not a network)"
    if any(c.isspace() for c in value):
        return "whitespace inside the entry"
    if ":" in value and "." in value:
        return "an IPv4 address written inside IPv6 (write the IPv4 network itself)"
    if re.search(r"/0[0-9]", value) or (":" not in value and re.search(r"(?:^|\.)0[0-9]", value)):
        return "leading zeros (read as octal by some parsers, decimal by others)"
    try:
        net = ipaddress.ip_network(value, strict=True)
    except ValueError as exc:
        return str(exc)
    if net.prefixlen == 0:
        return "the whole address space (/0)"
    if embedded_ipv4(net):
        return "an IPv6 form that embeds IPv4 (mapped, compatible or NAT64): write the IPv4 network"
    return "not in canonical form (no leading zeros, a prefix length in range)"


def parse_entry(value: Any, part: str) -> Network:
    """One scope entry of ``part``, parsed strictly, or :class:`ValueError` saying why not.

    Refused in every part: anything but a string matching :data:`ENTRY_PATTERN`, host bits, the
    whole address space (``/0``), a network touching a special-use block (:data:`SPECIAL_NETS`)
    or an IPv4-embedding IPv6 prefix (:data:`EMBEDDED_V4`).  In a ``trusted.*`` part, also a
    network broader than :data:`TRUSTED_FLOOR`.  A dynamic source (``{source: <name>}``, in
    :data:`DYNAMIC_PARTS` only) is specified, not implemented: refused with that reason."""
    if isinstance(value, dict) and part in DYNAMIC_PARTS and set(value) == {"source"}:
        raise ValueError(
            f"a dynamic source ({value['source']!r}): dynamic WAN sources are specified, not "
            "implemented; list the current WAN networks until a reader exists"
        )
    if not isinstance(value, str):
        raise ValueError(f"not a string ({type(value).__name__})")
    if not _ENTRY.match(value):
        raise ValueError(_why_not(value))
    net = ipaddress.ip_network(value, strict=True)  # host bits (IPv6: the pattern cannot tell)
    if net.prefixlen == 0:
        raise ValueError("the whole address space (/0)")
    if embedded_ipv4(net):
        raise ValueError(_why_not(value))
    for why, special in SPECIAL_NETS:
        if net.version == special.version and net.overlaps(special):
            raise ValueError(f"touches the {why} block {special}")
    floor = TRUSTED_FLOOR[net.version]
    if part.startswith("trusted.") and net.prefixlen < floor:
        raise ValueError(f"broader than /{floor}, the floor for a trusted part")
    return net


def _scope_node(site: Doc, part: str) -> Any:
    node: Any = site.get("scope")
    for key in part.split("."):
        node = node.get(key) if isinstance(node, dict) else None
    return node


def _part_networks(site: Doc, part: str) -> list[Network]:
    """The networks of one scope part (``trusted.wan``), parsed strictly, for any caller: the
    low-level read under :func:`scope_networks`, which modules use.

    The one parse of a selection's addresses: an absent or malformed part raises
    :class:`ScopeMissing`, and so does an empty one unless it is an exclusion
    (:data:`EMPTY_ALLOWED`), where an explicit ``[]`` means "nothing excluded".  So a module
    that excludes its trusted addresses can never run as if there were none, and an absent
    exclusion never reads as "nothing excluded"."""
    if part not in SCOPE_PARTS:
        raise ScopeMissing(f"scope.{part}: no such scope part")
    node = _scope_node(site, part)
    if node is None:
        raise ScopeMissing(f"scope.{part}: missing")
    if not isinstance(node, list):
        raise ScopeMissing(f"scope.{part}: not a list ({type(node).__name__})")
    if not node and part not in EMPTY_ALLOWED:
        raise ScopeMissing(f"scope.{part}: empty (only an exclusion may be an explicit [])")
    out: list[Network] = []
    for i, v in enumerate(node):
        try:
            out.append(parse_entry(v, part))
        except ValueError as exc:
            raise ScopeMissing(
                f"scope.{part}[{i}]: {v!r} is not a usable address or network ({exc})"
            ) from exc
    return out


def scope_problems(site: Doc) -> list[str]:
    """The scope block itself: it and each group are mappings of known parts only, and every
    present part is a list (non-empty unless an exclusion) whose entries parse strictly (:func:`parse_entry`) and
    name no network twice.  Which parts must be present is the needing modules' rule
    (``site_problems``).  The schema refuses the same shapes; this does not rely on it."""
    if "scope" not in site:
        return []
    block = site["scope"]
    if not isinstance(block, dict):
        return [f"scope: not a mapping ({type(block).__name__})"]
    out = []
    tree = scope_tree()
    for key in block:
        if key not in tree:
            out.append(f"scope.{key}: no such scope part")
    for group, leaves in tree.items():
        if leaves is None or group not in block:
            continue
        if not isinstance(block[group], dict):
            out.append(f"scope.{group}: not a mapping ({type(block[group]).__name__})")
            continue
        out += [f"scope.{group}.{k}: no such scope part" for k in block[group] if k not in leaves]
    for part in SCOPE_PARTS:
        if _scope_node(site, part) is None:
            continue
        try:
            nets = _part_networks(site, part)
        except ScopeMissing as exc:
            out.append(str(exc))
            continue
        if len(set(nets)) != len(nets):
            out.append(f"scope.{part}: a network is listed twice")
    return out


# ---- the module-facing reader -----------------------------------------------------------------


def declared_parts(module: Doc) -> set[str]:
    """The scope parts a module declares in ``requires.scope``."""
    return {n["part"] for n in module.get("requires", {}).get("scope", [])}


def scope_networks(site: Doc, module: Doc, part: str) -> list[Network]:
    """The networks of one scope part, for ``module``: the only reader a module calls.

    Raises :class:`ScopeUndeclared` when the module did not declare ``part`` in
    ``requires.scope`` (so the declaration is an access list, not a presence check, and the
    loader's "a required part is present" rule covers every part a module can read), and
    :class:`ScopeMissing` when the part is absent, empty (unless an exclusion) or malformed."""
    if part not in SCOPE_PARTS:
        raise ScopeMissing(f"scope.{part}: no such scope part")
    if part not in declared_parts(module):
        raise ScopeUndeclared(
            f"{module.get('id', '?')}: reads scope.{part}, which its requires.scope does not "
            "declare"
        )
    return _part_networks(site, part)


def runs_unattended(module: Doc) -> bool:
    """True when the module does work no human starts: a scheduler job, or an agent on a
    calendar or an event trigger."""
    contributes = module.get("contributes", {})
    if contributes.get("scheduler_jobs"):
        return True
    return any("schedule" in a or "trigger" in a for a in contributes.get("agents", []))


def manifest_scope_problems(module: Doc) -> list[str]:
    """What a module that acts on ``target`` must also declare.

    The manifest has no "offensive" or "mutating" marker, so the rule is keyed on the
    declarations it does have: a module that reads ``target`` acts on the addresses assessment
    tooling may touch, so it requires ``exclude.offensive``; one that also runs unattended
    (:func:`runs_unattended`) requires ``exclude.unattended_mutation`` too.  Both may be an
    explicit ``[]`` in the selection, but neither may be absent."""
    parts = declared_parts(module)
    if "target" not in parts:
        return []
    need = ["exclude.offensive"]
    if runs_unattended(module):
        need.append("exclude.unattended_mutation")
    return [
        f"requires.scope: target without {p} (a module that acts on target subtracts it; "
        "the selection may set it to [], never leave it out)"
        for p in need
        if p not in parts
    ]


def _subtract(nets: list[Network], minus: list[Network]) -> list[Network]:
    out = list(nets)
    for m in minus:
        nxt: list[Network] = []
        for n in out:
            if n.version != m.version or not n.overlaps(m):
                nxt.append(n)
            elif not m.supernet_of(n):  # m is strictly inside n: keep what is left of n
                nxt.extend(n.address_exclude(m))  # type: ignore[arg-type]
        out = nxt
    return out


def effective_targets(site: Doc, module: Doc) -> list[Network]:
    """``target`` minus ``exclude.offensive`` (and, for a module that runs unattended, minus
    ``exclude.unattended_mutation``): the only addresses offensive or mutating tooling may act on.

    Every part it reads must be declared by the module (:class:`ScopeUndeclared`) and present in
    the selection (:class:`ScopeMissing`); an exclusion may be an explicit ``[]``.  Subtraction
    is per IP version, and that is sound because an IPv4 range can only be excluded by an IPv4
    entry: IPv6 forms that embed IPv4 (mapped, compatible, NAT64) are refused by
    :func:`parse_entry`, so an exclusion written that way fails closed instead of silently
    excluding nothing."""
    targets = scope_networks(site, module, "target")
    minus = scope_networks(site, module, "exclude.offensive")
    if runs_unattended(module):
        minus = minus + scope_networks(site, module, "exclude.unattended_mutation")
    left = _subtract(targets, minus)
    v4 = ipaddress.collapse_addresses(n for n in left if n.version == 4)
    v6 = ipaddress.collapse_addresses(n for n in left if n.version == 6)
    return [*v4, *v6]
