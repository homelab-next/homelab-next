# SPDX-License-Identifier: Apache-2.0
"""The site's network scope (docs/modules.md, "The network scope"): its parts, the strict reader
and the rules over a selection's ``scope:`` block.

A neutral module: the schema generator (:mod:`homelabnext.schemas.module_manifest`), the loader
rules (:mod:`homelabnext.modules.rules`) and the public leak check (``tools/private_leak_check.py``)
all import it, and it imports nothing of theirs.
"""

from __future__ import annotations

import ipaddress
from typing import Any

from homelabnext.ids.lint import DOCUMENTATION_NETS

Doc = dict[str, Any]

__all__ = [
    "SCOPE_PARTS",
    "Network",
    "ScopeMissing",
    "is_documentation",
    "scope_networks",
    "scope_problems",
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
Network = ipaddress.IPv4Network | ipaddress.IPv6Network


class ScopeMissing(ValueError):
    """A scope part a reader needs is absent, empty or malformed: the reader stops (fails closed)."""


def _scope_node(site: Doc, part: str) -> Any:
    node: Any = site.get("scope")
    for key in part.split("."):
        node = node.get(key) if isinstance(node, dict) else None
    return node


def scope_networks(site: Doc, part: str) -> list[Network]:
    """The networks of one scope part (``trusted.wan``), parsed strictly.

    The one reader of a selection's addresses: an absent, empty or malformed part raises
    :class:`ScopeMissing`, never an empty list, so a module that excludes its trusted addresses
    can never run as if there were none."""
    if part not in SCOPE_PARTS:
        raise ScopeMissing(f"scope.{part}: no such scope part")
    node = _scope_node(site, part)
    if not isinstance(node, list) or not node:
        raise ScopeMissing(f"scope.{part}: missing or empty")
    out: list[Network] = []
    for i, v in enumerate(node):
        try:
            if not isinstance(v, str):
                raise TypeError("not a string")
            out.append(ipaddress.ip_network(v, strict=True))
        except (TypeError, ValueError) as exc:
            raise ScopeMissing(
                f"scope.{part}[{i}]: {v!r} is not an address or network ({exc})"
            ) from exc
    return out


def is_documentation(net: Network) -> bool:
    """True when every address of ``net`` is in a documentation range."""
    return any(net.version == d.version and net.subnet_of(d) for d in DOCUMENTATION_NETS)


def scope_problems(site: Doc) -> list[str]:
    """The scope block itself: every present part parses strictly (no host bits, no malformed
    CIDR), is non-empty and names no network twice.  Which parts must be present is the needing
    modules' rule (``site_problems``)."""
    out = []
    for part in SCOPE_PARTS:
        if _scope_node(site, part) is None:
            continue
        try:
            nets = scope_networks(site, part)
        except ScopeMissing as exc:
            out.append(str(exc))
            continue
        if len(set(nets)) != len(nets):
            out.append(f"scope.{part}: a network is listed twice")
    return out
