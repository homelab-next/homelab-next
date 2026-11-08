# SPDX-License-Identifier: Apache-2.0
"""A service-registry fragment (``zones:`` and ``hosts:``) derived from the guests.

Merge it into a registry document with :func:`merge_into_registry`; the existing registry
generators (DNS, proxy, monitoring, ...) then see every guest, so one guest file wires everything.
"""

from __future__ import annotations

import copy
from collections.abc import Iterable, Mapping
from typing import Any

from homelabnext.compute.model import ComputeError, Fleet

from ._text import HEADER, q


def fragment(fleet: Fleet) -> dict[str, Any]:
    zones: dict[str, Any] = {}
    hosts: dict[str, Any] = {}
    for g in fleet.sorted():
        z = fleet.zone(g)
        zones[z.id] = {"cidr": z.subnet}
        hosts[g.name] = {
            "address": g.ip,
            "zone": z.id,
            "role": g.capability.removeprefix("cap:"),
        }
    return {"zones": dict(sorted(zones.items())), "hosts": dict(sorted(hosts.items()))}


def merge_into_registry(doc: Mapping[str, Any], frag: Mapping[str, Any]) -> dict[str, Any]:
    """Overlay the fragment on a registry document.

    An entry the registry already has is kept as written (it may carry fields the guests do not,
    such as a zone description); it is an error only when it disagrees with the fragment on a
    field the fragment supplies.
    """
    out = copy.deepcopy(dict(doc))
    for section in ("zones", "hosts"):
        dst = out.setdefault(section, {})
        for k, v in frag[section].items():
            if k not in dst:
                dst[k] = v
                continue
            clash = {f for f, val in v.items() if dst[k].get(f) != val}
            if clash:
                raise ComputeError(
                    f"registry {section}.{k} differs from the guest-derived entry "
                    f"({', '.join(sorted(clash))})"
                )
    return out


def registry_problems(fleet: Fleet, hosts: Mapping[str, Any]) -> list[str]:
    """Where a service registry's ``hosts`` disagree with the guests on an address or a zone.

    ``hosts`` maps a host name to an object with ``address`` and ``zone`` (the registry model's
    hosts).  The registry's address feeds the router's service exceptions, DNS and DHCP; the
    guest's ``network.ip`` the hypervisor, cloud-init and the guest firewall: one fact, two files,
    so a difference is an error.  A registry host that is no guest, and a guest that is no
    registry host, are not compared.
    """
    out = []
    for name, want in fragment(fleet)["hosts"].items():
        have = hosts.get(name)
        if have is None:
            continue
        for field in ("address", "zone"):
            if str(getattr(have, field)) != str(want[field]):
                out.append(
                    f"guest {name}: registry hosts.{name}.{field} is {getattr(have, field)}, "
                    f"the guest file says {want[field]}"
                )
    return out


def capability_problems(fleet: Fleet, rows: Iterable[Any]) -> list[str]:
    """Where a guest's ``capability`` is not one the service registry places on it (ADR-0039
    decision 7).

    ``rows`` are the registry's rows of every tier (``Registry.rows`` with all four standings),
    each with ``name``, ``capability`` and ``host``: a guest runs its eval candidate or its legacy
    product as surely as its primary.  A guest whose host carries rows must declare the capability
    of one of them, so ``cap:orchestration`` fits only the guest that runs the orchestrator, and a
    catch-all borrowed from another host is refused.  A guest whose host carries no row (a
    hypervisor, a bench machine) serves no registered capability; it is still refused a
    capability the registry places on another host, and otherwise held to the platform's
    vocabulary alone, as without a registry.
    """
    on: dict[str, list[Any]] = {}
    placed: dict[str, set[str]] = {}
    for r in rows:
        on.setdefault(r.host, []).append(r)
        placed.setdefault(r.capability, set()).add(r.host)
    out = []
    for g in fleet.sorted():
        cap = g.capability.removeprefix("cap:")
        here = on.get(g.name, [])
        if cap in {r.capability for r in here}:
            continue
        hosts = sorted(placed.get(cap, set()) - {g.name})
        served = ", ".join(sorted(f"{r.capability} ({r.name})" for r in here))
        if hosts:
            where = f"the registry places {cap} on {', '.join(hosts)}"
            out.append(
                f"guest {g.name}: capability {g.capability} is not served on {g.name}: {where}"
                + (f"; the rows on {g.name} serve {served}" if here else "")
            )
        elif here:
            out.append(
                f"guest {g.name}: capability {g.capability} is no capability of a registry row on "
                f"{g.name}; the rows there serve {served}"
            )
    return out


def render(fleet: Fleet) -> dict[str, str]:
    f = fragment(fleet)
    L = [
        f"# {HEADER}",
        "# merge into services.yml: it supplies the zones and hosts sections",
        "zones:",
    ]
    for k, v in f["zones"].items():
        L.append(f"  {k}: {{cidr: {q(v['cidr'])}}}")
    L.append("hosts:")
    for k, v in f["hosts"].items():
        L.append(
            f"  {k}: {{address: {q(v['address'])}, zone: {q(v['zone'])}, role: {q(v['role'])}}}"
        )
    return {"registry-hosts.yml": "\n".join(L) + "\n"}
