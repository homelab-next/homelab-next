# SPDX-License-Identifier: Apache-2.0
"""A service-registry fragment (``zones:`` and ``hosts:``) derived from the guests.

Merge it into a registry document with :func:`merge_into_registry`; the existing registry
generators (DNS, proxy, monitoring, ...) then see every guest, so one guest file wires everything.
"""

from __future__ import annotations

import copy
import ipaddress
from collections.abc import Iterable, Mapping
from typing import Any

from homelabnext.compute.model import ROLE_GROUPS, ComputeError, Fleet, group_for_capability

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
            same = (
                _ip(have.address) == _ip(want["address"])
                if field == "address"
                else str(have.zone) == str(want["zone"])
            )
            if not same:
                out.append(
                    f"guest {name}: registry hosts.{name}.{field} is {getattr(have, field)}, "
                    f"the guest file says {want[field]}"
                )
    return out


#: capabilities a guest may declare on a host that carries no registry row, because they name no
#: service a consumer calls; each with why (with a registry, any other row-less guest is refused
#: unless it is a physical host or retired)
ROW_FREE = {
    "siem-source": "a log source: it sends to the SIEM and serves no consumer",
    "exposure-management": "an assessment scanner: it reaches out to targets and serves no "
    "consumer",
    "detonation": "a hand-fed sandbox serves no consumer; one with an API is a registry row, and "
    "then the rows rule holds",
}
#: the runner slot (ADR-0039 decision 7): no service row carries it, and ``hnx agent access``
#: finds the runner's host by its registry ``role``, so a guest declares ``cap:agent-runtime``
#: only on a registry host whose role is this one, with or without rows beside it
RUNNER_ROLE = "agent-runtime"
#: guest statuses that run nothing yet or any more, so hold no row
_NOT_RUNNING = ("planned", "retired")


def _ip(value: Any) -> str:
    """An address in canonical form (``2001:DB8::0:1`` and ``2001:db8::1`` are one address), or
    the text as written when it is no address."""
    try:
        return str(ipaddress.ip_address(str(value).strip()))
    except ValueError:
        return str(value)


def capability_problems(
    fleet: Fleet, rows: Iterable[Any], hosts: Mapping[str, Any] | None = None
) -> list[str]:
    """Where a guest's ``capability`` or a capability inventory group is not one the service
    registry places on it (ADR-0039 decision 7).

    ``rows`` are the registry's rows of every tier (``Registry.rows`` with all four standings),
    each with ``name``, ``capability`` and ``host``: a guest runs its eval candidate or its legacy
    product as surely as its primary.  ``hosts`` are the registry's hosts (``address``, ``role``).

    - A guest is judged as the registry host of its name, so a guest holding another registry
      host's address under a new name is refused: renaming cannot move it off its host's rows.
    - A guest whose host carries rows declares the capability of one of them.
    - ``cap:agent-runtime`` is declared only on a registry host whose ``role`` is
      :data:`RUNNER_ROLE`, rows or not: that role is how the runner is found.
    - A guest whose host carries no row may not take a capability the registry places on another
      host; it must be a physical host, planned or retired, declare one of :data:`ROW_FREE`, or
      declare its registry host's own ``role`` (a site's own row-free role, by name).
    - A ``cap_<capability>`` inventory group of a registry capability needs that capability's row
      on the guest's host: the group is what its playbooks target.  The group of a capability no
      row serves anywhere (one that is no named role group of docs/role-interface.md) is taken
      only by a guest that declares that capability.
    """
    rows = list(rows)
    hosts = hosts or {}
    on: dict[str, list[Any]] = {}
    placed: dict[str, set[str]] = {}
    for r in rows:
        on.setdefault(r.host, []).append(r)
        placed.setdefault(r.capability, set()).add(r.host)
    by_address = {_ip(h.address): name for name, h in hosts.items()}
    groups = {group_for_capability(c): c for c in placed}
    out = []
    for g in fleet.sorted():
        for a in g.addresses:
            other = by_address.get(_ip(a))
            if other is not None and other != g.name:
                out.append(
                    f"guest {g.name}: address {a} is registry host {other}'s; a guest is judged "
                    f"as the host of its name, so name it {other} (or give the registry host "
                    "this name)"
                )
        cap = g.capability.removeprefix("cap:")
        here = on.get(g.name, [])
        caps_here = {r.capability for r in here}
        served = ", ".join(sorted(f"{r.capability} ({r.name})" for r in here))
        role = getattr(hosts.get(g.name), "role", None)
        elsewhere = sorted(placed.get(cap, set()) - {g.name})
        if cap in caps_here:
            pass
        elif cap == RUNNER_ROLE:
            if role != RUNNER_ROLE:
                where = (
                    f"its registry host's role is {role}"
                    if role is not None
                    else f"{g.name} is no registry host"
                )
                out.append(
                    f"guest {g.name}: declares {g.capability}, but {where}; the runner is found "
                    f"by a registry host with role {RUNNER_ROLE}"
                )
        elif elsewhere:
            out.append(
                f"guest {g.name}: capability {g.capability} is not served on {g.name}: the "
                f"registry places {cap} on {', '.join(elsewhere)}"
                + (f"; the rows on {g.name} serve {served}" if here else "")
            )
        elif here:
            out.append(
                f"guest {g.name}: capability {g.capability} is no capability of a registry row on "
                f"{g.name}; the rows there serve {served}"
            )
        elif not (
            cap in ROW_FREE
            or (role is not None and cap == role)
            or g.kind == "host"
            or g.raw.get("status") in _NOT_RUNNING
        ):
            out.append(
                f"guest {g.name}: hosts no registry row, yet declares {g.capability}: add its row "
                "to the registry, declare its registry host's role, or a capability that serves "
                f"no consumer ({', '.join('cap:' + c for c in sorted(ROW_FREE))})"
            )
        for grp in g.groups:
            c = groups.get(grp)
            if c is not None and c not in caps_here:
                out.append(
                    f"guest {g.name}: capability_groups {grp} is capability {c}'s, which the "
                    f"registry places on {', '.join(sorted(placed[c]))}, not on {g.name}"
                )
            elif c is None and grp not in ROLE_GROUPS and grp != group_for_capability(cap):
                out.append(
                    f"guest {g.name}: capability_groups {grp} is the group of a capability no "
                    f"registry row serves; only a guest declaring that capability takes it"
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
