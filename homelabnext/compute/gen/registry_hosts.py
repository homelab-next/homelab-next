# SPDX-License-Identifier: Apache-2.0
"""A service-registry fragment (``zones:`` and ``hosts:``) derived from the guests.

Merge it into a registry document with :func:`merge_into_registry`; the existing registry
generators (DNS, proxy, monitoring, ...) then see every guest, so one guest file wires everything.
"""

from __future__ import annotations

import copy
from collections.abc import Mapping
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
    """Overlay the fragment on a registry document; a clash with different values is an error."""
    out = copy.deepcopy(dict(doc))
    for section in ("zones", "hosts"):
        dst = out.setdefault(section, {})
        for k, v in frag[section].items():
            if k in dst and dst[k] != v:
                raise ComputeError(f"registry {section}.{k} differs from the guest-derived entry")
            dst[k] = v
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
