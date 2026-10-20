# SPDX-License-Identifier: Apache-2.0
"""ZoneLookup implementations: a mapping stub, a ``site.yml`` reader and a ``load_site`` adapter."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

import yaml

from .model import ComputeError, ZoneFlow, ZoneInfo, ZoneLookup


class MappingZones:
    """A ZoneLookup over ready-made :class:`ZoneInfo` objects (tests, other tools)."""

    def __init__(self, zones: Iterable[ZoneInfo]):
        self._zones = {z.id: z for z in zones}

    def zone(self, zone_id: str) -> ZoneInfo | None:
        return self._zones.get(zone_id)


def zone_from_mapping(z: Mapping[str, Any]) -> ZoneInfo:
    """Build a ZoneInfo from a site-model style zone mapping (id, subnet, gateway, dhcp.range)."""
    dhcp = z.get("dhcp") or {}
    rng = dhcp.get("range")
    return ZoneInfo(
        id=z["id"],
        subnet=z.get("subnet") or z["cidr"],
        gateway=z.get("gateway"),
        dhcp_range=(str(rng[0]), str(rng[1])) if rng else None,
        vlan_id=z.get("vlan_id"),
    )


def load_zones_file(path: str | Path) -> tuple[ZoneLookup, str | None]:
    """Read the ``zones:`` list (and ``site.domain``) of a site.yml-shaped file."""
    try:
        doc = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise ComputeError(f"cannot read site file {path}: {exc}") from exc
    if not isinstance(doc, dict) or not isinstance(doc.get("zones"), list):
        raise ComputeError(f"{path}: expected a mapping with a 'zones' list")
    zones = MappingZones(zone_from_mapping(z) for z in doc["zones"])
    domain = (doc.get("site") or {}).get("domain")
    return zones, domain


class SiteAdapter:
    """Adapt a site-model object to ZoneLookup by duck typing.

    The object may offer ``zone(id)`` or a ``zones`` collection (mapping or list) whose items
    expose ``id``/``subnet``/``gateway``/``dhcp``/``vlan_id`` attributes or keys.
    """

    def __init__(self, site: Any):
        self._site = site

    @staticmethod
    def _get(obj: Any, name: str) -> Any:
        return obj.get(name) if isinstance(obj, Mapping) else getattr(obj, name, None)

    def _convert(self, z: Any) -> ZoneInfo:
        if isinstance(z, ZoneInfo):
            return z
        dhcp = self._get(z, "dhcp")
        rng = self._get(dhcp, "range") if dhcp else None
        return ZoneInfo(
            id=self._get(z, "id"),
            subnet=self._get(z, "subnet") or self._get(z, "cidr"),
            gateway=self._get(z, "gateway"),
            dhcp_range=(str(rng[0]), str(rng[1])) if rng else None,
            vlan_id=self._get(z, "vlan_id"),
        )

    def zone(self, zone_id: str) -> ZoneInfo | None:
        fn = getattr(self._site, "zone", None)
        found = fn(zone_id) if callable(fn) else None
        if found is None:
            zs = getattr(self._site, "zones", None)
            if isinstance(zs, Mapping):
                found = zs.get(zone_id)
            elif zs is not None:
                found = next((z for z in zs if self._get(z, "id") == zone_id), None)
        return None if found is None else self._convert(found)


def open_site(path: str | Path) -> tuple[ZoneLookup, str | None]:
    """Read zones and the domain through the network model's own loader.

    ``homelabnext.network.load_site`` is the one reader of a site document, so a file that parses
    for ``hnx site`` parses here the same way (duplicate keys rejected, same error text).  This
    does not run the site validation: use ``hnx site validate`` for that.
    """
    from homelabnext.network.loader import SiteError, load_site

    try:
        doc = load_site(path)
    except SiteError as exc:
        raise ComputeError(str(exc)) from exc
    zones = doc.get("zones")
    if not isinstance(zones, list):
        raise ComputeError(f"{path}: expected a mapping with a 'zones' list")
    domain = (doc.get("site") or {}).get("domain")
    return MappingZones(zone_from_mapping(z) for z in zones), domain


def flows_from_site(doc: Mapping[str, Any]) -> tuple[ZoneFlow, ...]:
    """The zone-to-zone allows of a site document, in document order.

    Follows the network model's evaluation order (``homelabnext.network.ir``): rules to a zone
    first, then rules to ``any`` (expanded to every other zone).  An allow is dropped when an
    earlier rule without ports denies the same pair, since that deny matches first.  Port-level
    denies and ``service_exceptions`` (host-specific, to a service) are not zone flows and are
    not read.
    """
    fw = doc.get("firewall") or {}
    rules = [r for r in fw.get("zone_to_zone") or [] if isinstance(r, Mapping)]
    zones = [z.get("id") for z in doc.get("zones") or [] if isinstance(z, Mapping)]
    ordered = [r for r in rules if r.get("to") != "any"] + [
        r for r in rules if r.get("to") == "any"
    ]
    denied: set[tuple[str, str]] = set()
    out: list[ZoneFlow] = []
    for r in ordered:
        src = str(r.get("from"))
        dsts = [z for z in zones if z != src] if r.get("to") == "any" else [str(r.get("to"))]
        for dst in dsts:
            if (src, dst) in denied:
                continue
            if r.get("action") == "deny":
                if not r.get("ports"):
                    denied.add((src, dst))
                continue
            if r.get("action") == "allow":
                out.append(
                    ZoneFlow(
                        src,
                        dst,
                        tuple(sorted(str(p) for p in r.get("protocols") or [])),
                        tuple(sorted(int(p) for p in r.get("ports") or [])),
                    )
                )
    return tuple(out)


def site_flows(path: str | Path) -> tuple[ZoneFlow, ...]:
    """:func:`flows_from_site` for a site file, read by the network model's own loader."""
    from homelabnext.network.loader import SiteError, load_site

    try:
        doc = load_site(path)
    except SiteError as exc:
        raise ComputeError(str(exc)) from exc
    return flows_from_site(doc) if isinstance(doc, Mapping) else ()
