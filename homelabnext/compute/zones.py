# SPDX-License-Identifier: Apache-2.0
"""ZoneLookup implementations: a mapping stub, a ``site.yml`` reader and a ``load_site`` adapter."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from homelabnext import sops

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
        doc = yaml.safe_load(sops.read_text(path))
    except (OSError, yaml.YAMLError, sops.SopsError) as exc:
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


#: the protocols a Tailscale rule can name (an IR rule for ``any`` covers them all)
TAILNET_PROTOCOLS = ("tcp", "udp", "icmp")


@dataclass
class _Decided:
    """First-match state of one protocol on one zone pair."""

    whole: str | None = None  # the action of the first rule matching every port
    ports: dict[int, str] = field(default_factory=dict)  # port -> the first matching action


def _ir_zone_rules(doc: Mapping[str, Any], zones: list[str]) -> list[Any]:
    """The network IR's own firewall rules for ``zone_to_zone``, in its evaluation order.

    ``homelabnext.network.ir`` builds the rules (protocol defaults, icmp beside ports, the
    ``to: any`` rules last); this only hands it the zone rules, so no registry is needed.
    """
    from homelabnext.network.ir import _rules

    fw = doc.get("firewall") or {}
    z2z = [dict(r) for r in fw.get("zone_to_zone") or [] if isinstance(r, Mapping)]
    nets: defaultdict[str, str] = defaultdict(str, dict.fromkeys(zones, ""))
    try:
        return _rules({"firewall": {"zone_to_zone": z2z}, "zones": []}, None, nets, {})
    except (KeyError, TypeError, ValueError) as exc:
        raise ComputeError(
            f"firewall.zone_to_zone: cannot read the rules ({exc!r}); check with hnx site validate"
        ) from exc


def flows_from_site(doc: Mapping[str, Any]) -> tuple[ZoneFlow, ...]:
    """The zone-to-zone traffic a site document allows, as flows between distinct zones.

    Derived from the network IR's evaluated rules (``homelabnext.network.ir``: first match wins,
    rules to a zone before rules to ``any``), never re-read from the document, so a flow allows
    exactly the (protocol, port) pairs the IR allows between the two zones, for tcp, udp and icmp.
    A zone pair whose three protocols are all allowed on every port is one flow with no
    protocols or ports (any).  ``service_exceptions`` (host-specific, to a service) are not zone
    flows and are not read.  An allow of a whole protocol after a port-level deny of it on the
    same pair (which the site validator refuses) cannot be written as allows and is an error.
    """
    zones = [str(z["id"]) for z in doc.get("zones") or [] if isinstance(z, Mapping) and z.get("id")]
    state: dict[tuple[str, str], dict[str, _Decided]] = {}
    for rule in _ir_zone_rules(doc, zones):
        if rule.src.kind != "zone":
            continue
        if rule.dst.kind == "zone":
            dsts = [rule.dst.name]
        elif rule.dst.kind == "any":
            dsts = list(zones)
        else:
            continue
        protos = TAILNET_PROTOCOLS if rule.protocol == "any" else (rule.protocol,)
        for dst in dsts:
            if dst == rule.src.name:
                continue
            pair = state.setdefault(
                (rule.src.name, dst), {p: _Decided() for p in TAILNET_PROTOCOLS}
            )
            for proto in protos:
                d = pair.get(proto)
                if d is None or d.whole is not None:
                    continue
                if rule.ports:
                    for port in rule.ports:
                        d.ports.setdefault(port, rule.action)
                else:
                    d.whole = rule.action
    out: list[ZoneFlow] = []
    for (src, dst), pair in state.items():
        whole: list[str] = []
        ported: dict[tuple[int, ...], list[str]] = {}
        for proto, d in pair.items():
            if d.whole == "allow":
                denied = sorted(p for p, a in d.ports.items() if a == "deny")
                if denied:
                    raise ComputeError(
                        f"firewall.zone_to_zone: {src} -> {dst} allows {proto} on every port but "
                        f"{denied} after a port-level deny; a deny applies to the whole zone pair"
                    )
                whole.append(proto)
                continue
            allowed = tuple(sorted(p for p, a in d.ports.items() if a == "allow"))
            if allowed:
                ported.setdefault(allowed, []).append(proto)
        if len(whole) == len(TAILNET_PROTOCOLS):
            out.append(ZoneFlow(src, dst))
        elif whole:
            out.append(ZoneFlow(src, dst, tuple(whole)))
        out.extend(ZoneFlow(src, dst, tuple(protos), ports) for ports, protos in ported.items())
    return tuple(out)


def site_power(path: str | Path) -> dict[str, Any] | None:
    """The site's power facts (:func:`homelabnext.power.site_power`) for a site file, or None
    when it has no ``power`` section."""
    from homelabnext.network.loader import SiteError, load_site
    from homelabnext.power import site_power as facts

    try:
        doc = load_site(path)
    except SiteError as exc:
        raise ComputeError(str(exc)) from exc
    return facts(doc) if isinstance(doc, Mapping) else None


def site_flows(path: str | Path) -> tuple[ZoneFlow, ...]:
    """:func:`flows_from_site` for a site file, read by the network model's own loader."""
    from homelabnext.network.loader import SiteError, load_site

    try:
        doc = load_site(path)
    except SiteError as exc:
        raise ComputeError(str(exc)) from exc
    return flows_from_site(doc) if isinstance(doc, Mapping) else ()


def site_deploy(path: str | Path) -> dict[str, Any] | None:
    """The deploy's tailnet access (:func:`homelabnext.tailnet.site_deploy`) for a site file, or
    None when it declares none; an invalid declaration is an error (the same rules as
    ``hnx site validate``), never read as "no deploy access"."""
    from homelabnext.network.loader import SiteError, load_site
    from homelabnext.tailnet import deploy_problems
    from homelabnext.tailnet import site_deploy as access

    try:
        doc = load_site(path)
    except SiteError as exc:
        raise ComputeError(str(exc)) from exc
    if not isinstance(doc, Mapping):
        return None
    problems = deploy_problems(doc)
    if problems:
        raise ComputeError(f"{path}: invalid tailnet.deploy", problems)
    return access(doc)
