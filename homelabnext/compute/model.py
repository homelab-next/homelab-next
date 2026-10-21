# SPDX-License-Identifier: Apache-2.0
"""Guest model: the parsed, schema-valid view of ``guest.schema.json`` plus the zone interface.

The compute model never imports the site-model package.  It codes against the small
:class:`ZoneLookup` protocol; a stub, a plain mapping, a ``site.yml`` reader and an adapter for
``homelabnext.network.load_site`` all satisfy it (see :mod:`homelabnext.compute.zones`).
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

#: The fifteen capabilities named in docs/interfaces.md (``hnx conform --list``).
KNOWN_CAPABILITIES: tuple[str, ...] = (
    "lake-query",
    "lake-catalog",
    "object-store",
    "inference",
    "fast-classifier",
    "notify",
    "cases",
    "events",
    "orchestration",
    "broker",
    "secrets",
    "idp",
    "records",
    "detections",
    "context",
)

#: The capability inventory groups named in docs/role-interface.md section 5.
ROLE_GROUPS: tuple[str, ...] = (
    "cap_siem",
    "cap_lake",
    "cap_query",
    "cap_inference",
    "cap_edge",
    "cap_idp",
    "cap_secrets",
    "cap_orchestration",
    "cap_broker",
    "cap_cases",
    "cap_tip",
    "cap_monitoring",
    "cap_decision",
    "cap_nifi",
    # central defense products (ADR-0016 decision 7): the host a central control's role runs on
    "cap_sensor",
    "cap_scanner",
    "cap_backup",
)


def group_for_capability(capability: str) -> str:
    """``cap:lake-query`` -> ``cap_lake_query`` (the derived group every capability may use)."""
    return "cap_" + capability.removeprefix("cap:").replace("-", "_")


def allowed_groups() -> frozenset[str]:
    return frozenset(ROLE_GROUPS) | {group_for_capability(f"cap:{c}") for c in KNOWN_CAPABILITIES}


@dataclass(frozen=True)
class ZoneInfo:
    """What the compute model needs to know about one network zone."""

    id: str
    subnet: str
    gateway: str | None = None
    dhcp_range: tuple[str, str] | None = None
    vlan_id: int | None = None

    @property
    def network(self) -> ipaddress.IPv4Network:
        return ipaddress.ip_network(self.subnet, strict=True)  # type: ignore[return-value]


@dataclass(frozen=True)
class ZoneFlow:
    """One zone-to-zone flow the site model allows (``firewall.zone_to_zone``, action allow).

    Empty ``protocols`` / ``ports`` mean any.  Read by :func:`homelabnext.compute.zones.site_flows`;
    the ``tailscale-acl`` target turns these into tailnet ACLs so remote access follows the
    site model."""

    src: str
    dst: str
    protocols: tuple[str, ...] = ()
    ports: tuple[int, ...] = ()


@runtime_checkable
class ZoneLookup(Protocol):
    """The only thing the compute model asks of a site model."""

    def zone(self, zone_id: str) -> ZoneInfo | None: ...


@dataclass(frozen=True)
class Problem:
    where: str
    message: str

    def __str__(self) -> str:
        return f"{self.where}: {self.message}"


class ComputeError(Exception):
    def __init__(self, message: str, problems: Iterable[Problem | str] = ()):
        self.problems = [str(p) for p in problems]
        super().__init__(message + "".join(f"\n  - {p}" for p in self.problems))


@dataclass(frozen=True)
class Guest:
    """A schema-valid guest.  ``raw`` is the document; properties give defaulted access."""

    raw: Mapping[str, Any] = field(repr=False)
    source: str = ""

    @property
    def id(self) -> str:
        return self.raw["id"]

    @property
    def name(self) -> str:
        return self.id.removeprefix("guest:")

    @property
    def kind(self) -> str:
        return self.raw["kind"]

    @property
    def provisioning(self) -> str:
        return self.raw["provisioning"]

    @property
    def node(self) -> str:
        return self.raw["placement"]["node"]

    @property
    def vmid(self) -> int | None:
        return self.raw["placement"].get("vmid")

    @property
    def vmid_scheme(self) -> str:
        return self.raw["placement"].get("vmid_scheme", "freeform")

    @property
    def ip(self) -> str:
        return self.raw["network"]["ip"]

    @property
    def zone(self) -> str:
        return self.raw["network"]["zone"]

    @property
    def capability(self) -> str:
        return self.raw["capability"]

    @property
    def groups(self) -> list[str]:
        return list(self.raw.get("capability_groups", []))

    @property
    def tags(self) -> list[str]:
        return list(self.raw.get("tags", []))

    @property
    def cpu(self) -> Mapping[str, Any]:
        return self.raw.get("resources", {}).get("cpu", {})

    @property
    def memory(self) -> Mapping[str, Any]:
        return self.raw.get("resources", {}).get("memory", {})

    @property
    def disks(self) -> list[Mapping[str, Any]]:
        return list(self.raw.get("resources", {}).get("disks", []))

    @property
    def image(self) -> Mapping[str, Any]:
        return self.raw.get("image", {})

    @property
    def cloudinit(self) -> Mapping[str, Any]:
        return self.raw.get("cloudinit", {})

    @property
    def network(self) -> Mapping[str, Any]:
        return self.raw["network"]

    @property
    def nic_firewall(self) -> bool:
        """Effective per-NIC firewall flag: on unless explicitly ``disabled`` (on by default)."""
        return self.network.get("firewall", "enabled") != "disabled"

    @property
    def firewall_exemption(self) -> Mapping[str, Any] | None:
        return self.network.get("firewall_exemption")

    @property
    def firewall_rules(self) -> list[Mapping[str, Any]]:
        """Inbound allow rules."""
        return list(self.raw.get("firewall_rules", {}).get("inbound_allow", []))

    @property
    def outbound_rules(self) -> list[Mapping[str, Any]]:
        """Outbound allow rules (meaningful with ``policy_out`` DROP or REJECT)."""
        return list(self.raw.get("firewall_rules", {}).get("outbound_allow", []))

    @property
    def policy_out(self) -> str:
        return self.raw.get("firewall_rules", {}).get("policy_out", "ACCEPT")

    @property
    def scope(self) -> str | None:
        """``in`` / ``out`` when the file says so, else None (see ``homelabnext.scope``)."""
        return self.raw.get("scope")

    @property
    def gpu(self) -> Mapping[str, Any] | None:
        return self.raw.get("gpu")

    @property
    def backup(self) -> Mapping[str, Any]:
        return self.raw.get("backup", {})

    @property
    def baseline(self) -> Mapping[str, Any]:
        """``baseline`` (1.3): ``names``/``add``/``remove`` or ``exemption``; {} when absent."""
        return self.raw.get("baseline", {})

    @property
    def lifecycle(self) -> Mapping[str, Any]:
        return self.raw.get("lifecycle", {})

    @property
    def shared_dirs(self) -> list[Mapping[str, Any]]:
        return list(self.raw.get("shared_dirs", []))

    @property
    def owners(self) -> Mapping[str, Any]:
        return self.raw["owners"]

    @property
    def backup_policy(self) -> str:
        return self.backup.get("policy", "none")

    @property
    def is_iac(self) -> bool:
        """Rendered into infrastructure-as-code output (terraform, libvirt, cloud-init)."""
        return self.provisioning == "terraform" and self.kind in ("vm", "lxc")


@dataclass(frozen=True)
class Fleet:
    """A validated set of guests plus everything the generators need besides them."""

    guests: tuple[Guest, ...]
    zones: ZoneLookup
    domain: str = "example.internal"
    keys: Mapping[str, str] = field(default_factory=dict)
    policies: Mapping[str, Mapping[str, Any]] = field(default_factory=dict)
    #: node name -> {"firewall": "enabled"|"disabled"}; a node not listed runs a firewall.
    nodes: Mapping[str, Mapping[str, Any]] = field(default_factory=dict)
    #: the baseline set (``_baselines.yml``, :mod:`homelabnext.compute.baselines`); None = no set,
    #: so no guest is required to declare a baseline
    baselines: Any = None
    #: the zone-to-zone flows the site model allows (empty: a zones-only site, or none read)
    flows: tuple[ZoneFlow, ...] = ()

    def node_firewall(self, node: str) -> bool:
        """Whether the node (hypervisor) itself enforces a firewall.  Unlisted = yes (safe default)."""
        return self.nodes.get(node, {}).get("firewall", "enabled") != "disabled"

    def sorted(self) -> list[Guest]:
        return sorted(self.guests, key=lambda g: g.id)

    def iac(self) -> list[Guest]:
        return [g for g in self.sorted() if g.is_iac]

    def manual(self) -> list[Guest]:
        return [g for g in self.sorted() if g.provisioning == "manual"]

    def zone(self, guest: Guest) -> ZoneInfo:
        info = self.zones.zone(guest.zone)
        if info is None:  # validate() would have said so; generators fail loudly, never guess
            raise ComputeError(f"{guest.id}: unknown zone {guest.zone!r}")
        return info

    def gateway(self, guest: Guest) -> str:
        gw = guest.network.get("gateway", "inherit")
        if gw == "inherit":
            zi = self.zone(guest)
            if not zi.gateway:
                raise ComputeError(f"{guest.id}: zone {zi.id!r} has no gateway to inherit")
            return zi.gateway
        return gw

    def prefix_len(self, guest: Guest) -> int:
        return self.zone(guest).network.prefixlen

    def fqdn(self, guest: Guest) -> str:
        return f"{guest.name}.{self.domain}"
