# SPDX-License-Identifier: Apache-2.0
"""UniFi-class controller adapter: DRY-RUN payload renderer.

This adapter only builds the JSON documents a UniFi-class controller would need for networks
(VLANs), firewall rules and switch port profiles.  It makes no network call, holds no credential
(``controller.json`` carries secret *reference names* only) and has no ``apply``:

    SERVER-only: applying the payloads to a live controller needs the controller, a session
    with write rights and a controller-version check.  None of that is part of this repository.

The shapes follow the controller's legacy REST object names (``networkconf``, ``firewallrule``,
``portconf``).  Golden files pin *our rendering* of those shapes; whether a given controller
version accepts every field is verified on the server, not here.

A mirror port renders as a port override with ``op_mode: mirror`` and ``mirror_port_idx`` (the
source port) and no profile. The field names are the controller's (``DevicePortOverrides`` in
go-unifi, generated from the controller's field definitions); that the destination port's
override names the source follows the controller UI and is checked on the server.  A mirror port
copies exactly one source port; the adapter refuses more rather than render only the first.
Objects that refer to each other use ``${network:<name>}`` and ``${firewallgroup:<name>}``
placeholders, resolved to controller ids at apply time.

One model of the legacy rule sets holds throughout: ``LAN_IN`` (and ``LANv6_IN``) sees every packet
a zone sends, routed LAN-to-WAN traffic included, and ends in a default-deny with no destination.
So a zone's internet allow is rendered, not left to the controller's defaults: a drop of what the
zone sends to any zone's network (the ``hnx-zones`` address group, ``hnx-zones6`` for prefixes,
in ``firewall-rules.json``'s ``groups``),
which only an earlier rule may allow, then an accept of the rest, both before the default-deny.
Every rule must fit between ``RULE_BASE + 10`` and the default-deny at ``RULE_BASE + 999``; a site
whose rules do not is an error, never a rule silently placed behind the deny.  A one-way zone gets a
``LAN_LOCAL`` drop of DNS: the gateway answers DNS on every network by default, and a resolver
would carry the zone's data out in queries.

A zone with a ``subnet6`` gets the network's static IPv6 settings (``ipv6_interface_type``,
``ipv6_subnet``, router advertisements) and the policy again in the controller's IPv6 rule sets
(``LANv6_IN``, ``WANv6_OUT``, ``NETv6`` network types): every rule that has an IPv6 form
(:func:`~homelabnext.network.ir.ipv6_form`), and the same allow-established, drop-invalid and
default-deny frame, so IPv6 is closed by default exactly as IPv4 is.  Both families number their
rules from ``RULE_BASE`` (2000) up to ``RULE_BASE + 999``: the IPv6 rule sets are separate rule
sets, so no offset is needed, and the range stays inside the custom-rule indexes the IPv4 rules
already use.  An IPv6 rule names its protocol in ``protocol_v6`` (``icmpv6`` for ICMP), the field
the controller's legacy object carries for IPv6 rule sets.  An allow to ``any`` from
a source without a global prefix is the ``intranet`` selector in IPv6 (everything but the
internet); the controller renders it as it does ``any``, in ``LANv6_IN``, preceded by a ``WANv6_OUT`` drop
for the same source: the legacy ``LANv6_IN`` also sees routed LAN-to-WAN traffic, so the accept
alone would not keep it off the internet.  A zone denied the internet gets its ``WANv6_OUT`` drop whatever its
prefix, so the controller's default never decides.  None of this is verified offline: the
index range, ``protocol_v6`` and its values are checked on the server, like every other shape here.
Traffic to the gateway itself (``LAN_LOCAL``, ``LANv6_LOCAL``) is left to the controller's
defaults but for the one-way zones' DNS drop, and so is the controller's anti-spoofing for IPv6
sources; both are checked on the server too.
"""

from __future__ import annotations

import json
from dataclasses import replace

from ..ir import NetworkIR, Rule, Selector, ipv6_form
from .base import Adapter, AdapterError, Rendered

PREFIX = "hnx-"
RULE_BASE = 2000
ZONES_GROUP = PREFIX + "zones"  # the address group of every zone's subnet (``+ "6"``: prefixes)
NOTE = "dry-run payload; live application is SERVER-only (see docs/network-model.md)"


def _doc(kind: str, objects: list[dict], ir: NetworkIR, extra: dict | None = None) -> str:
    body = {
        "adapter": "unifi",
        "dry_run": True,
        "site": ir.site_id,
        "kind": kind,
        "note": NOTE,
        "objects": objects,
        **(extra or {}),
    }
    return json.dumps(body, indent=2) + "\n"


def net_ref(zone: str) -> str:
    return "${network:" + PREFIX + zone + "}"


def group_ref(name: str) -> str:
    return "${firewallgroup:" + name + "}"


def _name(rule: Rule) -> str:
    return PREFIX + rule.id.replace("[", "-").replace("]", "").replace(":", "-")


class UnifiAdapter(Adapter):
    name = "unifi"
    roles = frozenset({"network", "switch"})
    summary = "DRY-RUN JSON payloads for networks/VLANs, firewall rules and switch ports (no calls)"

    def render(self, ir: NetworkIR) -> Rendered:
        files: Rendered = {
            "controller.json": self._controller(ir),
            "networks.json": _doc("networkconf", self._networks(ir), ir),
            "firewall-rules.json": _doc(
                "firewallrule", self._rules(ir), ir, {"groups": self._groups(ir)}
            ),
        }
        if ir.switches:
            profiles, ports = self._switches(ir)
            files["port-profiles.json"] = _doc("portconf", profiles, ir)
            files["switch-ports.json"] = _doc("switch-port-override", ports, ir)
        return dict(sorted(files.items()))

    def _controller(self, ir: NetworkIR) -> str:
        body = {
            "adapter": "unifi",
            "dry_run": True,
            "note": NOTE,
            "site": ir.site_id,
            "controller": {
                "endpoint": ir.router.mgmt_alias,
                "tls_pin": ir.router.tls_pin,
                "auth": ir.router.auth,
            },
        }
        return json.dumps(body, indent=2) + "\n"

    def _networks(self, ir: NetworkIR) -> list[dict]:
        pools = {p.zone: p for p in ir.pools}
        out = []
        for i in ir.interfaces:
            obj = {
                "name": PREFIX + i.zone,
                "purpose": "corporate",
                "enabled": True,
                "networkgroup": "LAN",
                "vlan_enabled": True,
                "vlan": i.vlan_id,
                "ip_subnet": f"{i.address}/{i.prefixlen}",
                "domain_name": ir.domain,
            }
            p = pools.get(i.zone)
            if p:
                obj.update(
                    dhcpd_enabled=True,
                    dhcpd_start=p.start,
                    dhcpd_stop=p.end,
                    dhcpd_leasetime=p.lease_hours * 3600,
                )
                if p.dns_servers:
                    obj["dhcpd_dns_enabled"] = True
                    for n, addr in enumerate(p.dns_servers[:4], 1):
                        obj[f"dhcpd_dns_{n}"] = addr
            else:
                obj["dhcpd_enabled"] = False
            if i.subnet6:
                obj.update(
                    ipv6_interface_type="static",
                    ipv6_subnet=f"{i.address6}/{i.subnet6.split('/')[1]}",
                    ipv6_ra_enabled=True,
                )
            out.append(obj)
        return out

    def _rules(self, ir: NetworkIR) -> list[dict]:
        out = self._ruleset(ir, list(ir.policy.rules), "")
        if ir.policy.zones6:
            six = [f for f in (ipv6_form(r, ir.policy.zones6) for r in ir.policy.rules) if f]
            out += self._ruleset(ir, six, "v6")
        return out

    def _groups(self, ir: NetworkIR) -> list[dict]:
        """The address groups the rules name: every zone's subnet, and every zone's prefix."""
        out = [
            {
                "name": ZONES_GROUP,
                "group_type": "address-group",
                "group_members": list(ir.policy.zones.values()),
            }
        ]
        if ir.policy.zones6:
            out.append(
                {
                    "name": ZONES_GROUP + "6",
                    "group_type": "ipv6-address-group",
                    "group_members": list(ir.policy.zones6.values()),
                }
            )
        return out

    def _ruleset(self, ir: NetworkIR, rules: list[Rule], v6: str) -> list[dict]:
        """One family's rules: ``v6`` is "" for IPv4 and "v6" for IPv6 (the rule set names)."""
        lan = f"LAN{v6}_IN"
        base = RULE_BASE  # each family's rules are their own rule sets, so both start at the base
        last = base + 999  # the default-deny's index: every other rule must come before it
        proto = "protocol_v6" if v6 else "protocol"
        tag = f"{v6}-" if v6 else ""
        out: list[dict] = [
            {
                "name": PREFIX + tag + "allow-established",
                "enabled": True,
                "ruleset": lan,
                "rule_index": base,
                "action": "accept",
                proto: "all",
                "state_established": True,
                "state_related": True,
                "logging": False,
            },
            {
                "name": PREFIX + tag + "drop-invalid",
                "enabled": True,
                "ruleset": lan,
                "rule_index": base + 1,
                "action": "drop",
                proto: "all",
                "state_invalid": True,
                "logging": False,
            },
        ]
        index = base

        def take() -> int:
            nonlocal index
            index += 10
            if index >= last:
                raise AdapterError(
                    f"{self.name}: the {'IPv6' if v6 else 'IPv4'} rules need more indexes than "
                    f"{base + 10} to {last - 1} hold, so some would land behind the default-deny "
                    f"at {last}; merge zone rules or service_exceptions"
                )
            return index

        for rule in rules:
            if rule.dst.kind == "internet" and rule.action == "allow":
                # LAN_IN also sees routed LAN -> WAN traffic, so the default-deny below would
                # drop it: the zone may reach what is not a zone, and no zone it is not allowed
                out.append(self._zones_drop(rule, take(), v6))
                out.append(self._rule(replace(rule, dst=Selector("any")), take(), v6))
                continue
            if v6 and rule.dst.kind == "intranet" and rule.action == "allow":
                # the controller's LANv6_IN also sees routed LAN -> WAN traffic, so the accept
                # alone would let this source reach the internet: drop it on the way out first
                out.append(self._internet_drop(rule, take(), v6))
            out.append(self._rule(rule, take(), v6))
        zones = ir.policy.zones6 if v6 else ir.policy.zones
        for zid in ir.policy.one_way:
            if zid in zones:
                out.append(self._no_resolver(zid, take(), v6))
        out.append(
            {
                "name": PREFIX + tag + "default-deny",
                "enabled": True,
                "ruleset": lan,
                "rule_index": last,
                "action": "drop",
                proto: "all",
                "logging": False,
                "description": "firewall.default_action: deny",
            }
        )
        return out

    def _no_resolver(self, zone: str, index: int, v6: str) -> dict:
        """The ``LAN_LOCAL`` drop of DNS from a one-way zone: the gateway answers DNS on every
        network by default, and a resolver would carry the zone's data out in queries."""
        return {
            "name": PREFIX + (f"{v6}-" if v6 else "") + f"one-way-{zone}-no-dns",
            "enabled": True,
            "ruleset": f"LAN{v6}_LOCAL",
            "rule_index": index,
            "action": "drop",
            "protocol_v6" if v6 else "protocol": "tcp_udp",
            "src_networkconf_type": "NETv6" if v6 else "NETv4",
            "src_networkconf_id": net_ref(zone),
            "dst_port": "53",
            "logging": False,
            "description": f"one-way zone {zone}: no resolver",
        }

    def _zones_drop(self, rule: Rule, index: int, v6: str) -> dict:
        """Ahead of a zone's internet accept: drop what it sends to any zone's network, which
        only an earlier rule may allow."""
        return {
            "name": _name(rule) + "-zones",
            "enabled": True,
            "ruleset": f"LAN{v6}_IN",
            "rule_index": index,
            "action": "drop",
            "protocol_v6" if v6 else "protocol": "all",
            "src_networkconf_type": "NETv6" if v6 else "NETv4",
            "src_networkconf_id": net_ref(rule.src.name),
            "dst_firewallgroup_ids": [group_ref(ZONES_GROUP + ("6" if v6 else ""))],
            "logging": False,
            "description": f"{rule.comment}: no zone but the rules above allow",
        }

    def _internet_drop(self, rule: Rule, index: int, v6: str) -> dict:
        """The ``WANv6_OUT`` drop for the source of an ``intranet`` allow: its prefix is not global,
        so nothing it sends belongs on the internet."""
        return {
            "name": _name(rule) + "-wan",
            "enabled": True,
            "ruleset": f"WAN{v6}_OUT",
            "rule_index": index,
            "action": "drop",
            "protocol_v6": "all",
            "src_networkconf_type": "NETv6",
            "src_networkconf_id": net_ref(rule.src.name),
            "logging": False,
            "description": f"{rule.comment} (never the internet: no global prefix)",
        }

    def _rule(self, rule: Rule, index: int, v6: str = "") -> dict:
        net = "NETv6" if v6 else "NETv4"
        protocol = rule.protocol if rule.protocol != "any" else "all"
        if v6 and protocol == "icmp":
            protocol = "icmpv6"
        obj: dict = {
            "name": _name(rule),
            "enabled": True,
            "ruleset": f"WAN{v6}_OUT" if rule.dst.kind == "internet" else f"LAN{v6}_IN",
            "rule_index": index,
            "action": "accept" if rule.action == "allow" else "drop",
            "protocol_v6" if v6 else "protocol": protocol,
            "src_networkconf_type": net,
            "src_networkconf_id": net_ref(rule.src.name),
            "logging": False,
            "description": rule.comment,
        }
        if rule.dst.kind == "zone":
            obj["dst_networkconf_type"] = net
            obj["dst_networkconf_id"] = net_ref(rule.dst.name)
        elif rule.dst.kind == "host":
            obj["dst_address"] = rule.dst.cidrs[0].split("/")[0]
        elif rule.dst.kind not in ("any", "internet", "intranet"):
            raise ValueError(f"unknown selector kind {rule.dst.kind!r}")
        if rule.ports:
            obj["dst_port"] = ",".join(str(p) for p in rule.ports)
        return obj

    def _switches(self, ir: NetworkIR) -> tuple[list[dict], list[dict]]:
        zone_of = {i.vlan_id: i.zone for i in ir.interfaces}
        profiles: dict[str, dict] = {}
        ports: list[dict] = []
        for sw in ir.switches:
            for p in sw.ports:
                if p.kind == "mirror":
                    # the controller copies one source port to a mirror port: never drop the rest
                    if len(p.mirror_from) != 1:
                        raise AdapterError(
                            f"{self.name}: switch {sw.id} port {p.port} mirrors ports "
                            f"{list(p.mirror_from)}; the controller copies exactly one source "
                            "port to a mirror port"
                        )
                    ports.append(
                        {
                            "name": f"{sw.id}/{p.port}",
                            "device": sw.id,
                            "device_mac": sw.mac,
                            "port_idx": p.port,
                            "op_mode": "mirror",
                            "mirror_port_idx": p.mirror_from[0],
                        }
                    )
                    continue
                if p.kind == "access":
                    pname = f"{PREFIX}access-{zone_of[p.native_vlan]}"
                    profiles.setdefault(
                        pname,
                        {
                            "name": pname,
                            "forward": "native",
                            "native_networkconf_id": net_ref(zone_of[p.native_vlan]),
                        },
                    )
                else:
                    tag = "-".join(zone_of[v] for v in p.tagged_vlans)
                    native = zone_of[p.native_vlan] if p.native_vlan else "none"
                    pname = f"{PREFIX}trunk-{native}-{tag}"
                    obj = {
                        "name": pname,
                        "forward": "customize",
                        "tagged_networkconf_ids": [net_ref(zone_of[v]) for v in p.tagged_vlans],
                    }
                    if p.native_vlan:
                        obj["native_networkconf_id"] = net_ref(zone_of[p.native_vlan])
                    profiles.setdefault(pname, obj)
                ports.append(
                    {
                        "name": f"{sw.id}/{p.port}",
                        "device": sw.id,
                        "device_mac": sw.mac,
                        "port_idx": p.port,
                        "portconf": pname,
                    }
                )
        return [profiles[k] for k in sorted(profiles)], ports
