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
override names the source follows the controller UI and is checked on the server.  Objects that refer to each
other use ``${network:<name>}`` placeholders, resolved to controller ids at apply time.
"""

from __future__ import annotations

import json

from ..ir import NetworkIR, Rule
from .base import Adapter, Rendered

PREFIX = "hnx-"
RULE_BASE = 2000
NOTE = "dry-run payload; live application is SERVER-only (see docs/network-model.md)"


def _doc(kind: str, objects: list[dict], ir: NetworkIR) -> str:
    body = {
        "adapter": "unifi",
        "dry_run": True,
        "site": ir.site_id,
        "kind": kind,
        "note": NOTE,
        "objects": objects,
    }
    return json.dumps(body, indent=2) + "\n"


def net_ref(zone: str) -> str:
    return "${network:" + PREFIX + zone + "}"


class UnifiAdapter(Adapter):
    name = "unifi"
    summary = "DRY-RUN JSON payloads for networks/VLANs, firewall rules and switch ports (no calls)"

    def render(self, ir: NetworkIR) -> Rendered:
        files: Rendered = {
            "controller.json": self._controller(ir),
            "networks.json": _doc("networkconf", self._networks(ir), ir),
            "firewall-rules.json": _doc("firewallrule", self._rules(ir), ir),
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
            out.append(obj)
        return out

    def _rules(self, ir: NetworkIR) -> list[dict]:
        out: list[dict] = [
            {
                "name": PREFIX + "allow-established",
                "enabled": True,
                "ruleset": "LAN_IN",
                "rule_index": RULE_BASE,
                "action": "accept",
                "protocol": "all",
                "state_established": True,
                "state_related": True,
                "logging": False,
            },
            {
                "name": PREFIX + "drop-invalid",
                "enabled": True,
                "ruleset": "LAN_IN",
                "rule_index": RULE_BASE + 1,
                "action": "drop",
                "protocol": "all",
                "state_invalid": True,
                "logging": False,
            },
        ]
        index = RULE_BASE + 10
        for rule in ir.policy.rules:
            if rule.dst.kind == "internet" and rule.action == "allow":
                continue  # the controller's default LAN -> WAN behaviour already allows it
            out.append(self._rule(rule, index))
            index += 10
        out.append(
            {
                "name": PREFIX + "default-deny",
                "enabled": True,
                "ruleset": "LAN_IN",
                "rule_index": RULE_BASE + 999,
                "action": "drop",
                "protocol": "all",
                "logging": False,
                "description": "firewall.default_action: deny",
            }
        )
        return out

    def _rule(self, rule: Rule, index: int) -> dict:
        obj: dict = {
            "name": PREFIX + rule.id.replace("[", "-").replace("]", "").replace(":", "-"),
            "enabled": True,
            "ruleset": "WAN_OUT" if rule.dst.kind == "internet" else "LAN_IN",
            "rule_index": index,
            "action": "accept" if rule.action == "allow" else "drop",
            "protocol": rule.protocol if rule.protocol != "any" else "all",
            "src_networkconf_type": "NETv4",
            "src_networkconf_id": net_ref(rule.src.name),
            "logging": False,
            "description": rule.comment,
        }
        if rule.dst.kind == "zone":
            obj["dst_networkconf_type"] = "NETv4"
            obj["dst_networkconf_id"] = net_ref(rule.dst.name)
        elif rule.dst.kind == "host":
            obj["dst_address"] = rule.dst.cidrs[0].split("/")[0]
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
                    # validate allows unifi exactly one source per mirror port
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
