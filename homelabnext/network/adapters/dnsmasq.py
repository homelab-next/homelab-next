# SPDX-License-Identifier: Apache-2.0
"""dnsmasq-style outputs: DHCP pools and reservations, plus local DNS records.

Three drop-in files for ``/etc/dnsmasq.d``.  Reservations pin a host by hardware address when the
site document names one, otherwise by the client-supplied host name (dnsmasq matches either).
"""

from __future__ import annotations

from ..ir import NetworkIR
from .base import Adapter, Rendered, header


class DnsmasqAdapter(Adapter):
    name = "dnsmasq"
    summary = "dnsmasq drop-ins: DHCP pools, DHCP reservations, local DNS records"

    def render(self, ir: NetworkIR) -> Rendered:
        return {  # already in sorted order: keep it so
            "etc/dnsmasq.d/10-hnx-dhcp.conf": self._pools(ir),
            "etc/dnsmasq.d/20-hnx-reservations.conf": self._reservations(ir),
            "etc/dnsmasq.d/30-hnx-dns.conf": self._records(ir),
        }

    def _pools(self, ir: NetworkIR) -> str:
        out = [header("dnsmasq"), f"domain={ir.domain}\nlocal=/{ir.domain}/\n"]
        for p in ir.pools:
            out.append(f"\n# zone: {p.zone}\n")
            out.append(f"dhcp-range=set:{p.zone},{p.start},{p.end},{p.netmask},{p.lease_hours}h\n")
            out.append(f"dhcp-option=tag:{p.zone},option:router,{p.gateway}\n")
            if p.dns_servers:
                out.append(
                    f"dhcp-option=tag:{p.zone},option:dns-server,{','.join(p.dns_servers)}\n"
                )
            out.append(f"dhcp-option=tag:{p.zone},option:domain-name,{p.domain}\n")
        return "".join(out)

    def _reservations(self, ir: NetworkIR) -> str:
        out = [header("dnsmasq")]
        for r in ir.reservations:
            key = f"{r.mac},{r.host}" if r.mac else r.host
            out.append(f"dhcp-host={key},{r.address}\n")
        return "".join(out)

    def _records(self, ir: NetworkIR) -> str:
        out = [header("dnsmasq"), f"local-ttl={ir.ttl}\n"]
        for rec in ir.dns_records:
            if rec.type == "A" and rec.origin == "split-horizon":
                continue
            if rec.type == "A":
                out.append(f"host-record={rec.fqdn},{rec.value}\n")
            else:
                out.append(f"cname={rec.fqdn},{rec.value.rstrip('.')}\n")
        overrides = [r for r in ir.dns_records if r.origin == "split-horizon"]
        if overrides:
            out.append("\n# split horizon: public names answered with the internal address\n")
            for rec in overrides:
                out.append(f"address=/{rec.fqdn}/{rec.value}\n")
        return "".join(out)
