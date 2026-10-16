# SPDX-License-Identifier: Apache-2.0
"""Zone-file style output (RFC 1035 master files) for any authoritative server.

One file per authoritative domain, plus one small file per split-horizon override domain.  The
SOA serial is ``adapters.options.zonefile.serial`` when given, otherwise derived from the content
so rendering stays deterministic; production callers should pass a monotonic serial.
"""

from __future__ import annotations

import hashlib

from ..ir import DnsRecord, NetworkIR
from .base import Adapter, AdapterError, Rendered, header


def _rel(fqdn: str, zone: str) -> str:
    if fqdn == zone:
        return "@"
    return fqdn[: -(len(zone) + 1)]


def _derived_serial(zone: str, recs: list[DnsRecord]) -> int:
    """Content-derived serial: only this zone's records matter, so a firewall change never bumps it."""
    blob = (
        zone
        + "\n"
        + "\n".join(
            f"{r.fqdn} {r.type} {r.value}"
            for r in sorted(recs, key=lambda r: (r.fqdn, r.type, r.value))
        )
    )
    return int(hashlib.sha256(blob.encode("utf-8")).hexdigest()[:8], 16) % 4294967294 + 1


def _in_zone(fqdn: str, zone: str) -> bool:
    return fqdn == zone or fqdn.endswith("." + zone)


class ZonefileAdapter(Adapter):
    name = "zonefile"
    summary = "RFC 1035 zone files for the authoritative domains and split-horizon overrides"

    def render(self, ir: NetworkIR) -> Rendered:
        if not ir.resolvers:
            raise AdapterError(
                "zonefile: the site declares no dns.resolvers; nothing is authoritative"
            )
        pinned = ir.options["zonefile"].get("serial")
        zones: dict[str, list[DnsRecord]] = {}
        for r in ir.resolvers:
            for z in r.authoritative_for:
                zones.setdefault(z, [])
        ns = [(r.host, r.address) for r in ir.resolvers if r.authoritative_for]
        files: Rendered = {}
        overrides: dict[str, list[DnsRecord]] = {}
        for rec in ir.dns_records:
            if rec.origin == "split-horizon":
                overrides.setdefault(rec.fqdn.split(".", 1)[1], []).append(rec)
                continue
            owners = [z for z in zones if _in_zone(rec.fqdn, z)]
            if owners:
                zones[max(owners, key=len)].append(rec)
        for zone, recs in sorted(zones.items()):
            files[f"var/lib/hnx/zones/{zone}.zone"] = self._zone(
                ir, zone, recs, ns, pinned or _derived_serial(zone, recs)
            )
        for zone, recs in sorted(overrides.items()):
            files[f"var/lib/hnx/zones/{zone}.split-horizon.zone"] = self._zone(
                ir, zone, recs, ns, pinned or _derived_serial(zone, recs), owner_domain=ir.domain
            )
        return files

    def _zone(self, ir, zone, recs, ns, serial, owner_domain=None) -> str:
        base = owner_domain or zone
        mname = f"{ns[0][0]}.{ir.domain}."
        out = [header("zonefile", ";"), f"$ORIGIN {zone}.\n$TTL {ir.ttl}\n"]
        out.append(f"@ IN SOA {mname} hostmaster.{base}. ( {serial} 3600 600 604800 {ir.ttl} )\n")
        for host, _addr in ns:
            out.append(f"@ IN NS {host}.{ir.domain}.\n")
        for rec in sorted(recs, key=lambda r: (r.fqdn, r.type)):
            value = rec.value if rec.type == "A" else rec.value.rstrip(".") + "."
            out.append(f"{_rel(rec.fqdn, zone)} IN {rec.type} {value}\n")
        return "".join(out)
