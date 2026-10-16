# SPDX-License-Identifier: Apache-2.0
"""OPNsense adapter: DEFERRED.

Choice made for the first drop: the interface is registered so a site document may select it and
the CLI answers with a clear message, but no config-XML is rendered.  Golden files for XML that
cannot be loaded into a real firewall in CI would prove only that we can print XML; the adapter
returns when a conformance run against a real or containerised instance can back it (SERVER).
The planned shape: ``<vlans>``, ``<interfaces>``, ``<dhcpd>`` and ``<filter>`` fragments, one
file each, rendered from the same :class:`~homelabnext.network.ir.NetworkIR` the other adapters use.
"""

from __future__ import annotations

from ..ir import NetworkIR
from .base import Adapter, AdapterDeferred, Rendered


class OpnsenseAdapter(Adapter):
    name = "opnsense"
    status = "deferred"
    summary = "deferred: config-XML fragments need a real instance to be provable"

    def render(self, ir: NetworkIR) -> Rendered:
        raise AdapterDeferred(
            self.name,
            "no config-XML is rendered in this release; use `linux` or `unifi` "
            "(see docs/network-model.md)",
        )
