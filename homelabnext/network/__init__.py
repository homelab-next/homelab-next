# SPDX-License-Identifier: Apache-2.0
"""Site / network model: one vendor-neutral document, rendered by interchangeable adapters.

Pipeline::

    site.yml + services.yml --load--> validate --build_ir--> NetworkIR --adapter--> files --plan--> diff

* :mod:`homelabnext.network.loader`    read the site document, resolve the registry
* :mod:`homelabnext.network.validate`  schema + semantic checks (fail closed, never repair)
* :mod:`homelabnext.network.ir`        vendor-neutral VLAN/interface plan and firewall policy
* :mod:`homelabnext.network.adapters`  renderers (linux, dnsmasq, zonefile, unifi dry-run, opnsense deferred)
* :mod:`homelabnext.network.plan`      what would change, as a diff against an existing tree

Everything here is pure: no network access, no credentials, no clock.  Applying a rendered
result to a live device is SERVER-only and is not implemented (see ``docs/network-model.md``).
"""

from __future__ import annotations

from .ir import NetworkIR, build_ir
from .loader import SiteError, load_site
from .validate import Report, validate

__all__ = ["NetworkIR", "Report", "SiteError", "build_ir", "load_site", "validate"]
