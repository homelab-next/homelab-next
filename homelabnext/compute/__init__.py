# SPDX-License-Identifier: Apache-2.0
"""Compute (guest) model: loader, semantic validation and renderers.

``load_fleet(dir, zones)`` -> :class:`Fleet`; ``render(fleet, target)`` -> ``{path: text}``.
"""

from .loader import load_fleet, load_guests, load_keys, load_nodes, load_policies
from .model import (
    KNOWN_CAPABILITIES,
    ComputeError,
    Fleet,
    Guest,
    Problem,
    ZoneFlow,
    ZoneInfo,
    ZoneLookup,
)
from .plan import Plan, plan
from .render import TARGETS, render
from .validate import validate
from .zones import MappingZones, SiteAdapter, load_zones_file, open_site, site_flows

__all__ = [
    "KNOWN_CAPABILITIES",
    "TARGETS",
    "ComputeError",
    "Fleet",
    "Guest",
    "MappingZones",
    "Plan",
    "Problem",
    "SiteAdapter",
    "ZoneFlow",
    "ZoneInfo",
    "ZoneLookup",
    "load_fleet",
    "load_guests",
    "load_keys",
    "load_nodes",
    "load_policies",
    "load_zones_file",
    "open_site",
    "plan",
    "render",
    "site_flows",
    "validate",
]
