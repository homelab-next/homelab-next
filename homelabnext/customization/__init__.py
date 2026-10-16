# SPDX-License-Identifier: Apache-2.0
"""Customizations: every lab- or vendor-specific deviation, held outside the core.

See ``docs/customization.md``. Public surface: :func:`load_all`, :func:`lint`,
:func:`build_plan`, :func:`render_register`.
"""

from .apply import PLAN_SCHEMA, build_plan, write_plan
from .lint import RULES, lint
from .loader import Settings, load_all, load_file, load_tree, resolve_settings
from .model import Customization, Finding, extension_points
from .register import build_register, render_register
from .resolve import Conflict, active, detect_conflicts
from .universe import Universe, discover

__all__ = [
    "PLAN_SCHEMA",
    "RULES",
    "Conflict",
    "Customization",
    "Finding",
    "Settings",
    "Universe",
    "active",
    "build_plan",
    "build_register",
    "detect_conflicts",
    "discover",
    "extension_points",
    "lint",
    "load_all",
    "load_file",
    "load_tree",
    "render_register",
    "resolve_settings",
    "write_plan",
]
