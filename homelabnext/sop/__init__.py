# SPDX-License-Identifier: Apache-2.0
"""Per-system SOP pages: one Markdown page per service-registry row, machine-known fields
prefilled, human sections left as marked TODO blocks.  ``hnx docs systems``; see
``docs/systems.md``."""

from __future__ import annotations

from .pages import (
    SECTIONS,
    CheckReport,
    check_pages,
    generate_pages,
    render_page,
    render_template,
)

__all__ = [
    "SECTIONS",
    "CheckReport",
    "check_pages",
    "generate_pages",
    "render_page",
    "render_template",
]
