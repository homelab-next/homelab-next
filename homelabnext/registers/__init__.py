# SPDX-License-Identifier: Apache-2.0
"""Registers: YAML sources of truth for lessons, runbooks and invariants.

Each register has a fatal schema (an entry without a root cause, a preventive control or a
falsifiable verification aborts the render) and a generator that emits one self-contained
static HTML page plus a JSON document. See ``python -m homelabnext.registers --help``.
"""

from .render import build_all, render_invariants, render_lessons, render_runbooks
from .schema import RegisterError, validate_invariants, validate_lessons, validate_runbooks

__all__ = [
    "RegisterError",
    "build_all",
    "render_invariants",
    "render_lessons",
    "render_runbooks",
    "validate_invariants",
    "validate_lessons",
    "validate_runbooks",
]
