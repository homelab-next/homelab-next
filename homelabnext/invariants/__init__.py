# SPDX-License-Identifier: Apache-2.0
"""Invariants runner: statement + observable + expected result, run live, evidence kept."""

from .api import (
    Check,
    CheckResult,
    Context,
    Registry,
    default_registry,
    load_directory,
    load_entry_points,
)
from .runner import (
    EXIT_COULD_NOT_MEASURE,
    EXIT_FAIL,
    EXIT_PASS,
    diff_state,
    overall_exit,
    page_changes,
    run_criteria,
)

__all__ = [
    "EXIT_COULD_NOT_MEASURE",
    "EXIT_FAIL",
    "EXIT_PASS",
    "Check",
    "CheckResult",
    "Context",
    "Registry",
    "default_registry",
    "diff_state",
    "load_directory",
    "load_entry_points",
    "overall_exit",
    "page_changes",
    "run_criteria",
]
