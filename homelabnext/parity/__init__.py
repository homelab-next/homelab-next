# SPDX-License-Identifier: Apache-2.0
"""Parity tools: prove the new implementation behaves like the old one before cutover.

Standard library plus the lake and notify libraries; no extra needed. See ``docs/swap.md``.
"""

from __future__ import annotations

from .events import EventRules, compare_event_streams
from .notifications import NotifyRules, compare_notifications
from .queries import ParityQuery, compare_queries, compare_tables
from .report import Check, ParityReport
from .rows import RowDiff, RowRules, Sample, Tolerance, diff_rows
from .schema import Drift, schema_drift

__all__ = [
    "Check",
    "Drift",
    "EventRules",
    "NotifyRules",
    "ParityQuery",
    "ParityReport",
    "RowDiff",
    "RowRules",
    "Sample",
    "Tolerance",
    "compare_event_streams",
    "compare_notifications",
    "compare_queries",
    "compare_tables",
    "diff_rows",
    "schema_drift",
]
