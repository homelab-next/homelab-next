# SPDX-License-Identifier: Apache-2.0
"""The swap kit: run the nine-step replacement procedure with gates, evidence and a record.

``hnx swap`` (``cli.py``) drives :class:`SwapRunner`; see ``docs/swap.md`` and ADR-0005.
The record needs ``jsonschema`` (extra ``schema``); everything else is standard library + PyYAML.
"""

from __future__ import annotations

from .backend import Backend, ManualBackend, Outcome
from .decommission import Finding, Retired, retired_from_record, scan
from .dualwrite import Divergence, DualWriter
from .flip import Change, FlipError, FlipPlan, flip_text, plan_flip
from .lakebackend import LakeBackend
from .machine import (
    STEP_SPECS,
    AdvanceResult,
    Gate,
    GateFailed,
    RollbackRefused,
    SwapError,
    SwapRunner,
    plan_text,
)
from .record import STEPS, RecordError

__all__ = [
    "STEPS",
    "STEP_SPECS",
    "AdvanceResult",
    "Backend",
    "Change",
    "Divergence",
    "DualWriter",
    "Finding",
    "FlipError",
    "FlipPlan",
    "Gate",
    "GateFailed",
    "LakeBackend",
    "ManualBackend",
    "Outcome",
    "RecordError",
    "Retired",
    "RollbackRefused",
    "SwapError",
    "SwapRunner",
    "flip_text",
    "plan_flip",
    "plan_text",
    "retired_from_record",
    "scan",
]
