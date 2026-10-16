# SPDX-License-Identifier: Apache-2.0
"""Decision cascade: deterministic floor, small and large classifiers, LLM, then a human."""

from .adapter import PROTOCOL, SystemOneServer, handle_decide, validate_request
from .cascade import Cascade, CascadeConfigError, Decision, Step
from .faults import FaultyTier
from .impact_scan import AhoCorasick, ImpactScanner, ScanResult
from .replay import (
    GateResult,
    Record,
    ReplayReport,
    baseline_from_records,
    compare,
    gate,
    load_records,
    replay,
)
from .spec import DecisionSpec, SpecError, load_spec, parse_spec
from .tiers import CallableTier, Item, ModelTier, TierAnswer, TierError, TierTimeout, regex_floor

__all__ = [
    "PROTOCOL",
    "AhoCorasick",
    "CallableTier",
    "Cascade",
    "CascadeConfigError",
    "Decision",
    "DecisionSpec",
    "FaultyTier",
    "GateResult",
    "ImpactScanner",
    "Item",
    "ModelTier",
    "Record",
    "ReplayReport",
    "ScanResult",
    "SpecError",
    "Step",
    "SystemOneServer",
    "TierAnswer",
    "TierError",
    "TierTimeout",
    "baseline_from_records",
    "compare",
    "gate",
    "handle_decide",
    "load_records",
    "load_spec",
    "parse_spec",
    "regex_floor",
    "replay",
    "validate_request",
]
