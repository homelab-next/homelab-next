# SPDX-License-Identifier: Apache-2.0
"""Behavioural novelty baselines (ADR-0036; docs/novelty.md).

A deterministic analyzer: per-entity first-seen baselines recomputed from the lake for an
injected ``as_of`` (:mod:`.engine`), declared by a spec (:mod:`.spec`), read through the lake's
TLP ceiling as the reader ``analyzer:novelty`` and written as advisory rows of
``novelty_finding``; :func:`corroborate` is the one path from them to escalation.
"""

from __future__ import annotations

from .corroborate import Candidate, corroborate
from .engine import SOURCE, TABLE, ProfileResult, batch_id, run, score_profile, windows
from .spec import Profile, Spec, SpecError, load_spec, parse_spec

#: the reader id the analyzer reads the lake as (its ceiling is declared in tlp_readers)
READER = "analyzer:novelty"

__all__ = [
    "READER",
    "SOURCE",
    "TABLE",
    "Candidate",
    "Profile",
    "ProfileResult",
    "Spec",
    "SpecError",
    "batch_id",
    "corroborate",
    "load_spec",
    "parse_spec",
    "run",
    "score_profile",
    "windows",
]
