# SPDX-License-Identifier: Apache-2.0
"""Agent building blocks: profile compiler, reader rule, screener, context-pack assembler,
report validator.

Vendor-neutral and fake-backed: parts come from a :class:`PartsLibrary` over the logical-id
resolver, nothing here touches a network or a model.  Contracts: ``schemas/agent/``; guide:
``docs/agent.md``.
"""

from .compiler import (
    BUDGET_KEYS,
    TIER_RANK,
    CeilingPolicy,
    Part,
    PartsLibrary,
    check_budgets,
    check_ceiling,
    compile_profile,
    profile_digest,
    verify_profile,
)
from .digest import canonical_json, digest_of, sha256_text
from .errors import (
    AgentError,
    BudgetError,
    CeilingViolation,
    MissingPartError,
    ReaderViolation,
    SpecError,
)
from .pack import TIERS, assemble_pack
from .readers import ToolClasses, lint_paths, reader_problems
from .report import validate_report
from .screen import Screener, screen_text

__all__ = [
    "BUDGET_KEYS",
    "TIERS",
    "TIER_RANK",
    "AgentError",
    "BudgetError",
    "CeilingPolicy",
    "CeilingViolation",
    "MissingPartError",
    "Part",
    "PartsLibrary",
    "ReaderViolation",
    "Screener",
    "SpecError",
    "ToolClasses",
    "assemble_pack",
    "canonical_json",
    "check_budgets",
    "check_ceiling",
    "compile_profile",
    "digest_of",
    "lint_paths",
    "profile_digest",
    "reader_problems",
    "screen_text",
    "sha256_text",
    "validate_report",
    "verify_profile",
]
