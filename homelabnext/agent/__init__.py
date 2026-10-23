# SPDX-License-Identifier: Apache-2.0
"""Agent building blocks: profile compiler, reader rule, reader->actor handoff, screener,
context-pack assembler with linked knowledge (``include:`` rules), report validator, controlled
memory, access block, the project's terms and keyring.

Vendor-neutral and fake-backed: parts come from a :class:`PartsLibrary` over the logical-id
resolver, nothing here touches a network or a model.  Contracts: ``schemas/agent/``; guide:
``docs/agent.md``.
"""

from .access import ACCESS_SECTION, access_block, render_access_block, start_session
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
    CatalogViolation,
    CeilingViolation,
    IncludeViolation,
    MissingPartError,
    ReaderViolation,
    SpecError,
)
from .handoff import Accepted, Handoff, HandoffError, HandoffRefused
from .keyring import build_keyring
from .memory import MemoryAccessError, MemoryStore, MemoryUpdateError
from .pack import TIERS, assemble_pack
from .readers import ToolClasses, grant_problems, lint_paths, reader_problems
from .report import validate_report
from .screen import Screener, screen_text
from .terms import TERMS_SECTION, terms_text

__all__ = [
    "ACCESS_SECTION",
    "BUDGET_KEYS",
    "TERMS_SECTION",
    "TIERS",
    "TIER_RANK",
    "Accepted",
    "AgentError",
    "BudgetError",
    "CatalogViolation",
    "CeilingPolicy",
    "CeilingViolation",
    "Handoff",
    "HandoffError",
    "HandoffRefused",
    "IncludeViolation",
    "MemoryAccessError",
    "MemoryStore",
    "MemoryUpdateError",
    "MissingPartError",
    "Part",
    "PartsLibrary",
    "ReaderViolation",
    "Screener",
    "SpecError",
    "ToolClasses",
    "access_block",
    "assemble_pack",
    "build_keyring",
    "canonical_json",
    "check_budgets",
    "check_ceiling",
    "compile_profile",
    "digest_of",
    "grant_problems",
    "lint_paths",
    "profile_digest",
    "reader_problems",
    "render_access_block",
    "screen_text",
    "sha256_text",
    "start_session",
    "terms_text",
    "validate_report",
    "verify_profile",
]
