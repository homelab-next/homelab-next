# SPDX-License-Identifier: Apache-2.0
"""Scope guard for writer tools: refuse to file work about out-of-scope targets."""

from .guard import (
    Decision,
    ScopeDenied,
    ScopeGuard,
    Target,
    guarded,
    targets_from_fleet,
    targets_from_services,
)
from .policy import PolicyError, ScopePolicy

__all__ = [
    "Decision",
    "PolicyError",
    "ScopeDenied",
    "ScopeGuard",
    "ScopePolicy",
    "Target",
    "guarded",
    "targets_from_fleet",
    "targets_from_services",
]
