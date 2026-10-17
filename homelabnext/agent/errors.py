# SPDX-License-Identifier: Apache-2.0
"""Error types for the agent package.  Every message names what to fix."""

from __future__ import annotations


class AgentError(ValueError):
    """Base class: the input cannot produce a valid profile or pack."""


class SpecError(AgentError):
    """The profile spec or manifest is malformed."""


class MissingPartError(AgentError):
    """Logical ids the profile needs that the parts library cannot supply."""

    def __init__(self, missing: list[str]) -> None:
        self.missing = sorted(missing)
        super().__init__(
            "parts library has no entry for: "
            + ", ".join(self.missing)
            + " (add them to the library, or remove them from the profile spec)"
        )


class CeilingViolation(AgentError):
    """The profile asks for more than its permission ceiling allows."""

    def __init__(self, problems: list[str]) -> None:
        self.problems = list(problems)
        super().__init__(
            "profile exceeds its ceiling: "
            + "; ".join(self.problems)
            + " (lower the grant or raise the ceiling in a reviewed change)"
        )


class BudgetError(AgentError):
    """Budgets are missing, malformed or above the ceiling's budget caps."""
