# SPDX-License-Identifier: Apache-2.0
"""Operator tools over agent memory (ADR-0037 decision 12): :class:`MemoryAdmin` and the
:class:`OperatorPrincipal` it takes.  Outside :mod:`homelabnext.agent` on purpose: the agent
runtime, the broker and orchestration never import this package (a test holds it), and only the
``hnx agent memory`` command builds an :class:`OperatorPrincipal`
(:func:`~homelabnext.memory_admin.principal.invoking_operator`)."""

from .admin import MemoryAdmin
from .principal import (
    DEFAULT_OPERATORS,
    MemoryAdminError,
    OperatorConfig,
    OperatorPrincipal,
    OperatorsUnreadable,
    load_operators,
    require_operator,
)

__all__ = [
    "DEFAULT_OPERATORS",
    "MemoryAdmin",
    "MemoryAdminError",
    "OperatorConfig",
    "OperatorPrincipal",
    "OperatorsUnreadable",
    "load_operators",
    "require_operator",
]
