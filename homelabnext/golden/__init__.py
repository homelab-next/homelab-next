# SPDX-License-Identifier: Apache-2.0
"""Golden tasks: prompt, expected structure, scoring function, runner and report."""

from .report import Report, TaskResult
from .runner import (
    Completer,
    Decider,
    client_completer,
    client_decider,
    run_decision_suite,
    run_suite,
)
from .scorers import SCORERS, ScoreError, score
from .tasks import Suite, Task, TaskError, load_suite, parse_suite

__all__ = [
    "SCORERS",
    "Completer",
    "Decider",
    "Report",
    "ScoreError",
    "Suite",
    "Task",
    "TaskError",
    "TaskResult",
    "client_completer",
    "client_decider",
    "load_suite",
    "parse_suite",
    "run_decision_suite",
    "run_suite",
    "score",
]
