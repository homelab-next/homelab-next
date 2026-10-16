# SPDX-License-Identifier: Apache-2.0
"""Golden tasks: prompt, expected structure, scoring function, runner and report."""

from .report import Report, TaskResult
from .runner import Completer, client_completer, run_suite
from .scorers import SCORERS, ScoreError, score
from .tasks import Suite, Task, TaskError, load_suite, parse_suite

__all__ = [
    "SCORERS",
    "Completer",
    "Report",
    "ScoreError",
    "Suite",
    "Task",
    "TaskError",
    "TaskResult",
    "client_completer",
    "load_suite",
    "parse_suite",
    "run_suite",
    "score",
]
