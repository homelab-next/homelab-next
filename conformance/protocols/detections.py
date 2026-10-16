# SPDX-License-Identifier: Apache-2.0
"""Contract for ``detections``: an engine that evaluates detection rules on events.

Subject = :class:`DetectionTarget`: an ``engine`` with ``matches(rule, event) -> bool`` (the
``homelabnext.detections.runner.Engine`` protocol) and the ``root`` directory holding the rules
(``sigma/``) and fixtures (``fixtures/<slug>/{must_fire,must_not_fire,evasion}/``).  A SIEM
adapter implements ``matches`` by shipping the event to the engine's rule tester.
"""

from __future__ import annotations

from pathlib import Path
from typing import Protocol, runtime_checkable

from homelabnext.detections.runner import Engine

__all__ = ["DetectionTarget", "Engine"]


@runtime_checkable
class DetectionTarget(Protocol):
    engine: Engine
    root: Path
