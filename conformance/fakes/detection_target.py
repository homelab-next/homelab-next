# SPDX-License-Identifier: Apache-2.0
"""``detections`` fake: the reference engine over the shipped rules and fixtures."""

from __future__ import annotations

from pathlib import Path

from homelabnext.detections.runner import FakeGenericEngine
from homelabnext.detections.sigma import load_mapping

DEFAULT_ROOT = Path(__file__).resolve().parents[2] / "detections"


class FakeDetectionTarget:
    features = frozenset()

    def __init__(self, root: Path | str | None = None) -> None:
        self.root = Path(root) if root else DEFAULT_ROOT
        mapping = self.root / "mappings" / "generic.yml"
        self.engine = FakeGenericEngine(load_mapping(mapping if mapping.exists() else None))


class _AlwaysFire:
    def matches(self, rule, event) -> bool:
        return True


class AlwaysFireDetectionTarget(FakeDetectionTarget):
    """Defect: the engine matches every event (a rule that cannot stay quiet)."""

    def __init__(self, root: Path | str | None = None) -> None:
        super().__init__(root)
        self.engine = _AlwaysFire()
