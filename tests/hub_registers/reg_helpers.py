# SPDX-License-Identifier: Apache-2.0
"""Helpers of the register page tests: the status hub tests' own helpers, reused.  The register
tests are a suite of their own (``tests/hub_registers``) so that ``tests/status`` keeps its time
budget; the helper modules live beside those tests, so their directory joins the import path."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "status"))

from agent_helpers import AUTHORIZED, front_door, request
from status_helpers import REGISTRY, ROOT, T0, VIEWS, Clock

__all__ = ["AUTHORIZED", "REGISTRY", "ROOT", "T0", "VIEWS", "Clock", "front_door", "request"]
