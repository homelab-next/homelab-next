# SPDX-License-Identifier: Apache-2.0
"""Shared by the module tests that compare a rendered play's variables."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

#: the play variable carrying the footprint as placed (its value is the golden's and the
#: placement tests' to pin, not these tests')
FOOTPRINT_VAR = "hnx_module_footprint"


def without_footprint(play_vars: Mapping[str, Any]) -> dict[str, Any]:
    """A play's variables minus the placed footprint, for a test that pins the rest exactly."""
    return {k: v for k, v in play_vars.items() if k != FOOTPRINT_VAR}
