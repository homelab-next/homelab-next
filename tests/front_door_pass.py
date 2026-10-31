# SPDX-License-Identifier: Apache-2.0
"""A trusted front door that lets every request through, for the tests of the withheld hub pages
(strategy, projects, orchestration, baselines, the maps and the directory pages).

Those pages have no release transform yet (ADR-0033 decision 8), so ``hnx status serve`` answers
them only through the front door the agent site carries; a test that is about a page, not about
the door, passes ``agents=FrontDoorPass()``.  The door itself is tested in
``tests/status/test_agents_private.py`` and ``tests/status/test_status_tlp.py``.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any


class FrontDoorPass:
    """Stands in for :class:`homelabnext.status.agents.pages.AgentSite`: authorizes everyone,
    serves no route of its own, keeps no access log."""

    access_log = None

    def authorize(self, client: str | None, headers: Any) -> SimpleNamespace:
        return SimpleNamespace(allowed=True, user="operator", reason="")

    def handle(self, *args: Any) -> None:
        return None
