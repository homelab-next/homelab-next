# SPDX-License-Identifier: Apache-2.0
"""The agent tests play the operator and the runtime with one uid, so the runtime's refusal of a
deny file it can write (``homelabnext.agent.memory._CHECK_DENY_WRITABLE``, ADR-0037 decision 12,
amended) is off here; ``test_agent_memory_retraction_audit.py`` turns it on to test it."""

import pytest


@pytest.fixture(autouse=True)
def _one_uid_plays_both(monkeypatch):
    from homelabnext.agent import memory

    monkeypatch.setattr(memory, "_CHECK_DENY_WRITABLE", False)


#: the clock the agent tests assemble packs at: five minutes after the fixtures' pre-gate output
#: was observed (``agent_support.GATE_OK``), inside its ``max_age_s``
FIXED_NOW = "2026-01-15T10:05:00+00:00"


@pytest.fixture(autouse=True, scope="session")
def _fixed_clock():
    """Session-wide, so module-scoped fixtures that assemble a pack see it too."""
    from datetime import datetime

    from homelabnext.agent import pack

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(pack, "_now", lambda: datetime.fromisoformat(FIXED_NOW), raising=False)
        yield
