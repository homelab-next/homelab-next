# SPDX-License-Identifier: Apache-2.0
"""The agent tests play the operator and the runtime with one uid, so the runtime's refusal of a
deny file it can write (``homelabnext.agent.memory._CHECK_DENY_WRITABLE``, ADR-0037 decision 12,
amended) is off here; ``test_agent_memory_retraction_audit.py`` turns it on to test it."""

import pytest


@pytest.fixture(autouse=True)
def _one_uid_plays_both(monkeypatch):
    from homelabnext.agent import memory

    monkeypatch.setattr(memory, "_CHECK_DENY_WRITABLE", False)
