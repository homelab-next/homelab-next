# SPDX-License-Identifier: Apache-2.0
"""Shared fixtures of the orchestration telemetry tests: the schema's own examples as the job
records, a fixed clock, and the first turn source adapter on a loopback fake of its gateway's
per-call log (:mod:`conformance.fakes.litellm_spend_log_api`, a recorded-shape page set)."""

from __future__ import annotations

import json
from pathlib import Path

from conformance.fakes.litellm_spend_log_api import KEY_ENV, NEVER, FakeSpendLogs, pages
from conformance.protocols.inference import TURN_FIELDS
from homelabnext.conform.adapters.litellm_spend_log import make as make_turn_source
from homelabnext.events.envelope import canonical_body
from homelabnext.status.model import parse_iso

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
EXAMPLES = ROOT / "schemas" / "events" / "examples"
CONTROLLER_EXAMPLE = "agent.job.finished.controller.json"
#: a controller backend name as it is emitted (local_backend_used, verbatim): a leading dot
DOTTED_EXAMPLE = "agent.job.finished.dotted-backend.json"
#: well after every example job finished (the last at 03:00)
T0 = parse_iso("2026-01-01T06:00:00Z")
#: a neutral turn record with every value unknown (``BLANK | {...}`` fills a test's turn)
BLANK = dict.fromkeys(TURN_FIELDS)
#: the turn source adapter, as ``--turn-source`` names it
TURN_SOURCE = "homelabnext.conform.adapters.litellm_spend_log:make"
__all__ = [
    "BLANK", "KEY_ENV", "NEVER", "ROOT", "T0", "TURN_SOURCE", "FakeSpendLogs", "body", "examples", "pages",
    "turn_source",
]  # fmt: skip


def turn_source(gw: FakeSpendLogs, **kw):
    """The adapter's turn source on the fake gateway ``gw``, with the viewer key set."""
    return make_turn_source(base_url=gw.url, env=KEY_ENV, **kw)


def examples() -> list[dict]:
    """The four triage ``agent.job.finished`` examples (completed, failed, no usage, shadow), in
    file order; ``controller`` (the controller's own test event) and ``dotted-backend`` are
    checked on their own."""
    return [
        json.loads(p.read_text(encoding="utf-8"))
        for p in sorted(EXAMPLES.glob("agent.job.finished.*.json"))
        if p.name not in (CONTROLLER_EXAMPLE, DOTTED_EXAMPLE)
    ]


def body(event: dict) -> bytes:
    return canonical_body(event)
