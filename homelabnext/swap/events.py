# SPDX-License-Identifier: Apache-2.0
"""Swap record -> ``homelabnext.swap.step`` events (schema ``events/swap.step`` 1.1).

The record's hash-chained transition log is the audit trail; this module turns it into the
CloudEvents-style envelope the rest of the platform consumes, so a subscriber can follow a swap
without reading the record.  Pure functions, no I/O: the caller publishes the events (the event
bus is a capability, not something the swap kit knows about).

Event ids are derived from the swap id and the transition sequence number, so republishing the
same record yields the same ids and redelivery is harmless (the envelope's idempotency rule).
"""

from __future__ import annotations

from typing import Any

from .record import STEPS

EVENT_TYPE = "homelabnext.swap.step"

# record transition event -> (event status, severity)
_STATUS = {
    "declared": ("started", "info"),
    "step-passed": ("passed", "info"),
    "gate-failed": ("failed", "low"),
    "cutover-reverted": ("rolled_back", "low"),
    "rolled-back": ("rolled_back", "low"),
}


def step_events(doc: dict[str, Any], *, source: str | None = None) -> list[dict[str, Any]]:
    """One event per state change of a swap record, oldest first.

    ``declared`` is reported as step 1 started; ``note`` and the ``closed`` marker (it duplicates
    the final ``step-passed``) produce no event.  ``source`` defaults to the swap's capability id.
    """
    cap = doc["capability"]
    out: list[dict[str, Any]] = []
    for t in doc["transitions"]:
        kind = t["event"]
        if kind not in _STATUS:
            continue
        status, severity = _STATUS[kind]
        name = t["step"] or STEPS[0]
        if name not in STEPS:
            continue
        out.append(
            {
                "specversion": "1.0",
                "id": f"swap.{doc['swap_id']}.{t['seq']}",
                "source": source or cap,
                "type": EVENT_TYPE,
                "time": t["at"],
                "subject": doc["swap_id"],
                "severity": severity,
                "correlationid": doc["swap_id"],
                "data": {
                    "swap_id": doc["swap_id"],
                    "capability": cap,
                    "step": STEPS.index(name) + 1,
                    "step_name": name,
                    "status": status,
                    "from_adapter": doc["from_adapter"],
                    "to_adapter": doc["to_adapter"],
                },
            }
        )
    return out
