# SPDX-License-Identifier: Apache-2.0
"""Orchestration telemetry (``docs/orchestration-telemetry.md``): what each agent job of the
orchestration controller cost and how it went, from two sources joined by a tag.

* **Per job**: ``homelabnext.agent.job.finished`` (``schemas/events/agent.job.finished.schema.json``),
  one event per run that reached a terminal state, published by the controller.  The hub
  consumes it from the bus into its store (:mod:`.store`, :func:`.bus.drain`), idempotent by event
  id and by run id.
* **Per turn**: the LLM gateway's spend log (LiteLLM ``/spend/logs/v2``, read with a read-only
  viewer key named by secret, :mod:`.gateway`); a turn belongs to the job whose ``gateway_tag``
  it carries in ``request_tags``.  Only names, counts, times and costs are kept.
* :mod:`.model` -- the rollup per profile, backend and lane (the Orchestration page and the
  recommendation engine's input, ``homelabnext.orchestration.rollup/1``);
* :mod:`.pages` -- the hub's Orchestration page (``hnx status serve --orchestration DB``);
* :mod:`.cli` -- ``hnx orchestration consume|ingest|turns|report``.

Names and numbers only: nothing here ever holds a prompt, task text, tool input or output or
model output, and the event schema and the turn mapping are both closed allow-lists.
"""

from .model import CONTROLLER_SOURCE, FINISHED_EVENT, ROLLUP_SCHEMA, percentile, rollup
from .store import TelemetryStore

__all__ = [
    "CONTROLLER_SOURCE",
    "FINISHED_EVENT",
    "ROLLUP_SCHEMA",
    "TelemetryStore",
    "percentile",
    "rollup",
]
