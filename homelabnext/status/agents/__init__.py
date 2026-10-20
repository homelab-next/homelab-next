# SPDX-License-Identifier: Apache-2.0
"""Agent activity in the status hub (ADR-0013 stage 1b, ``docs/status.md``): any runtime -- a
coding CLI on a workstation or in the cloud, an orchestrator, a generic pusher -- in two tiers.

* :mod:`.model` -- the summary and detail tiers (``schemas/status/agent_activity*.schema.json``),
  sessions and their state (working, waiting, stuck, errored, done) from an injected clock;
* :mod:`.store` -- both tiers in one SQLite file, redacted and capped before storage, purged by age;
* :mod:`.config` -- ``agents.yml``: retention, caps, thresholds, the front door, the senders;
* :mod:`.sources` -- the ``agent-activity`` status sources (hook spool, Agentmetry trail, push);
* :mod:`.ingest` -- the push listener (``POST /ingest/agent-activity``, a bearer token per sender);
* :mod:`.auth` -- the private tier's front door and its access log;
* :mod:`.pages` -- the server-rendered agent pages.

Agents are optional: without ``--agents`` none of this runs and the hub is unchanged.
"""

from .auth import AccessLog, Decision, authorize
from .config import AgentsConfig, AgentsConfigError, FrontDoor, load_config, secret_lookup
from .model import (
    ACTIVITY_EVENT,
    DETAIL_KEYS,
    SESSION_STATES,
    Thresholds,
    bus_event,
    derive_sessions,
    detail_problems,
    summary_problems,
)
from .sources import map_agentmetry
from .store import ActivityError, ActivityStore, Redactor

__all__ = [
    "ACTIVITY_EVENT",
    "DETAIL_KEYS",
    "SESSION_STATES",
    "AccessLog",
    "ActivityError",
    "ActivityStore",
    "AgentsConfig",
    "AgentsConfigError",
    "Decision",
    "FrontDoor",
    "Redactor",
    "Thresholds",
    "authorize",
    "bus_event",
    "derive_sessions",
    "detail_problems",
    "load_config",
    "map_agentmetry",
    "secret_lookup",
    "summary_problems",
]
