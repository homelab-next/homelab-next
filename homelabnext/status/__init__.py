# SPDX-License-Identifier: Apache-2.0
"""The status hub: one read-only place for activity and status (ADR-0013, ``docs/status.md``).

Every source of status is registered in the service registry (``status_sources:`` of a service)
and is therefore on the menu (``hnx status sources``, ``docs/status/sources.md``); views
(``examples/status/views.yml``) pick from that menu.  The pieces:

* :mod:`.model` -- :class:`SourceSpec` (a registered source), :class:`Observation` (one reading);
* :mod:`.mapping` -- payload -> drafts: declarative selectors or a named built-in mapper;
* :mod:`.collectors` -- one :class:`Collector` per kind (``poll-http-json``, ``poll-file``,
  ``push-event``, ``agent-activity``), all through an injected context; :mod:`.products` the
  product kinds of stage 2 (``poll-prometheus``, ``poll-uptime-kuma``, ``poll-stackstorm``,
  ``poll-nifi``);
* :mod:`.scheduler` -- each due source in its own thread under its own timeout (O-07);
* :mod:`.hub` -- latest + bounded history, staleness from expiry (O-06), state-diffed
  notifications through ``homelabnext.notify`` (O-08), ``status.observed`` events on the bus;
* :mod:`.views` -- ``views.yml`` and the ``status.json`` contract (exceptions-first O-05, grid
  O-02, sources); :mod:`.render` the static page; :mod:`.serve` the loopback GET-only server.

The hub observes and never acts: anything that changes something is a link to the broker or the
approval path.  Nothing here depends on agents, the broker or an agent dashboard; each is an
optional source or an optional external menu entry.
"""

from .collectors import (
    COLLECTORS,
    CollectContext,
    CollectError,
    Collector,
    HttpClient,
    PendingApprovals,
    UrllibClient,
    registry_endpoint,
)
from .hub import HubError, StatusHub, effective_state
from .mapping import BUILTINS, Draft, MappingError, apply_mapping, select_pairs
from .model import (
    KINDS,
    OBSERVED_EVENT,
    STATES,
    Observation,
    SourceSpec,
    observation_problems,
    sources_from_registry,
    worst,
)
from .scheduler import Scheduler, SourceResult, due
from .views import STATUS_SCHEMA, ViewsError, build_status, load_views, views_problems

__all__ = [
    "BUILTINS",
    "COLLECTORS",
    "KINDS",
    "OBSERVED_EVENT",
    "STATES",
    "STATUS_SCHEMA",
    "CollectContext",
    "CollectError",
    "Collector",
    "Draft",
    "HttpClient",
    "HubError",
    "MappingError",
    "Observation",
    "PendingApprovals",
    "Scheduler",
    "SourceResult",
    "SourceSpec",
    "StatusHub",
    "UrllibClient",
    "ViewsError",
    "apply_mapping",
    "build_status",
    "due",
    "effective_state",
    "load_views",
    "observation_problems",
    "registry_endpoint",
    "select_pairs",
    "sources_from_registry",
    "views_problems",
    "worst",
]
