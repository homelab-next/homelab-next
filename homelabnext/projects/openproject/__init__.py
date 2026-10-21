# SPDX-License-Identifier: Apache-2.0
"""OpenProject (pinned: 17.9) as a ``projects`` backend, plus the strategy sync and change feed.

* :mod:`.client` -- a small stdlib HAL+JSON client (token by secret name, TLS, pagination,
  ``lockVersion`` PATCH, retries with backoff);
* :mod:`.setup` -- what must exist (types, statuses, custom fields, projects, permissions),
  resolved by name, and :func:`~.setup.doctor` (``hnx projects doctor``);
* :mod:`.backend` -- the contract on work packages (:func:`openproject_store`);
* :mod:`.sync` -- the one-way strategy sync (``hnx projects sync-strategy``);
* :mod:`.feed` -- ``updatedAt`` poll plus webhook receiver -> ``homelabnext.project.changed``.

The admin steps OpenProject offers no API for are in ``docs/projects.md``.
"""

from __future__ import annotations

from typing import Any

from ..store import ProjectStore
from .backend import OpenProjectBackend
from .client import ApiError, OpenProjectClient
from .feed import ChangeFeed, adopt, make_webhook_server, verify_signature
from .setup import OpenProjectConfig, Setup, SetupError, discover, doctor, load_config
from .sync import SyncReport, sync_strategy

__all__ = [
    "ApiError",
    "ChangeFeed",
    "OpenProjectBackend",
    "OpenProjectClient",
    "OpenProjectConfig",
    "Setup",
    "SetupError",
    "SyncReport",
    "adopt",
    "discover",
    "doctor",
    "load_config",
    "make_webhook_server",
    "openproject_store",
    "sync_strategy",
    "verify_signature",
]


def openproject_store(
    cfg: OpenProjectConfig, *, client: OpenProjectClient | None = None, **kw: Any
) -> ProjectStore:
    """The ``projects`` contract on the instance ``cfg`` names (resolves its setup first)."""
    client = client or cfg.client()
    backend = OpenProjectBackend(client, cfg, discover(client, cfg))
    return ProjectStore(backend, records=backend.strategy_uids, **kw)
