# SPDX-License-Identifier: Apache-2.0
"""Broker grant tiers and the grant lookup: one definition for every reader of a broker manifest.

The broker's evaluator (:func:`homelabnext.broker.decide`), the agent profile compiler's ceiling
check, the reader->actor handoff, the session access block and keyring, and the playbook
validator all ask the same two questions of a ``broker/manifest`` document: which grant lets an
actor request an action, and is the action's tier within that grant's ``max_tier``.  They answer
them here, so a tier added or reordered in one place cannot change who may act in another
(``tools/shared_helpers_lint.py`` reports a private tier ranking anywhere else, rule ``tiers``).

Dependency-free on purpose: the broker and the agent package both import it, and neither may
import the other at module load.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

#: the broker tiers, least to most powerful (``schemas/broker/manifest.schema.json``)
TIERS = ("read", "write", "execute", "privileged")
#: each tier's rank: a grant's ``max_tier`` allows every tier of equal or lower rank
TIER_RANK = {tier: rank for rank, tier in enumerate(TIERS)}


def grant_for(manifest: Mapping[str, Any], actor: Any, action: Any) -> Mapping[str, Any] | None:
    """The first grant of ``manifest`` whose ``profile`` is ``actor`` and whose ``actions`` name
    ``action`` (``None``: the actor holds no grant for it)."""
    return next(
        (
            g
            for g in manifest.get("grants", [])
            if g.get("profile") == actor and action in (g.get("actions") or ())
        ),
        None,
    )


def tier_exceeds(tier: str, max_tier: str) -> bool:
    """True when ``tier`` is above ``max_tier`` (both must be one of :data:`TIERS`;
    ``KeyError`` otherwise, as a schema-valid manifest never has another)."""
    return TIER_RANK[tier] > TIER_RANK[max_tier]
