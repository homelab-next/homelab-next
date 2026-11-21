# SPDX-License-Identifier: Apache-2.0
"""A read-only probe for the provisional ``enrichment`` slot (the shared adapter of modules/intelowl).

The slot has no contract or conformance suite yet, so this is not one: it asks the service the two
things its health hook asks without a credential (the front answers its liveness, and an anonymous
call to the API is refused), from the endpoint the registry resolver gives
(``HNX_ENDPOINT_ENRICHMENT``; no default, no credential, nothing is written or submitted).
"""

from __future__ import annotations

from typing import Any

from homelabnext.conform.adapters._env import resolve
from homelabnext.conform.adapters._status_probe import StatusProbe

__all__ = ["EnrichmentProbe", "make"]


class EnrichmentProbe(StatusProbe):
    def health(self) -> bool:
        return self._status("/hc") == 200

    def api_is_private(self) -> bool:
        return self._status("/api/analyzer") in (401, 403)


def make(
    config: dict[str, Any] | None = None, *, resolver: Any = None, domain: str | None = None
) -> EnrichmentProbe:
    cfg = config or {}
    ep = resolve(
        "enrichment",
        resolver=resolver,
        domain=domain,
        env_only=resolver is None and domain is None,
        schemes=("http", "https"),
    )
    return EnrichmentProbe(ep.url, float(cfg.get("timeout", 10.0)))
