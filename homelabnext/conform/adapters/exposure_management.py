# SPDX-License-Identifier: Apache-2.0
"""A read-only probe for the provisional ``exposure-management`` slot (the shared adapter of modules/vulnerability-scanner).

The slot has no contract or conformance suite yet, so this is not one: it asks the scanner's front
the two things its health hook asks without a credential (the console's page answers, and the GMP
gateway refuses a caller that carries no session), from the endpoint the registry resolver gives
(``HNX_ENDPOINT_EXPOSURE_MANAGEMENT``; no default, no credential, nothing is written).
"""

from __future__ import annotations

import urllib.error
import urllib.request
from typing import Any

from homelabnext.conform.adapters._env import resolve

__all__ = ["ExposureManagementProbe", "make"]

#: what a gateway that refuses a caller with no session answers (never 200, never a server error)
_REFUSED = frozenset({400, 401, 403, 404, 405})


class ExposureManagementProbe:
    def __init__(self, base_url: str, timeout: float = 10.0) -> None:
        self._base = base_url.rstrip("/")
        self._timeout = timeout

    def _status(self, path: str) -> int:
        try:
            with urllib.request.urlopen(
                urllib.request.Request(self._base + path, method="GET"), timeout=self._timeout
            ) as r:
                return int(r.status)
        except urllib.error.HTTPError as e:
            return int(e.code)

    def health(self) -> bool:
        return self._status("/") == 200

    def gateway_is_private(self) -> bool:
        """True when the GMP gateway answers a caller with no session with a refusal."""
        return self._status("/gmp") in _REFUSED

    def close(self) -> None:  # the harness's teardown; nothing is held
        return None


def make(
    config: dict[str, Any] | None = None, *, resolver: Any = None, domain: str | None = None
) -> ExposureManagementProbe:
    cfg = config or {}
    ep = resolve(
        "exposure-management",
        resolver=resolver,
        domain=domain,
        env_only=resolver is None and domain is None,
        schemes=("https",),
    )
    return ExposureManagementProbe(ep.url, float(cfg.get("timeout", 10.0)))
