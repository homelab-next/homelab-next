# SPDX-License-Identifier: Apache-2.0
"""A read-only probe for the provisional ``file-analysis`` slot (the shared adapter of modules/assemblyline).

The slot has no contract or conformance suite yet, so this is not one: it asks the service the two
things its health hook asks without a credential (the front answers, and an anonymous call to the
API is refused), from the endpoint the registry resolver gives (``HNX_ENDPOINT_FILE_ANALYSIS``; no
default, no credential, nothing is written or submitted). The API path is the product's documented
``/api/v4/`` root; its exact anonymous answer is checked against a running instance in the module's
next change (ADR-0052), so the probe accepts the refusals a sign-in-protected API gives.
"""

from __future__ import annotations

from typing import Any

from homelabnext.conform.adapters._env import resolve
from homelabnext.conform.adapters._status_probe import StatusProbe

__all__ = ["FileAnalysisProbe", "make"]


class FileAnalysisProbe(StatusProbe):
    def health(self) -> bool:
        return self._status("/") in (200, 301, 302)

    def api_is_private(self) -> bool:
        return self._status("/api/v4/user/whoami/") in (401, 403)


def make(
    config: dict[str, Any] | None = None, *, resolver: Any = None, domain: str | None = None
) -> FileAnalysisProbe:
    cfg = config or {}
    ep = resolve(
        "file-analysis",
        resolver=resolver,
        domain=domain,
        env_only=resolver is None and domain is None,
        schemes=("http", "https"),
    )
    return FileAnalysisProbe(ep.url, float(cfg.get("timeout", 10.0)))
