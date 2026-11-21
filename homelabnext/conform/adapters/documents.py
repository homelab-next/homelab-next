# SPDX-License-Identifier: Apache-2.0
"""A read-only probe for the provisional ``documents`` slot (the shared adapter of modules/documents).

The slot has no contract or conformance suite yet, so this is not one: it asks the application
the two things its health hook asks without a credential (the sign-in page answers, and an
anonymous read of the library through the API is refused), from the endpoint the registry
resolver gives (``HNX_ENDPOINT_DOCUMENTS``; no default, no credential, nothing is written).
"""

from __future__ import annotations

from typing import Any

from homelabnext.conform.adapters._env import resolve
from homelabnext.conform.adapters._status_probe import StatusProbe

__all__ = ["DocumentsProbe", "make"]


class DocumentsProbe(StatusProbe):
    def health(self) -> bool:
        return self._status("/accounts/login/") == 200

    def library_is_private(self) -> bool:
        return self._status("/api/documents/?page_size=1") in (401, 403)


def make(
    config: dict[str, Any] | None = None, *, resolver: Any = None, domain: str | None = None
) -> DocumentsProbe:
    cfg = config or {}
    ep = resolve(
        "documents",
        resolver=resolver,
        domain=domain,
        env_only=resolver is None and domain is None,
        schemes=("http", "https"),
    )
    return DocumentsProbe(ep.url, float(cfg.get("timeout", 10.0)))
