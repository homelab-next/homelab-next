# SPDX-License-Identifier: Apache-2.0
"""A read-only probe for the provisional ``chat`` slot (the shared adapter of modules/openwebui).

The slot has no contract or conformance suite yet, so this is not one: it asks the app the two
things the role's health hook asks (``/health`` answers, and the anonymous ``/api/config`` shows a
deployed instance), from the endpoint the registry resolver gives (``HNX_ENDPOINT_CHAT``; no
default, no credential, nothing is written).  A deployed instance has an administrator (an
instance without one reports ``onboarding``, and its first visitor would become one), sign-up off,
and the sign-in providers it lists.
"""

from __future__ import annotations

import json
import urllib.request
from typing import Any

from homelabnext.conform.adapters._env import resolve

__all__ = ["ChatProbe", "make"]


class ChatProbe:
    def __init__(self, base_url: str, timeout: float = 10.0) -> None:
        self._base = base_url.rstrip("/")
        self._timeout = timeout

    def _get(self, path: str) -> str:
        req = urllib.request.Request(self._base + path, method="GET")
        with urllib.request.urlopen(req, timeout=self._timeout) as r:
            return r.read().decode("utf-8")

    def health(self) -> bool:
        return json.loads(self._get("/health")).get("status") is True

    def config(self) -> dict[str, Any]:
        return json.loads(self._get("/api/config"))

    def deployed(self) -> bool:
        """An administrator exists and sign-up is off."""
        cfg = self.config()
        return "onboarding" not in cfg and cfg.get("features", {}).get("enable_signup") is False

    def providers(self) -> list[str]:
        return sorted(self.config().get("oauth", {}).get("providers", {}))

    def close(self) -> None:  # the harness's teardown; nothing is held
        return None


def make(
    config: dict[str, Any] | None = None, *, resolver: Any = None, domain: str | None = None
) -> ChatProbe:
    cfg = config or {}
    ep = resolve(
        "chat",
        resolver=resolver,
        domain=domain,
        env_only=resolver is None and domain is None,
        schemes=("http", "https"),
    )
    return ChatProbe(ep.url, float(cfg.get("timeout", 10.0)))
