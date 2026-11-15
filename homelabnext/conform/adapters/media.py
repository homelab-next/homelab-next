# SPDX-License-Identifier: Apache-2.0
"""A read-only probe for the provisional ``media`` slot (the shared adapter of modules/media).

The slot has no contract or conformance suite yet, so this is not one: it asks the server the
three things the role's health hook asks (``/health`` says Healthy, ``/System/Info/Public``
answers with the server id, Quick Connect is enabled), from the endpoint the registry resolver
gives (``HNX_ENDPOINT_MEDIA``; no default, no credential, nothing is written).
"""

from __future__ import annotations

import json
import urllib.request
from typing import Any

from homelabnext.conform.adapters._env import resolve

__all__ = ["MediaProbe", "make"]


class MediaProbe:
    def __init__(self, base_url: str, timeout: float = 10.0) -> None:
        self._base = base_url.rstrip("/")
        self._timeout = timeout

    def _get(self, path: str) -> str:
        req = urllib.request.Request(self._base + path, method="GET")
        with urllib.request.urlopen(req, timeout=self._timeout) as r:
            return r.read().decode("utf-8")

    def health(self) -> bool:
        return self._get("/health").strip() == "Healthy"

    def info(self) -> dict[str, Any]:
        return json.loads(self._get("/System/Info/Public"))

    def quick_connect_enabled(self) -> bool:
        return self._get("/QuickConnect/Enabled").strip().lower() == "true"

    def close(self) -> None:  # the harness's teardown; nothing is held
        return None


def make(
    config: dict[str, Any] | None = None, *, resolver: Any = None, domain: str | None = None
) -> MediaProbe:
    cfg = config or {}
    ep = resolve(
        "media",
        resolver=resolver,
        domain=domain,
        env_only=resolver is None and domain is None,
        schemes=("http", "https"),
    )
    return MediaProbe(ep.url, float(cfg.get("timeout", 10.0)))
