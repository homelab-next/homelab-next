# SPDX-License-Identifier: Apache-2.0
"""A read-only probe for the provisional ``media-automation`` slot (the shared adapter of
modules/media-automation).

The slot has no contract or conformance suite yet, so this is not one: it asks the stack's front
door the one thing the role's health hook asks of it (the request app's ``/api/v1/status`` answers
with a version), from the endpoint the registry resolver gives (``HNX_ENDPOINT_MEDIA_AUTOMATION``;
no default, no credential, nothing is written).
"""

from __future__ import annotations

import json
import urllib.request
from typing import Any

from homelabnext.conform.adapters._env import resolve

__all__ = ["MediaAutomationProbe", "make"]


class MediaAutomationProbe:
    def __init__(self, base_url: str, timeout: float = 10.0) -> None:
        self._base = base_url.rstrip("/")
        self._timeout = timeout

    def status(self) -> dict[str, Any]:
        req = urllib.request.Request(self._base + "/api/v1/status", method="GET")
        with urllib.request.urlopen(req, timeout=self._timeout) as r:
            return json.loads(r.read().decode("utf-8"))

    def healthy(self) -> bool:
        return bool(str(self.status().get("version", "")))

    def close(self) -> None:  # the harness's teardown; nothing is held
        return None


def make(
    config: dict[str, Any] | None = None, *, resolver: Any = None, domain: str | None = None
) -> MediaAutomationProbe:
    cfg = config or {}
    ep = resolve(
        "media-automation",
        resolver=resolver,
        domain=domain,
        env_only=resolver is None and domain is None,
        schemes=("http", "https"),
    )
    return MediaAutomationProbe(ep.url, float(cfg.get("timeout", 10.0)))
