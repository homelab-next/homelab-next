# SPDX-License-Identifier: Apache-2.0
"""A read-only probe for the provisional ``web-search`` slot (the shared adapter of modules/searxng).

The slot has no contract or conformance suite yet, so this is not one: it asks the service the two
things its health hook asks (the health path answers, and a JSON search returns a non-empty list of
results), from the endpoint the registry resolver gives (``HNX_ENDPOINT_WEB_SEARCH``; no default, no
credential, nothing is written). An empty answer is reported as such, never as a pass.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from homelabnext.conform.adapters._env import resolve

__all__ = ["WebSearchProbe", "make"]


class WebSearchProbe:
    def __init__(self, base_url: str, timeout: float = 20.0) -> None:
        self._base = base_url.rstrip("/")
        self._timeout = timeout

    def _open(self, path: str) -> tuple[int, bytes]:
        try:
            with urllib.request.urlopen(self._base + path, timeout=self._timeout) as r:
                return int(r.status), r.read(1 << 20)
        except urllib.error.HTTPError as e:
            return int(e.code), b""

    def health(self) -> bool:
        return self._open("/healthz")[0] == 200

    def search_returns_results(self, query: str = "debian") -> bool:
        """True when ``/search?q=<query>&format=json`` answers 200 with a non-empty ``results`` list."""
        qs = urllib.parse.urlencode({"q": query, "format": "json"})
        status, raw = self._open("/search?" + qs)
        if status != 200:
            return False
        try:
            results = json.loads(raw).get("results")
        except (ValueError, AttributeError):
            return False
        return isinstance(results, list) and len(results) > 0

    def close(self) -> None:  # the harness's teardown; nothing is held
        return None


def make(
    config: dict[str, Any] | None = None, *, resolver: Any = None, domain: str | None = None
) -> WebSearchProbe:
    cfg = config or {}
    ep = resolve(
        "web-search",
        resolver=resolver,
        domain=domain,
        env_only=resolver is None and domain is None,
        schemes=("http", "https"),
    )
    return WebSearchProbe(ep.url, float(cfg.get("timeout", 20.0)))
