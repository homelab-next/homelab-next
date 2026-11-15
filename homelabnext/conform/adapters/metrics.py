# SPDX-License-Identifier: Apache-2.0
"""The ``metrics`` slot's client on the service's HTTP API (stdlib).

The slot has no contract yet (it is provisional): the adapter is the one thing every provider of
it must offer, a read-only view of the standard query, alert, rule and target endpoints that the
status hub's collectors and a module's own live check read.  ``make(**config)`` returns a
:class:`MetricsTarget` on ``HNX_ENDPOINT_METRICS`` (the registry resolver's override; there is no
default endpoint).  It sends no credential, reads nothing but JSON and bounds every body.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from homelabnext._http import DEFAULT_MAX_BYTES, read_bounded, safe_urlopen

from ._env import resolve

__all__ = ["MetricsError", "MetricsTarget", "make"]


class MetricsError(RuntimeError):
    """The metrics service did not answer, or did not answer success."""


class MetricsTarget:
    """A read-only view of one metrics service."""

    def __init__(self, base_url: str, *, timeout: float = 10.0, max_bytes: int = DEFAULT_MAX_BYTES):
        if not base_url.startswith(("http://", "https://")):
            raise ValueError("base_url must be an http(s) URL supplied by the caller")
        self._base = base_url.rstrip("/")
        self.timeout = timeout
        self.max_bytes = max_bytes

    def __repr__(self) -> str:
        return f"MetricsTarget({self._base!r})"

    def _get(self, path: str, **params: str) -> Any:
        url = self._base + path + (("?" + urllib.parse.urlencode(params)) if params else "")
        req = urllib.request.Request(url, headers={"Accept": "application/json"}, method="GET")
        try:
            with safe_urlopen(req, timeout=self.timeout) as resp:
                raw = read_bounded(resp, self.max_bytes)
        except urllib.error.HTTPError as exc:
            raise MetricsError(f"{path}: HTTP {exc.code}") from None
        except (urllib.error.URLError, OSError, ValueError) as exc:
            raise MetricsError(f"{path}: {type(exc).__name__}") from None
        try:
            doc = json.loads(raw.decode("utf-8"))
        except ValueError:
            raise MetricsError(f"{path}: not JSON") from None
        if not isinstance(doc, dict) or doc.get("status") != "success":
            raise MetricsError(f"{path}: the service did not answer success")
        return doc.get("data")

    def query(self, expr: str) -> list[dict[str, Any]]:
        """The instant vector of ``expr``: ``[{"metric": {...}, "value": [ts, "v"]}, ...]``."""
        data = self._get("/api/v1/query", query=expr)
        if not isinstance(data, dict) or data.get("resultType") != "vector":
            raise MetricsError("/api/v1/query: not an instant vector")
        return list(data.get("result", []))

    def alerts(self) -> list[dict[str, Any]]:
        """Every pending and firing alert."""
        return list((self._get("/api/v1/alerts") or {}).get("alerts", []))

    def rule_names(self) -> list[str]:
        """The names of every loaded rule, in group order."""
        groups = (self._get("/api/v1/rules") or {}).get("groups", [])
        return [r["name"] for g in groups for r in g.get("rules", [])]

    def targets(self) -> list[dict[str, Any]]:
        """Every active scrape target (job, health, last error)."""
        return list((self._get("/api/v1/targets") or {}).get("activeTargets", []))


def make(**config: Any) -> MetricsTarget:
    """A :class:`MetricsTarget` on ``HNX_ENDPOINT_METRICS``; ``timeout`` is its only setting."""
    unknown = sorted(set(config) - {"timeout"})
    if unknown:
        raise ValueError(f"metrics adapter: unknown setting(s) {', '.join(unknown)}")
    endpoint = resolve("metrics", env_only=True, schemes=("http", "https"))
    return MetricsTarget(endpoint.url, timeout=float(config.get("timeout", 10.0)))
