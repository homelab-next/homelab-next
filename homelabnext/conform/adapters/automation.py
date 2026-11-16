# SPDX-License-Identifier: Apache-2.0
"""The ``automation`` slot's client on the service's HTTP API (stdlib).

The slot has no contract yet (it is provisional): the adapter is the one thing every provider of
it must offer, a read-only view of its rules and executions, which the status hub's collector and
a module's own live check read.  ``make(**config)`` returns an :class:`AutomationTarget` on
``HNX_ENDPOINT_AUTOMATION`` (the registry resolver's override; there is no default endpoint),
authenticating with the API key in the variable ``api_key_env`` names (read when the target is built,
so a missing one fails at once, and again at every request, so the target never holds it), sent in
the header ``api_key_header`` names (the registry row's ``auth.header``; the provider's module owns
the product's spelling of both).  It follows no redirect, reads nothing but JSON and bounds every
body.
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from typing import Any

from homelabnext._http import DEFAULT_MAX_BYTES, check_plaintext, read_bounded, safe_urlopen

from ._env import env_secret, resolve

__all__ = ["AutomationError", "AutomationTarget", "make"]


class AutomationError(RuntimeError):
    """The automation service did not answer, or did not answer what was asked."""


class AutomationTarget:
    """A read-only view of one automation service."""

    def __init__(
        self,
        base_url: str,
        *,
        api_key: Callable[[], str],
        api_key_header: str,
        timeout: float = 10.0,
        max_bytes: int = DEFAULT_MAX_BYTES,
        allow_plaintext: bool = False,
    ):
        if not base_url.startswith(("http://", "https://")):
            raise ValueError("base_url must be an http(s) URL supplied by the caller")
        check_plaintext(base_url, credentials=True, allow_plaintext=allow_plaintext)
        self._base = base_url.rstrip("/")
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9-]{0,63}", api_key_header):
            raise ValueError("api_key_header is a plain header name")
        self._api_key = api_key
        self._header = api_key_header
        self.timeout = timeout
        self.max_bytes = max_bytes

    def __repr__(self) -> str:
        return f"AutomationTarget({self._base!r})"

    def _get(self, path: str, **params: str) -> Any:
        url = (
            self._base
            + "/api/v1"
            + path
            + (("?" + urllib.parse.urlencode(params)) if params else "")
        )
        req = urllib.request.Request(
            url,
            headers={"Accept": "application/json", self._header: self._api_key()},
            method="GET",
        )
        try:
            with safe_urlopen(req, timeout=self.timeout) as resp:
                raw = read_bounded(resp, self.max_bytes)
        except urllib.error.HTTPError as exc:
            raise AutomationError(f"{path}: HTTP {exc.code}") from None
        except (urllib.error.URLError, OSError, ValueError) as exc:
            raise AutomationError(f"{path}: {type(exc).__name__}") from None
        try:
            return json.loads(raw.decode("utf-8"))
        except ValueError:
            raise AutomationError(f"{path}: not JSON") from None

    def executions(self, limit: int = 100) -> list[dict[str, Any]]:
        """The most recent executions, newest first."""
        if not 1 <= limit <= 1000:
            raise ValueError("limit is 1 to 1000")
        doc = self._get("/executions", limit=str(limit))
        if not isinstance(doc, list):
            raise AutomationError("/executions: not a list")
        return doc

    def rules(self, pack: str) -> list[dict[str, Any]]:
        """The rules a pack registered, each with its ``enabled`` flag."""
        doc = self._get("/rules", pack=pack)
        if not isinstance(doc, list):
            raise AutomationError("/rules: not a list")
        return doc

    def rule_states(self, pack: str) -> dict[str, bool]:
        """``{rule name: enabled}`` for a pack."""
        return {r["name"]: bool(r.get("enabled")) for r in self.rules(pack)}


def make(**config: Any) -> AutomationTarget:
    """An :class:`AutomationTarget` on ``HNX_ENDPOINT_AUTOMATION``.

    ``api_key_env`` and ``api_key_header`` (both required) name the variable holding the read-only
    API key and the header it travels in; ``timeout`` and ``allow_plaintext`` (LAN http, the lab's
    own network) are the only other settings."""
    unknown = sorted(set(config) - {"api_key_env", "api_key_header", "timeout", "allow_plaintext"})
    if unknown:
        raise ValueError(f"automation adapter: unknown setting(s) {', '.join(unknown)}")
    for need in ("api_key_env", "api_key_header"):
        if need not in config:
            raise ValueError(f"automation adapter: {need} is required")
    key = env_secret(str(config["api_key_env"]))
    endpoint = resolve("automation", env_only=True, schemes=("http", "https"))
    return AutomationTarget(
        endpoint.url,
        api_key=key,
        api_key_header=str(config["api_key_header"]),
        timeout=float(config.get("timeout", 10.0)),
        allow_plaintext=bool(config.get("allow_plaintext", False)),
    )
