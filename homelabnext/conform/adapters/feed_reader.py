# SPDX-License-Identifier: Apache-2.0
"""A read-only probe for the provisional ``feed-reader`` slot (the shared adapter of modules/freshrss).

The slot has no contract or conformance suite yet, so this is not one: it asks the application
the two things its health hook asks without a credential (the sign-in page answers, and a feed-API
call that carries no valid key is refused), from the endpoint the registry resolver gives
(``HNX_ENDPOINT_FEED_READER``; no default, no credential, nothing is written).
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from homelabnext.conform.adapters._env import resolve

__all__ = ["FeedReaderProbe", "make"]

#: a key no account has (32 hex characters, the form the API wants): the reader must not accept it
_NO_ACCOUNT_KEY = "0" * 32


class FeedReaderProbe:
    def __init__(self, base_url: str, timeout: float = 10.0) -> None:
        self._base = base_url.rstrip("/")
        self._timeout = timeout

    def _open(self, req: urllib.request.Request) -> tuple[int, bytes]:
        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as r:
                return int(r.status), r.read(65536)
        except urllib.error.HTTPError as e:
            return int(e.code), b""

    def health(self) -> bool:
        return self._open(urllib.request.Request(self._base + "/i/", method="GET"))[0] == 200

    def api_is_private(self) -> bool:
        """True when the Fever endpoint answers and says the key is not authenticated."""
        body = urllib.parse.urlencode({"api_key": _NO_ACCOUNT_KEY}).encode()
        req = urllib.request.Request(self._base + "/api/fever.php?api", data=body, method="POST")
        status, raw = self._open(req)
        if status != 200:
            return False
        try:
            return int(json.loads(raw).get("auth", 1)) == 0
        except (ValueError, AttributeError):
            return False

    def close(self) -> None:  # the harness's teardown; nothing is held
        return None


def make(
    config: dict[str, Any] | None = None, *, resolver: Any = None, domain: str | None = None
) -> FeedReaderProbe:
    cfg = config or {}
    ep = resolve(
        "feed-reader",
        resolver=resolver,
        domain=domain,
        env_only=resolver is None and domain is None,
        schemes=("http", "https"),
    )
    return FeedReaderProbe(ep.url, float(cfg.get("timeout", 10.0)))
