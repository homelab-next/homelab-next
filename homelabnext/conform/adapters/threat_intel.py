# SPDX-License-Identifier: Apache-2.0
"""A read-only probe for the provisional ``threat-intel`` slot (the shared adapter of modules/misp).

The slot has no contract or conformance suite yet, so this is not one: it asks the platform the
two things its health hook asks without a credential (the sign-in page answers, and an API call
that carries no valid key is refused), from the endpoint the registry resolver gives
(``HNX_ENDPOINT_THREAT_INTEL``; no default, no credential, nothing is written). The platform
serves HTTPS: ``ca_file`` is the certificate (or the CA) the service presents, so the probe always
verifies what it talks to and never sends a secret.
"""

from __future__ import annotations

import urllib.error
import urllib.request
from typing import Any

from homelabnext._http import credential_opener
from homelabnext.conform.adapters._env import resolve

__all__ = ["ThreatIntelProbe", "make"]

#: a key no account has (40 alphanumeric characters, the form the API wants): the platform must
#: refuse it
_NO_ACCOUNT_KEY = "0" * 40


class ThreatIntelProbe:
    def __init__(self, base_url: str, timeout: float = 10.0, ca_file: str | None = None) -> None:
        self._base = base_url.rstrip("/")
        self._timeout = timeout
        self._opener = credential_opener(ca_file)

    def _status(self, req: urllib.request.Request) -> int:
        try:
            with self._opener.open(req, timeout=self._timeout) as r:
                return int(r.status)
        except urllib.error.HTTPError as e:
            return int(e.code)

    def health(self) -> bool:
        return self._status(urllib.request.Request(self._base + "/users/login")) == 200

    def api_is_private(self) -> bool:
        """True when the version call is refused with no key and with a key no account has."""
        for key in (None, _NO_ACCOUNT_KEY):
            req = urllib.request.Request(self._base + "/servers/getVersion")
            req.add_header("Accept", "application/json")
            if key:
                req.add_header("Authorization", key)
            if self._status(req) not in (401, 403):
                return False
        return True

    def close(self) -> None:  # the harness's teardown; nothing is held
        return None


def make(
    config: dict[str, Any] | None = None, *, resolver: Any = None, domain: str | None = None
) -> ThreatIntelProbe:
    cfg = config or {}
    ep = resolve(
        "threat-intel",
        resolver=resolver,
        domain=domain,
        env_only=resolver is None and domain is None,
        schemes=("http", "https"),
    )
    return ThreatIntelProbe(ep.url, float(cfg.get("timeout", 10.0)), cfg.get("ca_file"))
