# SPDX-License-Identifier: Apache-2.0
"""A read-only probe for the provisional ``graph-store`` slot (the shared adapter of modules/synapse-cortex).

The slot has no contract or conformance suite yet, so this is not one: it asks the service the two
things its health hook asks without a credential (it answers as the active one, and a query that
carries no session is refused), from the endpoint the registry resolver gives
(``HNX_ENDPOINT_GRAPH_STORE``; no default, no credential, nothing is written). The service's
certificate is its own: the probe trusts that one certificate (``ca_file``, the service's
``sslcert.pem``), never the system roots and never nothing.
"""

from __future__ import annotations

import json
import ssl
import urllib.error
import urllib.request
from typing import Any

from homelabnext.conform.adapters._env import AdapterConfigError, resolve

__all__ = ["GraphStoreProbe", "make"]


class GraphStoreProbe:
    def __init__(self, base_url: str, ca_file: str, timeout: float = 10.0) -> None:
        self._base = base_url.rstrip("/")
        self._timeout = timeout
        # the service's own certificate is the only trust anchor; the host is the registry's address, so
        # the name in the certificate is not compared (the certificate itself is)
        self._ctx = ssl.create_default_context(cafile=ca_file)
        self._ctx.check_hostname = False
        self._ctx.verify_flags |= getattr(ssl, "VERIFY_X509_PARTIAL_CHAIN", 0)

    def _open(self, req: urllib.request.Request) -> tuple[int, bytes]:
        try:
            with urllib.request.urlopen(req, timeout=self._timeout, context=self._ctx) as r:
                return int(r.status), r.read(65536)
        except urllib.error.HTTPError as e:
            return int(e.code), b""

    def health(self) -> bool:
        """True when the service answers as the active one."""
        status, raw = self._open(
            urllib.request.Request(self._base + "/api/v1/active", method="GET")
        )
        if status != 200:
            return False
        try:
            return json.loads(raw).get("result", {}).get("active") is True
        except (ValueError, AttributeError):
            return False

    def api_is_private(self) -> bool:
        """True when a storm call that carries no session is refused (401)."""
        body = json.dumps({"query": "inet:ipv4=0.0.0.0"}).encode()
        req = urllib.request.Request(
            self._base + "/api/v1/storm/nodes",
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        return self._open(req)[0] == 401

    def close(self) -> None:  # the harness's teardown; nothing is held
        return None


def make(
    config: dict[str, Any] | None = None, *, resolver: Any = None, domain: str | None = None
) -> GraphStoreProbe:
    cfg = config or {}
    ca_file = cfg.get("ca_file")
    if not isinstance(ca_file, str) or not ca_file:
        raise AdapterConfigError(
            "graph-store: config ca_file (the service's own certificate) is required"
        )
    ep = resolve(
        "graph-store",
        resolver=resolver,
        domain=domain,
        env_only=resolver is None and domain is None,
        schemes=("https",),
    )
    return GraphStoreProbe(ep.url, ca_file, float(cfg.get("timeout", 10.0)))
