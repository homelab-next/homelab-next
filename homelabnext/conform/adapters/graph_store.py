# SPDX-License-Identifier: Apache-2.0
"""A read-only probe for the provisional ``graph-store`` slot (the shared adapter of modules/synapse-cortex).

The slot has no contract or conformance suite yet, so this is not one: it asks the service the two
things its health hook asks without a credential (it answers as the active one, and a query that
carries no session is refused), from the endpoint the registry resolver gives
(``HNX_ENDPOINT_GRAPH_STORE``; no default, no credential, nothing is written). The service's
certificate is its own: the probe trusts that one certificate (``ca_file``, the service's
``sslcert.pem``), never the system roots and never nothing, and checks the name that certificate
carries (``server_name``), so the verification is whole.
"""

from __future__ import annotations

import http.client
import json
import socket
import ssl
import urllib.parse
from typing import Any

from homelabnext.conform.adapters._env import AdapterConfigError, resolve

__all__ = ["GraphStoreProbe", "make"]


class GraphStoreProbe:
    def __init__(
        self, base_url: str, ca_file: str, server_name: str, timeout: float = 10.0
    ) -> None:
        parts = urllib.parse.urlsplit(base_url)
        self._host, self._port = parts.hostname or "", parts.port or 443
        self._name = server_name
        self._timeout = timeout
        # the service's own certificate is the only trust anchor; it is a leaf, so a partial chain is enough
        self._ctx = ssl.create_default_context(cafile=ca_file)
        self._ctx.verify_flags |= getattr(ssl, "VERIFY_X509_PARTIAL_CHAIN", 0)

    def _open(self, method: str, path: str, body: bytes | None = None) -> tuple[int, bytes]:
        ctx, name = self._ctx, self._name

        class Conn(http.client.HTTPSConnection):
            def connect(
                self,
            ) -> None:  # the name checked is the certificate's own, not the registry's address
                sock = socket.create_connection((self.host, self.port), self.timeout)
                self.sock = ctx.wrap_socket(sock, server_hostname=name)

        conn = Conn(self._host, self._port, timeout=self._timeout)
        try:
            headers = {"Content-Type": "application/json"} if body is not None else {}
            conn.request(method, path, body=body, headers=headers)
            resp = conn.getresponse()
            return int(resp.status), resp.read(65536)
        finally:
            conn.close()

    def health(self) -> bool:
        """True when the service answers as the active one."""
        status, raw = self._open("GET", "/api/v1/active")
        if status != 200:
            return False
        try:
            return json.loads(raw).get("result", {}).get("active") is True
        except (ValueError, AttributeError):
            return False

    def api_is_private(self) -> bool:
        """True when a storm call that carries no session is refused (401)."""
        body = json.dumps({"query": "inet:ipv4=0.0.0.0"}).encode()
        return self._open("POST", "/api/v1/storm/nodes", body)[0] == 401

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
    server_name = cfg.get("server_name")
    if not isinstance(server_name, str) or not server_name:
        raise AdapterConfigError(
            "graph-store: config server_name (the name that certificate carries) is required"
        )
    ep = resolve(
        "graph-store",
        resolver=resolver,
        domain=domain,
        env_only=resolver is None and domain is None,
        schemes=("https",),
    )
    return GraphStoreProbe(ep.url, ca_file, server_name, float(cfg.get("timeout", 10.0)))
