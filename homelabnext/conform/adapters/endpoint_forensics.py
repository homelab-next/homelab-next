# SPDX-License-Identifier: Apache-2.0
"""A read-only probe for the provisional ``endpoint-forensics`` slot (the shared adapter of
modules/velociraptor).

The slot has no contract or conformance suite yet, so this is not one: it asks the server the two
things its health hook asks from inside its container, from the endpoint the registry resolver
gives (``HNX_ENDPOINT_ENDPOINT_FORENSICS``, the GUI's address; no default, no credential, nothing is
written): the clients' port serves the server's certificate, and the GUI refuses a request that
carries no sign-in. Both are TLS connections verified against ``ca_file`` (the server's own
authority: its client configuration carries it) under the name the server's certificates are
issued to, never with verification off.
"""

from __future__ import annotations

import socket
import ssl
from typing import Any
from urllib.parse import urlsplit

from homelabnext.conform.adapters._env import AdapterConfigError, resolve

__all__ = ["EndpointForensicsProbe", "make"]

_MAX = 1 << 16


class EndpointForensicsProbe:
    def __init__(
        self,
        base_url: str,
        ca_file: str,
        *,
        server_name: str,
        frontend_port: int = 8000,
        timeout: float = 10.0,
    ) -> None:
        parts = urlsplit(base_url)
        if parts.scheme != "https" or not parts.hostname:
            raise AdapterConfigError("endpoint-forensics: the GUI endpoint is https://host:port")
        if not ca_file or not server_name:
            raise AdapterConfigError(
                "endpoint-forensics: ca_file (the server's authority) and server_name (the name "
                "its certificates are issued to) are required"
            )
        self._host = parts.hostname
        self._gui_port = parts.port or 443
        self._frontend_port = int(frontend_port)
        self._name = server_name
        self._timeout = timeout
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)  # verifies the certificate and the name
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_verify_locations(cafile=ca_file)
        self._ctx = ctx

    def _get(self, port: int, path: str) -> tuple[int, bytes]:
        with (
            socket.create_connection((self._host, port), timeout=self._timeout) as raw,
            self._ctx.wrap_socket(raw, server_hostname=self._name) as tls,
        ):
            tls.sendall(
                f"GET {path} HTTP/1.0\r\nHost: {self._name}\r\nConnection: close\r\n\r\n".encode()
            )
            data = b""
            while len(data) < _MAX:
                chunk = tls.recv(4096)
                if not chunk:
                    break
                data += chunk
        status = data.split(b"\r\n", 1)[0].split()
        code = int(status[1]) if len(status) >= 2 and status[1].isdigit() else 0
        return code, data.partition(b"\r\n\r\n")[2]

    def health(self) -> bool:
        """The clients' port serves the server's certificate (verified)."""
        try:
            code, body = self._get(self._frontend_port, "/server.pem")
        except (OSError, ssl.SSLError):
            return False
        return code == 200 and b"BEGIN CERTIFICATE" in body

    def gui_is_private(self) -> bool:
        """True when the GUI answers a request with no sign-in with 401 (verified TLS)."""
        try:
            code, _ = self._get(self._gui_port, "/app/index.html")
        except (OSError, ssl.SSLError):
            return False
        return code == 401

    def close(self) -> None:  # the harness's teardown; nothing is held
        return None


def make(
    config: dict[str, Any] | None = None, *, resolver: Any = None, domain: str | None = None
) -> EndpointForensicsProbe:
    cfg = config or {}
    ep = resolve(
        "endpoint-forensics",
        resolver=resolver,
        domain=domain,
        env_only=resolver is None and domain is None,
        schemes=("https",),
    )
    return EndpointForensicsProbe(
        ep.url,
        str(cfg.get("ca_file") or ""),
        server_name=str(cfg.get("server_name") or ""),
        frontend_port=int(cfg.get("frontend_port", 8000)),
        timeout=float(cfg.get("timeout", 10.0)),
    )
