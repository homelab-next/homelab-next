# SPDX-License-Identifier: Apache-2.0
"""Read-only probes for the provisional ``siem-source`` and ``hot-index`` slots (the shared adapters
of modules/wazuh).

Neither slot has a contract or a conformance suite yet, so these are not suites: each asks the
service the one thing its health hook asks without a credential, from the endpoint the registry
resolver gives (``HNX_ENDPOINT_SIEM_SOURCE`` and ``HNX_ENDPOINT_HOT_INDEX``; no default, no
credential, nothing is written).  The event port answers a TCP connection; the index's API
refuses an anonymous request (a 401) over TLS verified against ``ca_file`` (the module's private
CA), never with verification off.
"""

from __future__ import annotations

import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from homelabnext.conform.adapters._env import resolve

__all__ = ["HotIndexProbe", "SiemSourceProbe", "make_hot_index", "make_siem_source"]


def _hostport(url: str, default_port: int) -> tuple[str, int]:
    parts = urllib.parse.urlsplit(url if "//" in url else "//" + url)
    if not parts.hostname:
        raise ValueError("an endpoint with a host is required")
    return parts.hostname, parts.port or default_port


class SiemSourceProbe:
    def __init__(self, host: str, port: int, timeout: float = 10.0) -> None:
        self._addr = (host, port)
        self._timeout = timeout

    def health(self) -> bool:
        """The event port accepts a TCP connection."""
        try:
            with socket.create_connection(self._addr, timeout=self._timeout):
                return True
        except OSError:
            return False

    def close(self) -> None:  # the harness's teardown; nothing is held
        return None


class HotIndexProbe:
    def __init__(self, base_url: str, ca_file: str, timeout: float = 10.0) -> None:
        parts = urllib.parse.urlsplit(base_url)
        if parts.scheme != "https" or not parts.netloc:
            raise ValueError("the index is reached over https")
        self._base = f"{parts.scheme}://{parts.netloc}"
        self._timeout = timeout
        self._ctx = ssl.create_default_context(cafile=ca_file)

    def _status(self, path: str) -> int:
        req = urllib.request.Request(self._base + path, method="GET")
        try:
            with urllib.request.urlopen(req, timeout=self._timeout, context=self._ctx) as r:
                return int(r.status)
        except urllib.error.HTTPError as e:
            return int(e.code)

    def health(self) -> bool:
        """The certificate verifies against the CA and the API answers."""
        try:
            return self._status("/") in (200, 401)
        except (OSError, urllib.error.URLError):
            return False

    def anonymous_is_refused(self) -> bool:
        return self._status("/_cluster/health") == 401

    def close(self) -> None:  # the harness's teardown; nothing is held
        return None


def make_siem_source(
    config: dict[str, Any] | None = None, *, resolver: Any = None, domain: str | None = None
) -> SiemSourceProbe:
    cfg = config or {}
    ep = resolve(
        "siem-source",
        resolver=resolver,
        domain=domain,
        env_only=resolver is None and domain is None,
        schemes=("tcp", "http", "https"),
    )
    host, port = _hostport(ep.url, 1514)
    return SiemSourceProbe(host, port, float(cfg.get("timeout", 10.0)))


def make_hot_index(
    config: dict[str, Any] | None = None, *, resolver: Any = None, domain: str | None = None
) -> HotIndexProbe:
    cfg = config or {}
    if not cfg.get("ca_file"):
        raise ValueError("ca_file (the module's private CA) is required")
    ep = resolve(
        "hot-index",
        resolver=resolver,
        domain=domain,
        env_only=resolver is None and domain is None,
        schemes=("https",),
    )
    return HotIndexProbe(ep.url, str(cfg["ca_file"]), float(cfg.get("timeout", 10.0)))
