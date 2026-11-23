# SPDX-License-Identifier: Apache-2.0
"""A read-only probe for the provisional ``network-sensor`` slot (the shared adapter of the sensor modules).

The slot has no contract or conformance suite yet, so this is not one: a passive sensor listens
on nothing, so the one thing a caller can ask of it without a credential is that its host answers
on the port the registry row names (the host's SSH). Whether the capture itself is healthy
(running, kernel drops under a bound, event output growing) is the sensor role's health hook,
which reads the engine, not the network. The endpoint is the one the registry resolver gives
(``HNX_ENDPOINT_NETWORK_SENSOR``; no default); nothing is sent and nothing is written.
"""

from __future__ import annotations

import socket
from typing import Any

from homelabnext.conform.adapters._env import resolve

__all__ = ["NetworkSensorProbe", "make"]


class NetworkSensorProbe:
    def __init__(self, host: str, port: int, timeout: float = 5.0) -> None:
        self._addr = (host, port)
        self._timeout = timeout

    def health(self) -> bool:
        """True when the sensor host accepts a connection on the row's port (nothing is sent)."""
        try:
            with socket.create_connection(self._addr, timeout=self._timeout):
                return True
        except OSError:
            return False

    def close(self) -> None:  # the harness's teardown; nothing is held
        return None


def make(
    config: dict[str, Any] | None = None, *, resolver: Any = None, domain: str | None = None
) -> NetworkSensorProbe:
    cfg = config or {}
    ep = resolve(
        "network-sensor",
        resolver=resolver,
        domain=domain,
        env_only=resolver is None and domain is None,
        schemes=("tcp", "ssh"),
    )
    return NetworkSensorProbe(ep.host, int(ep.port), float(cfg.get("timeout", 5.0)))
