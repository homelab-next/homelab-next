# SPDX-License-Identifier: Apache-2.0
"""Contract for ``edge`` (extended suite): a reverse proxy with forward authentication.

Routing is by ``Host`` (case-insensitive, port ignored) and then longest path prefix, after the
path is normalised (``..`` and ``//`` resolved *before* matching).  A route that requires auth
is never forwarded without an authenticated identity; the proxy sets the identity header itself
and drops any copy a client sent.  Upstream failures are 502, never a crash.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

__all__ = ["IDENTITY_HEADER", "EdgeProxy", "Request", "Response"]

IDENTITY_HEADER = "x-auth-user"


@dataclass(frozen=True)
class Request:
    host: str
    path: str = "/"
    method: str = "GET"
    headers: Mapping[str, str] = field(default_factory=dict)  # lower-case names
    client: str = "203.0.113.7"  # no-raw-endpoint: allow RFC 5737 documentation address


@dataclass(frozen=True)
class Response:
    status: int
    body: str = ""
    headers: Mapping[str, str] = field(default_factory=dict)


@runtime_checkable
class EdgeProxy(Protocol):
    def add_upstream(self, name: str, handler: Callable[[Request], Response]) -> None: ...

    def add_route(
        self, host: str, upstream: str, *, prefix: str = "/", auth: bool = False
    ) -> None: ...

    def set_authenticator(self, fn: Callable[[Mapping[str, str]], str | None]) -> None:
        """``fn(headers)`` returns the user name or None."""

    def handle(self, request: Request) -> Response: ...
