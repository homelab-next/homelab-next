# SPDX-License-Identifier: Apache-2.0
"""The one seam every byte of network traffic of this module goes through.

Adapters take a :class:`Transport`; a test passes a fake.  ``stage`` mode builds none (the
:class:`NoNetwork` transport raises on any call), ``dry-run`` wraps the real one in
:class:`ReadOnly` (only GET and HEAD pass), ``live`` uses :class:`Urllib`.
"""

from __future__ import annotations

import urllib.error
import urllib.request
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Protocol

from homelabnext._http import no_redirect_urlopen


class NetworkForbidden(RuntimeError):
    """A call the mode does not allow (stage: any; dry-run: a write)."""


@dataclass(frozen=True)
class Request:
    method: str
    url: str
    headers: Mapping[str, str] = field(default_factory=dict)
    body: bytes = b""


@dataclass(frozen=True)
class Response:
    status: int
    headers: Mapping[str, str]
    body: bytes


class Transport(Protocol):
    def send(self, request: Request) -> Response: ...


class NoNetwork:
    """stage mode: any call is a bug, and loud."""

    def send(self, request: Request) -> Response:
        raise NetworkForbidden(f"stage mode makes no network call ({request.method} refused)")


class ReadOnly:
    """dry-run: reads pass, anything that could change the remote is refused before it is sent."""

    def __init__(self, inner: Transport) -> None:
        self._inner = inner

    def send(self, request: Request) -> Response:
        if request.method.upper() not in ("GET", "HEAD"):
            raise NetworkForbidden(f"dry-run is read-only ({request.method} refused)")
        return self._inner.send(request)


class Urllib:
    """The live transport: HTTPS only, no redirects followed, bounded time."""

    def __init__(self, timeout: float = 120.0) -> None:
        self.timeout = timeout

    def send(self, request: Request) -> Response:
        if not request.url.startswith("https://"):
            raise NetworkForbidden("only https is used")
        req = urllib.request.Request(
            request.url,
            data=request.body or None,
            headers=dict(request.headers),
            method=request.method,
        )
        try:
            with no_redirect_urlopen(req, timeout=self.timeout) as resp:
                return Response(
                    resp.status, {k.lower(): v for k, v in resp.headers.items()}, resp.read()
                )
        except urllib.error.HTTPError as exc:
            return Response(
                exc.code, {k.lower(): v for k, v in (exc.headers or {}).items()}, exc.read()
            )
