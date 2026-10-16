# SPDX-License-Identifier: Apache-2.0
"""In-memory reverse proxy (``edge`` fake) and a header-spoofing defect."""

from __future__ import annotations

import posixpath
from collections.abc import Callable, Mapping
from dataclasses import replace

from conformance.protocols.edge import IDENTITY_HEADER, Request, Response

HOP_BY_HOP = ("connection", "keep-alive", "te", "trailer", "transfer-encoding", "upgrade")


class FakeEdgeProxy:
    features = frozenset()

    def __init__(self) -> None:
        self._up: dict[str, Callable[[Request], Response]] = {}
        self._routes: list[tuple[str, str, str, bool]] = []
        self._auth: Callable[[Mapping[str, str]], str | None] = lambda h: None

    def add_upstream(self, name, handler):
        self._up[name] = handler

    def add_route(self, host, upstream, *, prefix="/", auth=False):
        self._routes.append((host.lower(), prefix, upstream, auth))

    def set_authenticator(self, fn):
        self._auth = fn

    @staticmethod
    def _path(path: str) -> str:
        p = posixpath.normpath("/" + path.split("?")[0].lstrip("/"))
        return "//" if p.startswith("//") else p

    def _clean(self, headers: Mapping[str, str]) -> dict[str, str]:
        out = {k.lower(): v for k, v in headers.items() if k.lower() not in HOP_BY_HOP}
        out.pop(IDENTITY_HEADER, None)  # the proxy alone decides who the user is
        return out

    def handle(self, request: Request) -> Response:
        host = (
            request.host.lower().rsplit(":", 1)[0] if ":" in request.host else request.host.lower()
        )
        path = self._path(request.path)
        cands = [
            r
            for r in self._routes
            if r[0] == host
            and (path == r[1].rstrip("/") or path.startswith(r[1].rstrip("/") + "/"))
        ]
        if not cands:
            return Response(404, "no such host or path")
        _, _prefix, upstream, needs_auth = max(cands, key=lambda r: len(r[1]))
        headers = self._clean(request.headers)
        if needs_auth:
            user = self._auth(request.headers)
            if user is None:
                return Response(401, "authentication required")
            headers[IDENTITY_HEADER] = user
        prior = request.headers.get("x-forwarded-for")
        headers["x-forwarded-for"] = f"{prior}, {request.client}" if prior else request.client
        try:
            return self._up[upstream](replace(request, path=path, headers=headers))
        except Exception:
            return Response(502, "bad gateway")


class SpoofableEdgeProxy(FakeEdgeProxy):
    """Defect: a client-supplied identity header is forwarded as if the proxy had set it."""

    def _clean(self, headers):
        return {k.lower(): v for k, v in headers.items() if k.lower() not in HOP_BY_HOP}
