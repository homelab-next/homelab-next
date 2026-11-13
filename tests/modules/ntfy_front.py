# SPDX-License-Identifier: Apache-2.0
"""A deny-all front for the loopback ntfy stand-in (``conformance.fakes.ntfy_api.FakeNtfy``), the
way the ``ntfy`` module configures the server: a request without the publisher's bearer token is
refused (403 on a topic, as ntfy answers an anonymous publish under deny-all; 401 for a bad
token), ``/v1/health`` is open, and ``GET /v1/account`` answers the admin's basic-auth sign-in.
The publish and poll themselves are the stand-in's, unchanged, so the notify suite runs exactly
as it does against the open stand-in.  Shared by tests/modules/test_ntfy_module.py and
tests/roles/test_ntfy_role.py."""

from __future__ import annotations

import base64
import hmac
import json
from typing import Any

from conformance.fakes.ntfy_api import FakeNtfy

__all__ = ["DenyAllNtfy"]


class DenyAllNtfy(FakeNtfy):
    def __init__(self, *, token: str, admin: tuple[str, str], **kw: Any):
        self.token = token
        self.admin = admin
        self.refused = 0
        super().__init__(**kw)

    def _handler(self):
        base = super()._handler()
        front = self

        class Handler(base):  # type: ignore[misc, valid-type]
            def _bearer_ok(self) -> bool | None:
                auth = self.headers.get("Authorization") or ""
                if not auth:
                    return None
                return hmac.compare_digest(auth, "Bearer " + front.token)

            def _refuse(self, ok: bool | None) -> None:
                front.refused += 1
                if ok is None:
                    self._send(403, b'{"code":40301,"error":"forbidden"}')
                else:
                    self._send(401, b'{"code":40101,"error":"unauthorized"}')

            def do_POST(self) -> None:
                ok = self._bearer_ok()
                if not ok:
                    n = int(self.headers.get("Content-Length") or 0)
                    if n:
                        self.rfile.read(n)
                    self._refuse(ok)
                    return
                super().do_POST()

            def do_GET(self) -> None:
                path = self.path.split("?", 1)[0]
                if path == "/v1/health":
                    super().do_GET()
                    return
                if path == "/v1/account":
                    want = "Basic " + base64.b64encode(":".join(front.admin).encode()).decode()
                    if hmac.compare_digest(self.headers.get("Authorization") or "", want):
                        doc = {"username": front.admin[0], "role": "admin"}
                        self._send(200, json.dumps(doc).encode())
                    else:
                        self._send(401, b'{"code":40101,"error":"unauthorized"}')
                    return
                ok = self._bearer_ok()
                if not ok:
                    self._refuse(ok)
                    return
                super().do_GET()

        return Handler
