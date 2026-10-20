# SPDX-License-Identifier: Apache-2.0
"""``hnx status serve``: the same page and ``status.json``, live from the hub's state.

Read-only by construction: the handler answers ``GET`` and ``HEAD`` for ``/``, ``/index.html``
and ``/status.json`` and nothing else (every other method is ``405``, every other path ``404``).
Each request builds the document from the state file only -- it never calls a source -- so a hung
or blackholed source cannot stall the console (O-07); collection runs elsewhere
(``hnx status collect``).

It binds loopback by default.  Another address is refused unless ``allow_remote=True``: the
server has no authentication of its own, so exposing it is a decision for the proxy in front
(the forward-auth edge), not a default.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from homelabnext._http import is_loopback

from .render import render_html
from .views import dumps

LOOPBACK = "127.0.0.1"  # no-raw-endpoint: allow the read-only console binds loopback by default
_HEADERS = {
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'",
    "Referrer-Policy": "no-referrer",
}


def make_server(
    document: Callable[[], Mapping[str, Any]],
    *,
    host: str = LOOPBACK,
    port: int = 0,
    allow_remote: bool = False,
    docs_base: str = "docs",
) -> ThreadingHTTPServer:
    """A server for ``document()`` (called once per request).  ``port=0`` picks a free port."""
    if not is_loopback(host) and not allow_remote:
        raise ValueError(
            f"refusing to bind {host}: the status console is loopback-only unless allow_remote "
            "is set (put the forward-auth proxy in front of it)"
        )

    class Handler(BaseHTTPRequestHandler):
        server_version = "hnx-status"
        sys_version = ""

        def _reply(self, code: int, ctype: str, body: bytes, extra: dict | None = None) -> None:
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            for k, v in {**_HEADERS, **(extra or {})}.items():
                self.send_header(k, v)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def _get(self) -> None:
            route = self.path.split("?", 1)[0]
            if route in ("/", "/index.html"):
                html = render_html(document(), docs_base=docs_base).encode("utf-8")
                self._reply(200, "text/html; charset=utf-8", html)
            elif route == "/status.json":
                self._reply(200, "application/json", dumps(document()).encode("utf-8"))
            else:
                self._reply(404, "text/plain; charset=utf-8", b"not found\n")

        do_GET = _get
        do_HEAD = _get

        def _refuse(self) -> None:
            self._reply(
                405, "text/plain; charset=utf-8", b"read-only: GET only\n", {"Allow": "GET, HEAD"}
            )

        do_POST = do_PUT = do_PATCH = do_DELETE = do_OPTIONS = _refuse

        def log_message(self, *a: Any) -> None:  # quiet; the CLI prints the URL once
            pass

    return ThreadingHTTPServer((host, port), Handler)
