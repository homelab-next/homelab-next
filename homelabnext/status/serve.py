# SPDX-License-Identifier: Apache-2.0
"""``hnx status serve``: the same page and ``status.json``, live from the hub's state.

Read-only by construction: the handler answers ``GET`` and ``HEAD`` for ``/``, ``/index.html``
and ``/status.json`` and nothing else (every other method is ``405``, every other path ``404``).
The one exception is ``POST /approvals/decide``, and only when the Approvals page is configured
(:mod:`homelabnext.status.approvals`: front door, approver group, same-origin, a CSRF token and
the digest the person saw); every other ``POST`` is still ``405``.
Each request builds the document from the state file only -- it never calls a source -- so a hung
or blackholed source cannot stall the console (O-07); collection runs elsewhere
(``hnx status collect``).

It binds loopback by default.  Another address is refused unless ``allow_remote=True``, which
also requires ``allowed_hosts``: the server has no authentication of its own, so exposing it is a
decision for the proxy in front (the forward-auth edge), not a default.

**DNS rebinding.**  Binding loopback is not enough: a web page the operator visits can point a
hostname of its own at the loopback address and read ``status.json`` same-origin.  So every request whose
``Host`` hostname (or ``Origin`` hostname, when the header is present) is not in the allowed set --
the IPv4 loopback address, ``localhost``, ``::1`` plus any configured ``allowed_hosts`` -- gets ``403``, as does
a request without ``Host``.  No CORS header is ever sent.  Every response carries ``nosniff``,
``no-store`` and a CSP that allows exactly the page's one inline stylesheet (by hash), nothing
else (after the AOS-1 monitor's ``hostAllowed``, MIT).
"""

from __future__ import annotations

import contextlib
import threading
import urllib.parse
from collections.abc import Callable, Iterable, Mapping
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from homelabnext._http import is_loopback

from .render import render_html, style_hash
from .views import dumps

LOOPBACK = "127.0.0.1"  # no-raw-endpoint: allow the read-only console binds loopback by default
LOOPBACK_NAMES = frozenset({LOOPBACK, "localhost", "::1"})
#: connections the console serves at once; more are answered 503 at once (BoundedHTTPServer)
DEFAULT_MAX_CONNECTIONS = 64
_BUSY = (
    b"HTTP/1.1 503 Service Unavailable\r\nContent-Type: text/plain; charset=utf-8\r\n"
    b"Content-Length: 5\r\nConnection: close\r\nRetry-After: 5\r\n\r\nbusy\n"
)
_HEADERS = {
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    "Content-Security-Policy": (
        f"default-src 'none'; style-src {style_hash()}; img-src 'self' data:; "
        "frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
    ),
    "Referrer-Policy": "no-referrer",
    "X-Frame-Options": "DENY",
}


def host_header_name(value: str | None) -> str | None:
    """The hostname of a ``Host`` header (``name``, ``name:port``, ``[v6]:port``), lower-cased;
    None when absent or malformed."""
    if not value or any(c in value for c in "/@ \t"):
        return None
    try:
        name = urllib.parse.urlsplit(f"//{value.strip()}").hostname
    except ValueError:
        return None
    return name.rstrip(".") if name else None


def origin_name(value: str) -> str | None:
    """The hostname of an ``Origin`` header (``null`` and garbage -> None)."""
    try:
        parts = urllib.parse.urlsplit(value.strip())
    except ValueError:
        return None
    if parts.scheme not in ("http", "https") or not parts.hostname:
        return None
    return parts.hostname.rstrip(".")


def host_allowed(host: str | None, origin: str | None, allowed: frozenset[str]) -> bool:
    """True when the Host hostname, and the Origin hostname if one was sent, are both allowed."""
    if host_header_name(host) not in allowed:
        return False
    return origin is None or origin_name(origin) in allowed


class BoundedHTTPServer(ThreadingHTTPServer):
    """A :class:`ThreadingHTTPServer` that serves at most ``max_connections`` connections at
    once: one more is answered ``503`` on the accepting thread and closed, without a thread of its
    own, so clients that connect and send nothing cannot pin a thread and a socket each until the
    host runs out (each handler also has a read timeout)."""

    daemon_threads = True

    def __init__(self, address, handler, *, max_connections: int = DEFAULT_MAX_CONNECTIONS):
        if max_connections < 1:
            raise ValueError("max_connections is at least 1")
        self.slots = threading.BoundedSemaphore(max_connections)
        super().__init__(address, handler)

    def process_request(self, request, client_address) -> None:
        if not self.slots.acquire(blocking=False):
            with contextlib.suppress(OSError):
                request.setblocking(False)  # never block the accepting thread on this peer
                request.send(_BUSY)
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()


def make_server(
    document: Callable[[], Mapping[str, Any]],
    *,
    host: str = LOOPBACK,
    port: int = 0,
    allow_remote: bool = False,
    allowed_hosts: Iterable[str] = (),
    docs_base: str = "docs",
    agents: Any = None,
    strategy: Any = None,
    baselines: Any = None,
    projects: Any = None,
    approvals: Any = None,
    orchestration: Any = None,
    maps: Any = None,
    max_connections: int = DEFAULT_MAX_CONNECTIONS,
) -> ThreadingHTTPServer:
    """A server for ``document()`` (called once per request).  ``port=0`` picks a free port;
    at most ``max_connections`` are served at once (:class:`BoundedHTTPServer`).

    ``allowed_hosts``: hostnames (no port) a request's ``Host``/``Origin`` may name besides the
    loopback names; required with ``allow_remote``.  ``agents``: an
    :class:`homelabnext.status.agents.pages.AgentSite` adds the agent pages (and, behind its
    trusted front door only, the private tier); ``strategy``: a
    :class:`homelabnext.strategy.pages.StrategySite` adds the strategy pages; ``baselines``: a
    :class:`homelabnext.compute.pages.BaselineSite` adds the Baselines page; ``approvals``: a
    :class:`homelabnext.status.approvals.ApprovalsSite` adds the Approvals page and its one
    ``POST`` route; ``maps``: a :class:`homelabnext.status.maps.MapSite` adds the generated maps
    (topology, dataflow, architecture, roadmap: ADR-0018); ``projects``: a
    :class:`homelabnext.projects.pages.ProjectsSite` adds the Projects page; ``orchestration``: an
    :class:`homelabnext.orchestration.pages.OrchestrationSite` adds the Orchestration page."""
    extra = frozenset(h.strip().lower().rstrip(".") for h in allowed_hosts if h.strip())
    if allow_remote and not extra:
        raise ValueError("allow_remote needs allowed_hosts: the hostnames clients will use")
    if not is_loopback(host) and not allow_remote:
        raise ValueError(
            f"refusing to bind {host}: the status console is loopback-only unless allow_remote "
            "is set (put the forward-auth proxy in front of it)"
        )
    allowed = LOOPBACK_NAMES | extra

    class Handler(BaseHTTPRequestHandler):
        server_version = "hnx-status"
        sys_version = ""
        timeout = 30  # a client that stops mid-request (a form body) cannot hold a thread

        def _reply(self, code: int, ctype: str, body: bytes, extra: dict | None = None) -> None:
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            for k, v in {**_HEADERS, **(extra or {})}.items():
                self.send_header(k, v)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def _guard(self) -> bool:
            """403 unless Host (and Origin, if sent) name an allowed host (DNS rebinding)."""
            if host_allowed(self.headers.get("Host"), self.headers.get("Origin"), allowed):
                return True
            self._reply(403, "text/plain; charset=utf-8", b"forbidden: host not allowed\n")
            return False

        def _get(self) -> None:
            if not self._guard():
                return
            route, _, query = self.path.partition("?")
            client = self.client_address[0] if self.client_address else None
            if route in ("/", "/index.html"):
                private = bool(agents) and agents.authorize(client, self.headers).allowed
                html = render_html(document(), docs_base=docs_base, live=True, private=private)
                self._reply(200, "text/html; charset=utf-8", html.encode("utf-8"))
            elif route == "/status.json":
                doc = dict(document())  # the public contract: the private group is not listed
                doc["menu"] = [m for m in doc["menu"] if m.get("group") != "private"]
                self._reply(200, "application/json", dumps(doc).encode("utf-8"))
            elif hit := self._page(route, query, client):
                self._reply(*hit)
            elif route.startswith("/private"):  # no activity store: still never served
                self._reply(403, "text/plain; charset=utf-8", b"forbidden: private view\n")
            else:
                self._reply(404, "text/plain; charset=utf-8", b"not found\n")

        def _page(self, route: str, query: str, client: str | None) -> Any:
            """The first page site's response for ``route``, or None; the document is built
            once, and only when some site is configured."""
            # (site, whether its handler also judges the caller), in the order routes resolve
            sites = [
                (approvals, True),
                (strategy, False),
                (projects, False),
                (orchestration, False),
                (baselines, False),
                (maps, False),
                (agents, True),
            ]
            sites = [(s, auth) for s, auth in sites if s is not None]
            if not sites:
                return None
            doc = document()
            for site, auth in sites:
                args = (client, self.headers) if auth else ()
                if hit := site.handle(route, query, doc, *args):
                    return hit
            return None

        do_GET = _get
        do_HEAD = _get

        def _refuse(self) -> None:
            if not self._guard():
                return
            self._reply(
                405, "text/plain; charset=utf-8", b"read-only: GET only\n", {"Allow": "GET, HEAD"}
            )

        def do_POST(self) -> None:
            route = self.path.partition("?")[0]
            if approvals is None or route != "/approvals/decide":
                self._refuse()
                return
            client = self.client_address[0] if self.client_address else None
            if not host_allowed(self.headers.get("Host"), self.headers.get("Origin"), allowed):
                # the same DNS-rebinding refusal as every route, and logged like every attempt
                self._reply(*approvals.refuse(client, self.headers, 403, "host not allowed"))
                return
            self._reply(*approvals.decide(document(), client, self.headers, self.rfile.read))

        do_PUT = do_PATCH = do_DELETE = do_OPTIONS = _refuse

        def log_message(self, *a: Any) -> None:  # quiet; the CLI prints the URL once
            pass

    return BoundedHTTPServer((host, port), Handler, max_connections=max_connections)
