# SPDX-License-Identifier: Apache-2.0
"""The ``edge`` contract on Caddy (pinned: 2.11.7), configured as the edge module configures it.

``make(**config)`` returns a :class:`CaddyEdge`: a Caddy process of its own, on loopback, whose
configuration is rebuilt from the contract's routes with **the production pieces**: the edge
generator's ``hnx_forward_auth`` snippet (:func:`homelabnext.generators.builtin._forward_auth_snippet`,
the strip of every client-sent identity header in a ``route`` before ``forward_auth``), its
site-level strip and its foreign-identity strip, and the module role's catch-all site (a host no
site names answers 404).  Only the routing table is the contract's: each ``add_route`` is a
``handle`` on a ``path <prefix> <prefix>/*`` matcher, the longest prefix written first (Caddy
runs the first ``handle`` that matches), and an ``auth=True`` route imports the snippet.

Never the lab's edge: the adapter starts its own ``caddy run`` (admin API on a free loopback
port, its own temporary ``HOME``/``XDG_*`` directories) and loads each new configuration through
that admin API.  The binary is ``$HNX_CADDY`` (``caddy_env`` names another variable), else
``caddy`` on ``PATH``; to prove the lab's pin, copy the binary out of the module's pinned image
(``docker cp``) or use the release CI installs.

**Translation at the boundary** (the contract is product-neutral, Caddy and its auth proxy are
not):

* The contract's identity header (``x-auth-user``) is the platform's identity headers
  (:data:`homelabnext.edge_identity.IDENTITY_HEADERS`: user, groups, e-mail, username).  A
  client-sent ``x-auth-user`` is sent to Caddy as **every** one of them and as other proxies'
  (``X-Forwarded-User``, ``Remote-User``, ...), each in the ``-``, the ``_`` and a mixed spelling
  (a forgery of the real headers, not of a name nothing reads).  The upstream's ``x-auth-user`` is
  every distinct value any of those headers arrived with, joined by ``,``: the auth proxy's one
  user when the strip held, the user and the forged value side by side when any copy got through,
  so a strip that let one spelling of one header through fails the contract's check.
* The authenticator is the auth proxy: a loopback server answering ``forward_auth``.  The
  contract's ``fn(headers)`` is called with the headers Caddy forwards to it (lower-cased); a
  user name is a 200 with the identity headers, ``None`` a 401.
* The snippet turns the auth proxy's 401 into a redirect to the sign-in page
  (``/oauth2/sign_in``): that redirect is the contract's ``401``.
* An upstream handler that raises makes its loopback server drop the connection without an
  answer, which Caddy reports as 502 (a real dead upstream, not a canned status).

**Findings** (fidelity of the product, reported, not hidden):

* ``forwarded-for-appended`` (SHOULD) fails: Caddy does not trust a client's ``X-Forwarded-For``
  unless the client is a configured ``trusted_proxies`` (the edge has none: it is the first
  proxy), so it sets the header to the connection's address instead of appending, and the
  connection's address is the adapter's own loopback, never the contract's documentation
  address.  Replacing a client's header is the safer behaviour for a front door.
* The adapter speaks plain HTTP to its Caddy: the contract is routing, auth and header hygiene;
  TLS on the lab's edge is the module role's health hook's to prove.
* Not proved here (the contract has no such check): the auth proxy's 403 for a signed-in user
  outside a site's allowed groups (the stand-in answers 200 or 401 only), and the sites as the
  generator renders them for a registry (the routes are the contract's; the snippet and strips
  are the generator's own code). The module's tests adapt the generated sites with Caddy.
* Its admin API is on loopback without authentication, on a port picked free just before Caddy
  binds it (a race with another local process is possible, and fails the run, never passes it).
"""

from __future__ import annotations

import contextlib
import http.client
import os
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from conformance.protocols.edge import IDENTITY_HEADER, Request, Response
from homelabnext._http import DEFAULT_MAX_BYTES, content_length, read_bounded
from homelabnext.edge_identity import AUTH_PROXY_SIGN_IN, IDENTITY_HEADERS, foreign_strip_lines
from homelabnext.generators.builtin import FOREIGN_STRIP_SNIPPET, _forward_auth_snippet

from ._env import AdapterConfigError

__all__ = ["CaddyEdge", "make"]

_LOOPBACK = (
    "127.0.0.1"  # no-raw-endpoint: allow the adapter's own Caddy and stubs are local by design
)
#: the allowed-groups argument the snippet passes the auth proxy (the stand-in ignores it)
_GROUPS = "conformance"
_TIMEOUT = 10.0


def _free_port() -> int:
    with socket.socket() as s:
        s.bind((_LOOPBACK, 0))
        return s.getsockname()[1]


class _Server(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, handler: Callable[[BaseHTTPRequestHandler], None]):
        self.respond = handler

        class H(BaseHTTPRequestHandler):
            def log_message(self, *args):  # quiet
                return

            def _any(self):
                self.server.respond(self)  # type: ignore[attr-defined]

            do_GET = do_POST = do_PUT = do_DELETE = do_HEAD = do_PATCH = do_OPTIONS = _any

        super().__init__((_LOOPBACK, 0), H)
        self.thread = threading.Thread(target=self.serve_forever, daemon=True)
        self.thread.start()

    @property
    def port(self) -> int:
        return self.server_address[1]

    def stop(self) -> None:
        self.shutdown()
        self.server_close()


def _body(h: BaseHTTPRequestHandler) -> bytes:
    n = content_length(h.headers.get("Content-Length")) or 0
    return h.rfile.read(min(n, DEFAULT_MAX_BYTES)) if n else b""


def _reply(h: BaseHTTPRequestHandler, resp: Response) -> None:
    data = resp.body.encode("utf-8")
    h.send_response(resp.status)
    for k, v in resp.headers.items():
        h.send_header(k, v)
    h.send_header("Content-Length", str(len(data)))
    h.end_headers()
    if h.command != "HEAD":
        h.wfile.write(data)


#: other proxies' identity headers a forgery also sends (homelabnext.edge_identity.FOREIGN_IDENTITY
#: stems, as an app would read them)
_FOREIGN_FORGED = ("X-Forwarded-User", "X-Forwarded-Groups", "X-Forwarded-Preferred-Username",
                   "Remote-User", "X-WEBAUTH-USER")  # fmt: skip


def _spelled(name: str) -> list[str]:
    """``name`` with ``-`` and with ``_`` at every separator, and a mixed spelling of each."""
    parts = name.split("-")
    mixed = "".join(p + ("_" if i % 2 else "-") for i, p in enumerate(parts[:-1])) + parts[-1]
    return list(dict.fromkeys([name, name.replace("-", "_"), mixed]))


def _identity_names() -> tuple[str, ...]:
    """Every identity header in every spelling (what a forgery sends)."""
    return tuple(s for name in IDENTITY_HEADERS.headers for s in _spelled(name))


def _forged_names() -> tuple[str, ...]:
    """The identity headers and other proxies' ones, every spelling: the whole forgery."""
    return _identity_names() + tuple(s for name in _FOREIGN_FORGED for s in _spelled(name))


def _norm(name: str) -> str:
    return name.lower().replace("_", "-")


class CaddyEdge:
    """One Caddy process and its loopback stand-ins (an auth proxy, one server per upstream)."""

    features = frozenset()

    def __init__(self, caddy: str):
        self._caddy = caddy
        self._up: dict[str, Callable[[Request], Response]] = {}
        self._servers: dict[str, _Server] = {}
        self._routes: list[tuple[str, str, str, bool]] = []
        self._auth: Callable[[Mapping[str, str]], str | None] = lambda h: None
        self._dirty = True
        self._proc: subprocess.Popen | None = None
        self._tmp = tempfile.TemporaryDirectory(prefix="hnx-caddy-edge-")
        self._auth_server = _Server(self._answer_auth)
        # Caddy's ports are picked when it starts (_load), after the stand-ins have bound theirs:
        # a port picked earlier and released could be handed to a stand-in bound after it
        self._port = 0
        self._admin = 0

    def __repr__(self) -> str:
        return f"CaddyEdge({self._caddy!r}, port={self._port})"

    # ------------------------------------------------------------------ the contract
    def add_upstream(self, name: str, handler: Callable[[Request], Response]) -> None:
        self._up[name] = handler
        if name not in self._servers:
            self._servers[name] = _Server(lambda h, n=name: self._answer_upstream(n, h))
        self._dirty = True

    def add_route(self, host: str, upstream: str, *, prefix: str = "/", auth: bool = False) -> None:
        self._routes.append((host.lower(), prefix, upstream, auth))
        self._dirty = True

    def set_authenticator(self, fn: Callable[[Mapping[str, str]], str | None]) -> None:
        self._auth = fn

    def handle(self, request: Request) -> Response:
        if self._dirty:
            self._load()
        headers: dict[str, str] = {}
        for k, v in request.headers.items():
            if k.lower() == IDENTITY_HEADER:
                headers.update(dict.fromkeys(_forged_names(), v))
            else:
                headers[k] = v
        conn = http.client.HTTPConnection(_LOOPBACK, self._port, timeout=_TIMEOUT)
        try:
            conn.putrequest(request.method, request.path, skip_host=True, skip_accept_encoding=True)
            conn.putheader("Host", request.host)
            for k, v in headers.items():
                conn.putheader(k, v)
            conn.endheaders()
            r = conn.getresponse()
            body = read_bounded(r).decode("utf-8", "replace")
            got = {k.lower(): v for k, v in r.getheaders()}
        finally:
            conn.close()
        if r.status in (302, 303, 307) and got.get("location", "").startswith(AUTH_PROXY_SIGN_IN):
            return Response(401, "authentication required (sign-in redirect)", got)
        return Response(r.status, body, got)

    def close(self) -> None:
        if self._proc is not None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=_TIMEOUT)
            except subprocess.TimeoutExpired:
                self._proc.kill()
                self._proc.wait()
            self._proc = None
        for s in [*self._servers.values(), self._auth_server]:
            s.stop()
        self._servers.clear()
        self._tmp.cleanup()

    # ------------------------------------------------------------------ the stand-ins
    def _answer_auth(self, h: BaseHTTPRequestHandler) -> None:
        _body(h)
        user = self._auth({k.lower(): v for k, v in h.headers.items()})
        if user is None:
            _reply(h, Response(401, "not signed in"))
            return
        # the auth proxy's answer: every identity header names the user (copy_headers copies all)
        _reply(h, Response(200, "", dict.fromkeys(IDENTITY_HEADERS.headers, user)))

    def _answer_upstream(self, name: str, h: BaseHTTPRequestHandler) -> None:
        _body(h)  # read and dropped: the contract's upstreams answer from the headers and path
        forged = {_norm(n) for n in _forged_names()}
        seen = {k.lower(): v for k, v in h.headers.items()}
        headers = {k: v for k, v in seen.items() if _norm(k) not in forged}
        # every value any identity header (the platform's or another proxy's, any spelling)
        # arrived with: the proxy's one user when it is right, the user and the forgery side by
        # side (so not equal to the user) when a forged copy got through
        values = sorted({v for k, v in seen.items() if _norm(k) in forged})
        headers.pop(IDENTITY_HEADER, None)  # never sent: the adapter forges the real headers
        if values:
            headers[IDENTITY_HEADER] = ",".join(values)
        req = Request(
            host=seen.get("host", ""),
            path=h.path,
            method=h.command,
            headers=headers,
            client=h.client_address[0],
        )
        try:
            resp = self._up[name](req)
        except Exception:
            # a dead upstream: the connection closes with no answer, and Caddy says 502
            h.close_connection = True
            with contextlib.suppress(OSError):
                h.connection.shutdown(socket.SHUT_RDWR)
            return
        _reply(h, resp)

    # ------------------------------------------------------------------ the configuration
    def caddyfile(self) -> str:
        """The configuration for the routes so far (also what a test reads)."""
        auth = f"http://{_LOOPBACK}:{self._auth_server.port}"
        strip = IDENTITY_HEADERS.strip_lines("\t") + f"\timport {FOREIGN_STRIP_SNIPPET}\n"
        parts = [
            "{\n"
            f"\tadmin {_LOOPBACK}:{self._admin}\n"
            f"\thttp_port {self._port}\n"
            "\tauto_https off\n"
            "\tpersist_config off\n"
            "}\n",
            _forward_auth_snippet(auth),
            f"({FOREIGN_STRIP_SNIPPET}) {{\n{foreign_strip_lines(chr(9))}}}\n",
            # the module role's catch-all: a host no site names reaches nothing
            f'http://:{self._port} {{\n\trespond "no such site" 404\n}}\n',
        ]
        hosts = sorted({r[0] for r in self._routes})
        for host in hosts:
            routes = sorted(
                (r for r in self._routes if r[0] == host), key=lambda r: -len(r[1].rstrip("/"))
            )
            body = [strip]
            for i, (_, prefix, upstream, needs_auth) in enumerate(routes):
                server = self._servers.get(upstream)
                dial = f"{_LOOPBACK}:{server.port}" if server else f"{_LOOPBACK}:1"
                inner = f"\t\timport hnx_forward_auth {_GROUPS}\n" if needs_auth else ""
                inner += f"\t\treverse_proxy {dial}\n"
                p = prefix.rstrip("/")
                if p:
                    body.append(f"\t@r{i} path {p} {p}/*\n\thandle @r{i} {{\n{inner}\t}}\n")
                else:
                    body.append(f"\thandle {{\n{inner}\t}}\n")
            parts.append(f"http://{host}:{self._port} {{\n{''.join(body)}}}\n")
        return "\n".join(parts)

    def _env(self) -> dict[str, str]:
        base = Path(self._tmp.name)
        env = {k: os.environ[k] for k in ("PATH", "LANG") if k in os.environ}
        for k, sub in (("HOME", "home"), ("XDG_DATA_HOME", "data"), ("XDG_CONFIG_HOME", "config")):
            (base / sub).mkdir(exist_ok=True)
            env[k] = str(base / sub)
        return env

    def _load(self) -> None:
        if self._proc is None:
            taken = {s.port for s in [*self._servers.values(), self._auth_server]}
            ports: list[int] = []
            while len(ports) < 2:
                p = _free_port()
                if p not in taken and p not in ports:
                    ports.append(p)
            self._port, self._admin = ports
        text = self.caddyfile()
        path = Path(self._tmp.name) / "Caddyfile"
        path.write_text(text, encoding="utf-8")
        if self._proc is None:
            log = (Path(self._tmp.name) / "caddy.log").open("wb")
            self._proc = subprocess.Popen(
                [self._caddy, "run", "--config", str(path), "--adapter", "caddyfile"],
                env=self._env(),
                stdout=log,
                stderr=subprocess.STDOUT,
            )
            log.close()
            self._wait_ready()
        else:
            req = urllib.request.Request(
                f"http://{_LOOPBACK}:{self._admin}/load",
                data=text.encode("utf-8"),
                headers={"Content-Type": "text/caddyfile"},
                method="POST",
            )
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            try:
                with opener.open(req, timeout=_TIMEOUT) as r:
                    read_bounded(r)
            except urllib.error.HTTPError as e:
                raise RuntimeError(f"caddy refused the configuration: {read_bounded(e)!r}") from e
        self._dirty = False

    def _wait_ready(self, clock: Callable[[], float] = time.monotonic) -> None:
        deadline = clock() + _TIMEOUT
        while clock() < deadline:
            if self._proc is not None and self._proc.poll() is not None:
                log = (Path(self._tmp.name) / "caddy.log").read_text(errors="replace")
                raise RuntimeError(f"caddy exited ({self._proc.returncode}): {log[-2000:]}")
            try:
                with socket.create_connection((_LOOPBACK, self._port), timeout=0.5):
                    return
            except OSError:
                time.sleep(0.05)
        raise RuntimeError(f"caddy did not listen on {_LOOPBACK}:{self._port} within {_TIMEOUT}s")


def make(caddy_env: str = "HNX_CADDY", **_: Any) -> CaddyEdge:
    """A fresh :class:`CaddyEdge`: the binary named by ``$<caddy_env>``, else ``caddy`` on PATH."""
    if not isinstance(caddy_env, str) or not caddy_env.isidentifier():
        raise AdapterConfigError("caddy_env names an environment variable")
    path = os.environ.get(caddy_env) or shutil.which("caddy")
    if not path or not os.access(path, os.X_OK):
        raise AdapterConfigError(
            f"edge: no caddy binary (set {caddy_env} to one, or put caddy on PATH)"
        )
    return CaddyEdge(path)
