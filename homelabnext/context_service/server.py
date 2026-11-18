# SPDX-License-Identifier: Apache-2.0
"""The HTTP surface of the ``context`` service (standard library only).

Unauthenticated, and holding no content: ``GET /health`` (the process answers) and ``GET /ready``
(``{ready}`` alone; 503 until the first index; with any caller's valid token also how many
documents, whether the judge is on and the last reindex's outcome).

Bearer-authenticated (``Authorization: Bearer <token>``; each caller is the sha256 of its token
and a set of scopes; the admin caller's token comes from the environment):

* ``POST /v1/query`` (scope ``query``): ``{text, allowed, seeds?, kinds?, budget?,
  include_inactive?, ceiling?}`` -> ``{hits: [...], ceiling, judged}``.  Read at the caller's TLP
  ceiling; ``ceiling`` may only lower it.  Each hit carries its ``tlp``.
* ``POST /v1/get`` (scope ``query``): ``{id, allowed, ceiling?}`` -> one hit, or 404 exactly as for
  an id that does not exist.
* ``POST /v1/reindex`` (scope ``reindex``): fetch, collect and index now; 200 with the run's report,
  500 with it when the run failed (the index unchanged, but for documents whose label changed in
  that run, which stay dropped: :mod:`.service`), 409 while another runs, 429 for a caller asking
  sooner than ``reindex_min_interval_s`` after the last run finished (the admin, the timer's
  caller, is not limited).  The hook an automation rule calls, and the timer's.
* ``POST /v1/check`` (the admin's ``health`` scope): the canned query finds its item and the judge,
  when on, clears it; 200 or 503 with the reason.

A missing or unknown token is 401, a scope the caller lacks 403; a malformed query 400 (the
message never echoes the text), a body over the limit 413.  A connection idle for
:data:`SOCKET_TIMEOUT_S` is closed (the body is read before authentication).
"""

from __future__ import annotations

import hashlib
import hmac
import json
from collections.abc import Mapping
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from homelabnext import tlp as _tlp
from homelabnext.context import Hit, InvalidQuery, NotFound, Query

from .config import ADMIN_ENV, Caller
from .service import ContextService, ReindexBusy

__all__ = ["ApiError", "Routes", "make_server"]


class ApiError(Exception):
    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status, self.message = status, message


ADMIN_SCOPES = frozenset({"reindex", "health"})
#: seconds a connection may sit idle (reading the request or its body) before it is closed
SOCKET_TIMEOUT_S = 30


class Routes:
    """The routes, independent of the socket (the tests call :meth:`handle`)."""

    def __init__(self, service: ContextService, env: Mapping[str, str]) -> None:
        self.service = service
        self._callers: list[Caller] = list(service.cfg.callers)
        token = env.get(ADMIN_ENV, "")
        if len(token) < 32 or any(c.isspace() or not c.isprintable() for c in token):
            raise ValueError(f"{ADMIN_ENV} must be a token of 32 characters or more")
        digest = hashlib.sha256(token.encode()).hexdigest()
        if digest in {c.sha256 for c in self._callers}:
            raise ValueError("the admin token is also a caller's token")
        self._callers.append(Caller("admin", digest, _tlp.Label.CLEAR, ADMIN_SCOPES))

    # -- auth ---------------------------------------------------------------------------------
    def caller(self, header: str | None) -> Caller:
        if not header or not header.startswith("Bearer "):
            raise ApiError(401, "a bearer token is required")
        got = hashlib.sha256(header[len("Bearer ") :].strip().encode()).hexdigest()
        found = None
        for c in self._callers:  # every digest is compared, whichever matches
            if hmac.compare_digest(got, c.sha256):
                found = c
        if found is None:
            raise ApiError(401, "unknown token")
        return found

    @staticmethod
    def _need(caller: Caller, scope: str) -> None:
        if scope not in caller.scopes:
            raise ApiError(403, f"the caller lacks the {scope} scope")

    # -- bodies -------------------------------------------------------------------------------
    @staticmethod
    def _query(body: Mapping[str, Any]) -> Query:
        allowed = body.get("allowed")
        if not isinstance(allowed, list):
            raise ApiError(400, "allowed is required: a list of ids and namespaces")
        kinds, seeds = body.get("kinds"), body.get("seeds", [])
        try:
            return Query(
                allowed=frozenset(allowed),
                text=body.get("text", ""),
                seeds=tuple(seeds) if isinstance(seeds, list) else seeds,
                kinds=None if kinds is None else frozenset(kinds),
                budget=body.get("budget", 10),
                include_inactive=body.get("include_inactive", False),
            )
        except TypeError as exc:
            raise ApiError(400, "a field has the wrong type") from exc

    def _ceiling(self, caller: Caller, body: Mapping[str, Any]) -> _tlp.Label:
        asked = body.get("ceiling")
        if asked is not None and not isinstance(asked, str):
            raise ApiError(400, "ceiling must be a TLP label")
        try:
            return ContextService.ceiling(caller, asked)
        except ValueError as exc:
            raise ApiError(400, "ceiling must be a TLP label") from exc

    @staticmethod
    def _hit(h: Hit, label: _tlp.Label) -> dict[str, Any]:
        return {
            "id": h.id,
            "kind": h.kind,
            "title": h.title,
            "path": h.path,
            "score": h.score,
            "snippet": h.snippet,
            "content": h.content,
            "digest": h.digest,
            "tlp": str(label),
        }

    # -- dispatch -----------------------------------------------------------------------------
    def handle(
        self, method: str, path: str, auth: str | None, body: Mapping[str, Any] | None
    ) -> tuple[int, dict[str, Any]]:
        if method == "GET" and path == "/health":
            return 200, {"status": "ok"}
        if method == "GET" and path == "/ready":
            r = self.service.ready()
            status = 200 if r["ready"] else 503
            try:
                self.caller(auth)
            except ApiError:
                return status, {"ready": r["ready"]}  # no counts without a token
            return status, r
        routes = {"/v1/query": "query", "/v1/get": "query", "/v1/reindex": "reindex",
                  "/v1/check": "health"}  # fmt: skip
        if path not in routes:
            raise ApiError(404, "no such route")
        if method != "POST":
            raise ApiError(405, "POST only")
        caller = self.caller(auth)
        self._need(caller, routes[path])
        body = body or {}
        if path == "/v1/reindex":
            last = self.service.last_finished
            wait = self.service.cfg.reindex_min_interval_s
            if (
                caller.name != "admin"
                and last is not None
                and self.service.monotonic() - last < wait
            ):
                raise ApiError(429, f"a reindex finished less than {wait:g} s ago")
            try:
                report = self.service.reindex()
            except ReindexBusy as exc:
                raise ApiError(409, str(exc)) from exc
            return (200 if report.get("ok") else 500), report
        if path == "/v1/check":
            r = self.service.check()
            return (200 if r["ok"] else 503), r
        ceiling = self._ceiling(caller, body)
        if path == "/v1/get":
            doc_id, allowed = body.get("id"), body.get("allowed")
            if not isinstance(doc_id, str) or not isinstance(allowed, list):
                raise ApiError(400, "id and allowed are required")
            try:
                hit, label = self.service.get(doc_id, frozenset(allowed), ceiling)
            except NotFound as exc:
                raise ApiError(404, "no such document in scope") from exc
            except (InvalidQuery, TypeError) as exc:
                raise ApiError(400, "malformed scope") from exc
            return 200, {"hit": self._hit(hit, label), "ceiling": str(ceiling)}
        q = self._query(body)
        try:
            hits, labels = self.service.query(q, ceiling)
        except InvalidQuery as exc:
            raise ApiError(400, str(exc)) from exc
        return 200, {
            "hits": [self._hit(h, lb) for h, lb in zip(hits, labels, strict=True)],
            "ceiling": str(ceiling),
            "judged": self.service.judged_at(ceiling),
        }


def make_server(routes: Routes, bind: str, port: int) -> ThreadingHTTPServer:
    limit = routes.service.cfg.max_body_bytes

    class Handler(BaseHTTPRequestHandler):
        server_version = "hnx-context"
        sys_version = ""
        timeout = SOCKET_TIMEOUT_S

        def log_message(self, fmt: str, *args: Any) -> None:  # no query text in the logs
            return

        def _send(self, status: int, doc: dict[str, Any]) -> None:
            data = json.dumps(doc).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            if status == 401:
                self.send_header("WWW-Authenticate", "Bearer")
            self.end_headers()
            self.wfile.write(data)

        def _serve(self, method: str) -> None:
            try:
                body = None
                if method == "POST":
                    try:
                        n = int(self.headers.get("Content-Length") or 0)
                    except ValueError as exc:
                        raise ApiError(400, "bad Content-Length") from exc
                    if n > limit or n < 0:
                        raise ApiError(413, "the body is too large")
                    raw = self.rfile.read(n) if n else b"{}"
                    try:
                        body = json.loads(raw.decode("utf-8"))
                    except (UnicodeDecodeError, ValueError) as exc:
                        raise ApiError(400, "the body is not JSON") from exc
                    if not isinstance(body, dict):
                        raise ApiError(400, "the body is a JSON object")
                path = self.path.split("?", 1)[0]
                status, doc = routes.handle(method, path, self.headers.get("Authorization"), body)
            except ApiError as exc:
                status, doc = exc.status, {"error": exc.message}
            except Exception as exc:  # never a traceback (or a query) in the answer
                status, doc = 500, {"error": f"internal error ({type(exc).__name__})"}
            self._send(status, doc)

        def do_GET(self) -> None:
            self._serve("GET")

        def do_POST(self) -> None:
            self._serve("POST")

    srv = ThreadingHTTPServer((bind, port), Handler)
    srv.daemon_threads = True
    return srv
