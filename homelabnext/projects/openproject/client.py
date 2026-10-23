# SPDX-License-Identifier: Apache-2.0
"""A small stdlib client for the OpenProject API v3 (HAL+JSON; pinned against 17.9).

* **Auth:** a personal API token sent as ``Authorization: Basic apikey:<token>`` (OpenProject's
  documented form), read by *secret name* (``secret:openproject/api-token`` ->
  ``HNX_SECRET_OPENPROJECT_API_TOKEN``, :func:`homelabnext.registry.model.secret_env_name`) at
  every request, so no object holds the value and no message ever contains it.
* **TLS on:** https with the default verifying context; plain http only to loopback (the
  recorded fake in tests) or with ``allow_plaintext=True`` (:func:`homelabnext._http.check_plaintext`).
  Redirects stay on the same origin (:func:`homelabnext._http.safe_opener`).
* **Pagination:** :meth:`OpenProjectClient.collect` follows ``offset``/``pageSize`` until
  ``total`` items are read (``pageSize`` 1000, OpenProject's default maximum).
* **Concurrency:** a ``PATCH`` carries the ``lockVersion`` it read; a stale one is HTTP 409,
  raised as :class:`~homelabnext.projects.model.Conflict`.
* **Retries:** a timeout, a refused connection, 429 and 5xx are retried with exponential backoff
  (``retries`` times, ``backoff * 2**n`` seconds, ``sleep`` injectable); other 4xx are not.
  Only GET and DELETE are retried after the server may have acted; a POST or a PATCH is retried
  only on a refused connection (nothing reached the server).  A PATCH is not idempotent here: if
  the first attempt was applied before the 5xx or the timeout, its retry quotes a lockVersion
  that has moved, gets 409 and would report a write that succeeded as a conflict.
"""

from __future__ import annotations

import base64
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Iterator, Mapping, Sequence
from typing import Any

from homelabnext._http import check_plaintext, read_bounded, safe_opener
from homelabnext.registry.model import secret_env_name

from ..model import Conflict, NotFound, ProjectsError

__all__ = ["ApiError", "OpenProjectClient", "all_work_packages", "filters"]

MAX_BYTES = 16 << 20
PAGE_SIZE = 1000
_RETRY_STATUS = frozenset({429, 500, 502, 503, 504})
#: retried only when nothing reached the server (a refused connection)
_UNSAFE = frozenset({"POST", "PATCH"})


class ApiError(ProjectsError):
    """OpenProject answered with an error (``status``, ``identifier`` from the HAL error body)."""

    def __init__(self, status: int, message: str, identifier: str = "") -> None:
        self.status, self.identifier = status, identifier
        super().__init__(f"OpenProject {status}: {message}")


def filters(**conds: tuple[str, Sequence[Any]]) -> str:
    """``filters(type=("=", ["3"]))`` -> the URL value of ``filters`` (AND of each condition)."""
    out = [{name: {"operator": op, "values": [str(v) for v in vals]}} for name, (op, vals) in conds.items()]  # fmt: skip
    return json.dumps(out, separators=(",", ":"))


def all_work_packages(
    client: OpenProjectClient,
    project: int,
    where: Mapping[str, tuple[str, Sequence[Any]]] | None = None,
    **params: Any,
) -> Iterator[dict[str, Any]]:
    """Every work package of ``project`` matching ``where``, whatever its status.

    A work-package collection requested without ``filters`` gets OpenProject's default filter
    ``[{"status":{"operator":"o"}}]`` (open only), so closed work packages would be missing; the
    status filter "all" (``*``) is always sent, ANDed with ``where``.
    """
    conds = {"status": ("*", []), **dict(where or {})}
    path = f"/api/v3/projects/{project}/work_packages"
    return client.collect(path, filters=filters(**conds), **params)


class OpenProjectClient:
    def __init__(
        self,
        base_url: str,
        *,
        token: str = "secret:openproject/api-token",
        env: Mapping[str, str] | None = None,
        timeout: float = 30.0,
        retries: int = 3,
        backoff: float = 0.5,
        sleep: Callable[[float], None] = time.sleep,
        allow_plaintext: bool = False,
    ) -> None:
        if not base_url.startswith(("https://", "http://")):
            raise ValueError("base_url must be an http(s) URL")
        if not token.startswith("secret:"):
            raise ValueError("token is a secret reference (secret:<name>), never a value")
        check_plaintext(base_url, credentials=True, allow_plaintext=allow_plaintext)
        self.base = base_url.rstrip("/")
        self.token_ref = token
        self._env = env
        self.timeout, self.retries, self.backoff, self._sleep = timeout, retries, backoff, sleep
        self._opener = safe_opener()
        self.requests = 0  # how many HTTP requests this client sent (budgets, tests)

    # ------------------------------------------------------------------ plumbing
    def _auth(self) -> str:
        var = secret_env_name(self.token_ref)
        value = (os.environ if self._env is None else self._env).get(var, "")
        if not value:
            raise ProjectsError(f"the OpenProject API token is not set: {var} ({self.token_ref})")
        return "Basic " + base64.b64encode(f"apikey:{value}".encode()).decode()

    def url(self, path: str, params: Mapping[str, Any] | None = None) -> str:
        if path.startswith(("http://", "https://")):
            raise ValueError("pass an API path, not a URL")
        q = f"?{urllib.parse.urlencode(params)}" if params else ""
        return f"{self.base}{path if path.startswith('/') else '/' + path}{q}"

    def request(
        self,
        method: str,
        path: str,
        body: Mapping[str, Any] | None = None,
        *,
        params: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        url = self.url(path, params)
        data = json.dumps(body).encode() if body is not None else None
        attempt = 0
        while True:
            req = urllib.request.Request(url, data=data, method=method)
            req.add_header("Accept", "application/hal+json")
            req.add_header("Authorization", self._auth())
            if data is not None:
                req.add_header("Content-Type", "application/json")
            self.requests += 1
            try:
                with self._opener.open(req, timeout=self.timeout) as resp:
                    raw = read_bounded(resp, MAX_BYTES)
                return json.loads(raw) if raw.strip() else {}
            except urllib.error.HTTPError as exc:
                status, err = exc.code, _hal_error(exc)
                if status in _RETRY_STATUS and attempt < self.retries and method not in _UNSAFE:
                    attempt += 1
                    self._sleep(self.backoff * 2 ** (attempt - 1))
                    continue
                if status == 404:
                    raise NotFound(f"OpenProject: {path} not found") from None
                if status == 409:
                    raise Conflict(f"OpenProject: {path} changed since it was read") from None
                raise ApiError(status, err[0], err[1]) from None
            except (TimeoutError, urllib.error.URLError, ConnectionError) as exc:
                reason = getattr(exc, "reason", exc)
                refused = isinstance(reason, ConnectionRefusedError)
                if attempt < self.retries and (method not in _UNSAFE or refused):
                    attempt += 1
                    self._sleep(self.backoff * 2 ** (attempt - 1))
                    continue
                raise ApiError(0, f"cannot reach OpenProject ({type(reason).__name__})") from None

    def get(self, path: str, **params: Any) -> dict[str, Any]:
        return self.request("GET", path, params=params or None)

    def post(self, path: str, body: Mapping[str, Any]) -> dict[str, Any]:
        return self.request("POST", path, body)

    def patch(self, path: str, body: Mapping[str, Any]) -> dict[str, Any]:
        if "lockVersion" not in body:
            raise ValueError("a PATCH carries the lockVersion it read")
        return self.request("PATCH", path, body)

    def delete(self, path: str) -> None:
        self.request("DELETE", path)

    def collect(self, path: str, **params: Any) -> Iterator[dict[str, Any]]:
        """Every element of a collection, page by page (``offset`` is the 1-based page)."""
        page = 1
        seen = 0
        while True:
            doc = self.get(path, **params, offset=page, pageSize=PAGE_SIZE)
            elements = (doc.get("_embedded") or {}).get("elements") or []
            yield from elements
            seen += len(elements)
            total = int(doc.get("total", seen))
            if not elements or seen >= total:
                return
            page += 1


def _hal_error(exc: urllib.error.HTTPError) -> tuple[str, str]:
    """(message, errorIdentifier) of a HAL error body; never the request's headers."""
    try:
        doc = json.loads(read_bounded(exc, 1 << 16) or b"{}")
    except (ValueError, OSError):
        return exc.reason if isinstance(exc.reason, str) else "error", ""
    if not isinstance(doc, dict):
        return "error", ""
    ident = str(doc.get("errorIdentifier") or "").rsplit(":", 1)[-1]
    return str(doc.get("message") or "error")[:300], ident
