# SPDX-License-Identifier: Apache-2.0
"""The ``case-management`` slot's client on the service's HTTP API (stdlib).

The slot has no contract yet (it is provisional): the adapter is the one thing every provider of
it must offer, a read-only view of the API's two guarantees, that it refuses a caller with no
credential and that it answers one with a valid API key, plus the running version.  ``make(**config)``
returns a :class:`CaseManagementTarget` on ``HNX_ENDPOINT_CASE_MANAGEMENT`` (the registry resolver's
override; there is no default endpoint).

``credential`` is a secret reference (``secret:<name>``, never a value) whose value, delivered in
``HNX_SECRET_<NAME>``, is the API key sent as a bearer token; ``ca_file`` is the lab CA that issued
the service's certificate.  It reads nothing but JSON, bounds every body, follows no redirect and
uses no proxy.
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from typing import Any

from homelabnext._http import DEFAULT_MAX_BYTES, credential_opener, read_bounded

from ._env import optional_credential, resolve

__all__ = ["CaseManagementError", "CaseManagementTarget", "make"]

_SECRET_REF = re.compile(r"secret:[a-z0-9][a-z0-9/_.-]{0,127}")


class CaseManagementError(RuntimeError):
    """The service did not answer, or did not answer what the slot expects."""


class CaseManagementTarget:
    """A read-only view of one case-management service."""

    def __init__(
        self,
        base_url: str,
        *,
        token: Any = None,
        ca_file: str | None = None,
        timeout: float = 10.0,
        max_bytes: int = DEFAULT_MAX_BYTES,
    ):
        if not base_url.startswith(("http://", "https://")):
            raise ValueError("base_url must be an http(s) URL supplied by the caller")
        self._base = base_url.rstrip("/")
        self._token = token  # a callable returning the API key, or None
        self._opener = credential_opener(ca_file)
        self.timeout = timeout
        self.max_bytes = max_bytes

    def __repr__(self) -> str:
        return f"CaseManagementTarget({self._base!r})"

    def _open(self, path: str, *, authed: bool) -> tuple[int, bytes]:
        headers = {"Accept": "application/json"}
        if authed:
            value = self._token() if self._token is not None else ""
            if not value or any(c in value for c in "\r\n\0"):
                raise CaseManagementError("no credential that can be sent as a header")
            headers["Authorization"] = f"Bearer {value}"
        req = urllib.request.Request(self._base + path, headers=headers, method="GET")
        try:
            with self._opener.open(req, timeout=self.timeout) as resp:
                return resp.status, read_bounded(resp, self.max_bytes)
        except urllib.error.HTTPError as exc:
            return exc.code, b""
        except (urllib.error.URLError, OSError, ValueError) as exc:
            raise CaseManagementError(f"{path}: {type(exc).__name__}") from None

    def _json(self, path: str) -> dict:
        status, body = self._open(path, authed=True)
        if status != 200:
            raise CaseManagementError(f"{path}: HTTP {status}")
        try:
            doc = json.loads(body.decode("utf-8"))
        except ValueError:
            raise CaseManagementError(f"{path}: not JSON") from None
        if not isinstance(doc, dict) or doc.get("status") != "success":
            raise CaseManagementError(f"{path}: not a success answer")
        return doc

    def api_is_private(self) -> bool:
        """True when a call with no credential is refused (401 or 403)."""
        return self._open("/api/ping", authed=False)[0] in (401, 403)

    def api_answers(self) -> bool:
        """True when the API key is accepted and the API answers its ping."""
        return self._json("/api/ping").get("message") == "pong"

    def version(self) -> str:
        """The running product version (needs the credential)."""
        data = self._json("/api/versions").get("data")
        if not isinstance(data, dict):
            raise CaseManagementError("/api/versions: no data object")
        return str(data.get("iris_current", ""))

    def close(self) -> None:  # the harness's teardown; nothing is held
        return None


def make(**config: Any) -> CaseManagementTarget:
    """A :class:`CaseManagementTarget` on ``HNX_ENDPOINT_CASE_MANAGEMENT``.

    Settings: ``timeout`` (seconds), ``ca_file`` (a path) and ``credential`` (``secret:<name>``)."""
    unknown = sorted(set(config) - {"timeout", "ca_file", "credential"})
    if unknown:
        raise ValueError(f"case-management adapter: unknown setting(s) {', '.join(unknown)}")
    endpoint = resolve("case-management", env_only=True, schemes=("http", "https"))
    token = optional_credential(config.get("credential"), _SECRET_REF)
    return CaseManagementTarget(
        endpoint.url,
        token=token,
        ca_file=config.get("ca_file"),
        timeout=float(config.get("timeout", 10.0)),
    )
