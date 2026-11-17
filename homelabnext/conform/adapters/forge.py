# SPDX-License-Identifier: Apache-2.0
"""The ``forge`` slot's client on the service's HTTP API (stdlib).

The slot has no contract yet (it is provisional): the adapter is the one thing every provider of
it must offer, a read-only view of the service's health, its version, the repositories an
authenticated reader can see and its container registry's authentication challenge: what the
role's health hook and a consumer's pull read.  ``make(**config)`` returns a :class:`ForgeTarget`
on ``HNX_ENDPOINT_FORGE`` (the registry resolver's override; there is no default endpoint).

The service answers nothing about its content anonymously, so a read without a credential is
refused by the service, never sent as an anonymous success.  ``credential`` is a secret reference
(``secret:<name>``, never a value) whose value, delivered in ``HNX_SECRET_<NAME>``, is an access
token the service accepts; ``ca_file`` is the lab CA that issued its certificate.  It reads nothing
but JSON, bounds every body, follows no redirect and uses no proxy.
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from homelabnext._http import DEFAULT_MAX_BYTES, credential_opener, read_bounded

from ._env import optional_credential, resolve

__all__ = ["ForgeError", "ForgeTarget", "make"]

_SECRET_REF = re.compile(r"secret:[a-z0-9][a-z0-9/_.-]{0,127}")


def _pairs(message) -> list[tuple[str, str]]:
    """Every header, a repeated one (two authentication challenges) kept as separate entries."""
    return [(k, v) for k, v in message.items()]


class ForgeError(RuntimeError):
    """The forge did not answer, or did not answer what the contract says."""


class ForgeTarget:
    """A read-only view of one forge."""

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
        self._token = token  # a callable returning the access token, or None
        self._opener = credential_opener(ca_file)
        self.timeout = timeout
        self.max_bytes = max_bytes

    def __repr__(self) -> str:
        return f"ForgeTarget({self._base!r})"

    def _open(
        self, path: str, *, authed: bool, **params: str
    ) -> tuple[int, list[tuple[str, str]], bytes]:
        url = self._base + path + (("?" + urllib.parse.urlencode(params)) if params else "")
        headers = {"Accept": "application/json"}
        if authed:
            value = self._token() if self._token is not None else ""
            if not value or any(c in value for c in "\r\n\0"):
                raise ForgeError("no credential that can be sent as a header")
            headers["Authorization"] = f"token {value}"
        req = urllib.request.Request(url, headers=headers, method="GET")
        try:
            with self._opener.open(req, timeout=self.timeout) as resp:
                return resp.status, _pairs(resp.headers), read_bounded(resp, self.max_bytes)
        except urllib.error.HTTPError as exc:
            return exc.code, _pairs(exc.headers), b""
        except (urllib.error.URLError, OSError, ValueError) as exc:
            raise ForgeError(f"{path}: {type(exc).__name__}") from None

    def _json(self, path: str, *, authed: bool, **params: str) -> Any:
        status, _, body = self._open(path, authed=authed, **params)
        if status != 200:
            raise ForgeError(f"{path}: HTTP {status}")
        try:
            return json.loads(body.decode("utf-8"))
        except ValueError:
            raise ForgeError(f"{path}: not JSON") from None

    def healthy(self) -> bool:
        """``/api/healthz`` reports ``pass`` (no credential needed)."""
        doc = self._json("/api/healthz", authed=False)
        return isinstance(doc, dict) and doc.get("status") == "pass"

    def version(self) -> str:
        """The running version; needs a credential (the service answers nothing anonymously)."""
        doc = self._json("/api/v1/version", authed=True)
        if not isinstance(doc, dict):
            raise ForgeError("/api/v1/version: not an object")
        return str(doc.get("version", ""))

    def anonymous_read_refused(self) -> bool:
        """True when a read with no credential is refused (401 or 403)."""
        status, _, _ = self._open("/api/v1/version", authed=False)
        return status in (401, 403)

    def repositories(self, limit: int = 50) -> list[str]:
        """``owner/name`` of the repositories the credential can see (at most ``limit``, 1 to 50)."""
        if not 1 <= int(limit) <= 50:
            raise ValueError("limit is 1 to 50")
        doc = self._json("/api/v1/repos/search", authed=True, limit=str(int(limit)))
        rows = doc.get("data") if isinstance(doc, dict) else None
        if not isinstance(rows, list):
            raise ForgeError("/api/v1/repos/search: no data list")
        return [str(r["full_name"]) for r in rows if isinstance(r, dict) and "full_name" in r]

    def registry_challenges(self) -> bool:
        """The container registry answers 401 with a bearer challenge (it is on, and it is closed)."""
        status, headers, _ = self._open("/v2/", authed=False)
        challenge = ", ".join(v for k, v in headers if k.lower() == "www-authenticate")
        return status == 401 and "bearer" in challenge.lower()

    def close(self) -> None:  # the harness's teardown; nothing is held
        return None


def make(**config: Any) -> ForgeTarget:
    """A :class:`ForgeTarget` on ``HNX_ENDPOINT_FORGE``.

    Settings: ``timeout`` (seconds), ``ca_file`` (a path) and ``credential`` (``secret:<name>``)."""
    unknown = sorted(set(config) - {"timeout", "ca_file", "credential"})
    if unknown:
        raise ValueError(f"forge adapter: unknown setting(s) {', '.join(unknown)}")
    endpoint = resolve("forge", env_only=True, schemes=("http", "https"))
    token = optional_credential(config.get("credential"), _SECRET_REF)
    return ForgeTarget(
        endpoint.url,
        token=token,
        ca_file=config.get("ca_file"),
        timeout=float(config.get("timeout", 10.0)),
    )
