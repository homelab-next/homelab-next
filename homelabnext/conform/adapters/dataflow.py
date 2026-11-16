# SPDX-License-Identifier: Apache-2.0
"""The ``dataflow`` slot's client on the service's REST API (stdlib).

The slot has no contract yet (it is provisional): the adapter is the one thing every provider of
it must offer, a read-only view of the controller's status, its cluster summary, its version and
its bulletin board, the endpoints the status hub's ``poll`` collector and a module's own live
check read.  ``make(**config)`` returns a :class:`DataflowTarget` on ``HNX_ENDPOINT_DATAFLOW`` (the
registry resolver's override; there is no default endpoint).

The service answers nothing anonymously, so a call without a credential is refused by the
service, never sent as an anonymous success.  ``credential`` is a secret reference
(``secret:<name>``, never a value) whose value, delivered in ``HNX_SECRET_<NAME>``, is a bearer
token the service accepts; ``ca_file`` is the lab CA that issued its certificate.  It reads
nothing but JSON, bounds every body, follows no redirect and uses no proxy.
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from homelabnext._http import DEFAULT_MAX_BYTES, credential_opener, read_bounded
from homelabnext.registry.model import secret_env_name

from ._env import AdapterConfigError, env_secret, resolve

__all__ = ["DataflowError", "DataflowTarget", "make"]

_SECRET_REF = re.compile(r"secret:[a-z0-9][a-z0-9/_.-]{0,127}")
_API_ROOT = re.compile(r"/[A-Za-z0-9._~-]+(/[A-Za-z0-9._~-]+)*")


class DataflowError(RuntimeError):
    """The dataflow service did not answer, or did not answer what the contract says."""


class DataflowTarget:
    """A read-only view of one dataflow service."""

    def __init__(
        self,
        base_url: str,
        *,
        token: Any = None,
        ca_file: str | None = None,
        api_root: str,
        timeout: float = 10.0,
        max_bytes: int = DEFAULT_MAX_BYTES,
    ):
        if not _API_ROOT.fullmatch(api_root):
            raise ValueError(
                "api_root is the service's API path (a path starting with /, no trailing /)"
            )
        if not base_url.startswith(("http://", "https://")):
            raise ValueError("base_url must be an http(s) URL supplied by the caller")
        self._base = base_url.rstrip("/") + api_root
        self._token = token  # a callable returning the bearer token, or None
        self._opener = credential_opener(ca_file)
        self.timeout = timeout
        self.max_bytes = max_bytes

    def __repr__(self) -> str:
        return f"DataflowTarget({self._base!r})"

    def _get(self, path: str, **params: str) -> dict[str, Any]:
        url = self._base + path
        if params:
            url += "?" + urllib.parse.urlencode(params)
        headers = {"Accept": "application/json"}
        if self._token is not None:
            value = self._token()
            if not value or any(c in value for c in "\r\n\0"):
                raise DataflowError("the credential cannot be sent as a header")
            headers["Authorization"] = f"Bearer {value}"
        req = urllib.request.Request(url, headers=headers, method="GET")
        try:
            with self._opener.open(req, timeout=self.timeout) as resp:
                raw = read_bounded(resp, self.max_bytes)
        except urllib.error.HTTPError as exc:
            raise DataflowError(f"{path}: HTTP {exc.code}") from None
        except (urllib.error.URLError, OSError, ValueError) as exc:
            raise DataflowError(f"{path}: {type(exc).__name__}") from None
        try:
            doc = json.loads(raw.decode("utf-8"))
        except ValueError:
            raise DataflowError(f"{path}: not JSON") from None
        if not isinstance(doc, dict):
            raise DataflowError(f"{path}: not a JSON object")
        return doc

    def _section(self, path: str, key: str, **params: str) -> dict[str, Any]:
        section = self._get(path, **params).get(key)
        if not isinstance(section, dict):
            raise DataflowError(f"{path}: no {key} section")
        return section

    def version(self) -> str:
        """The running version (``/flow/about``)."""
        return str(self._section("/flow/about", "about").get("version", ""))

    def cluster_summary(self) -> dict[str, Any]:
        """``/flow/cluster/summary``: a single node reports ``clustered: false``."""
        return self._section("/flow/cluster/summary", "clusterSummary")

    def status(self) -> dict[str, Any]:
        """``/flow/status``: queued flowfiles and the running, stopped, invalid and disabled counts."""
        return self._section("/flow/status", "controllerStatus")

    def bulletins(self, limit: int = 100) -> list[dict[str, Any]]:
        """The bulletin board's entries (at most ``limit``, 1 to 100)."""
        if not 1 <= int(limit) <= 100:
            raise ValueError("limit is 1 to 100")
        items = self._section("/flow/bulletin-board", "bulletinBoard", limit=str(int(limit)))
        return [b for b in items.get("bulletins", []) if isinstance(b, dict)]

    def close(self) -> None:  # the harness's teardown; nothing is held
        return None


def make(**config: Any) -> DataflowTarget:
    """A :class:`DataflowTarget` on ``HNX_ENDPOINT_DATAFLOW``.

    Settings: ``api_root`` (required: the service's API path, which the status hub's source also
    names), ``timeout`` (seconds), ``ca_file`` (a path) and ``credential`` (``secret:<name>``)."""
    unknown = sorted(set(config) - {"api_root", "timeout", "ca_file", "credential"})
    if "api_root" not in config:
        raise AdapterConfigError("dataflow adapter: api_root is required (the service's API path)")
    if unknown:
        raise ValueError(f"dataflow adapter: unknown setting(s) {', '.join(unknown)}")
    endpoint = resolve("dataflow", env_only=True, schemes=("http", "https"))
    token = None
    ref = config.get("credential")
    if ref is not None:
        if not isinstance(ref, str) or not _SECRET_REF.fullmatch(ref):
            raise AdapterConfigError("credential is a secret name (secret:<name>), never a value")
        token = env_secret(secret_env_name(ref))
    return DataflowTarget(
        endpoint.url,
        token=token,
        api_root=config["api_root"],
        ca_file=config.get("ca_file"),
        timeout=float(config.get("timeout", 10.0)),
    )
