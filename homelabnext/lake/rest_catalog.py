# SPDX-License-Identifier: Apache-2.0
"""A standard-library client for the Iceberg REST catalog API (written against Lakekeeper 0.9).

Only what the lake adapter needs: the warehouse ``prefix`` from ``GET /v1/config``, listing a
namespace's tables (with ``pageToken`` paging), loading a table's metadata, and committing
``set-properties`` / ``remove-properties`` updates guarded by ``assert-table-uuid``.  Errors use
the spec's error model (``{"error": {"message", "type", "code"}}``): 404 becomes
:class:`~.errors.UnknownTable`, everything else :class:`~.errors.LakeError`; a ``409`` commit
conflict is :class:`CommitConflict` so the caller can reload and retry.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Mapping
from typing import Any

from homelabnext._http import ResponseTooLarge, read_bounded, safe_urlopen

from .errors import LakeError, UnknownTable

__all__ = ["CommitConflict", "RestCatalog"]


class CommitConflict(LakeError):
    pass


def _q(part: str) -> str:
    return urllib.parse.quote(part, safe="")


class RestCatalog:
    def __init__(
        self,
        base_url: str,
        *,
        warehouse: str,
        api_root: str = "/catalog",
        auth: Callable[[], str | None] | None = None,
        timeout: float = 15.0,
        max_bytes: int = 16 << 20,
    ):
        parts = urllib.parse.urlsplit(base_url)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise LakeError("catalog base URL must be http(s)://host:port")
        self.root = base_url.rstrip("/") + "/" + api_root.strip("/")
        self.warehouse = warehouse
        self._auth = auth
        self._timeout = timeout
        self.max_bytes = max_bytes
        self._prefix: str | None = None

    def __repr__(self) -> str:
        return f"RestCatalog(<endpoint>, warehouse={self.warehouse!r})"

    # ---------------------------------------------------------------- transport
    def _call(self, method: str, path: str, body: Any = None) -> Any:
        headers = {"Accept": "application/json"}
        data = None
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        if self._auth is not None:
            tok = self._auth()
            if tok:
                headers["Authorization"] = tok
        req = urllib.request.Request(self.root + path, data=data, headers=headers, method=method)
        try:
            with safe_urlopen(req, timeout=self._timeout) as resp:
                raw = read_bounded(resp, self.max_bytes)
        except urllib.error.HTTPError as exc:
            detail = exc.read(4000)
            msg = detail.decode("utf-8", "replace")[:300]
            try:
                err = json.loads(detail).get("error") or {}
                msg = f"{err.get('type', '')}: {err.get('message', '')}".strip(": ")
            except (ValueError, AttributeError):
                pass
            text = f"catalog {method} {path.split('?')[0]}: HTTP {exc.code} {msg}"
            if exc.code == 404:
                raise UnknownTable(text) from None
            if exc.code == 409:
                raise CommitConflict(text) from None
            raise LakeError(text) from None
        except ResponseTooLarge as exc:
            raise LakeError(f"catalog reply: {exc}") from None
        except (urllib.error.URLError, OSError) as exc:
            raise LakeError(f"cannot reach the catalog: {type(exc).__name__}: {exc}") from None
        if not raw:
            return None
        try:
            return json.loads(raw)
        except ValueError:
            raise LakeError("catalog reply is not JSON") from None

    @property
    def prefix(self) -> str:
        if self._prefix is None:
            doc = self._call("GET", f"/v1/config?warehouse={_q(self.warehouse)}") or {}
            pre = (doc.get("overrides") or {}).get("prefix") or (doc.get("defaults") or {}).get(
                "prefix"
            )
            if not pre:
                raise LakeError(f"catalog config for warehouse {self.warehouse!r} has no prefix")
            self._prefix = str(pre)
        return self._prefix

    def _ns(self, namespace: str) -> str:
        return f"/v1/{_q(self.prefix)}/namespaces/{_q(namespace)}"

    # ---------------------------------------------------------------- API
    def list_tables(self, namespace: str) -> list[str]:
        names: list[str] = []
        token: str | None = None
        for _ in range(10_000):
            path = self._ns(namespace) + "/tables"
            if token:
                path += f"?pageToken={_q(token)}"
            doc = self._call("GET", path) or {}
            names += [str(i["name"]) for i in doc.get("identifiers") or []]
            token = doc.get("next-page-token")
            if not token:
                return names
        raise LakeError("catalog table listing did not terminate")

    def load_table(self, namespace: str, table: str) -> dict[str, Any]:
        doc = self._call("GET", self._ns(namespace) + f"/tables/{_q(table)}")
        meta = (doc or {}).get("metadata")
        if not isinstance(meta, dict):
            raise LakeError(f"catalog: table {table!r} has no metadata in its load result")
        return meta

    def set_properties(
        self,
        namespace: str,
        table: str,
        updates: Mapping[str, str],
        *,
        table_uuid: str,
        removals: list[str] | None = None,
    ) -> dict[str, Any]:
        changes: list[dict[str, Any]] = [{"action": "set-properties", "updates": dict(updates)}]
        if removals:
            changes.append({"action": "remove-properties", "removals": list(removals)})
        body = {
            "requirements": [{"type": "assert-table-uuid", "uuid": table_uuid}],
            "updates": changes,
        }
        doc = self._call("POST", self._ns(namespace) + f"/tables/{_q(table)}", body)
        return (doc or {}).get("metadata") or {}


def current_schema_fields(meta: Mapping[str, Any]) -> list[dict[str, Any]]:
    sid = meta.get("current-schema-id")
    for s in meta.get("schemas") or []:
        if s.get("schema-id") == sid:
            return list(s.get("fields") or [])
    if "schema" in meta:  # format v1
        return list(meta["schema"].get("fields") or [])
    raise LakeError("table metadata has no current schema")


def current_snapshot(meta: Mapping[str, Any]) -> dict[str, Any] | None:
    sid = meta.get("current-snapshot-id")
    if sid in (None, -1):
        return None
    for s in meta.get("snapshots") or []:
        if s.get("snapshot-id") == sid:
            return dict(s)
    return None
