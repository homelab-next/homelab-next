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
        opener: urllib.request.OpenerDirector | None = None,
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
        #: how requests are sent: by default same-origin redirects only; a caller that sends a
        #: credential passes :func:`homelabnext._http.credential_opener` (no redirect, no proxy)
        self._opener = opener

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
            send = self._opener.open if self._opener is not None else safe_urlopen
            with send(req, timeout=self._timeout) as resp:
                raw = read_bounded(resp, self.max_bytes)
        except urllib.error.HTTPError as exc:
            detail = exc.read(4000)
            msg = detail.decode("utf-8", "replace")[:300]
            try:
                err = json.loads(detail).get("error") or {}
                msg = f"{err.get('type', '')}: {err.get('message', '')}".strip(": ")
            except (ValueError, AttributeError):
                pass
            bare = f"catalog {method} {path.split('?')[0]}: HTTP {exc.code}"
            cls = {404: UnknownTable, 409: CommitConflict}.get(exc.code, LakeError)
            err_out = cls(f"{bare} {msg}")
            # the status line alone, without the server's words, for a caller that must not
            # repeat them (a reply can echo the request, its credential included)
            err_out.bare = bare  # type: ignore[attr-defined]
            raise err_out from None
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
    def list_namespaces(
        self, limit: int | None = None, parent: list[str] | None = None
    ) -> list[list[str]]:
        """Every top-level namespace of the warehouse (or every namespace directly under
        ``parent``), each as its levels (``["ocsf"]``); more than ``limit`` fails."""
        names: list[list[str]] = []
        token: str | None = None
        for _ in range(10_000):
            path = f"/v1/{_q(self.prefix)}/namespaces"
            query = []
            if parent:
                query.append(f"parent={_q(chr(0x1F).join(parent))}")
            if token:
                query.append(f"pageToken={_q(token)}")
            if query:
                path += "?" + "&".join(query)
            doc = self._call("GET", path) or {}
            for ns in doc.get("namespaces") or []:
                if not isinstance(ns, list) or not all(isinstance(p, str) for p in ns):
                    raise LakeError("catalog namespace listing: a namespace is not a list of text")
                names.append(ns)
            if limit is not None and len(names) > limit:
                raise LakeError(f"catalog namespace listing: over {limit} namespaces")
            token = doc.get("next-page-token")
            if not token:
                return names
        raise LakeError("catalog namespace listing did not terminate")

    def list_tables(self, namespace: str, limit: int | None = None) -> list[str]:
        """The tables of ``namespace``; more than ``limit`` fails."""
        names: list[str] = []
        token: str | None = None
        for _ in range(10_000):
            path = self._ns(namespace) + "/tables"
            if token:
                path += f"?pageToken={_q(token)}"
            doc = self._call("GET", path) or {}
            for ident in doc.get("identifiers") or []:
                if not isinstance(ident, dict) or not isinstance(ident.get("name"), str):
                    raise LakeError("catalog table listing: an identifier names no table")
                names.append(ident["name"])
            if limit is not None and len(names) > limit:
                raise LakeError(f"catalog table listing: over {limit} tables")
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
