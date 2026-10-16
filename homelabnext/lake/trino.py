# SPDX-License-Identifier: Apache-2.0
"""Trino client for the ``lake-query`` capability (SERVER: needs a running Trino).

One adapter for every consumer. What is fixed here, and tested without a server:

* the endpoint comes from the registry/resolver; an unset endpoint raises, there is no default;
* the session time zone is pinned to UTC;
* TLS is on and certificates are verified; plain ``http`` to a non-loopback host is refused
  unless the caller opts in with ``allow_plaintext=True``;
* queries use the same ``:name`` parameter syntax as the other adapters.

Writes are not done through Trino: use the catalog adapter (``IcebergLake``).
"""

from __future__ import annotations

import ipaddress
from collections.abc import Mapping, Sequence
from typing import Any

from .base import AdapterBase
from .endpoints import endpoint_for
from .errors import EndpointNotConfigured, LakeError, MissingExtra, WriteNotSupported
from .protocol import TableInfo, WriteResult
from .sqlparams import check_params, to_qmark
from .tables import table_name


def _is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


class TrinoLake(AdapterBase):
    def __init__(
        self,
        *,
        catalog: str,
        schema: str,
        user: str,
        resolver: Any = None,
        registry: Any = None,
        environ: Mapping[str, str] | None = None,
        verify: bool | str = True,
        allow_plaintext: bool = False,
        auth: Any = None,
        named_queries: Mapping[str, str] | None = None,
    ):
        ep = endpoint_for("lake-query", resolver=resolver, registry=registry, environ=environ)
        if ep.scheme not in ("http", "https"):
            raise EndpointNotConfigured(
                f"lake-query endpoint has scheme {ep.scheme!r}, expected http(s)"
            )
        if ep.scheme == "http" and not allow_plaintext and not _is_loopback(ep.host):
            raise LakeError(
                f"refusing plaintext http to {ep.host}: use https or pass allow_plaintext=True explicitly"
            )
        if verify is False and not allow_plaintext:
            raise LakeError(
                "certificate verification may only be disabled together with allow_plaintext=True"
            )
        self.endpoint = ep
        self._kw = {
            "host": ep.host,
            "port": ep.port,
            "user": user,
            "catalog": catalog,
            "schema": schema,
            "http_scheme": ep.scheme,
            "verify": verify,
            "timezone": "UTC",
            "auth": auth,
        }
        self._named = dict(named_queries or {})

    def _connect(self) -> Any:
        try:
            import trino.dbapi as dbapi
        except ImportError as e:
            raise MissingExtra("trino", "trino") from e
        return dbapi.connect(**{k: v for k, v in self._kw.items() if v is not None})

    def query(self, sql: str, params: Mapping[str, Any] | None = None) -> list[dict[str, Any]]:
        bound = check_params(sql, params)
        text, args = to_qmark(sql, bound)
        conn = self._connect()
        try:
            cur = conn.cursor()
            cur.execute(text, args or None)
            names = [d[0] for d in cur.description or []]
            return [dict(zip(names, r, strict=True)) for r in cur.fetchall()]
        finally:
            conn.close()

    def list_tables(self) -> list[str]:
        rows = self.query(
            "SELECT table_name FROM information_schema.tables WHERE table_schema = :s ORDER BY 1",
            {"s": self._kw["schema"]},
        )
        return [r["table_name"] for r in rows]

    def describe(self, table: str) -> TableInfo:
        from .tables import Column

        n = table_name(table)
        rows = self.query(
            "SELECT column_name, data_type, is_nullable FROM information_schema.columns "
            "WHERE table_schema = :s AND table_name = :t ORDER BY ordinal_position",
            {"s": self._kw["schema"], "t": n},
        )
        cols = tuple(
            Column(r["column_name"], r["data_type"], r["is_nullable"] == "NO") for r in rows
        )
        return TableInfo(n, "", cols, ())

    def write_batch(
        self,
        table: str,
        rows: Sequence[Mapping[str, Any]],
        *,
        idempotency_key: str,
        source: str | None = None,
        high_water: str | None = None,
    ) -> WriteResult:
        raise WriteNotSupported("write through the catalog adapter (IcebergLake), not Trino")
