# SPDX-License-Identifier: Apache-2.0
"""A standard-library client for Trino's HTTP client protocol (``POST /v1/statement``).

What it does, and what the tests pin without a server:

* a statement is POSTed as text; the client follows ``nextUri`` until it is absent, collecting
  ``columns`` and every page of ``data``; a ``nextUri`` to another origin is refused, ``503``
  (the coordinator is busy) is retried a few times;
* the session is pinned to UTC (``X-Trino-Time-Zone``); catalog, schema and user are headers;
* values are decoded from the column ``typeSignature``: ``row`` -> ``dict`` keyed by field name,
  ``array`` -> ``list``, ``timestamp(p) with time zone`` -> aware UTC ``datetime``, ``timestamp``
  -> naive ``datetime`` (UTC wall time), ``decimal`` -> ``Decimal``, ``date``, ``double``
  (including ``NaN``/``Infinity``), ``varbinary`` (base64) -> ``bytes``;
* parameters are **bound server-side** with ``EXECUTE IMMEDIATE '<sql>' USING v1, v2, ...``: the
  statement text keeps its ``?`` placeholders (found by :mod:`.sqlparams`, which skips literals,
  identifiers and comments) and every value travels as one typed literal in the ``USING`` list,
  where it is an expression of its own and can never be re-read as SQL text or as another
  placeholder.  :func:`literal` is the only encoder: strings become ``'...'`` with ``'`` doubled
  (Trino string literals have no backslash escapes), ``datetime`` becomes ``TIMESTAMP '...
  UTC'``, lists ``ARRAY[...]``, :class:`Row` values ``ROW(...)``; anything else is refused.

Errors from the server become :class:`~.errors.LakeError` (``UnknownTable`` for a missing table
or schema) carrying Trino's ``errorName`` and message.
"""

from __future__ import annotations

import base64
import json
import math
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, timedelta, timezone
from decimal import Decimal
from typing import Any

from homelabnext._http import ResponseTooLarge, read_bounded, safe_urlopen

from .errors import LakeError, UnknownTable

__all__ = ["QueryResult", "Row", "TrinoError", "TrinoHTTP", "decode_value", "literal"]

INT64 = (-(2**63), 2**63 - 1)
_NOT_FOUND = {"TABLE_NOT_FOUND", "SCHEMA_NOT_FOUND", "CATALOG_NOT_FOUND", "COLUMN_NOT_FOUND"}


class TrinoError(LakeError):
    """A statement failed on the server."""

    def __init__(self, message: str, error_name: str = "", query_id: str = ""):
        super().__init__(message)
        self.error_name = error_name
        self.query_id = query_id


class UnknownTrinoTable(TrinoError, UnknownTable):
    pass


class Row(tuple):
    """A struct value for :func:`literal`: its fields in declaration order."""


# ---------------------------------------------------------------- literals (the binder)
def literal(v: Any) -> str:
    """One value as a self-contained Trino literal expression; raises ``LakeError`` otherwise."""
    if v is None:
        return "NULL"
    if isinstance(v, bool):
        return "TRUE" if v else "FALSE"
    if isinstance(v, int):
        if not INT64[0] <= v <= INT64[1]:
            raise LakeError(f"integer parameter {v} does not fit in BIGINT")
        return f"BIGINT '{v}'"
    if isinstance(v, float):
        if math.isnan(v):
            return "nan()"
        if math.isinf(v):
            return "infinity()" if v > 0 else "-infinity()"
        return f"DOUBLE '{v!r}'"
    if isinstance(v, Decimal):
        if not v.is_finite():
            raise LakeError("a non-finite Decimal has no SQL literal")
        return f"DECIMAL '{v}'"
    if isinstance(v, str):
        return "'" + v.replace("'", "''") + "'"
    if isinstance(v, datetime):
        u = v.replace(tzinfo=UTC) if v.tzinfo is None else v.astimezone(UTC)  # naive = UTC
        return f"TIMESTAMP '{u:%Y-%m-%d %H:%M:%S}.{u.microsecond:06d} UTC'"
    if isinstance(v, date):
        return f"DATE '{v.isoformat()}'"
    if isinstance(v, bytes | bytearray):
        return f"X'{bytes(v).hex()}'"
    if isinstance(v, Row):
        return "ROW(" + ", ".join(literal(x) for x in v) + ")"
    if isinstance(v, list | tuple):
        return "ARRAY[" + ", ".join(literal(x) for x in v) + "]"
    raise LakeError(f"no SQL literal for a parameter of type {type(v).__name__}")


def execute_immediate(sql: str, args: Sequence[Any]) -> str:
    """``sql`` (with ``?`` placeholders) and its arguments as one ``EXECUTE IMMEDIATE``."""
    if not args:
        return sql
    return f"EXECUTE IMMEDIATE {literal(sql)} USING " + ", ".join(literal(a) for a in args)


# ---------------------------------------------------------------- decoding
_TS = re.compile(r"^(\d{4}-\d\d-\d\d)[ T](\d\d:\d\d:\d\d)(?:\.(\d+))? ?(.*)$")


def _parse_ts(text: str, with_zone: bool) -> datetime:
    m = _TS.match(text)
    if not m:
        raise LakeError(f"unexpected timestamp text {text!r}")
    day, clock, frac, zone = m.groups()
    micro = int((frac or "0")[:6].ljust(6, "0"))
    base = datetime.fromisoformat(f"{day}T{clock}").replace(microsecond=micro)
    if not with_zone:
        return base
    zone = zone.strip()
    if zone in ("UTC", "Z", "", "Etc/UTC", "GMT"):
        return base.replace(tzinfo=UTC)
    off = re.fullmatch(r"([+-])(\d\d):?(\d\d)", zone)
    if off:
        sign = 1 if off.group(1) == "+" else -1
        tz = timezone(sign * timedelta(hours=int(off.group(2)), minutes=int(off.group(3))))
        return base.replace(tzinfo=tz).astimezone(UTC)
    from zoneinfo import ZoneInfo

    return base.replace(tzinfo=ZoneInfo(zone)).astimezone(UTC)


def _args(sig: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    return list(sig.get("arguments") or [])


def decode_value(value: Any, sig: Mapping[str, Any]) -> Any:
    """A JSON value of the client protocol as Python, driven by the column's typeSignature."""
    if value is None:
        return None
    raw = str(sig.get("rawType", "")).lower()
    if raw == "row":
        out = {}
        for i, arg in enumerate(_args(sig)):
            inner = arg.get("value") or {}
            name = ((inner.get("fieldName") or {}).get("name")) or f"field{i}"
            item = value.get(name) if isinstance(value, Mapping) else value[i]
            out[name] = decode_value(item, inner.get("typeSignature") or {})
        return out
    if raw == "array":
        (arg,) = _args(sig)
        return [decode_value(x, arg.get("value") or {}) for x in value]
    if raw == "map":
        k, v = (a.get("value") or {} for a in _args(sig))
        return {decode_value(a, k): decode_value(b, v) for a, b in value.items()}
    if raw == "timestamp with time zone":
        return _parse_ts(value, True)
    if raw == "timestamp":
        return _parse_ts(value, False)
    if raw == "date":
        return date.fromisoformat(value)
    if raw == "decimal":
        return Decimal(str(value))
    if raw in ("double", "real"):
        return float(value)
    if raw in ("bigint", "integer", "smallint", "tinyint"):
        return int(value)
    if raw == "boolean":
        return bool(value)
    if raw == "varbinary":
        return base64.b64decode(value)
    return value


# ---------------------------------------------------------------- the client
@dataclass
class QueryResult:
    query_id: str
    columns: list[dict[str, Any]] = field(default_factory=list)
    rows: list[dict[str, Any]] = field(default_factory=list)
    update_type: str | None = None
    update_count: int | None = None


class TrinoHTTP:
    """One coordinator.  ``base_url`` comes from the caller (the registry resolver)."""

    def __init__(
        self,
        base_url: str,
        *,
        user: str,
        catalog: str | None = None,
        schema: str | None = None,
        source: str = "homelabnext",
        auth: Callable[[], str | None] | None = None,
        timeout: float = 30.0,
        max_bytes: int = 64 << 20,
        retries: int = 5,
        sleep: Callable[[float], None] = time.sleep,
    ):
        parts = urllib.parse.urlsplit(base_url)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise LakeError("Trino base URL must be http(s)://host:port")
        self._base = base_url.rstrip("/")
        self._origin = (parts.scheme, parts.netloc.lower())
        self.user, self.catalog, self.schema, self.source = user, catalog, schema, source
        self._auth = auth
        self._timeout = timeout
        self.max_bytes = max_bytes
        self._retries = retries
        self._sleep = sleep

    def __repr__(self) -> str:
        return f"TrinoHTTP(<endpoint>, user={self.user!r})"

    def _headers(self) -> dict[str, str]:
        h = {
            "X-Trino-User": self.user,
            "X-Trino-Source": self.source,
            "X-Trino-Time-Zone": "UTC",
            "Accept": "application/json",
        }
        if self.catalog:
            h["X-Trino-Catalog"] = self.catalog
        if self.schema:
            h["X-Trino-Schema"] = self.schema
        if self._auth is not None:
            tok = self._auth()
            if tok:
                h["Authorization"] = tok
        return h

    def _request(self, url: str, body: bytes | None) -> dict[str, Any]:
        p = urllib.parse.urlsplit(url)
        if (p.scheme, p.netloc.lower()) != self._origin:
            raise LakeError("Trino returned a nextUri on another origin; refusing to follow it")
        headers = self._headers()
        if body is not None:
            headers["Content-Type"] = "text/plain; charset=utf-8"
        for attempt in range(self._retries + 1):
            req = urllib.request.Request(
                url, data=body, headers=headers, method="POST" if body is not None else "GET"
            )
            try:
                with safe_urlopen(req, timeout=self._timeout) as resp:
                    raw = read_bounded(resp, self.max_bytes)
                break
            except urllib.error.HTTPError as exc:
                if exc.code in (502, 503, 504) and attempt < self._retries:
                    self._sleep(0.2 * (attempt + 1))
                    continue
                detail = exc.read(2000).decode("utf-8", "replace").strip()
                raise LakeError(f"Trino HTTP {exc.code}: {detail[:300]}") from None
            except ResponseTooLarge as exc:
                raise LakeError(f"Trino reply: {exc}") from None
            except (urllib.error.URLError, OSError) as exc:
                raise LakeError(f"cannot reach Trino: {type(exc).__name__}: {exc}") from None
        try:
            doc = json.loads(raw)
        except ValueError:
            raise LakeError("Trino reply is not JSON") from None
        if not isinstance(doc, dict):
            raise LakeError("Trino reply is not an object")
        return doc

    def execute(self, sql: str, args: Sequence[Any] = ()) -> QueryResult:
        """Run one statement (``?`` placeholders bound to ``args``) to completion."""
        doc = self._request(self._base + "/v1/statement", execute_immediate(sql, args).encode())
        res = QueryResult(str(doc.get("id", "")))
        while True:
            err = doc.get("error")
            if err:
                name = str(err.get("errorName", ""))
                msg = f"Trino {name or 'error'}: {err.get('message', '')}"
                cls = UnknownTrinoTable if name in _NOT_FOUND else TrinoError
                raise cls(msg, name, res.query_id)
            if doc.get("columns") and not res.columns:
                res.columns = list(doc["columns"])
            for raw_row in doc.get("data") or []:
                res.rows.append(
                    {
                        c["name"]: decode_value(v, c.get("typeSignature") or {})
                        for c, v in zip(res.columns, raw_row, strict=True)
                    }
                )
            if doc.get("updateType"):
                res.update_type = doc["updateType"]
            if doc.get("updateCount") is not None:
                res.update_count = int(doc["updateCount"])
            nxt = doc.get("nextUri")
            if not nxt:
                return res
            doc = self._request(nxt, None)
