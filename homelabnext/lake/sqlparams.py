# SPDX-License-Identifier: Apache-2.0
"""Named query parameters, one syntax for every engine: ``:name``.

``named_params`` finds them, skipping string literals, quoted identifiers, comments and the
``::`` cast operator. ``to_dollar`` rewrites to the ``$name`` form DuckDB expects. The SQL used
across adapters is the portable subset documented in ``README.md``.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from .errors import LakeError


def _scan(sql: str):
    """Yield (start, end, name) of every ``:name`` placeholder outside literals/comments."""
    i, n = 0, len(sql)
    while i < n:
        ch = sql[i]
        if ch in ("'", '"'):
            j = i + 1
            while j < n:
                if sql[j] == ch:
                    if j + 1 < n and sql[j + 1] == ch:
                        j += 2
                        continue
                    break
                j += 1
            i = j + 1
        elif sql.startswith("--", i):
            j = sql.find("\n", i)
            i = n if j < 0 else j + 1
        elif sql.startswith("/*", i):
            j = sql.find("*/", i + 2)
            i = n if j < 0 else j + 2
        elif ch == ":" and sql.startswith("::", i):
            i += 2
        elif ch == ":" and i + 1 < n and (sql[i + 1].isalpha() or sql[i + 1] == "_"):
            j = i + 1
            while j < n and (sql[j].isalnum() or sql[j] == "_"):
                j += 1
            yield i, j, sql[i + 1 : j]
            i = j
        else:
            i += 1


def named_params(sql: str) -> list[str]:
    seen: list[str] = []
    for _, _, name in _scan(sql):
        if name not in seen:
            seen.append(name)
    return seen


def check_params(sql: str, params: Mapping[str, Any] | None) -> dict[str, Any]:
    params = dict(params or {})
    need = named_params(sql)
    missing = [p for p in need if p not in params]
    if missing:
        raise LakeError(f"query needs parameter(s) {missing} that were not supplied")
    extra = [p for p in params if p not in need]
    if extra:
        raise LakeError(f"parameter(s) {extra} are not used by the query")
    return params


def to_dollar(sql: str) -> str:
    out, last = [], 0
    for s, e, name in _scan(sql):
        out.append(sql[last:s])
        out.append("$" + name)
        last = e
    out.append(sql[last:])
    return "".join(out)


def to_qmark(sql: str, params: Mapping[str, Any]) -> tuple[str, list[Any]]:
    """Positional form (``?``) for engines without named parameters (the Trino client)."""
    out, last, args = [], 0, []
    for s, e, name in _scan(sql):
        out.append(sql[last:s])
        out.append("?")
        args.append(params[name])
        last = e
    out.append(sql[last:])
    return "".join(out), args
