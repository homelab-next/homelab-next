# SPDX-License-Identifier: Apache-2.0
"""Target-file factories for the lake capabilities on real products.

``make_lake`` builds a :class:`homelabnext.lake.trino_rest.TrinoRestLake`: queries through the
``lake-query`` endpoint (Trino), metadata and the batch ledger through the ``lake-catalog``
endpoint (an Iceberg REST catalog such as Lakekeeper).  Both suites, ``lake-query`` and
``lake-catalog``, need the whole ``LakeClient`` (they seed through ``write_batch`` and count
through ``query``), so both targets use this one factory.

Every subject of one run shares a scratch namespace ``hnx_conform_<run>`` (created with the pinned
tables on first use), so a run never sees another run's rows.  Plain ``http`` is accepted only to
a loopback address unless ``allow_plaintext=True`` (the same rule as ``TrinoLake``).
"""

from __future__ import annotations

import os
from typing import Any

from homelabnext._http import is_loopback
from homelabnext.lake.errors import LakeError
from homelabnext.lake.rest_catalog import RestCatalog
from homelabnext.lake.trino_http import TrinoHTTP
from homelabnext.lake.trino_rest import TrinoRestLake

from ._env import resolve, run_token

__all__ = ["make_lake"]


def _url(capability: str, resolver: Any, domain: str | None, allow_plaintext: bool) -> str:
    ep = resolve(capability, resolver=resolver, domain=domain)
    if ep.scheme not in ("http", "https"):
        raise LakeError(f"{capability} endpoint has scheme {ep.scheme!r}, expected http(s)")
    if ep.scheme == "http" and not allow_plaintext and not is_loopback(ep.host):
        raise LakeError(
            f"refusing plaintext http to the {capability} endpoint (not loopback): use https "
            "or pass allow_plaintext=True explicitly"
        )
    return ep.url


def make_lake(
    *,
    domain: str | None = None,
    resolver: Any = None,
    namespace: str = "auto",
    trino_catalog: str = "iceberg",
    warehouse: str | None = None,
    warehouse_env: str = "LAB_WAREHOUSE",
    user: str = "hnx-conform",
    api_root: str = "/catalog",
    allow_plaintext: bool = False,
) -> TrinoRestLake:
    wh = warehouse or os.environ.get(warehouse_env, "")
    if not wh:
        raise LookupError(f"no warehouse: pass warehouse= or set {warehouse_env}")
    trino = TrinoHTTP(_url("lake-query", resolver, domain, allow_plaintext), user=user)
    catalog = RestCatalog(
        _url("lake-catalog", resolver, domain, allow_plaintext), warehouse=wh, api_root=api_root
    )
    ns = f"hnx_conform_{run_token()}" if namespace == "auto" else namespace
    return TrinoRestLake(trino, catalog, namespace=ns, trino_catalog=trino_catalog)
