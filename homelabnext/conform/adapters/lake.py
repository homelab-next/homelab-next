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

**Every reader signs in to the engine** (ADR-0033 decision 6: the row filters of
``lake-access.json`` are keyed on the session user, so a user named by a bare header would make
every ceiling honour-system).  ``credential`` is a secret reference (``secret:<name>``, never a
value), delivered in ``HNX_SECRET_<NAME>`` (:func:`homelabnext.registry.model.secret_env_name`):
the reader's password in the engine's per-reader password file.  The engine client sends it as
HTTP Basic for the reader's login (:func:`homelabnext.lake.trino_http.engine_login`;
:func:`reader_secret` is the conventional name).  ``catalog_credential`` is a second secret
reference, the catalog's bearer token, when the catalog asks for one.  With a credential, both
clients send through :func:`homelabnext._http.credential_opener` (``ca_file`` for a private CA):
no redirect is followed and no proxy is used, so the credential reaches only the endpoint.

**A ``lake-query`` endpoint that is not loopback is refused without a credential**, outright:
there is no flag that reads a lab's lake unauthenticated.  Only the lab-in-a-box, bound to
loopback, runs without one.  The value is read from its variable when the lake is built (a
missing one fails at once) and again at every request, so no object holds it.
"""

from __future__ import annotations

import os
import re
import urllib.parse
from collections.abc import Callable
from typing import Any

from homelabnext._http import check_plaintext, credential_opener, is_loopback
from homelabnext.lake.errors import LakeError
from homelabnext.lake.rest_catalog import RestCatalog
from homelabnext.lake.trino_http import TrinoHTTP, engine_login, password_auth
from homelabnext.lake.trino_rest import TrinoRestLake
from homelabnext.registry.model import secret_env_name

from ._env import AdapterConfigError, env_secret, resolve, run_token

__all__ = ["READERS", "engine_login", "make_clients", "make_lake", "password_auth", "reader_secret"]

#: the secret-store area holding each reader's engine password (:func:`reader_secret`)
READERS = "lake-query/readers"
_SECRET_REF = re.compile(r"secret:[a-z0-9][a-z0-9/_.-]{0,127}")


def reader_secret(user: str) -> str:
    """The conventional secret reference of ``user``'s engine password: the secret
    ``lake-query/readers/<login>`` (for ``analyzer:novelty`` the secret
    ``lake-query/readers/analyzer.novelty``, delivered in
    ``HNX_SECRET_LAKE_QUERY_READERS_ANALYZER_NOVELTY``)."""
    return f"secret:{READERS}/{engine_login(user)}"


def _secret(ref: Any, what: str) -> Callable[[], str]:
    if not (isinstance(ref, str) and _SECRET_REF.fullmatch(ref)):
        raise AdapterConfigError(f"{what} is a secret name (secret:<name>), never a value")
    return env_secret(secret_env_name(ref))  # checked now, read again at every request


def _url(capability: str, resolver: Any, domain: str | None, allow_plaintext: bool) -> str:
    ep = resolve(capability, resolver=resolver, domain=domain, schemes=("http", "https"))
    try:
        check_plaintext(ep.url, credentials=True, allow_plaintext=allow_plaintext)
    except ValueError as exc:
        raise LakeError(f"{capability} endpoint: {exc}") from None
    return ep.url


def make_clients(
    *,
    domain: str | None = None,
    resolver: Any = None,
    warehouse: str | None = None,
    warehouse_env: str = "LAB_WAREHOUSE",
    user: str = "hnx-conform",
    api_root: str = "/catalog",
    allow_plaintext: bool = False,
    credential: str | None = None,
    catalog_credential: str | None = None,
    ca_file: str | None = None,
) -> tuple[Any, RestCatalog]:
    """The engine client and the catalog client :func:`make_lake` reads and writes through, as
    ``user`` (see the module doc for ``credential`` and ``catalog_credential``); nothing is sent
    while they are built."""
    wh = warehouse or os.environ.get(warehouse_env, "")
    if not wh:
        raise LookupError(f"no warehouse: pass warehouse= or set {warehouse_env}")
    query_url = _url("lake-query", resolver, domain, allow_plaintext)
    if credential is None and not is_loopback(urllib.parse.urlsplit(query_url).hostname):
        raise LakeError(
            f"lake-query endpoint is not loopback, so {user!r} must sign in to the engine: pass "
            f"credential= (a secret reference, conventionally {reader_secret(user)})"
        )
    signed_in = credential is not None or catalog_credential is not None
    opener = credential_opener(ca_file) if signed_in else None
    auth = None
    if credential is not None:
        auth = password_auth(user, _secret(credential, "credential"))
    bearer = None
    if catalog_credential is not None:
        token = _secret(catalog_credential, "catalog_credential")
        bearer = lambda: f"Bearer {token()}"  # noqa: E731
    engine = TrinoHTTP(query_url, user=user, auth=auth, opener=opener)
    catalog = RestCatalog(
        _url("lake-catalog", resolver, domain, allow_plaintext),
        warehouse=wh,
        api_root=api_root,
        auth=bearer,
        opener=opener,
    )
    return engine, catalog


def make_lake(
    *,
    namespace: str = "auto",
    trino_catalog: str = "iceberg",
    **clients: Any,
) -> TrinoRestLake:
    """The lake of the registry's ``lake-query`` and ``lake-catalog`` endpoints: ``clients`` are
    :func:`make_clients`' keywords (``domain``, ``warehouse``, ``user``, ``credential``, ...)."""
    engine, catalog = make_clients(**clients)
    ns = f"hnx_conform_{run_token()}" if namespace == "auto" else namespace
    return TrinoRestLake(engine, catalog, namespace=ns, trino_catalog=trino_catalog)
