# SPDX-License-Identifier: Apache-2.0
"""Endpoints come from the registry resolver only; an unset endpoint raises. Heavy dependencies are
optional and lazy with a clear error."""

from __future__ import annotations

import subprocess
import sys
import types
from pathlib import Path

import pytest

from homelabnext.lake import EndpointNotConfigured, MissingExtra, TrinoLake
from homelabnext.lake.endpoints import endpoint_for
from homelabnext.registry import FakeDNS, Resolver

ROOT = Path(__file__).resolve().parents[2]
_HOST = "lake-query.svc.example.internal"
_URL_TLS = f"https://{_HOST}:{8443}"
_URL_PLAIN = f"http://{_HOST}:{8080}"


def _resolver(env=None, dns=None):
    return Resolver(domain="example.internal", dns=dns or FakeDNS(), hosts={}, environ=env or {})


def test_unset_endpoint_raises_not_defaults():
    with pytest.raises(EndpointNotConfigured, match="lake-query"):
        endpoint_for("lake-query", resolver=_resolver())


def test_no_resolver_and_no_registry_raises():
    with pytest.raises(EndpointNotConfigured, match="there is no default"):
        endpoint_for("lake-query")
    with pytest.raises(EndpointNotConfigured):
        TrinoLake(catalog="c", schema="s", user="u")


def test_trino_unset_endpoint_raises():
    with pytest.raises(EndpointNotConfigured):
        TrinoLake(catalog="c", schema="s", user="u", resolver=_resolver())


def test_rest_catalog_unset_endpoint_raises():
    from homelabnext.lake.iceberg import open_rest_catalog

    with pytest.raises(EndpointNotConfigured, match="lake-catalog"):
        open_rest_catalog(resolver=_resolver())


def test_env_override_resolves(monkeypatch):
    env = {"HNX_ENDPOINT_LAKE_QUERY": _URL_TLS}
    ep = endpoint_for("lake-query", resolver=_resolver(env))
    assert (ep.host, ep.port, ep.scheme) == (_HOST, 8443, "https")


def _fake_trino(monkeypatch):
    calls = {}

    class Cur:
        description = (("n",),)

        def execute(self, sql, args=None):
            calls["sql"], calls["args"] = sql, args

        def fetchall(self):
            return [(7,)]

    class Conn:
        def cursor(self):
            return Cur()

        def close(self):
            calls["closed"] = True

    dbapi = types.ModuleType("trino.dbapi")
    dbapi.connect = lambda **kw: calls.update(kw=kw) or Conn()
    pkg = types.ModuleType("trino")
    pkg.dbapi = dbapi
    monkeypatch.setitem(sys.modules, "trino", pkg)
    monkeypatch.setitem(sys.modules, "trino.dbapi", dbapi)
    return calls


def test_trino_pins_utc_tls_and_binds_params(monkeypatch):
    calls = _fake_trino(monkeypatch)
    env = {"HNX_ENDPOINT_LAKE_QUERY": _URL_TLS}
    t = TrinoLake(catalog="lake", schema="ocsf", user="svc", resolver=_resolver(env))
    assert t.query(
        "SELECT count(*) AS n FROM authentication WHERE user_name = :u", {"u": "alice"}
    ) == [{"n": 7}]
    kw = calls["kw"]
    assert kw["timezone"] == "UTC" and kw["http_scheme"] == "https" and kw["verify"] is True
    assert kw["host"] == _HOST and kw["port"] == 8443
    assert calls["sql"].endswith("user_name = ?") and calls["args"] == ["alice"] and calls["closed"]


def test_trino_refuses_remote_plaintext_http():
    env = {"HNX_ENDPOINT_LAKE_QUERY": _URL_PLAIN}
    with pytest.raises(Exception, match="plaintext"):
        TrinoLake(catalog="c", schema="s", user="u", resolver=_resolver(env))
    ok = TrinoLake(catalog="c", schema="s", user="u", resolver=_resolver(env), allow_plaintext=True)
    assert ok.endpoint.scheme == "http"


def test_trino_cannot_disable_verification_alone():
    env = {"HNX_ENDPOINT_LAKE_QUERY": _URL_TLS}
    with pytest.raises(Exception, match="verification"):
        TrinoLake(catalog="c", schema="s", user="u", resolver=_resolver(env), verify=False)


def test_missing_trino_package_is_a_clear_error(monkeypatch):
    monkeypatch.setitem(sys.modules, "trino", None)
    monkeypatch.setitem(sys.modules, "trino.dbapi", None)
    env = {"HNX_ENDPOINT_LAKE_QUERY": _URL_TLS}
    t = TrinoLake(catalog="c", schema="s", user="u", resolver=_resolver(env))
    with pytest.raises(MissingExtra, match=r"homelabnext\[trino\]"):
        t.query("SELECT 1")


@pytest.mark.parametrize("missing", ["duckdb", "pyiceberg"])
def test_missing_heavy_dependency_is_a_clear_error(monkeypatch, missing):
    monkeypatch.setitem(sys.modules, missing, None)
    from homelabnext.lake import DuckDBLake, IcebergLake

    def build():
        return DuckDBLake({}).query("SELECT 1") if missing == "duckdb" else IcebergLake(object())

    with pytest.raises(MissingExtra, match=r"pip install 'homelabnext\[lake\]'"):
        build()


def test_importing_the_package_loads_no_heavy_dependency():
    code = (
        "import sys, homelabnext.lake as L; L.FakeLake(); "
        "bad = [m for m in ('duckdb','pyarrow','pyiceberg','trino') if m in sys.modules]; "
        "print(bad); sys.exit(1 if bad else 0)"
    )
    r = subprocess.run(
        [sys.executable, "-c", code], cwd=ROOT, capture_output=True, text=True, check=False
    )
    assert r.returncode == 0, r.stdout + r.stderr


def test_no_literal_endpoints_in_the_package():
    # the repository gate (tools/no_raw_endpoints.py) is the real control; this is a fast local echo
    import re

    pat = re.compile(
        r"(?:https?|grpc)://[A-Za-z0-9.-]+:\d+|localhost:\d+|\b\d{1,3}(?:\.\d{1,3}){3}\b"
    )
    for p in (ROOT / "homelabnext" / "lake").glob("*.py"):
        for n, line in enumerate(p.read_text().splitlines(), 1):
            assert not pat.search(line), f"{p.name}:{n}: {line}"
