# SPDX-License-Identifier: Apache-2.0
"""``lab_init``'s catalog step against a loopback fake of Lakekeeper 0.14's management API.

The fake's routes and payload shapes are those of Lakekeeper v0.14.1
(``crates/lakekeeper/src/api/management/v1/server.rs`` and ``warehouse/mod.rs``): ``GET /health``,
``GET /management/v1/info`` (``bootstrapped``), ``POST /management/v1/bootstrap``
(``accept-terms-of-use``, ``204``; ``400 TermsOfUseNotAccepted`` without it, ``400
CatalogAlreadyBootstrapped`` a second time), ``GET``/``POST /management/v1/warehouse``
(``{"warehouses": [GetWarehouseResponse, ...]}``; a kebab-case create request answered ``201``
with the whole ``GetWarehouseResponse``, an unknown storage-profile type or a missing field
``422``, a name taken twice ``409 WarehouseAlreadyExists``, from
``service/catalog_store/warehouse.rs``).

Since 0.11 the catalog vends credentials to a client that sends no ``X-Iceberg-Access-Delegation``
header whenever it can (``service/storage/s3.rs``, ``generate_table_config``): it can for a
warehouse with STS on, or with a Cloudflare R2 or Alibaba OSS credential; otherwise it falls back
to remote signing when that is enabled.  ``delegation_for_a_client_without_the_header`` is that
decision, copied from Lakekeeper v0.14.1 ``crates/lakekeeper/src/service/storage/s3.rs``,
``S3Profile::generate_table_config``, lines 490-524 (the ``DataAccessMode::ServerDelegated``
arm).  A vended credential is always a temporary one (STS, R2 or OSS), never the stored key; the
tests pin that the lab's warehouse vends nothing, so clients get remote signing (as on 0.9) or
nothing.
"""

from __future__ import annotations

import importlib.util
import json
import sys
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
LAB_INIT = ROOT / "compose" / "lab-in-a-box" / "fakes" / "lab_init.py"
LOOPBACK = "127.0.0.1"  # no-raw-endpoint: allow test servers bind loopback only
WAREHOUSE = "lab"
PROJECT = "00000000-0000-0000-0000-000000000000"  # Lakekeeper's default project id
KNOWN_TYPES = ("s3", "adls", "azdls", "onelake", "stackit", "gcs")  # StorageProfile
S3 = {
    "bucket": "lab-lake",
    "region": "garage",
    "endpoint": "http://object-store.svc.example.internal",
    "access": "GK000000000000000000000000",
    "secret": "0" * 64,
}


def load_lab_init():
    spec = importlib.util.spec_from_file_location("lab_init_catalog", LAB_INIT)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["lab_init_catalog"] = mod
    spec.loader.exec_module(mod)
    return mod


def delegation_for_a_client_without_the_header(profile: dict, credential: dict) -> str:
    """What Lakekeeper >= 0.11 hands a client that does not name an access-delegation mode.

    Lakekeeper v0.14.1 ``crates/lakekeeper/src/service/storage/s3.rs``,
    ``S3Profile::generate_table_config``, lines 490-524: vend when STS is on or the credential is
    Cloudflare R2 or Alibaba OSS, else remote signing when it is enabled, else nothing.
    """
    can_vend = profile.get("sts-enabled") is True or credential.get("credential-type") in (
        "cloudflare-r2",
        "aliyun-oss",
    )
    if can_vend:
        return "vended-credentials"
    if profile.get("remote-signing-enabled", True):  # serde default: true
        return "remote-signing"
    return "none"


class Lakekeeper:
    def __init__(self) -> None:
        self.bootstrapped = False
        self.warehouses: dict[str, dict] = {}  # id -> GetWarehouseResponse
        self.credentials: dict[str, dict] = {}  # id -> the stored credential (never served)
        self.calls: list[tuple[str, str]] = []
        self.fail: dict[str, int] = {}


def make_handler(state: Lakekeeper):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args) -> None:  # keep pytest output clean
            pass

        def _send(self, code: int, body: object = None) -> None:
            raw = b"" if body is None else json.dumps(body).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def _error(self, code: int, kind: str, message: str) -> None:
            self._send(code, {"error": {"code": code, "type": kind, "message": message}})

        def _body(self) -> dict:
            n = int(self.headers.get("Content-Length") or 0)
            return json.loads(self.rfile.read(n) or b"{}")

        def _route(self, method: str) -> None:
            state.calls.append((method, self.path))
            if self.path in state.fail:
                return self._error(state.fail[self.path], "Injected", "a broken server")
            route = ROUTES.get((method, self.path))
            if route is None:
                return self._error(404, "NotFound", f"no route {method} {self.path}")
            route(self)

        def do_GET(self) -> None:
            self._route("GET")

        def do_POST(self) -> None:
            self._route("POST")

        def health(self) -> None:
            self._send(200, {"health": "healthy", "services": {}})

        def info(self) -> None:
            self._send(200, {"version": "0.14.1", "bootstrapped": state.bootstrapped})

        def bootstrap(self) -> None:
            body = self._body()
            if body.get("accept-terms-of-use") is not True:
                return self._error(
                    400,
                    "TermsOfUseNotAccepted",
                    "You must accept the terms of use to bootstrap the catalog.",
                )
            if state.bootstrapped:
                return self._error(
                    400, "CatalogAlreadyBootstrapped", "Catalog is not open for bootstrap"
                )
            state.bootstrapped = True
            self._send(204)

        def list_warehouses(self) -> None:
            self._send(200, {"warehouses": list(state.warehouses.values())})

        def create_warehouse(self) -> None:
            if not state.bootstrapped:
                return self._error(503, "CatalogNotBootstrapped", "bootstrap first")
            body = self._body()
            profile, credential = body.get("storage-profile"), body.get("storage-credential")
            name = body.get("warehouse-name")
            # axum's JSON extractor answers a body that does not deserialize with 422
            if not name or not isinstance(profile, dict) or profile.get("type") not in KNOWN_TYPES:
                return self._error(422, "UnprocessableEntity", "unknown storage profile type")
            if any(k not in profile for k in ("bucket", "region", "sts-enabled")):
                return self._error(422, "UnprocessableEntity", "missing a required field")
            if any(name == w["name"] for w in state.warehouses.values()):
                return self._error(
                    409, "WarehouseAlreadyExists", f"Warehouse '{name}' already exists"
                )
            wid = str(uuid.UUID(int=len(state.warehouses) + 1))
            response = {
                "id": wid,  # deprecated since 0.11, still sent
                "warehouse-id": wid,
                "name": name,
                "project-id": PROJECT,
                "storage-profile": profile,
                # adjacently tagged (service/storage/mod.rs, StorageCredentialType)
                "storage-credential-type": {
                    "type": (credential or {}).get("type"),
                    "credential-type": (credential or {}).get("credential-type"),
                },
                "delete-profile": {"type": "hard"},
                "status": "active",
                "protected": False,
                "managed-by": "self-managed",
                "allowed-format-versions": [1, 2, 3],
                "updated-at": None,
            }
            state.warehouses[wid] = response
            state.credentials[wid] = credential or {}
            self._send(201, response)

    ROUTES = {
        ("GET", "/health"): Handler.health,
        ("GET", "/management/v1/info"): Handler.info,
        ("POST", "/management/v1/bootstrap"): Handler.bootstrap,
        ("GET", "/management/v1/warehouse"): Handler.list_warehouses,
        ("POST", "/management/v1/warehouse"): Handler.create_warehouse,
    }
    return Handler


@pytest.fixture
def catalog():
    state = Lakekeeper()
    httpd = ThreadingHTTPServer((LOOPBACK, 0), make_handler(state))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield state, f"http://{LOOPBACK}:{httpd.server_address[1]}"
    httpd.shutdown()
    httpd.server_close()


@pytest.fixture(scope="module")
def lab_init():
    return load_lab_init()


def test_a_fresh_catalog_is_bootstrapped_and_gets_the_warehouse(lab_init, catalog):
    state, url = catalog
    lab_init.init_catalog(url, WAREHOUSE, S3)
    assert state.bootstrapped
    (wh,) = state.warehouses.values()
    assert wh["name"] == WAREHOUSE
    profile = wh["storage-profile"]
    assert profile["bucket"] == S3["bucket"] and profile["endpoint"] == S3["endpoint"]
    assert profile["flavor"] == "s3-compat" and profile["path-style-access"] is True
    assert wh["storage-credential-type"] == {"type": "s3", "credential-type": "access-key"}


def test_the_warehouse_states_both_access_modes_and_never_vends_its_key(lab_init, catalog):
    state, url = catalog
    lab_init.init_catalog(url, WAREHOUSE, S3)
    (wh,) = state.warehouses.values()
    profile = wh["storage-profile"]
    assert profile["sts-enabled"] is False
    assert profile["remote-signing-enabled"] is True  # stated, not left to a default
    credential = state.credentials[wh["warehouse-id"]]
    assert delegation_for_a_client_without_the_header(profile, credential) == "remote-signing"


def test_the_delegation_rule_bites():
    """The rule the previous test leans on tells the modes apart."""
    key = {"credential-type": "access-key"}
    assert delegation_for_a_client_without_the_header({"sts-enabled": True}, key) == (
        "vended-credentials"
    )
    r2 = {"credential-type": "cloudflare-r2"}
    assert delegation_for_a_client_without_the_header({"sts-enabled": False}, r2) == (
        "vended-credentials"
    )
    off = {"sts-enabled": False, "remote-signing-enabled": False}
    assert delegation_for_a_client_without_the_header(off, key) == "none"


def test_a_second_run_changes_nothing(lab_init, catalog):
    state, url = catalog
    lab_init.init_catalog(url, WAREHOUSE, S3)
    lab_init.init_catalog(url, WAREHOUSE, S3)
    assert len(state.warehouses) == 1
    posts = [path for method, path in state.calls if method == "POST"]
    assert posts == ["/management/v1/bootstrap", "/management/v1/warehouse"]


def test_negative_a_refused_warehouse_create_fails_loudly(lab_init, catalog):
    state, url = catalog
    state.fail["/management/v1/warehouse"] = 500
    with pytest.raises(SystemExit, match="lab_init: warehouse create failed"):
        lab_init.init_catalog(url, WAREHOUSE, S3)


def test_negative_a_refused_bootstrap_fails_loudly(lab_init, catalog):
    state, url = catalog
    state.fail["/management/v1/bootstrap"] = 400
    with pytest.raises(SystemExit, match="lab_init: catalog bootstrap failed"):
        lab_init.init_catalog(url, WAREHOUSE, S3)
