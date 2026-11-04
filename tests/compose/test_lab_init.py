# SPDX-License-Identifier: Apache-2.0
"""``lab_init``'s object-store step against a loopback fake of Garage's admin API v2.

The fake's routes and payload shapes are those of Garage v2.5.0's
``doc/api/garage-admin-v2.json`` (``/v2/<OperationName>``, bearer token, ``404`` with a JSON
``code`` for an unknown key or bucket alias).  Like the real v2 server it still answers
``GET /v1/status``, with the v2 ``GetClusterStatus`` body, which has no ``node`` field: the v1
initialiser fails on it, every other ``/v1/`` call is a 404 here.
"""

from __future__ import annotations

import importlib.util
import json
import sys
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
LAB_INIT = ROOT / "compose" / "lab-in-a-box" / "fakes" / "lab_init.py"
LOOPBACK = "127.0.0.1"  # no-raw-endpoint: allow test servers bind loopback only
TOKEN = "fake-admin-token-0000"
NODE = "a" * 64
ACCESS = "GK000000000000000000000000"
SECRET = "0" * 64
BUCKET = "lab-lake"


def load_lab_init():
    spec = importlib.util.spec_from_file_location("lab_init", LAB_INIT)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["lab_init"] = mod
    spec.loader.exec_module(mod)
    return mod


class GarageV2:
    """In-memory state of a single-node Garage cluster, as the admin API v2 shows it."""

    def __init__(self) -> None:
        self.layout_version = 0
        self.roles: list[dict] = []
        self.staged: list[dict] = []
        self.keys: dict[str, dict] = {}
        self.buckets: dict[str, dict] = {}  # id -> bucket
        self.calls: list[tuple[str, str]] = []

    def status(self) -> dict:
        node = {"id": NODE, "isUp": True, "draining": False, "hostname": "object-store"}
        return {"layoutVersion": self.layout_version, "nodes": [node]}


def make_handler(state: GarageV2, token: str = TOKEN):
    class Handler(BaseHTTPRequestHandler):
        def _send(self, code: int, doc=None) -> None:
            body = b"" if doc is None else json.dumps(doc).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _error(self, code: int, name: str, message: str) -> None:
            self._send(code, {"code": name, "message": message, "region": "garage", "path": ""})

        def _route(self, method: str) -> None:
            url = urllib.parse.urlsplit(self.path)
            query = dict(urllib.parse.parse_qsl(url.query))
            state.calls.append((method, url.path))
            if self.headers.get("Authorization") != f"Bearer {token}":
                return self._error(403, "Forbidden", "invalid admin token")
            body = None
            if method == "POST":
                raw = self.rfile.read(int(self.headers.get("Content-Length") or 0))
                try:
                    body = json.loads(raw) if raw else None
                except ValueError:
                    return self._error(400, "InvalidRequest", "body is not JSON")
            handler = ROUTES.get((method, url.path))
            if handler is None:
                return self._error(404, "NotFound", f"no admin endpoint {method} {url.path}")
            return handler(self, query, body)

        def do_GET(self):
            self._route("GET")

        def do_POST(self):
            self._route("POST")

        def log_message(self, *args):
            pass

        # --- endpoints ---------------------------------------------------------------
        def get_cluster_status(self, query, body):
            self._send(200, state.status())

        def get_node_info(self, query, body):
            if query.get("node") not in ("self", "*", NODE):
                return self._error(400, "InvalidRequest", "node is required")
            info = {
                "nodeId": NODE,
                "garageVersion": "v2.5.0",
                "rustVersion": "1",
                "dbEngine": "sqlite",
            }
            self._send(200, {"success": {NODE: info}, "error": {}})

        def get_cluster_layout(self, query, body):
            self._send(
                200,
                {
                    "version": state.layout_version,
                    "roles": state.roles,
                    "parameters": {"zoneRedundancy": "maximum"},
                    "partitionSize": 0,
                    "stagedRoleChanges": state.staged,
                },
            )

        def update_cluster_layout(self, query, body):
            if not isinstance(body, dict) or not isinstance(body.get("roles"), list):
                return self._error(400, "InvalidRequest", "UpdateClusterLayoutRequest.roles")
            for role in body["roles"]:
                if not {"id", "zone", "tags"} <= set(role) or role["id"] != NODE:
                    return self._error(400, "InvalidRequest", f"bad role change {role}")
            state.staged = body["roles"]
            self.get_cluster_layout(query, body)

        def apply_cluster_layout(self, query, body):
            if not isinstance(body, dict) or body.get("version") != state.layout_version + 1:
                return self._error(400, "InvalidRequest", "version must be current + 1")
            if not state.staged:
                return self._error(400, "InvalidRequest", "no staged changes")
            state.roles, state.staged = state.staged, []
            state.layout_version += 1
            self._send(200, {"message": [], "layout": {"version": state.layout_version}})

        def get_key_info(self, query, body):
            key = state.keys.get(query.get("id", ""))
            if key is None:
                return self._error(404, "NoSuchAccessKey", "no such key")
            self._send(200, key)

        def import_key(self, query, body):
            if not isinstance(body, dict) or not {"accessKeyId", "secretAccessKey"} <= set(body):
                return self._error(400, "InvalidRequest", "ImportKeyRequest")
            if body["accessKeyId"] in state.keys:
                return self._error(409, "KeyAlreadyExists", "key exists")
            state.keys[body["accessKeyId"]] = {
                "accessKeyId": body["accessKeyId"],
                "name": body.get("name") or "",
                "expired": False,
                "permissions": {"createBucket": False},
                "buckets": [],
            }
            self._send(200, state.keys[body["accessKeyId"]])

        def update_key(self, query, body):
            key = state.keys.get(query.get("id", ""))
            if key is None:
                return self._error(404, "NoSuchAccessKey", "no such key")
            for perm, value in ((body or {}).get("allow") or {}).items():
                key["permissions"][perm] = value
            self._send(200, key)

        def _bucket_by_alias(self, alias):
            return next((b for b in state.buckets.values() if alias in b["globalAliases"]), None)

        def get_bucket_info(self, query, body):
            bucket = self._bucket_by_alias(query.get("globalAlias"))
            if bucket is None:
                return self._error(404, "NoSuchBucket", "no such bucket")
            self._send(200, bucket)

        def create_bucket(self, query, body):
            alias = (body or {}).get("globalAlias")
            if not alias or self._bucket_by_alias(alias):
                return self._error(409, "BucketAlreadyExists", "bucket exists")
            bucket_id = f"{len(state.buckets) + 1:064x}"
            state.buckets[bucket_id] = {"id": bucket_id, "globalAliases": [alias], "keys": []}
            self._send(200, state.buckets[bucket_id])

        def allow_bucket_key(self, query, body):
            if not isinstance(body, dict) or not {"bucketId", "accessKeyId", "permissions"} <= set(
                body
            ):
                return self._error(400, "InvalidRequest", "BucketKeyPermChangeRequest")
            bucket = state.buckets.get(body["bucketId"])
            if bucket is None:
                return self._error(404, "NoSuchBucket", "no such bucket")
            if body["accessKeyId"] not in state.keys:
                return self._error(404, "NoSuchAccessKey", "no such key")
            bucket["keys"] = [k for k in bucket["keys"] if k["accessKeyId"] != body["accessKeyId"]]
            bucket["keys"].append(
                {"accessKeyId": body["accessKeyId"], "permissions": body["permissions"]}
            )
            self._send(200, bucket)

    ROUTES = {
        ("GET", "/v1/status"): Handler.get_cluster_status,  # v2 still serves it, v2-shaped
        ("GET", "/v2/GetClusterStatus"): Handler.get_cluster_status,
        ("GET", "/v2/GetNodeInfo"): Handler.get_node_info,
        ("GET", "/v2/GetClusterLayout"): Handler.get_cluster_layout,
        ("POST", "/v2/UpdateClusterLayout"): Handler.update_cluster_layout,
        ("POST", "/v2/ApplyClusterLayout"): Handler.apply_cluster_layout,
        ("GET", "/v2/GetKeyInfo"): Handler.get_key_info,
        ("POST", "/v2/ImportKey"): Handler.import_key,
        ("POST", "/v2/UpdateKey"): Handler.update_key,
        ("GET", "/v2/GetBucketInfo"): Handler.get_bucket_info,
        ("POST", "/v2/CreateBucket"): Handler.create_bucket,
        ("POST", "/v2/AllowBucketKey"): Handler.allow_bucket_key,
    }
    return Handler


@pytest.fixture
def garage():
    state = GarageV2()
    httpd = ThreadingHTTPServer((LOOPBACK, 0), make_handler(state))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield state, f"http://{LOOPBACK}:{httpd.server_address[1]}"
    httpd.shutdown()
    httpd.server_close()


@pytest.fixture(scope="module")
def lab_init():
    return load_lab_init()


def test_a_fresh_cluster_gets_layout_key_bucket_and_grant(lab_init, garage):
    state, url = garage
    lab_init.init_object_store(url, TOKEN, ACCESS, SECRET, BUCKET)
    assert state.layout_version == 1
    assert [(r["id"], r["zone"]) for r in state.roles] == [(NODE, "lab")]
    assert state.keys[ACCESS]["permissions"] == {"createBucket": True}
    (bucket,) = state.buckets.values()
    assert bucket["globalAliases"] == [BUCKET]
    assert bucket["keys"] == [
        {"accessKeyId": ACCESS, "permissions": {"read": True, "write": True, "owner": True}}
    ]
    assert all(path.startswith("/v2/") for _, path in state.calls), state.calls


def test_a_second_run_changes_nothing(lab_init, garage):
    state, url = garage
    lab_init.init_object_store(url, TOKEN, ACCESS, SECRET, BUCKET)
    lab_init.init_object_store(url, TOKEN, ACCESS, SECRET, BUCKET)
    assert state.layout_version == 1
    assert len(state.buckets) == 1 and len(state.keys) == 1
    assert [c for c in state.calls if c[1] in ("/v2/ImportKey", "/v2/CreateBucket")] == [
        ("POST", "/v2/ImportKey"),
        ("POST", "/v2/CreateBucket"),
    ]


def test_negative_a_wrong_admin_token_fails_loudly(lab_init, garage):
    state, url = garage
    with pytest.raises(SystemExit, match="lab_init:"):
        lab_init.init_object_store(url, "not-the-token", ACCESS, SECRET, BUCKET)
    assert not state.keys and not state.buckets
