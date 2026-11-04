# SPDX-License-Identifier: Apache-2.0
"""``lab_init``'s object-store step against a loopback fake of Garage's admin API v2.

The fake's routes and payload shapes are those of Garage v2.5.0's
``doc/api/garage-admin-v2.json`` (``/v2/<OperationName>``, bearer token, ``404`` with a JSON
``code`` for an unknown key or bucket alias, ``403 AccessDenied`` for a wrong token), with the
behaviour of its handlers in ``src/api/admin/`` where the spec is silent: ``AllowBucketKey`` only
sets the flags sent as true, ``ApplyClusterLayout`` checks only the version, ``ImportKey`` refuses
any id the cluster has ever held.  Like the real v2 server (``router_v2.rs``, ``from_v1``) it
refuses the v1 calls whose semantics changed, ``GET /v1/status`` and ``POST /v1/layout``, with
``400 InvalidRequest`` "v1/ endpoint is no longer supported"; the v1 initialiser fails on that.
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
        self.deleted_keys: set[str] = set()  # tombstones: invisible, but their ids stay taken
        self.fail: dict[str, int] = {}  # path -> status to answer instead (a broken server)
        self.buckets: dict[str, dict] = {}  # id -> bucket
        self.calls: list[tuple[str, str]] = []

    def status(self) -> dict:
        node = {"id": NODE, "isUp": True, "draining": False, "hostname": "object-store"}
        return {"layoutVersion": self.layout_version, "nodes": [node]}


V1_REFUSED = {"/v1/status": "GetClusterStatus", "/v1/layout": "UpdateClusterLayout"}


def url_path(target: str) -> str:
    return urllib.parse.urlsplit(target).path


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
                return self._error(403, "AccessDenied", "Forbidden: invalid admin token")
            if url.path in state.fail:
                return self._error(state.fail[url.path], "InternalError", "injected failure")
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
        def v1_refused(self, query, body):
            name = V1_REFUSED[url_path(self.path)]
            self._error(400, "InvalidRequest", f"v1/ endpoint is no longer supported: {name}")

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
                    "stagedParameters": None,
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
            # like Garage, nothing staged is not an error: the next version repeats the roles
            state.roles, state.staged = state.staged or state.roles, []
            state.layout_version += 1
            self._send(200, {"message": [], "layout": {"version": state.layout_version}})

        def get_key_info(self, query, body):
            key = state.keys.get(query.get("id", ""))
            if key is None:
                return self._error(404, "NoSuchAccessKey", "no such key")
            self._send(200, key)

        # Garage's ImportKey looks the id up in its key table, tombstones included, and
        # answers 409 KeyAlreadyExists for any id it has held: a key is never re-imported,
        # not even after DeleteKey (so a new secret for the same id needs a fresh store).
        def import_key(self, query, body):
            if not isinstance(body, dict) or not {"accessKeyId", "secretAccessKey"} <= set(body):
                return self._error(400, "InvalidRequest", "ImportKeyRequest")
            if body["accessKeyId"] in state.keys or body["accessKeyId"] in state.deleted_keys:
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
            state.buckets[bucket_id] = {
                "id": bucket_id,
                "created": "2026-01-01T00:00:00Z",
                "globalAliases": [alias],
                "websiteAccess": False,
                "keys": [],
                "objects": 0,
                "bytes": 0,
            }
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
            access = body["accessKeyId"]
            entry = next((k for k in bucket["keys"] if k["accessKeyId"] == access), None)
            if entry is None:
                entry = {
                    "accessKeyId": access,
                    "name": state.keys[access]["name"],
                    "permissions": {"read": False, "write": False, "owner": False},
                    "bucketLocalAliases": [],
                }
                bucket["keys"].append(entry)
            # Garage (bucket.rs, handle_bucket_change_key_perm) sets only the flags sent as
            # true; a false or missing flag leaves the current grant as it is
            for flag in ("read", "write", "owner"):
                if body["permissions"].get(flag):
                    entry["permissions"][flag] = True
            self._send(200, bucket)

    ROUTES = {
        ("GET", "/v1/status"): Handler.v1_refused,
        ("POST", "/v1/layout"): Handler.v1_refused,
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
    assert [(k["accessKeyId"], k["permissions"]) for k in bucket["keys"]] == [
        (ACCESS, {"read": True, "write": True, "owner": True})
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


def test_a_failed_key_lookup_stops_instead_of_importing(lab_init, garage):
    state, url = garage
    state.fail["/v2/GetKeyInfo"] = 500
    with pytest.raises(SystemExit, match="key lookup failed: 500"):
        lab_init.init_object_store(url, TOKEN, ACCESS, SECRET, BUCKET)
    assert ("POST", "/v2/ImportKey") not in state.calls


def test_a_deleted_key_id_cannot_be_imported_again(lab_init, garage):
    """Garage v2 keeps the id of a deleted key: the import is refused (409) and the run stops
    loudly, which is why rotating the lab secret needs a fresh store (``down -v``)."""
    state, url = garage
    state.deleted_keys.add(ACCESS)
    with pytest.raises(SystemExit, match="key import failed: 409"):
        lab_init.init_object_store(url, TOKEN, ACCESS, SECRET, BUCKET)


def test_the_fake_refuses_the_v1_calls_garage_v2_refuses(lab_init, garage):
    _, url = garage
    auth = {"Authorization": f"Bearer {TOKEN}"}
    code, out = lab_init.call("GET", f"{url}/v1/status", headers=auth)
    assert code == 400 and "no longer supported: GetClusterStatus" in out["message"]
    code, out = lab_init.call("POST", f"{url}/v1/layout", [], auth)
    assert code == 400 and "no longer supported: UpdateClusterLayout" in out["message"]


def test_the_fake_grant_only_adds_flags_like_garage(lab_init, garage):
    state, url = garage
    lab_init.init_object_store(url, TOKEN, ACCESS, SECRET, BUCKET)
    (bucket,) = state.buckets.values()
    grant = {"bucketId": bucket["id"], "accessKeyId": ACCESS, "permissions": {"read": False}}
    code, out = lab_init.call(
        "POST", f"{url}/v2/AllowBucketKey", grant, {"Authorization": f"Bearer {TOKEN}"}
    )
    assert code == 200
    assert out["keys"][0]["permissions"] == {"read": True, "write": True, "owner": True}
