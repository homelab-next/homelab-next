# SPDX-License-Identifier: Apache-2.0
"""A stand-in for the dataflow service's REST API (shared by the dataflow role tests).

It implements what the role's API script calls, with the behaviours the script depends on: every
route but the sign-in answers 401 without a bearer; the sign-in is a form post; the parameter
provider is fetched and applied through a request that completes on its second look; a context
filled by the provider holds provided parameters with the sensitivity the request gave; the flow
registry client is created, updated and deleted; a flow definition is uploaded as multipart and its
processors start only when the group is set RUNNING; a definition downloads back.  ``https=`` serves
it over TLS with a throwaway certificate that is also its own CA.
"""

from __future__ import annotations

import json
import ssl
import subprocess
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit


def make_pki(directory: Path) -> tuple[Path, Path]:
    """A self-signed certificate for localhost that can also be the trust anchor, and its key."""
    cert, key = directory / "cert.pem", directory / "key.pem"
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
         "-subj", "/CN=localhost", "-keyout", str(key), "-out", str(cert),
         "-addext", "subjectAltName=DNS:localhost",
         "-addext", "basicConstraints=critical,CA:TRUE",
         "-addext", "keyUsage=critical,digitalSignature,keyCertSign",
         "-addext", "subjectKeyIdentifier=hash"],
        check=True, capture_output=True,
    )  # fmt: skip
    return cert, key


class Controller:
    def __init__(self, *, user="admin", password="p" * 14, bearer=None, version="2.12.0",
                 https=None, root_id="root-0", allow_anonymous=False):  # fmt: skip
        self.user, self.password, self.bearer = user, password, bearer
        self.version, self.root_id, self.allow_anonymous = version, root_id, allow_anonymous
        self.cluster = {"clustered": False, "connectedToCluster": False}
        self.status = {
            "invalidCount": 0,
            "syncFailureCount": 0,
            "flowFilesQueued": 0,
            "stoppedCount": 0,
        }
        self.providers: dict[str, dict] = {}
        self.contexts: dict[str, dict] = {}
        self.clients: dict[str, dict] = {}
        self.groups: dict[str, dict] = {}
        self.requests: dict[str, int] = {}
        self.calls: list[tuple[str, str]] = []
        self.token = "jwt-" + "0123456789abcdef" * 2
        self._n = 0
        outer = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _reply(self, status, doc=None, raw=None):
                body = (
                    raw
                    if raw is not None
                    else (json.dumps(doc).encode() if doc is not None else b"")
                )
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def _go(self, method):
                n = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(n) if n else b""
                url = urlsplit(self.path)
                outer.calls.append((method, url.path))
                status, doc = outer.route(method, url.path, parse_qs(url.query), body,
                                          self.headers.get("Authorization"),
                                          self.headers.get("Content-Type", ""))  # fmt: skip
                if isinstance(doc, bytes):
                    self._reply(status, raw=doc)
                elif isinstance(doc, str):
                    self._reply(status, raw=doc.encode())
                else:
                    self._reply(status, doc)

            def do_GET(self):
                self._go("GET")

            def do_POST(self):
                self._go("POST")

            def do_PUT(self):
                self._go("PUT")

            def do_DELETE(self):
                self._go("DELETE")

        self._httpd = ThreadingHTTPServer(("localhost", 0), H)
        self._tmp = None
        if https:
            cert, key = https
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(str(cert), str(key))
            self._httpd.socket = ctx.wrap_socket(self._httpd.socket, server_side=True)
        self.scheme = "https" if https else "http"

    # -- the routes ---------------------------------------------------------------------------

    def nid(self, prefix="id") -> str:
        self._n += 1
        return f"{prefix}-{self._n}"

    def route(self, method, path, query, body, auth, ctype):
        p = "/" + path.lstrip("/").split("/", 1)[1]  # the first segment is the service's API root
        if p == "/access/token" and method == "POST":
            form = {k: v[0] for k, v in parse_qs(body.decode()).items()}
            if form.get("username") == self.user and form.get("password") == self.password:
                return 201, self.token
            return 401, "Unauthorized"
        valid = [f"Bearer {self.token}"] + ([f"Bearer {self.bearer}"] if self.bearer else [])
        ok = auth in valid
        if not ok and not self.allow_anonymous:
            return 401, "Unauthorized"
        if p == "/flow/about":
            return 200, {"about": {"version": self.version}}
        if p == "/flow/cluster/summary":
            return 200, {"clusterSummary": self.cluster}
        if p == "/flow/status":
            return 200, {"controllerStatus": self.status}
        if p == "/flow/bulletin-board":
            return 200, {"bulletinBoard": {"bulletins": []}}
        doc = json.loads(body) if body and "json" in ctype else None
        # parameter providers
        if p == "/flow/parameter-providers":
            return 200, {"parameterProviders": [self._provider(i) for i in self.providers]}
        if p == "/controller/parameter-providers" and method == "POST":
            i = self.nid("pp")
            self.providers[i] = {"version": 1, "name": doc["component"]["name"],
                                 "properties": dict(doc["component"].get("properties", {}))}  # fmt: skip
            return 201, self._provider(i)
        m = p.removeprefix("/parameter-providers/")
        if p.startswith("/parameter-providers/"):
            i, _, rest = m.partition("/")
            if method == "PUT" and not rest:
                self.providers[i]["properties"].update(doc["component"]["properties"])
                self.providers[i]["version"] += 1
                return 200, self._provider(i)
            if rest == "parameters/fetch-requests":
                return 200, self._provider(i)
            if rest == "apply-parameters-requests" and method == "POST":
                for g in doc["parameterGroupConfigurations"]:
                    self.contexts[g["parameterContextName"]] = {
                        n: {"sensitive": s == "SENSITIVE", "provided": True}
                        for n, s in g["parameterSensitivities"].items()
                    }
                self.requests["r1"] = 0
                return 202, {"request": {"requestId": "r1", "complete": False}}
            if rest.startswith("apply-parameters-requests/"):
                if method == "DELETE":
                    return 200, {}
                self.requests["r1"] += 1
                return 200, {"request": {"requestId": "r1", "complete": self.requests["r1"] > 1}}
        if p == "/flow/parameter-contexts":
            return 200, {"parameterContexts": [
                {"component": {"name": n, "parameters": [
                    {"parameter": {"name": k, **v}} for k, v in params.items()]}}
                for n, params in self.contexts.items()]}  # fmt: skip
        # registry clients
        if p == "/controller/registry-clients":
            if method == "GET":
                return 200, {"registries": [self._client(i) for i in self.clients]}
            i = self.nid("rc")
            self.clients[i] = {"version": 1, "name": doc["component"]["name"],
                               "properties": dict(doc["component"]["properties"])}  # fmt: skip
            return 201, self._client(i)
        if p.startswith("/controller/registry-clients/"):
            i = p.rsplit("/", 1)[1]
            if method == "PUT":
                self.clients[i]["properties"] = dict(doc["component"]["properties"])
                self.clients[i]["version"] += 1
                return 200, self._client(i)
            if method == "DELETE":
                del self.clients[i]
                return 200, {}
        # process groups
        if p == "/flow/process-groups/root":
            return 200, {"processGroupFlow": {"id": self.root_id}}
        if p.startswith("/flow/process-groups/"):
            gid = p.rsplit("/", 1)[1]
            if method == "PUT":
                for pr in self.groups[gid]["processors"]:
                    pr["state"] = doc["state"]
                return 200, {}
            if gid == self.root_id:
                return 200, {
                    "processGroupFlow": {
                        "flow": {
                            "processGroups": [
                                {"id": i, "component": {"name": g["name"]}}
                                for i, g in self.groups.items()
                            ]
                        }
                    }
                }
            return 200, {
                "processGroupFlow": {
                    "flow": {
                        "processors": [
                            {"component": {"state": pr["state"]}}
                            for pr in self.groups[gid]["processors"]
                        ]
                    }
                }
            }
        if p == f"/process-groups/{self.root_id}/process-groups/upload":
            fields = _multipart(body, ctype)
            flow = json.loads(fields["file"])
            gid = self.nid("pg")
            self.groups[gid] = {"name": fields["groupName"], "definition": fields["file"].encode(),
                                "processors": [{"state": "STOPPED"} for _ in
                                               flow["flowContents"]["processors"]]}  # fmt: skip
            return 201, {"id": gid}
        if p.startswith("/process-groups/") and p.endswith("/download"):
            return 200, self.groups[p.split("/")[2]]["definition"]
        return 404, "not found"

    def _provider(self, i):
        v = self.providers[i]
        return {"id": i, "revision": {"version": v["version"]},
                "component": {"name": v["name"], "properties": v["properties"]}}  # fmt: skip

    def _client(self, i):
        v = self.clients[i]
        return {"id": i, "revision": {"version": v["version"]},
                "component": {"name": v["name"], "properties": v["properties"]}}  # fmt: skip

    # -- life ---------------------------------------------------------------------------------

    def __enter__(self):
        threading.Thread(target=self._httpd.serve_forever, daemon=True).start()
        return self

    def __exit__(self, *a):
        self._httpd.shutdown()
        self._httpd.server_close()

    @property
    def port(self) -> int:
        return self._httpd.server_address[1]

    @property
    def url(self) -> str:
        return f"{self.scheme}://localhost:{self.port}"


def _multipart(body: bytes, ctype: str) -> dict[str, str]:
    boundary = ctype.split("boundary=", 1)[1].encode()
    out = {}
    for part in body.split(b"--" + boundary):
        if b"Content-Disposition" not in part:
            continue
        head, _, value = part.partition(b"\r\n\r\n")
        name = head.split(b'name="', 1)[1].split(b'"', 1)[0].decode()
        out[name] = value.removesuffix(b"\r\n").decode()
    return out


def smoke_definition(processors=3) -> str:
    return json.dumps({"flowContents": {"name": "hnx-smoke", "processors": [{}] * processors}})


def temp_pki() -> tuple[Path, Path]:
    return make_pki(Path(tempfile.mkdtemp()))
