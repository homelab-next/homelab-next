# SPDX-License-Identifier: Apache-2.0
"""A loopback HTTP stand-in for the OpenBao API subset the ``secrets`` adapter uses.

Shaped after OpenBao 2.1 (``vault/token_store.go``, the KV v2 plugin): KV v2 data/metadata
endpoints with versions, ``?list=true`` folder listings (keys, sub-folders with a trailing ``/``,
404 for an empty folder), ``DELETE metadata`` answering 204 whether or not the path exists,
``sys/mounts``, ACL policies with ``path "<glob>*"`` read rules, child tokens with a TTL and
metadata, ``lookup-accessor`` (400 ``invalid accessor``; 403 ``bad token`` once the TTL lapsed)
and ``revoke-accessor``.  Error bodies are ``{"errors": [...]}``; with ``echo_errors`` they also
echo the request body, so a test can prove the adapter never surfaces a server's error text.

Not modelled: namespaces, response wrapping, renewals, CAS, ``max_versions`` pruning.
"""

from __future__ import annotations

import fnmatch
import itertools
import json
import threading
import time
import urllib.parse
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

LOOPBACK = "127.0.0.1"  # no-raw-endpoint: allow fake server binds loopback only


class FakeOpenBao:
    def __init__(
        self,
        root_token: str = "fake-root-token-0000",  # scrub-allow: fake placeholder
        *,
        clock: Callable[[], float] = time.time,
        mounted: bool = True,
        ignore_ttl: bool = False,
        echo_errors: bool = False,
        host: str = LOOPBACK,
        port: int = 0,
    ):
        self.root = root_token
        self._clock = clock
        self.mounts: dict[str, dict[str, Any]] = {}
        if mounted:
            self.mounts["secret"] = {"type": "kv", "options": {"version": "2"}}
        self.kv: dict[tuple[str, str], list[dict[str, str]]] = {}
        self.policies: dict[str, str] = {}
        self.tokens: dict[str, dict[str, Any]] = {}  # token -> entry
        self.ignore_ttl = ignore_ttl
        self.echo_errors = echo_errors
        self.requests: list[tuple[str, str]] = []
        self._n = itertools.count(1)
        self._lock = threading.Lock()
        self._httpd = ThreadingHTTPServer((host, port), self._handler())
        self._thread: threading.Thread | None = None

    # -------------------------------------------------------------- lifecycle
    @property
    def url(self) -> str:
        host, port = self._httpd.server_address[:2]
        return f"http://{host}:{port}"

    def start(self) -> FakeOpenBao:
        self._thread = threading.Thread(
            target=self._httpd.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True
        )
        self._thread.start()
        return self

    def stop(self) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()
        if self._thread:
            self._thread.join(timeout=5)

    def __enter__(self) -> FakeOpenBao:
        return self.start()

    def __exit__(self, *exc: object) -> None:
        self.stop()

    # -------------------------------------------------------------- model
    def _alive(self, entry: dict[str, Any]) -> bool:
        if entry.get("revoked"):
            return False
        return self.ignore_ttl or self._clock() < entry["expires"]

    def _may_read(self, token: str, kv_path: str) -> bool:
        if token == self.root:
            return True
        entry = self.tokens.get(token)
        if entry is None or not self._alive(entry):
            return False
        for name in entry["policies"]:
            rules = self.policies.get(name, "")
            for line in rules.splitlines():
                if line.startswith("path ") and '"read"' in line:
                    glob = line.split('"')[1]
                    if fnmatch.fnmatchcase(kv_path, glob):
                        return True
        return False

    def handle(
        self, method: str, path: str, query: dict[str, str], token: str, body: dict
    ) -> tuple[int, Any]:
        self.requests.append((method, path))
        if not token or (token != self.root and token not in self.tokens):
            return 403, {"errors": ["permission denied"]}
        is_root = token == self.root
        parts = path.split("/")
        if parts[0] in self.mounts and len(parts) >= 2:
            mount, kind, rest = parts[0], parts[1], "/".join(parts[2:])
            if kind == "config":
                return 200, {"data": {"max_versions": 0}}
            if not (
                is_root or (method == "GET" and kind == "data" and self._may_read(token, path))
            ):
                return 403, {"errors": ["permission denied"]}
            return self._kv(method, mount, kind, rest, query, body)
        if not is_root and path not in ("auth/token/lookup-self",):
            return 403, {"errors": ["permission denied"]}
        if parts[:2] == ["sys", "mounts"] and len(parts) == 3:
            if method == "GET":
                m = self.mounts.get(parts[2])
                return (
                    (200, {**m, "data": m}) if m else (400, {"errors": ["No secret engine mount"]})
                )
            self.mounts[parts[2]] = {"type": body.get("type"), "options": body.get("options") or {}}
            return 204, None
        if parts[:3] == ["sys", "policies", "acl"] and len(parts) == 4:
            if method == "DELETE":
                self.policies.pop(parts[3], None)
            else:
                self.policies[parts[3]] = str(body.get("policy", ""))
            return 204, None
        if path == "auth/token/create":
            ttl = float(str(body.get("ttl", "0s")).rstrip("s") or 0)
            n = next(self._n)
            tok, acc = f"fake-child-token-{n}", f"fake-accessor-{n:04d}"
            self.tokens[tok] = {
                "accessor": acc,
                "policies": list(body.get("policies") or []),
                "expires": self._clock() + ttl,
                "meta": dict(body.get("meta") or {}),
            }
            return 200, {
                "auth": {
                    "client_token": tok,
                    "accessor": acc,
                    "lease_duration": int(ttl),
                    "renewable": False,
                }
            }
        if path in ("auth/token/lookup-accessor", "auth/token/revoke-accessor"):
            acc = body.get("accessor") or ""
            if not acc:
                return 400, {"errors": ["missing accessor"]}
            entry = next(
                (e for e in self.tokens.values() if e["accessor"] == acc and not e.get("revoked")),
                None,
            )
            if entry is None:
                return 400, {"errors": ["invalid accessor"]}
            if path.endswith("revoke-accessor"):
                entry["revoked"] = True
                return 204, None
            if not self._alive(entry):
                return 403, {"errors": ["bad token"]}
            left = max(0, int(entry["expires"] - self._clock()))
            return 200, {"data": {"id": "", "accessor": acc, "meta": entry["meta"], "ttl": left}}
        return 404, {"errors": [f"no handler for route {path!r}"]}

    def _kv(
        self, method: str, mount: str, kind: str, rest: str, query: dict[str, str], body: dict
    ) -> tuple[int, Any]:
        key = (mount, rest)
        if kind == "data" and method in ("POST", "PUT"):
            versions = self.kv.setdefault(key, [])
            versions.append(dict(body.get("data") or {}))
            return 200, {"data": {"version": len(versions), "destroyed": False}}
        if kind == "data" and method == "GET":
            versions = self.kv.get(key)
            if not versions:
                return 404, {"errors": []}
            v = int(query.get("version") or 0) or len(versions)
            if not 1 <= v <= len(versions):
                return 404, {"errors": []}
            return 200, {"data": {"data": versions[v - 1], "metadata": {"version": v}}}
        if kind == "metadata" and method == "GET" and query.get("list") == "true":
            folder = rest.rstrip("/") + "/" if rest else ""
            keys = set()
            for m, p in self.kv:
                if m == mount and p.startswith(folder):
                    head, sep, _tail = p[len(folder) :].partition("/")
                    keys.add(head + sep)
            if not keys:
                return 404, {"errors": []}
            return 200, {"data": {"keys": sorted(keys)}}
        if kind == "metadata" and method == "GET":
            versions = self.kv.get(key)
            if not versions:
                return 404, {"errors": []}
            return 200, {"data": {"current_version": len(versions), "versions": {}}}
        if kind == "metadata" and method == "DELETE":
            self.kv.pop(key, None)
            return 204, None
        return 405, {"errors": ["unsupported operation"]}

    # -------------------------------------------------------------- HTTP
    def _handler(self) -> type[BaseHTTPRequestHandler]:
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a: object) -> None:  # quiet
                return

            def _go(self) -> None:
                url = urllib.parse.urlsplit(self.path)
                n = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(n) if n else b""
                try:
                    body = json.loads(raw) if raw else {}
                except ValueError:
                    body = {}
                path = urllib.parse.unquote(url.path)
                if not path.startswith("/v1/"):
                    status, doc = 404, {"errors": []}
                else:
                    query = dict(urllib.parse.parse_qsl(url.query))
                    with fake._lock:
                        status, doc = fake.handle(
                            self.command,
                            path[4:],
                            query,
                            self.headers.get("X-Vault-Token", ""),
                            body,
                        )
                if fake.echo_errors and status >= 400 and isinstance(doc, dict):
                    doc = {**doc, "request": raw.decode("utf-8", "replace")}
                out = b"" if doc is None else json.dumps(doc).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(out)))
                self.end_headers()
                self.wfile.write(out)

            do_GET = do_POST = do_PUT = do_DELETE = _go

        return Handler
