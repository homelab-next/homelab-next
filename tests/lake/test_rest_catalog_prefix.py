# SPDX-License-Identifier: Apache-2.0
"""A catalog that names no warehouse prefix in its config (the Apache REST catalog serves
``/v1/namespaces`` directly) is an error for the client unless the caller says that is its shape:
the strict default is what catches a catalog configured without its warehouse."""

from __future__ import annotations

import http.server
import json
import threading

import pytest

from homelabnext.lake.errors import LakeError
from homelabnext.lake.rest_catalog import RestCatalog


class _Catalog(http.server.ThreadingHTTPServer):
    def __init__(self, config: dict):
        super().__init__(("localhost", 0), _Handler)
        self.config, self.paths = config, []


class _Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        self.server.paths.append(self.path)
        doc = (
            self.server.config
            if self.path.startswith("/v1/config")
            else {"namespaces": [["a"], ["b"]]}
        )
        raw = json.dumps(doc).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


@pytest.fixture
def serve():
    servers = []

    def start(config):
        s = _Catalog(config)
        threading.Thread(target=s.serve_forever, daemon=True).start()
        servers.append(s)
        return s

    yield start
    for s in servers:
        s.shutdown()


def _url(s) -> str:
    return f"http://localhost:{s.server_port}"


def test_a_catalog_without_a_prefix_is_refused_by_default(serve):
    s = serve({"defaults": {}, "overrides": {}})
    with pytest.raises(LakeError, match="no prefix"):
        RestCatalog(_url(s), warehouse="s3://w/", api_root="").list_namespaces()


def test_a_catalog_without_a_prefix_is_used_at_v1_when_the_caller_says_so(serve):
    s = serve({"defaults": {}, "overrides": {"namespace-separator": "%2E"}})
    cat = RestCatalog(_url(s), warehouse="s3://w/", api_root="", prefix_optional=True)
    assert cat.list_namespaces() == [["a"], ["b"]]
    assert s.paths == ["/v1/config?warehouse=s3%3A%2F%2Fw%2F", "/v1/namespaces"]


def test_a_catalog_with_a_prefix_is_unchanged_whatever_the_flag(serve):
    s = serve({"defaults": {"prefix": "wh-1"}})
    for flag in (False, True):
        s.paths.clear()
        assert RestCatalog(
            _url(s), warehouse="w", api_root="", prefix_optional=flag
        ).list_namespaces()
        assert s.paths[-1] == "/v1/wh-1/namespaces"
