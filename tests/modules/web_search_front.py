# SPDX-License-Identifier: Apache-2.0
"""A stand-in for the web-search service's HTTP surface (shared by the web-search tests): the health
path, and the JSON search (``/search?q=...&format=json``) that answers a list of results, none, a
refusal of the JSON format, or a body that is not a result list at all."""

from __future__ import annotations

import json
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Server:
    """``results`` how many results a search returns; ``healthz`` the health path's status;
    ``json_status`` the status of the JSON search (403: the format is not enabled); ``body`` replaces
    the JSON document the search answers with (a string is sent as it is)."""

    def __init__(self, results=3, healthz=200, json_status=200, body=None):
        outer = self
        self.results, self.healthz, self.json_status, self.body = (
            results,
            healthz,
            json_status,
            body,
        )
        self.paths: list[str] = []

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _send(self, status, body="", ctype="application/json"):
                data = body.encode()
                self.send_response(status)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                outer.paths.append(self.path)
                url = urllib.parse.urlsplit(self.path)
                query = urllib.parse.parse_qs(url.query)
                if url.path == "/healthz":
                    self._send(outer.healthz, "OK", "text/plain")
                elif url.path == "/search" and query.get("format") == ["json"] and query.get("q"):
                    if outer.json_status != 200:
                        self._send(outer.json_status, "forbidden", "text/plain")
                        return
                    doc = outer.body
                    if doc is None:
                        doc = {
                            "query": query["q"][0],
                            "results": [
                                {"url": f"https://r{i}.example.internal/", "title": f"r{i}"}
                                for i in range(outer.results)
                            ],
                        }
                    self._send(200, doc if isinstance(doc, str) else json.dumps(doc))
                else:
                    self.send_error(404)

        self._httpd = ThreadingHTTPServer(("localhost", 0), H)

    def __enter__(self):
        threading.Thread(
            target=self._httpd.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True
        ).start()
        return self

    def __exit__(self, *a):
        self._httpd.shutdown()
        self._httpd.server_close()

    @property
    def addr(self):
        return self._httpd.server_address[:2]
