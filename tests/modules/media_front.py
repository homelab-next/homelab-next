# SPDX-License-Identifier: Apache-2.0
"""A stand-in for the media server's anonymous endpoints and its library list (shared by the media
tests)."""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SERVER_ID = "0123456789abcdef0123456789abcdef"


class Server:
    """A stand-in for the media server: ``/health``, ``/System/Info/Public`` (``started``: the
    first-run setup complete), ``/QuickConnect/Enabled`` and, for the ``token`` only,
    ``/Library/VirtualFolders`` listing ``folders`` libraries."""

    def __init__(
        self,
        health="Healthy",
        server_id=SERVER_ID,
        quick_connect="true",
        started=True,
        folders=2,
        token=None,
    ):
        outer = self
        self.paths = []
        self.auth = []
        self.health, self.server_id, self.quick_connect = health, server_id, quick_connect
        self.started, self.folders, self.token = started, folders, token

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                outer.paths.append(self.path)
                if self.path == "/health":
                    body, ctype = outer.health, "text/plain"
                elif self.path == "/System/Info/Public":
                    info = {"Id": outer.server_id, "ProductName": "Media Server"}
                    if outer.started is not None:
                        info["StartupWizardCompleted"] = outer.started
                    body, ctype = json.dumps(info), "application/json"
                elif self.path == "/Library/VirtualFolders":
                    got = self.headers.get("Authorization", "")
                    outer.auth.append(got)
                    if outer.token is None or got != f'MediaBrowser Token="{outer.token}"':
                        self.send_error(401)
                        return
                    folders = [{"Name": f"lib{n}", "Locations": []} for n in range(outer.folders)]
                    body, ctype = json.dumps(folders), "application/json"
                elif self.path == "/QuickConnect/Enabled":
                    body, ctype = outer.quick_connect, "application/json"
                else:
                    self.send_error(404)
                    return
                data = body.encode()
                self.send_response(200)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        self._httpd = ThreadingHTTPServer(("localhost", 0), H)

    def __enter__(self):
        threading.Thread(target=self._httpd.serve_forever, daemon=True).start()
        return self

    def __exit__(self, *a):
        self._httpd.shutdown()
        self._httpd.server_close()

    @property
    def addr(self):
        return self._httpd.server_address[:2]
