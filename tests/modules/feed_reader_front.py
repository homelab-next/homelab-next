# SPDX-License-Identifier: Apache-2.0
"""A stand-in for the feed reader's HTTP surface (shared by the feed-reader tests): the sign-in page,
the Fever endpoint (the api_key the product derives from a known account is accepted, any other is
not) and the Google Reader sign-in (name and API password in the form)."""

from __future__ import annotations

import json
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

#: account name -> API password: short stand-in words, never key-looking literals
ACCOUNTS = {"reader-one": "pw-one-" + "a" * 12, "reader-two": "pw-two-" + "b" * 12}
#: what the Fever endpoint expects for each of them: the product fixes the lookup value as the md5 of
#: "<name>:<API password>"; written out here so the stand-in does no hashing of its own
FEVER_LOOKUP = {
    "reader-one": "d9baf683a4392a267632ad2ac148d9f9",
    "reader-two": "2130fcb7b343371f849f6394204c9e3b",
}


class Server:
    """``accounts`` the names and API passwords it knows; ``login`` the sign-in page's status;
    ``open_api`` makes a broken deployment that accepts every key; ``greader`` whether the Google
    Reader sign-in is served."""

    def __init__(self, accounts=None, login=200, open_api=False, greader=True):
        outer = self
        self.accounts = dict(ACCOUNTS if accounts is None else accounts)
        self.login, self.open_api, self.greader = login, open_api, greader
        self.paths: list[str] = []
        self.bodies: list[dict] = []
        # an account the stand-in knows is accepted on the Fever endpoint by its lookup value
        keys = lambda: {FEVER_LOOKUP[name] for name in outer.accounts if name in FEVER_LOOKUP}  # noqa: E731

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
                if self.path == "/i/":
                    self._send(outer.login, "<html>sign in</html>", "text/html")
                else:
                    self.send_error(404)

            def do_POST(self):
                outer.paths.append(self.path)
                raw = self.rfile.read(int(self.headers.get("Content-Length", "0"))).decode()
                form = {k: v[0] for k, v in urllib.parse.parse_qs(raw).items()}
                outer.bodies.append(form)
                if self.path == "/api/fever.php?api":
                    ok = outer.open_api or form.get("api_key") in keys()
                    self._send(200, json.dumps({"api_version": 4, "auth": 1 if ok else 0}))
                elif self.path == "/api/greader.php/accounts/ClientLogin" and outer.greader:
                    if outer.accounts.get(form.get("Email")) == form.get("Passwd"):
                        self._send(
                            200, "SID=x\nLSID=null\nAuth=" + form["Email"] + "/t\n", "text/plain"
                        )
                    else:
                        self._send(401, "Error=BadAuthentication\n", "text/plain")
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
