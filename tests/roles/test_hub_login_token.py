# SPDX-License-Identifier: Apache-2.0
"""The status hub's login-token helper (role status_hub, files/hnx-hub-login-token.py): it posts a
user name and password to a verified https endpoint, writes the answer as a token file by rename,
and never follows a redirect, trusts a plain-http url, or leaves a half-written or wrong file."""

from __future__ import annotations

import http.server
import importlib.util
import json
import ssl
import subprocess
import threading
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "ansible/roles/status_hub/files/hnx-hub-login-token.py"
spec = importlib.util.spec_from_file_location("hnx_hub_login_token", SCRIPT)
helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)

# short, obviously fake pieces joined at run time (no key-looking literal in the history)
PW = " ".join(["a@b", "c"])
PW_ENCODED = "a%40b+c"


def _cert(tmp_path: Path) -> tuple[Path, Path]:
    crt, key = tmp_path / "ca.crt", tmp_path / "ca.key"
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-keyout",
         str(key), "-out", str(crt), "-subj", "/CN=localhost", "-addext",
         "subjectAltName=DNS:localhost"],
        check=True, capture_output=True,
    )  # fmt: skip
    return crt, key


class _Server:
    def __init__(self, tmp_path: Path, answer: bytes, status: int = 200):
        crt, key = _cert(tmp_path)
        self.crt, self.seen = crt, []
        outer = self

        class H(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                n = int(self.headers.get("Content-Length", "0"))
                outer.seen.append(self.rfile.read(n).decode())
                if status == 302:
                    self.send_response(302)
                    self.send_header("Location", "https://redirect.example.internal/elsewhere")
                    self.end_headers()
                    return
                self.send_response(status)
                self.end_headers()
                self.wfile.write(answer)

            def log_message(self, *a):
                pass

        self.httpd = http.server.HTTPServer(("localhost", 0), H)
        ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ctx.load_cert_chain(crt, key)
        self.httpd.socket = ctx.wrap_socket(self.httpd.socket, server_side=True)
        self.port = self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def url(self) -> str:
        return f"https://localhost:{self.port}/api/access/token"

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


def _entry(tmp_path, srv, **over):
    pw = tmp_path / "pw"
    pw.write_text(PW + "\n")
    pw.chmod(0o600)
    out = tmp_path / "issued"
    out.mkdir(exist_ok=True)
    return {"name": "flow-reader", "url": srv.url(), "username": "reader",
            "password_file": str(pw), "out": str(out / "flow-reader"), **over}  # fmt: skip


def _config(tmp_path, srv, entries):
    cfg = tmp_path / "cfg.json"
    cfg.write_text(json.dumps({"ca_file": str(srv.crt), "entries": entries}))
    return cfg


def test_a_login_writes_the_token_file_and_prints_no_token(tmp_path, capsys):
    token = ".".join(["eyJhbGciOiJIUzI1NiJ9", "payload", "signature"])
    srv = _Server(tmp_path, token.encode())
    try:
        entry = _entry(tmp_path, srv)
        assert helper.main(["x", "--config", str(_config(tmp_path, srv, [entry]))]) == 0
    finally:
        srv.close()
    out = Path(entry["out"])
    assert out.read_text() == token + "\n" and oct(out.stat().st_mode & 0o777) == "0o640"
    assert srv.seen == [f"username=reader&password={PW_ENCODED}"]  # a form, encoded
    assert token not in capsys.readouterr().out
    assert [p.name for p in out.parent.iterdir()] == ["flow-reader"]  # no temp file left behind


@pytest.mark.parametrize(
    "answer,status",
    [(b"not a token because of spaces", 200), (b"", 200), (b"x" * 20, 401), (b"short", 200)],
)
def test_a_bad_answer_fails_that_entry_and_keeps_the_old_token(tmp_path, answer, status):
    srv = _Server(tmp_path, answer, status)
    try:
        entry = _entry(tmp_path, srv)
        Path(entry["out"]).write_text("previous-token-value\n")
        assert helper.main(["x", "--config", str(_config(tmp_path, srv, [entry]))]) == 1
    finally:
        srv.close()
    assert Path(entry["out"]).read_text() == "previous-token-value\n"


def test_a_redirect_is_never_followed(tmp_path):
    srv = _Server(tmp_path, b"", 302)
    try:
        entry = _entry(tmp_path, srv)
        assert helper.main(["x", "--config", str(_config(tmp_path, srv, [entry]))]) == 1
    finally:
        srv.close()
    assert not Path(entry["out"]).exists()


def test_plain_http_and_a_group_readable_password_file_are_refused(tmp_path):
    srv = _Server(tmp_path, b"a" * 20)
    try:
        plain = _entry(tmp_path, srv, url="http://hub.example.internal/token")
        ctx = ssl.create_default_context(cafile=str(srv.crt))
        with pytest.raises(ValueError, match="https"):
            helper.fetch_token(plain, ctx)
        entry = _entry(tmp_path, srv)
        Path(entry["password_file"]).chmod(0o640)
        with pytest.raises(ValueError, match="readable"):
            helper.fetch_token(entry, ctx)
        assert srv.seen == []  # nothing was sent
    finally:
        srv.close()


def test_a_bad_configuration_is_a_usage_error(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text('{"entries": []}')
    assert helper.main(["x", "--config", str(bad)]) == 2
    assert helper.main(["x"]) == 2
