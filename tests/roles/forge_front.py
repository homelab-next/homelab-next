# SPDX-License-Identifier: Apache-2.0
"""Stand-ins for the forge role tests: a throwaway PKI for the service's name, an HTTPS front that
answers what the role's helper asks (with the behaviours the checks depend on), an SSH banner
listener with fake ``ssh-keyscan`` and ``ssh-keygen``, a fake ``docker``, and builders for the
instance's dump archive (a real zip holding a real SQL dump)."""

from __future__ import annotations

import base64
import contextlib
import json
import os
import socket
import sqlite3
import ssl
import subprocess
import threading
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import yaml
from rolerun import fake

LOOPBACK = socket.gethostbyname("localhost")

NAME = "git.example.internal"


def _module_id() -> str:
    """The id of the module that fills the forge slot (the tests name the slot, not the product)."""
    ROOT = Path(__file__).resolve().parents[2]
    for d in sorted((ROOT / "modules").iterdir()):
        m = d / "module.yml"
        if m.is_file() and "forge" in (
            yaml.safe_load(m.read_text()).get("provides", {}).get("slots") or {}
        ):
            return d.name
    raise AssertionError("no module fills the forge slot")


MID = _module_id()


def free_port() -> int:
    """A port nothing listens on."""
    s = socket.socket()
    s.bind((LOOPBACK, 0))
    port = s.getsockname()[1]
    s.close()
    return port


def pem(kind: str, body: str = "x" * 20) -> str:
    """A PEM block assembled at run time from short pieces: no complete block (and nothing a secret
    scanner reads as a key) is ever in the source."""
    label = " ".join(kind.split("|"))
    return "-----BEGIN " + label + "-----\n" + body + "\n-----END " + label + "-----"


def make_pki(directory: Path, name: str = NAME) -> tuple[str, str, str]:
    """(chain, key, ca) as text: a CA and a server certificate for ``name`` (NAME by default),
    signed by it."""
    d = directory
    run = lambda *a: subprocess.run(a, check=True, capture_output=True, cwd=d)  # noqa: E731
    run("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2", "-subj", "/CN=lab-ca",
        "-keyout", "ca.key", "-out", "ca.pem", "-addext", "basicConstraints=critical,CA:TRUE",
        "-addext", "keyUsage=critical,keyCertSign")  # fmt: skip
    run(
        "openssl",
        "req",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-subj",
        f"/CN={name}",
        "-keyout",
        "srv.key",
        "-out",
        "srv.csr",
    )
    (d / "ext").write_text(
        f"subjectAltName=DNS:{name}\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n"
    )
    run("openssl", "x509", "-req", "-in", "srv.csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial",
        "-out", "srv.pem", "-days", "2", "-extfile", "ext")  # fmt: skip
    return (d / "srv.pem").read_text(), (d / "srv.key").read_text(), (d / "ca.pem").read_text()


class Front:
    """The service's HTTPS surface.  ``anonymous_ok`` leaves reading open (a defect the health
    check must catch), ``registry`` is the challenge header ("" for none), ``version`` what it reports."""

    def __init__(self, chain: str, key: str, workdir: Path, *, admin="admin", password="p" * 20,
                 version="28.4.0", anonymous_ok=False, registry='Bearer realm="x"', pull=None,
                 pull_writable=False):  # fmt: skip
        outer = self
        self.admin, self.password, self.version = admin, password, version
        self.anonymous_ok, self.registry, self.pull = anonymous_ok, registry, pull
        self.pull_writable = pull_writable  # a wrongly scoped pull token: writes are accepted
        self.repos, self.requests = 2, []

        def authed(handler) -> bool:
            h = handler.headers.get("Authorization", "")
            if not h.startswith("Basic "):
                return False
            return base64.b64decode(h[6:]).decode() == f"{outer.admin}:{outer.password}"

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _send(self, code, doc=None, headers=()):
                body = json.dumps(doc).encode() if doc is not None else b""
                self.send_response(code)
                for k, v in headers:
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_POST(self):
                outer.requests.append(f"POST {self.path}")
                self.rfile.read(int(self.headers.get("Content-Length") or 0))
                h = self.headers.get("Authorization", "")
                if (
                    outer.pull
                    and h.startswith("Basic ")
                    and base64.b64decode(h[6:]).decode() == outer.pull
                ):
                    return self._send(202 if outer.pull_writable else 403, {})
                return self._send(401, {})

            def do_GET(self):
                outer.requests.append(self.path)
                p = self.path.split("?")[0]
                if p == "/api/healthz":
                    return self._send(200, {"status": "pass"})
                if p == "/v2/":
                    h = self.headers.get("Authorization", "")
                    if outer.pull and h.startswith("Basic "):
                        ok = base64.b64decode(h[6:]).decode() == outer.pull
                        return self._send(200 if ok else 401, {})
                    return self._send(
                        401, {}, [("WWW-Authenticate", outer.registry)] if outer.registry else []
                    )
                h = self.headers.get("Authorization", "")
                if (
                    outer.pull
                    and h.startswith("Basic ")
                    and base64.b64decode(h[6:]).decode() == outer.pull
                ):
                    # the pull token reads the registry only: the API is out of its scope
                    return self._send(200 if outer.pull_writable else 403, {"login": "puller"})
                if not (authed(self) or outer.anonymous_ok):
                    return self._send(401, {"message": "user does not exist"})
                if p == "/api/v1/version":
                    return self._send(200, {"version": outer.version})
                if p == "/api/v1/user":
                    return self._send(200, {"login": outer.admin, "is_admin": True})
                if p == "/api/v1/repos/search":
                    return self._send(200, {"data": []}, [("X-Total-Count", str(outer.repos))])
                return self._send(404, {})

        self.httpd = ThreadingHTTPServer((LOOPBACK, 0), H)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        (workdir / "chain.pem").write_text(chain)
        (workdir / "front.key").write_text(key)
        ctx.load_cert_chain(str(workdir / "chain.pem"), str(workdir / "front.key"))
        self.httpd.socket = ctx.wrap_socket(self.httpd.socket, server_side=True)
        self.port = self.httpd.server_address[1]

    def __enter__(self):
        threading.Thread(
            target=self.httpd.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True
        ).start()
        return self

    def __exit__(self, *a):
        self.httpd.shutdown()
        self.httpd.server_close()


class Banner:
    """A TCP listener that answers with an SSH banner (the SSH server's liveness)."""

    def __init__(self):
        self.sock = socket.socket()
        self.sock.bind((LOOPBACK, 0))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        while True:
            try:
                c, _ = self.sock.accept()
            except OSError:
                return
            c.sendall(b"SSH-2.0-stand-in\r\n")
            c.close()

    def close(self):
        with contextlib.suppress(OSError):  # wake the thread blocked in accept()
            self.sock.shutdown(socket.SHUT_RDWR)
        self.sock.close()


def ssh_tools(bindir: Path, presented: str = "AAAAkey1", held: str = "AAAAkey1") -> dict:
    """Fake ``ssh-keyscan`` (presents ``presented``) and ``ssh-keygen -y`` (derives ``held``)."""
    bindir.mkdir(exist_ok=True)
    fake(bindir / "ssh-keyscan", f'import sys\nprint("host ssh-fake {presented}")\n')
    fake(bindir / "ssh-keygen", f'import sys\nsys.stdin.read()\nprint("ssh-fake {held} comment")\n')
    return {}


#: rows that hold data encrypted with the application's SECRET_KEY, one statement per table the
#: role's helper reads for them (``dump_sql(encrypted=[...])`` inserts the named ones); short
#: placeholder values, never a real ciphertext
ENCRYPTED_ROWS = {
    "two_factor": "INSERT INTO two_factor VALUES (1, 1, 'c1')",
    "secret": "INSERT INTO secret VALUES (1, 1, 0, 'NAME', 'c2')",
    "webhook": "INSERT INTO webhook VALUES (1, 1, 'https://hook.example.internal/', 'c3')",
    "login_source": """INSERT INTO login_source VALUES (1, 2, 'dir', '{"BindPasswordEncrypt": "c4"}')""",
    "task": """INSERT INTO task VALUES (1, 1, '{"auth_token_encrypted": "c5"}')""",
}


def dump_sql(
    *,
    users=2,
    orgs=1,
    repos=(("labs", "alpha"), ("labs", "beta")),
    admin_hash="h1",
    encrypted=(),
    key_tables=True,
) -> str:
    """The SQL of a database with the tables the role reads, as the product's dump writes it;
    ``encrypted`` names tables of ENCRYPTED_ROWS that get a row, ``key_tables=False`` leaves those
    tables out (a schema the helper does not know). Rows the key does not encrypt are always there:
    a webhook without an authorization header, an OAuth2 source, a finished task without credentials."""
    c = sqlite3.connect(":memory:")
    c.executescript(
        'CREATE TABLE "user" (id INTEGER PRIMARY KEY, lower_name TEXT, type INTEGER, is_admin INTEGER, passwd TEXT, email TEXT);'
        "CREATE TABLE repository (id INTEGER PRIMARY KEY, owner_id INTEGER, lower_name TEXT, is_private INTEGER, default_branch TEXT);"
        "CREATE TABLE issue (id INTEGER PRIMARY KEY);"
        "CREATE TABLE public_key (id INTEGER PRIMARY KEY, owner_id INTEGER, fingerprint TEXT);"
        "CREATE TABLE access_token (id INTEGER PRIMARY KEY, uid INTEGER, token_hash TEXT);"
        "CREATE TABLE package (id INTEGER PRIMARY KEY);"
    )
    if key_tables:
        c.executescript(
            "CREATE TABLE two_factor (id INTEGER PRIMARY KEY, uid INTEGER, secret TEXT);"
            "CREATE TABLE secret (id INTEGER PRIMARY KEY, owner_id INTEGER, repo_id INTEGER, name TEXT, data TEXT);"
            "CREATE TABLE webhook (id INTEGER PRIMARY KEY, repo_id INTEGER, url TEXT, header_authorization_encrypted TEXT);"
            "CREATE TABLE login_source (id INTEGER PRIMARY KEY, type INTEGER, name TEXT, cfg TEXT);"
            "CREATE TABLE task (id INTEGER PRIMARY KEY, type INTEGER, payload_content TEXT);"
            "INSERT INTO webhook VALUES (10, 1, 'https://plain.example.internal/', '');"
            """INSERT INTO login_source VALUES (10, 6, 'sso', '{"Provider": "openidConnect"}');"""
            """INSERT INTO task VALUES (10, 0, '{"clone_addr": "https://src.example.internal/r.git"}');"""
        )
        for table in encrypted:
            c.execute(ENCRYPTED_ROWS[table])
    for i in range(users):
        c.execute(
            'INSERT INTO "user" VALUES (?,?,?,?,?,?)',
            (i + 1, f"user{i}", 0, int(i == 0), admin_hash if i == 0 else "h", f"u{i}@x"),
        )
    for j in range(orgs):
        c.execute('INSERT INTO "user" VALUES (?,?,?,?,?,?)', (100 + j, f"org{j}", 1, 0, "", ""))
    for k, (_o, n) in enumerate(repos):
        c.execute("INSERT INTO repository VALUES (?,?,?,?,?)", (k + 1, 1, n, 1, "main"))
    return "\n".join(c.iterdump()) + "\n"


def make_dump(
    path: Path, *, repos=(("labs", "alpha"), ("labs", "beta")), extra=(), sql_extra="", **sql_kw
) -> Path:
    """A dump archive: the SQL, the repositories' files, data directories the restore takes and
    members it must not (host keys, configuration)."""
    with zipfile.ZipFile(path, "w") as z:
        z.writestr(f"{MID}-db.sql", dump_sql(repos=repos, **sql_kw) + sql_extra)
        z.writestr("app.ini", "[server]\nSSH_PORT = 22\n")
        for o, n in repos:
            base = f"repos/{o}/{n}.git"
            z.writestr(f"{base}/HEAD", "ref: refs/heads/main\n")
            z.writestr(f"{base}/refs/heads/main", "0" * 40 + "\n")
        z.writestr("data/avatars/a.png", "png")
        z.writestr("data/jwt/private.pem", "signing")
        z.writestr(f"data/ssh/{MID}.rsa", "NOT-TO-BE-TAKEN")
        z.writestr("data/log/x.log", "log")
        for name, content in extra:
            z.writestr(name, content)
    return path


def tsv(repos=(("labs", "alpha"), ("labs", "beta")), fsck="ok") -> str:
    return "".join(f"{o}/{n}.git\t1\t{(n * 64)[:64]}\t{fsck}\n" for o, n in repos)


def docker(
    tmp: Path,
    *,
    dump: Path | None = None,
    repos_out: str = "",
    users: str = "ID\tUsername\n",
    auth: str = "ID\tName\tType\tEnabled\n",
    health: str = "healthy",
    running: bool = True,
) -> dict:
    """A fake ``docker``.  Every call is appended to ``docker.log`` (one line, argv joined); what a
    call needs from the environment is read from files under ``tmp`` so a test can change it:
    ``users.txt`` / ``auth.txt`` (what the product's listings print), ``repos.out`` (the repositories'
    manifest), ``dump.zip`` (what ``dump`` writes), and the markers ``dump.fails`` and ``run.fails``.  ``running=False``: ``ps`` lists nothing (a fresh guest)."""
    bindir = tmp / "bin"
    bindir.mkdir(exist_ok=True)
    (tmp / "users.txt").write_text(users)
    (tmp / "auth.txt").write_text(auth)
    (tmp / "repos.out").write_text(repos_out)
    if dump is not None:
        (tmp / "dump.zip").write_bytes(dump.read_bytes())
    body = f"""
import json, os, sys
a = sys.argv[1:]
T = {str(tmp)!r}
open(T + "/docker.log", "a").write(" ".join(a) + "\\n")
def env_seen(n):
    open(T + "/env.log", "a").write(n + "=" + ("set" if os.environ.get(n) else "unset") + "\\n")
if "ps" in a and not {running!r}:
    pass  # a guest with no container yet: nothing is listed
elif "ps" in a:
    sys.stdout.write(json.dumps({{"Service": {MID!r}, "State": "running", "Health": {health!r}}}) + "\\n")
elif "exec" in a and a[-3:] == ["admin", "user", "list"]:
    sys.stdout.write(open(T + "/users.txt").read())
elif "exec" in a and a[-3:] == ["admin", "auth", "list"]:
    sys.stdout.write(open(T + "/auth.txt").read())
elif "exec" in a and "sh" in a and "-c" in a:
    script = a[a.index("-c") + 1]
    if "user create" in script:
        env_seen("HNX_FORGE_PASSWORD")
        open(T + "/users.txt", "a").write("1\\tadmin\\n")
    elif "user change-password" in script:
        env_seen("HNX_FORGE_PASSWORD")
    elif "auth" in script:
        env_seen("HNX_FORGE_OIDC_SECRET")
elif "run" in a and "dump" in a:
    if os.path.exists(T + "/dump.fails"):
        sys.exit(1)
    dest = a[a.index("--file") + 1]
    host = os.path.join(T, "data", "export", os.path.basename(dest))
    open(host, "wb").write(open(T + "/dump.zip", "rb").read())
elif "run" in a and "-c" in a:
    if os.path.exists(T + "/run.fails"):
        sys.exit(1)
    sys.stdout.write(open(T + "/repos.out").read())
"""
    fake(bindir / "docker", body)
    return {"PATH": f"{bindir}:{os.environ['PATH']}"}


def calls(tmp: Path) -> list[str]:
    log = tmp / "docker.log"
    return log.read_text().splitlines() if log.exists() else []
