#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# hnx-script:
#   id: forge-helper
#   kind: tool
#   purpose: Read-only checks of the forge service (wait, health, signin) and the counts and content fingerprint of its database, read from a dump or a database file.
#   owner: platform
#   trigger: [role:gitea]
#   inputs: "wait | health | signin | dbcounts, with the settings as JSON on standard input (the credential is among them)"
#   outputs: JSON of facts on stdout; a one-line reason on stderr
#   exit:
#     "0": done
#     "1": a check failed or the input is not usable (the reason on stderr, never a credential)
#     "2": usage error
"""The forge role's helper (run on the guest as ``python3 -I hnx_gitea.py <command>`` with its
settings as JSON on standard input, never a command line: the credential is among them).

* ``wait``   -- poll ``/api/healthz`` over HTTPS until it passes or ``wait_s`` runs out.
* ``health`` -- read-only checks of a running service (see :func:`health`); prints JSON facts.
* ``signin`` -- whether the administrator's password signs in (``{"signin": bool}``).
* ``dbcounts`` -- row counts and a content fingerprint of the instance's database, read from a
  dump's ``gitea-db.sql`` (``{"zip": path}``) or from a database file (``{"db": path}``, opened
  read-only and immutable); an unrecognised schema or an empty ``user`` table is an error.

The service is reached on its bind address with the certificate verified against the lab CA and
checked for the *name* (``hostname``), as a client of the name would.  Nothing is written.
"""

from __future__ import annotations

import base64
import hashlib
import http.client
import json
import socket
import sqlite3
import ssl
import subprocess
import sys
import time
import zipfile
from pathlib import Path

#: table -> the column that tells what is counted; the first six are the instance's contract
COUNT_SQL = {
    "users": 'SELECT count(*) FROM "user" WHERE type = 0',
    "orgs": 'SELECT count(*) FROM "user" WHERE type = 1',
    "repos": "SELECT count(*) FROM repository",
    "issues": "SELECT count(*) FROM issue",
    "public_keys": "SELECT count(*) FROM public_key",
    "access_tokens": "SELECT count(*) FROM access_token",
    "packages": "SELECT count(*) FROM package",
}
#: per table, the columns whose values are hashed row by row in id order: an edit that moves no
#: count (a changed password hash, a renamed repository, a swapped key) still moves the fingerprint
FINGERPRINT = {
    "user": ("id", "lower_name", "type", "is_admin", "passwd", "email"),
    "repository": ("id", "owner_id", "lower_name", "is_private", "default_branch"),
    "public_key": ("id", "owner_id", "fingerprint"),
    "access_token": ("id", "uid", "token_hash"),
}
MAX_SQL = 1 << 30


class HelperError(RuntimeError):
    pass


def db_facts(conn: sqlite3.Connection) -> dict:
    """Counts and fingerprints of an open database; refuses a schema it does not know."""
    have = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
    need = {"user", "repository", "issue", "public_key", "access_token", "package"}
    if not need <= have:
        raise HelperError(f"not an instance database: no table {', '.join(sorted(need - have))}")
    counts = {k: int(conn.execute(sql).fetchone()[0]) for k, sql in COUNT_SQL.items()}
    fingerprint = {}
    for table, cols in FINGERPRINT.items():
        got = {r[1] for r in conn.execute(f'PRAGMA table_info("{table}")')}
        if not set(cols) <= got:
            raise HelperError(f"table {table} lacks columns {sorted(set(cols) - got)}")
        h = hashlib.sha256()
        for row in conn.execute(f'SELECT {", ".join(cols)} FROM "{table}" ORDER BY id'):
            h.update(json.dumps(row, separators=(",", ":"), default=str).encode() + b"\n")
        fingerprint[table] = h.hexdigest()
    if counts["users"] == 0:
        raise HelperError("the database has no account: refusing to report it as an instance")
    return {"counts": counts, "fingerprint": fingerprint}


def dbcounts(cfg: dict) -> dict:
    if "zip" in cfg:
        with zipfile.ZipFile(cfg["zip"]) as z:
            try:
                info = z.getinfo("gitea-db.sql")
            except KeyError:
                raise HelperError(
                    "the dump has no gitea-db.sql (a dump of another database type?)"
                ) from None
            if info.file_size > MAX_SQL:
                raise HelperError("gitea-db.sql is too large to load")
            sql = z.read(info).decode("utf-8")
        conn = sqlite3.connect(":memory:")
        try:
            conn.executescript(sql)
            return db_facts(conn)
        finally:
            conn.close()
    path = Path(cfg["db"])
    conn = sqlite3.connect(f"file:{path}?mode=ro&immutable=1", uri=True)
    try:
        return db_facts(conn)
    finally:
        conn.close()


class _Conn(http.client.HTTPSConnection):
    """Connect to the bind address, verify the certificate for the service's name."""

    def __init__(self, bind, port, name, context, timeout):
        super().__init__(name, port, context=context, timeout=timeout)
        self._bind = bind

    def connect(self):
        sock = socket.create_connection((self._bind, self.port), self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


def _basic(user: str, password: str) -> dict:
    blob = base64.b64encode(f"{user}:{password}".encode()).decode()
    return {"Authorization": f"Basic {blob}"}


def _get(cfg: dict, path: str, headers: dict | None = None) -> tuple[int, dict, bytes]:
    ctx = ssl.create_default_context(cafile=cfg["ca_file"])
    conn = _Conn(cfg["bind"], int(cfg["port"]), cfg["hostname"], ctx, float(cfg.get("timeout", 15)))
    try:
        conn.request("GET", path, headers={"Accept": "application/json", **(headers or {})})
        resp = conn.getresponse()
        body = resp.read(1 << 20)
        merged: dict[str, str] = {}
        for (
            k,
            v,
        ) in resp.getheaders():  # a repeated header (two challenges) is joined, not overwritten
            merged[k.lower()] = f"{merged[k.lower()]}, {v}" if k.lower() in merged else v
        return resp.status, merged, body
    finally:
        conn.close()


def wait(cfg: dict) -> dict:
    deadline = time.monotonic() + float(cfg.get("wait_s", 300))
    last = "no answer"
    while True:
        try:
            status, _, body = _get(cfg, "/api/healthz")
            if status == 200 and json.loads(body).get("status") == "pass":
                return {"healthz": "pass"}
            last = f"HTTP {status}"
        except (OSError, ssl.SSLError, ValueError, http.client.HTTPException) as exc:
            last = type(exc).__name__
        if time.monotonic() >= deadline:
            raise HelperError(f"/api/healthz did not pass in time ({last})")
        time.sleep(3)


def _host_key_fingerprints(cfg: dict) -> dict:
    """For each configured key type: the public key the server presents and the one its private
    key file yields must be the same."""
    facts = {}
    for kind, path in sorted(cfg.get("ssh_keys", {}).items()):
        scan = subprocess.run(
            ["ssh-keyscan", "-T", "10", "-p", str(cfg["ssh_port"]), "-t", kind, cfg["bind"]],
            capture_output=True, text=True, check=False,
        )  # fmt: skip
        presented = [
            ln.split()[1:3] for ln in scan.stdout.splitlines() if ln and not ln.startswith("#")
        ]
        # the private key goes in on standard input: ssh-keygen refuses a key file others can read
        # (the container's group must), and the key is never copied anywhere
        own = subprocess.run(
            ["ssh-keygen", "-y", "-f", "/dev/stdin"], input=Path(path).read_text(),
            capture_output=True, text=True, check=False,
        )  # fmt: skip
        if own.returncode != 0 or not own.stdout.split():
            raise HelperError(f"the {kind} host key file cannot be read")
        want = own.stdout.split()[:2]
        if not presented:
            raise HelperError(f"the SSH server presented no {kind} host key")
        if presented[0] != want:
            raise HelperError(f"the SSH server's {kind} host key is not the one the secret holds")
        facts[kind] = "match"
    return facts


def health(cfg: dict) -> dict:
    facts: dict = {}
    status, _, body = _get(cfg, "/api/healthz")
    if status != 200 or json.loads(body).get("status") != "pass":
        raise HelperError(f"/api/healthz: HTTP {status}")
    facts["healthz"] = "pass"
    anon, _, _ = _get(cfg, "/api/v1/version")
    if anon not in (401, 403):
        raise HelperError(
            f"an anonymous /api/v1/version was answered HTTP {anon}: reading is not closed"
        )
    facts["anonymous_read"] = "refused"
    auth = _basic(cfg["admin_user"], cfg["admin_password"])
    status, _, body = _get(cfg, "/api/v1/version", auth)
    if status in (401, 403):
        raise HelperError(
            f"the administrator {cfg['admin_user']!r} cannot sign in with the secret's password "
            "(set gitea_admin_password_sync, or: gitea admin user change-password)"
        )
    version = json.loads(body).get("version", "") if status == 200 else ""
    if not version.startswith(cfg["expect_version"]):
        raise HelperError(
            f"version {version or 'unreadable'} is not the expected {cfg['expect_version']}"
        )
    facts["version"] = version
    status, _, body = _get(cfg, "/api/v1/user", auth)
    me = json.loads(body) if status == 200 else {}
    if not me.get("is_admin"):
        raise HelperError(f"{cfg['admin_user']!r} is not a site administrator")
    status, hdr, _ = _get(cfg, "/api/v1/repos/search?limit=1", auth)
    if status != 200 or "x-total-count" not in hdr:
        raise HelperError(f"repository search: HTTP {status}")
    facts["repos"] = int(hdr["x-total-count"])
    status, hdr, _ = _get(cfg, "/v2/")
    if status != 401 or "bearer" not in hdr.get("www-authenticate", "").lower():
        raise HelperError(
            f"the container registry did not answer its authentication challenge (HTTP {status})"
        )
    facts["registry"] = "challenge"
    if cfg.get("pull_user"):
        status, _, _ = _get(cfg, "/v2/", _basic(cfg["pull_user"], cfg["pull_token"]))
        if status != 200:
            raise HelperError(
                f"the registry pull account {cfg['pull_user']!r} was refused (HTTP {status})"
            )
        facts["registry_pull"] = "accepted"
    try:
        banner = socket.create_connection((cfg["bind"], int(cfg["ssh_port"])), 10)
    except OSError as exc:
        raise HelperError(f"the SSH port did not answer ({type(exc).__name__})") from None
    try:
        first = banner.recv(64)
    finally:
        banner.close()
    if not first.startswith(b"SSH-2.0-"):
        raise HelperError("the SSH port did not answer with an SSH banner")
    facts["ssh"] = "banner"
    facts["ssh_host_keys"] = _host_key_fingerprints(cfg)
    return facts


def signin(cfg: dict) -> dict:
    """Whether the administrator's password signs in (a refusal is an answer, not an error)."""
    status, _, _ = _get(cfg, "/api/v1/user", _basic(cfg["admin_user"], cfg["admin_password"]))
    return {"signin": status == 200}


COMMANDS = {"wait": wait, "health": health, "dbcounts": dbcounts, "signin": signin}


def main(argv: list[str]) -> int:
    if len(argv) != 2 or argv[1] not in COMMANDS:
        print(
            "usage: hnx_gitea.py wait|health|signin|dbcounts (settings as JSON on stdin)",
            file=sys.stderr,
        )
        return 2
    try:
        cfg = json.load(sys.stdin)
        print(json.dumps(COMMANDS[argv[1]](cfg), sort_keys=True))
    except (HelperError, KeyError, OSError, ssl.SSLError, ValueError, sqlite3.Error,
            zipfile.BadZipFile, http.client.HTTPException) as exc:  # fmt: skip
        # a one-line reason that holds no credential (the settings are never echoed)
        print(f"{type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
