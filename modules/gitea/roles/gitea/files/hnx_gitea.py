#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# hnx-script:
#   id: forge-helper
#   kind: tool
#   purpose: Read-only checks of the forge service (wait, health, signin) and the counts and content fingerprint of its database, read from a dump or a database file.
#   owner: platform
#   trigger: [role:gitea]
#   inputs: "wait | health | signin | dbcounts | strip | secretfp | appkey, with the settings as JSON on standard input (the credential is among them)"
#   outputs: JSON of facts on stdout; a one-line reason on stderr
#   exit:
#     "0": done
#     "1": a check failed or the input is not usable (the reason on stderr, never a credential)
#     "2": usage error
"""The forge role's helper (run on the guest as ``python3 -I hnx_gitea.py <command>`` with its
settings as JSON on standard input, never a command line: the credential is among them).

* ``wait``   -- poll ``/api/healthz`` over HTTPS until it passes or ``wait_s`` runs out.
* ``health`` -- read-only checks of a running service (see :func:`health`); prints JSON facts.
* ``strip`` -- copy a dump (``{"zip": path, "to": new path}``) without its ``app.ini``.
* ``secretfp`` -- HMAC fingerprints of the three application secrets (``{"values": {...}}``);
  with ``"expect"`` a refusal when they are not the export's.
* ``appkey`` -- before a restore: whether the configured application secrets fit the export
  (``{"values", "origin", "manifest", "zip"}``, see :func:`check_app_key`): the source's own
  SECRET_KEY copied, or, only for a source that ran on the built-in default with nothing encrypted
  under it (proved by the dump and proved again on the archive), a fresh generated one.
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
import hmac
import http.client
import json
import os
import shutil
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
#: the three application secrets whose value must be the source's after a migration (the keys the
#: accounts' two-factor seeds and stored credentials are encrypted and signed with)
SECRET_NAMES = ("secret_key", "internal_token", "jwt_secret")
_FP_MESSAGE = b"hnx-forge-secret-fingerprint-v1"
#: the member of a dump that holds the configuration (and with it the application secrets)
CONFIG_MEMBER = "app.ini"

# ----- a source whose SECRET_KEY was never set
# Gitea falls back to a fixed key published in its own source when [security] SECRET_KEY is empty
# (modules/setting/security.go, kept "until it supports rotating an existing secret key", issue
# 16832). That value cannot be copied (the role's rule refuses it, and a key every reader of the
# source knows is not one to carry on), and a new key cannot read what the old one encrypted. So a
# fresh key is allowed only when nothing in the database is encrypted under the old one, which the
# dump proves and records, and the restore proves again on the archive it restores.
#: the built-in fallback, assembled from pieces (it is public, but never a long literal here)
BUILTIN_APP_KEY = "".join(("!#@", "FDEWREWR", "&*("))
#: where the export's SECRET_KEY came from: the source's configuration, or the built-in fallback
KEY_CONFIGURED, KEY_BUILTIN = "configured", "builtin-default"
#: how the target's SECRET_KEY is chosen (the role's gitea_app_key_origin): the source's, or a fresh one
KEY_ORIGINS = ("source", "generated")
#: the release whose source the list below was read from (a proof made under another list is
#: refused); a test ties it to the pinned image's version, so an image bump fails until the list is
#: audited again against the new release's source
APP_KEY_USES_RULES = "28.4.0"
#: every place that release keeps data encrypted with SECRET_KEY (every caller of
#: secret.EncryptSecret/AesEncrypt with setting.SecretKey), table -> columns read:
#:   two_factor.secret          a TOTP seed, AES under md5(SECRET_KEY)   models/auth/twofactor.go
#:   secret.data                an Actions secret                         models/secret/secret.go
#:   webhook.header_authorization_encrypted   a webhook's Authorization   models/webhook/webhook.go
#:   login_source.cfg           an LDAP source's BindPasswordEncrypt      services/auth/source/ldap
#:   task.payload_content       a migration task's *_encrypted fields     services/task/task.go
#: Not encrypted with it (so not listed): access tokens and OAuth2 application secrets (hashed),
#: WebAuthn credentials (public keys), mirror and push-mirror credentials (in the repository's git
#: configuration, not the database).
APP_KEY_USES = {
    "two_factor": ("id", "secret"),
    "secret": ("id", "data"),
    "webhook": ("id", "header_authorization_encrypted"),
    "login_source": ("id", "cfg"),
    "task": ("id", "payload_content"),
}
_LDAP_ENCRYPTED = ("BindPasswordEncrypt",)
_TASK_ENCRYPTED = (
    "clone_addr_encrypted",
    "auth_password_encrypted",
    "auth_token_encrypted",
    "aws_secret_access_key_encrypted",
)
#: the application secrets other than SECRET_KEY: always the source's
OTHER_SECRET_NAMES = ("internal_token", "jwt_secret")


#: what a database call can raise (for a caller that does not import sqlite3 itself)
SQLITE_ERRORS = (sqlite3.Error,)


class HelperError(RuntimeError):
    pass


def secret_fingerprint(value: str) -> str:
    """A non-reversible fingerprint of a secret (HMAC-SHA256 of a fixed message, keyed by the secret).
    Two places that hold the same secret compute the same text; nothing here can be turned back into
    the secret, and the secret itself is never printed."""
    if not value:
        raise HelperError("a secret is empty: nothing to fingerprint")
    return hmac.new(value.encode("utf-8"), _FP_MESSAGE, hashlib.sha256).hexdigest()


def secret_fingerprints(values: dict, names: tuple[str, ...] = SECRET_NAMES) -> dict:
    """Fingerprints of exactly the named application secrets (by default all three; a missing or
    empty one is an error)."""
    missing = [n for n in names if not values.get(n)]
    if missing:
        raise HelperError(f"no value for the application secret(s): {', '.join(missing)}")
    return {n: secret_fingerprint(str(values[n])) for n in names}


def compare_fingerprints(got: dict, want, names: tuple[str, ...] = SECRET_NAMES) -> None:
    """Refuse when ``got`` is not ``want`` for the named secrets (the names are told, never a
    value); ``want`` missing or not exactly those names is a refusal too (an export that cannot
    prove the secrets are the source's)."""
    if not isinstance(want, dict) or sorted(want) != sorted(names):
        raise HelperError(
            "the export records no fingerprint of the application secrets: refusing to "
            "go on without proof they are the source's"
        )
    differ = [n for n in names if not hmac.compare_digest(got[n], str(want[n]))]
    if differ:
        raise HelperError(
            f"the configured {', '.join(differ)} is not the source's: accounts' two-factor "
            "seeds and stored credentials would be unreadable (set the secret to the source's value)"
        )


def secretfp(cfg: dict) -> dict:
    """Command: the fingerprints of ``cfg['values']``; with ``cfg['expect']`` present (even null),
    a refusal when they are not the export's."""
    got = secret_fingerprints(cfg["values"])
    if "expect" in cfg:
        compare_fingerprints(got, cfg["expect"])
    return {"fingerprints": got}


def _holds_any(text, keys: tuple[str, ...]) -> bool:
    """Whether a JSON object column sets any of ``keys``; text that is not a JSON object cannot be
    proved to hold none, so it counts as holding one."""
    try:
        doc = json.loads(text or "{}")
    except ValueError:
        return True
    return not isinstance(doc, dict) or any(doc.get(k) for k in keys)


def app_key_uses(conn: sqlite3.Connection) -> dict:
    """Per table of :data:`APP_KEY_USES`, the rows that hold data encrypted with SECRET_KEY; a
    table or column missing is an unknown schema (an error, never a zero)."""
    have = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
    missing = sorted(set(APP_KEY_USES) - have)
    if missing:
        raise HelperError(
            f"cannot prove what is encrypted with SECRET_KEY: no table {', '.join(missing)}"
        )
    for table, cols in APP_KEY_USES.items():
        got = {r[1] for r in conn.execute(f'PRAGMA table_info("{table}")')}
        if not set(cols) <= got:
            raise HelperError(f"table {table} lacks columns {sorted(set(cols) - got)}")
    one = lambda sql: int(conn.execute(sql).fetchone()[0])  # noqa: E731
    return {
        "two_factor": one("SELECT count(*) FROM two_factor"),
        "secret": one('SELECT count(*) FROM "secret"'),
        "webhook": one(
            "SELECT count(*) FROM webhook WHERE coalesce(header_authorization_encrypted, '') <> ''"
        ),
        "login_source": sum(
            _holds_any(r[0], _LDAP_ENCRYPTED) for r in conn.execute("SELECT cfg FROM login_source")
        ),
        "task": sum(
            _holds_any(r[0], _TASK_ENCRYPTED)
            for r in conn.execute("SELECT payload_content FROM task")
        ),
    }


def unused_key_proof(uses: dict) -> dict:
    """The proof a dump records that nothing is encrypted under the built-in key, or a refusal that
    names every table holding such rows and what the operator can do."""
    held = {t: n for t, n in sorted(uses.items()) if n}
    if held:
        raise HelperError(
            "the source runs on the built-in default SECRET_KEY and holds data encrypted under it "
            f"({', '.join(f'{t}: {n}' for t, n in held.items())} rows): a fresh key could not read "
            "it and the default cannot be carried. Remove those rows on the source (two-factor "
            "enrolments, Actions secrets, webhook authorization headers, LDAP bind passwords, "
            "finished migration tasks; their owners set them again on the target), then dump again"
        )
    return {"rules": APP_KEY_USES_RULES, "encrypted_rows": dict(sorted(uses.items()))}


def check_unused_proof(proof) -> None:
    """Refuse a recorded proof that is absent, made under another list, incomplete or not zero."""
    if (
        not isinstance(proof, dict)
        or proof.get("rules") != APP_KEY_USES_RULES
        or not isinstance(proof.get("encrypted_rows"), dict)
        or sorted(proof["encrypted_rows"]) != sorted(APP_KEY_USES)
    ):
        raise HelperError(
            "the export carries no proof (for this release's list of encrypted tables) that nothing "
            "is encrypted under the source's built-in SECRET_KEY: dump the source again"
        )
    held = {t: n for t, n in proof["encrypted_rows"].items() if n != 0}
    if held:
        raise HelperError(
            f"the export records rows encrypted under the built-in SECRET_KEY ({held}): refusing a fresh key"
        )


def check_app_key(cfg: dict) -> dict:
    """Command: whether the configured application secrets (``values``) fit the export
    (``manifest``: its ``secret_key_source``, ``app_key_fingerprints`` and, for a built-in key,
    ``secret_key_unused_proof``) under the chosen ``origin``; ``zip`` (the export's archive) is
    read again for rows encrypted under the key.

    A source with its own SECRET_KEY (or an export that does not say, as before this check): the
    origin must be ``source`` and all three secrets the source's.  A source on the built-in default:
    the origin must be ``generated``, the proof present and zero, the archive itself holding no such
    row, the configured key not the default, and the other two secrets the source's."""
    manifest, values, origin = cfg.get("manifest") or {}, cfg["values"], cfg.get("origin")
    if origin not in KEY_ORIGINS:
        raise HelperError(f"the SECRET_KEY origin must be one of {', '.join(KEY_ORIGINS)}")
    src = manifest.get("secret_key_source", KEY_CONFIGURED)
    if src == KEY_CONFIGURED:
        if origin != "source":
            raise HelperError(
                "the source has its own SECRET_KEY: the target must carry it (origin source); a fresh "
                "key would leave whatever it encrypted unreadable"
            )
        compare_fingerprints(secret_fingerprints(values), manifest.get("app_key_fingerprints"))
        return {"secret_key": "copied"}
    if src != KEY_BUILTIN:
        raise HelperError(f"the export names an unknown SECRET_KEY source {src!r}")
    if origin != "generated":
        raise HelperError(
            "the source ran on the built-in default SECRET_KEY, which cannot be carried: declare a "
            "fresh one (origin generated, a generated secret) after the dump proved nothing is "
            "encrypted under the default"
        )
    check_unused_proof(manifest.get("secret_key_unused_proof"))
    if not cfg.get("zip"):
        raise HelperError(
            "a fresh SECRET_KEY needs the export's archive to prove again that nothing is "
            "encrypted under the built-in one: refusing on the manifest's word alone"
        )
    unused_key_proof(from_dump(cfg["zip"], app_key_uses))
    if values.get("secret_key") in ("", None, BUILTIN_APP_KEY):
        raise HelperError(
            "the configured SECRET_KEY is empty or the built-in default: set a fresh one"
        )
    compare_fingerprints(
        secret_fingerprints(values, OTHER_SECRET_NAMES),
        manifest.get("app_key_fingerprints"),
        OTHER_SECRET_NAMES,
    )
    return {"secret_key": "fresh"}


def sql_connection(path: str) -> sqlite3.Connection:
    """A connection fit to run SQL that came out of an export: ATTACH (and with it VACUUM INTO) can
    write a file anywhere the process may, so an authorizer refuses it, and the number of attachable
    databases is set to 0 where the library has the limit."""
    conn = sqlite3.connect(path)
    if hasattr(conn, "setlimit") and hasattr(sqlite3, "SQLITE_LIMIT_ATTACHED"):
        conn.setlimit(sqlite3.SQLITE_LIMIT_ATTACHED, 0)

    def deny(action, *_args):
        if action in (sqlite3.SQLITE_ATTACH, sqlite3.SQLITE_DETACH):
            return sqlite3.SQLITE_DENY
        return sqlite3.SQLITE_OK

    conn.set_authorizer(deny)
    return conn


def load_sql(conn: sqlite3.Connection, sql: str) -> None:
    """Run an export's SQL on a connection from :func:`sql_connection`."""
    try:
        conn.executescript(sql)
    except sqlite3.DatabaseError as exc:
        raise HelperError(f"the dump's SQL was refused: {exc}") from exc


def strip_config(src: str, dst: str) -> dict:
    """Copy the dump ``src`` to the NEW file ``dst`` (mode 0600, never overwritten) without its
    configuration file, which holds the application secrets (the restore rebuilds it from the
    secret store).  Returns the names left out."""
    left_out = []
    with zipfile.ZipFile(src) as zin:
        fd = os.open(dst, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, "wb") as raw, zipfile.ZipFile(raw, "w") as zout:
                for info in zin.infolist():
                    if info.filename.rstrip("/").rsplit("/", 1)[-1] == CONFIG_MEMBER:
                        left_out.append(info.filename)
                        continue
                    with zin.open(info) as member, zout.open(info, "w", force_zip64=True) as out:
                        shutil.copyfileobj(member, out, 1 << 20)
        except BaseException:
            os.unlink(dst)  # the one file this call created
            raise
    return {"left_out": left_out}


def strip(cfg: dict) -> dict:
    return strip_config(cfg["zip"], cfg["to"])


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


def from_dump(zpath: str, read):
    """``read(conn)`` over the database a dump archive holds (its SQL loaded into memory)."""
    with zipfile.ZipFile(zpath) as z:
        try:
            info = z.getinfo("gitea-db.sql")
        except KeyError:
            raise HelperError(
                "the dump has no gitea-db.sql (a dump of another database type?)"
            ) from None
        if info.file_size > MAX_SQL:
            raise HelperError("gitea-db.sql is too large to load")
        sql = z.read(info).decode("utf-8")
    conn = sql_connection(":memory:")
    try:
        load_sql(conn, sql)
        conn.set_authorizer(None)
        return read(conn)
    finally:
        conn.close()


def dbcounts(cfg: dict) -> dict:
    if "zip" in cfg:
        return from_dump(cfg["zip"], db_facts)
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


def _get(
    cfg: dict,
    path: str,
    headers: dict | None = None,
    *,
    method: str = "GET",
    body: bytes | None = None,
) -> tuple[int, dict, bytes]:
    ctx = ssl.create_default_context(cafile=cfg["ca_file"])
    conn = _Conn(cfg["bind"], int(cfg["port"]), cfg["hostname"], ctx, float(cfg.get("timeout", 15)))
    try:
        conn.request(
            method, path, body=body, headers={"Accept": "application/json", **(headers or {})}
        )
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


def _prove_pull_is_read_only(cfg: dict) -> None:
    """The pull token is read-only by what the service REFUSES it, not by what it was meant for:
    a write to the registry (opening a blob upload in the account's own namespace), a write through
    the API (creating a repository) and a read outside the registry (the account itself) must each
    be refused.  An answer other than a refusal is an error, and says which probe it was."""
    auth = _basic(cfg["pull_user"], cfg["pull_token"])
    user = cfg["pull_user"].lower()
    probes = (
        ("a registry write", "POST", f"/v2/{user}/hnx-health-probe/blobs/uploads/", None),
        (
            "an API write",
            "POST",
            "/api/v1/user/repos",
            json.dumps({"name": "hnx-health-probe"}).encode(),
        ),
        ("a read outside the registry", "GET", "/api/v1/user", None),
    )
    for what, method, path, body in probes:
        hdrs = {**auth, **({"Content-Type": "application/json"} if body else {})}
        status, _, _ = _get(cfg, path, hdrs, method=method, body=body)
        if status not in (401, 403):
            raise HelperError(
                f"the registry pull account {cfg['pull_user']!r} is not read-only: "
                f"{what} was answered HTTP {status} (a token needs the read:package scope only)"
            )


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
        _prove_pull_is_read_only(cfg)
        facts["registry_pull_read_only"] = "writes refused"
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


COMMANDS = {
    "wait": wait,
    "health": health,
    "dbcounts": dbcounts,
    "signin": signin,
    "strip": strip,
    "secretfp": secretfp,
    "appkey": check_app_key,
}


def main(argv: list[str]) -> int:
    if len(argv) != 2 or argv[1] not in COMMANDS:
        print(
            "usage: hnx_gitea.py wait|health|signin|dbcounts|strip|secretfp|appkey (settings as JSON on stdin)",
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
