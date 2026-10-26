# SPDX-License-Identifier: Apache-2.0
"""Find every credential a lab names, and create the missing ones in OpenBao (and Vaultwarden).

Git holds credential *names* (``secret:<name>``); OpenBao holds the values, which the deploy reads
by name (``ansible/plugins/lookup/hnx_secret.py``, docs/private-overlay.md).  On a new site every
one of those values has to exist before the first deploy.  This module:

* :func:`scan` lists every ``secret:<name>`` the given files name (comment lines skipped), with
  where each is named: the overlay's site, registry, guests and inventory, and the roles' defaults;
* :class:`Spec` says how each name gets its value, by the first rule whose glob matches it:
  ``password`` (letters, digits, ``-`` and ``_``), ``token`` (URL-safe base64 of N random bytes),
  ``hex`` (N random bytes), or ``external`` (issued elsewhere, such as an API key: never generated,
  asked for with ``--ask`` or reported as still needed);
* :func:`seed` creates each missing value in OpenBao's KV v2 with check-and-set 0, so an existing
  secret is never overwritten (not even by a concurrent run), and optionally copies it into
  Vaultwarden through the Bitwarden CLI.

Values exist only in memory, in the HTTPS request body and on the ``bw`` processes' standard
input: never in a file, a command line, an argument list or the output, which names secrets only.
"""

from __future__ import annotations

import base64
import fnmatch
import json
import os
import re
import secrets
import ssl
import string
import subprocess
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

#: a reference as the roles' validators accept it (``secret:<seg>[/<seg>...]``)
REF = re.compile(r"secret:([a-z0-9][a-z0-9._-]*(?:/[a-z0-9][a-z0-9._-]*)*)")
NAME = re.compile(r"[a-z0-9][a-z0-9._-]*(?:/[a-z0-9][a-z0-9._-]*)*\Z")
SCANNED = {".yml", ".yaml", ".json", ".hujson", ".j2", ".toml", ".cfg", ".ini"}
SKIPPED_DIRS = {".git", "__pycache__", "node_modules", ".terraform", ".venv"}
KINDS = ("password", "token", "hex", "external")
PASSWORD_ALPHABET = string.ascii_letters + string.digits + "-_"


class SeedError(Exception):
    """A spec, a backend or a request that cannot be used; the message never carries a value."""


# --------------------------------------------------------------------------------- scanning
def _files(paths: Iterable[Path]) -> Iterable[Path]:
    for p in paths:
        if p.is_file():
            yield p
        elif p.is_dir():
            for f in sorted(p.rglob("*")):
                if f.is_file() and f.suffix in SCANNED and not SKIPPED_DIRS & set(f.parts):
                    yield f
        else:
            raise SeedError(f"{p}: no such file or directory")


def scan(paths: Iterable[str | Path]) -> dict[str, list[str]]:
    """``{name: ["file:line", ...]}`` for every ``secret:<name>`` the files name, sorted.  A line
    that is only a comment (``#`` or ``//``) is skipped: an example in a comment is not a
    credential the lab uses."""
    found: dict[str, list[str]] = {}
    for f in _files(Path(p) for p in paths):
        try:
            text = f.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        for n, line in enumerate(text.splitlines(), 1):
            if line.lstrip().startswith(("#", "//")):
                continue
            for m in REF.finditer(line):
                found.setdefault(m.group(1), []).append(f"{f}:{n}")
    return dict(sorted(found.items()))


# ------------------------------------------------------------------------------------ spec
@dataclass(frozen=True)
class Rule:
    match: str
    kind: str = "password"
    length: int = 32  # password
    nbytes: int = 32  # token, hex
    how: str = ""  # external: where the value comes from
    prefix: str = ""  # token: a fixed start some software requires (LiteLLM keys: sk-)

    def generate(self) -> str:
        if self.kind == "password":
            return "".join(secrets.choice(PASSWORD_ALPHABET) for _ in range(self.length))
        if self.kind == "token":
            raw = secrets.token_bytes(self.nbytes)
            return self.prefix + base64.urlsafe_b64encode(raw).decode().rstrip("=")
        if self.kind == "hex":
            return secrets.token_hex(self.nbytes)
        raise SeedError(f"{self.match}: an external secret is never generated")


@dataclass(frozen=True)
class Spec:
    default: Rule = field(default_factory=lambda: Rule("*"))
    rules: tuple[Rule, ...] = ()
    vaultwarden_folder: str = "homelab"
    vaultwarden_include: tuple[str, ...] = ("*",)
    vaultwarden_exclude: tuple[str, ...] = ()

    def rule(self, name: str) -> Rule:
        return next((r for r in self.rules if fnmatch.fnmatchcase(name, r.match)), self.default)

    def to_vaultwarden(self, name: str) -> bool:
        def hit(globs: Iterable[str]) -> bool:
            return any(fnmatch.fnmatchcase(name, g) for g in globs)

        return hit(self.vaultwarden_include) and not hit(self.vaultwarden_exclude)


def _rule(where: str, raw: Any, *, default: bool = False) -> Rule:
    if not isinstance(raw, dict):
        raise SeedError(f"{where}: a mapping")
    allowed = {"kind", "length", "bytes", "how", "prefix"} | (set() if default else {"match"})
    extra = set(raw) - allowed
    if extra:
        raise SeedError(f"{where}: unknown key(s) {sorted(extra)}")
    match = "*" if default else raw.get("match")
    if not isinstance(match, str) or not match:
        raise SeedError(f"{where}: match is a glob over secret names (without 'secret:')")
    kind = raw.get("kind", "password")
    if kind not in KINDS:
        raise SeedError(f"{where}: kind is one of {', '.join(KINDS)}")
    length, nbytes = raw.get("length", 32), raw.get("bytes", 32)
    if kind == "password" and not (isinstance(length, int) and 20 <= length <= 128):
        raise SeedError(f"{where}: a password's length is 20 to 128 characters")
    if kind in ("token", "hex") and not (isinstance(nbytes, int) and 16 <= nbytes <= 128):
        raise SeedError(f"{where}: a {kind}'s bytes is 16 to 128")
    how = raw.get("how", "")
    if kind == "external" and not (isinstance(how, str) and how.strip()):
        raise SeedError(f"{where}: an external secret says how to get it (how)")
    prefix = raw.get("prefix", "")
    if prefix and (kind != "token" or not re.fullmatch(r"[A-Za-z0-9_-]{1,16}", str(prefix))):
        raise SeedError(f"{where}: prefix is up to 16 of [A-Za-z0-9_-], on a token only")
    return Rule(match, kind, length, nbytes, how, prefix)


def load_spec(path: str | Path) -> Spec:
    """Read ``secrets.yml``: ``{secrets_version: 1, default, rules: [...], vaultwarden}``."""
    import yaml

    from homelabnext._yaml import UniqueKeyLoader

    p = Path(path)
    try:
        doc = yaml.load(p.read_text(encoding="utf-8"), Loader=UniqueKeyLoader)
    except (OSError, yaml.YAMLError) as exc:
        raise SeedError(f"cannot read {p}: {exc}") from exc
    if not isinstance(doc, dict) or doc.get("secrets_version") != 1:
        raise SeedError(f"{p}: expected a mapping with secrets_version: 1")
    extra = set(doc) - {"secrets_version", "default", "rules", "vaultwarden"}
    if extra:
        raise SeedError(f"{p}: unknown key(s) {sorted(extra)}")
    default = _rule(f"{p}: default", doc.get("default", {}), default=True)
    if default.kind == "external":
        raise SeedError(f"{p}: default: the default cannot be external")
    rules = tuple(_rule(f"{p}: rules[{i}]", r) for i, r in enumerate(doc.get("rules") or []))
    vw = doc.get("vaultwarden") or {}
    if not isinstance(vw, dict) or set(vw) - {"folder", "include", "exclude"}:
        raise SeedError(f"{p}: vaultwarden takes folder, include and exclude")
    folder = vw.get("folder", "homelab")
    if not isinstance(folder, str) or not folder.strip():
        raise SeedError(f"{p}: vaultwarden.folder is a folder name")
    globs = {}
    for key, dflt in (("include", ["*"]), ("exclude", [])):
        val = vw.get(key, dflt)
        if not isinstance(val, list) or not all(isinstance(g, str) and g for g in val):
            raise SeedError(f"{p}: vaultwarden.{key} is a list of globs")
        globs[key] = tuple(val)
    return Spec(default, rules, folder, globs["include"], globs["exclude"])


# --------------------------------------------------------------------------------- OpenBao
class OpenBaoKV:
    """OpenBao's KV v2 by name, as the operator: ``BAO_ADDR`` (https, or http on loopback only),
    ``BAO_TOKEN``, ``BAO_CACERT``, ``BAO_KV_MOUNT`` (default ``secret``) and ``BAO_FIELD``
    (default ``value``, the field the ``hnx_secret`` lookup reads).  No redirect is followed and
    no proxy is used, so the token reaches the configured address only."""

    def __init__(
        self, addr: str, token: str, *, cacert: str | None = None, mount: str = "secret",
        field: str = "value",
    ):  # fmt: skip
        u = urllib.parse.urlsplit(addr)
        loopback = u.hostname in ("127.0.0.1", "::1", "localhost")
        if u.scheme != "https" and not (u.scheme == "http" and loopback):
            raise SeedError("BAO_ADDR must be https:// (plain http only on loopback)")
        if not token:
            raise SeedError("BAO_TOKEN is not set: seed as an operator token with write access")
        if not NAME.match(mount) or "/" in mount:
            raise SeedError(f"BAO_KV_MOUNT {mount!r} is not a mount name")
        self.base = addr.rstrip("/")
        self.mount, self.field, self._token = mount, field, token
        handlers: list[Any] = [urllib.request.ProxyHandler({}), _NoRedirect()]
        if u.scheme == "https":
            ctx = ssl.create_default_context(cafile=cacert)
            handlers.append(urllib.request.HTTPSHandler(context=ctx))
        self._open = urllib.request.build_opener(*handlers).open

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> OpenBaoKV:
        e = os.environ if env is None else env
        if not e.get("BAO_ADDR"):
            raise SeedError("BAO_ADDR is not set")
        return cls(
            e["BAO_ADDR"],
            e.get("BAO_TOKEN", ""),
            cacert=e.get("BAO_CACERT") or None,
            mount=e.get("BAO_KV_MOUNT", "secret"),
            field=e.get("BAO_FIELD", "value"),
        )

    def _url(self, kind: str, name: str) -> str:
        if not NAME.match(name):
            raise SeedError(f"secret:{name} is not a secret name")
        path = "/".join(urllib.parse.quote(s, safe="") for s in name.split("/"))
        return f"{self.base}/v1/{self.mount}/{kind}/{path}"

    def _call(self, method: str, url: str, body: dict | None = None) -> tuple[int, dict]:
        data = None if body is None else json.dumps(body).encode()
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header("X-Vault-Token", self._token)
        if data is not None:
            req.add_header("Content-Type", "application/json")
        try:
            with self._open(req, timeout=15) as resp:
                raw = resp.read(1 << 20)
                return resp.status, (json.loads(raw) if raw else {})
        except urllib.error.HTTPError as exc:
            try:
                doc = json.loads(exc.read(1 << 16) or b"{}")
            except ValueError:
                doc = {}
            return exc.code, doc if isinstance(doc, dict) else {}
        except (urllib.error.URLError, OSError) as exc:
            raise SeedError(f"OpenBao is unreachable: {getattr(exc, 'reason', exc)}") from None

    def exists(self, name: str) -> bool:
        status, _ = self._call("GET", self._url("metadata", name))
        if status == 200:
            return True
        if status == 404:
            return False
        raise SeedError(f"secret:{name}: OpenBao answered {status} reading its metadata")

    def create(self, name: str, value: str) -> bool:
        """Write ``value`` only if the name has no version yet (check-and-set 0): True when it was
        written, False when it already existed."""
        body = {"options": {"cas": 0}, "data": {self.field: value}}
        status, doc = self._call("POST", self._url("data", name), body)
        if status in (200, 204):
            return True
        if status == 400 and any("check-and-set" in str(e) for e in doc.get("errors", [])):
            return False
        raise SeedError(f"secret:{name}: OpenBao answered {status} writing it")

    def read(self, name: str) -> str:
        status, doc = self._call("GET", self._url("data", name))
        value = ((doc.get("data") or {}).get("data") or {}).get(self.field)
        if status != 200 or not isinstance(value, str) or not value:
            raise SeedError(f"secret:{name}: OpenBao answered {status} with no {self.field!r}")
        return value


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(req.full_url, code, "redirect refused", headers, fp)


# ------------------------------------------------------------------------------ Vaultwarden
class Vaultwarden:
    """A Vaultwarden (or Bitwarden) vault through the official ``bw`` CLI, already pointed at the
    server (``bw config server``), logged in and unlocked: ``BW_SESSION`` holds the session.
    An item is a login named ``secret:<name>`` whose password is the value, in one folder; the
    value reaches ``bw`` on standard input only."""

    def __init__(self, folder: str, *, bw: str = "bw", env: Mapping[str, str] | None = None):
        self.env = dict(os.environ if env is None else env)
        if not self.env.get("BW_SESSION"):
            raise SeedError(
                "BW_SESSION is not set: run `bw config server <url>`, `bw login`, then "
                "`export BW_SESSION=$(bw unlock --raw)`"
            )
        self.bw, self.folder_name = bw, folder
        self._run("sync")
        self.folder_id = self._folder()
        self._names = {
            i.get("name")
            for i in json.loads(self._run("list", "items", "--folderid", self.folder_id) or "[]")
        }

    def _run(self, *args: str, stdin: str | None = None) -> str:
        try:
            r = subprocess.run(
                [self.bw, *args, "--nointeraction"],
                input=stdin, capture_output=True, text=True, env=self.env, timeout=120,
            )  # fmt: skip
        except (OSError, subprocess.SubprocessError) as exc:
            raise SeedError(f"bw {args[0]}: {exc}") from None
        if r.returncode != 0:
            # bw's message names the command, never a value: values are never in its arguments
            raise SeedError(f"bw {args[0]} failed: {r.stderr.strip()[:200]}")
        return r.stdout

    def _encoded(self, doc: dict) -> str:
        return self._run("encode", stdin=json.dumps(doc)).strip()

    def _folder(self) -> str:
        found = json.loads(self._run("list", "folders", "--search", self.folder_name) or "[]")
        for f in found:
            if f.get("name") == self.folder_name:
                return f["id"]
        made = json.loads(
            self._run("create", "folder", stdin=self._encoded({"name": self.folder_name}))
        )
        return made["id"]

    def has(self, name: str) -> bool:
        return f"secret:{name}" in self._names

    def create(self, name: str, value: str, note: str) -> None:
        item = {
            "type": 1,
            "name": f"secret:{name}",
            "folderId": self.folder_id,
            "notes": note,
            "login": {"username": None, "password": value, "uris": []},
        }
        self._run("create", "item", stdin=self._encoded(item))
        self._names.add(f"secret:{name}")


# ------------------------------------------------------------------------------------ seed
@dataclass
class Outcome:
    name: str
    kind: str
    openbao: str  # created | exists | would-create | needs-value | error
    vaultwarden: str = "-"  # created | exists | would-create | skipped | error | -
    detail: str = ""


def seed(
    names: Iterable[str],
    spec: Spec,
    bao: OpenBaoKV | None,
    vault: Vaultwarden | None = None,
    *,
    dry_run: bool = False,
    ask: Callable[[str, Rule], str] | None = None,
) -> list[Outcome]:
    """Create each missing secret in OpenBao, and copy it into Vaultwarden when ``vault`` is given
    and the spec includes it.  ``bao`` may be None only for a dry run (nothing is read).  An
    external secret is asked for through ``ask`` (an empty answer leaves it), else reported."""
    out = []
    for name in names:
        rule = spec.rule(name)
        o = Outcome(name, rule.kind, "would-create" if dry_run else "")
        value: str | None = None
        try:
            present = bao.exists(name) if bao is not None else False
            if present:
                o.openbao = "exists"
            elif dry_run:
                o.openbao = "needs-value" if rule.kind == "external" else "would-create"
            else:
                if rule.kind == "external":
                    value = ask(name, rule) if ask else ""
                    if not value:
                        o.openbao, o.detail = "needs-value", rule.how
                else:
                    value = rule.generate()
                if value:
                    assert bao is not None
                    o.openbao = "created" if bao.create(name, value) else "exists"
                    if o.openbao == "exists":
                        value = None  # another run won the race: its value is the one
        except SeedError as exc:
            o.openbao, o.detail = "error", str(exc)
        if vault is not None and o.openbao != "error":
            o.vaultwarden = _to_vault(name, spec, bao, vault, value, o, dry_run)
        out.append(o)
    return out


def _to_vault(
    name: str, spec: Spec, bao: OpenBaoKV | None, vault: Vaultwarden, value: str | None,
    o: Outcome, dry_run: bool,
) -> str:  # fmt: skip
    if not spec.to_vaultwarden(name):
        return "skipped"
    if vault.has(name):
        return "exists"
    if o.openbao == "needs-value":
        return "-"
    if dry_run:
        return "would-create"
    try:
        if value is None:
            assert bao is not None
            value = bao.read(name)
        where = f"{bao.mount}/{name}" if bao is not None else name
        vault.create(
            name, value, f"Copy of OpenBao {where} (the source of truth); hnx secrets seed."
        )
        return "created"
    except SeedError as exc:
        o.detail = (o.detail + "; " if o.detail else "") + str(exc)
        return "error"
