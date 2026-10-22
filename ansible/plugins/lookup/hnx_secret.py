# SPDX-License-Identifier: Apache-2.0
"""Minimal secret lookup used by the reference roles: a role names a secret, never holds it.

    {{ lookup('hnx_secret', 'secret:siem/enrollment-password') }}

A reference ``secret:<name>`` resolves on the controller from one of two backends:

* **OpenBao** (the private overlay's deploy, docs/private-overlay.md): when ``BAO_ADDR`` is set,
  every reference is read from OpenBao's KV v2 engine by name, ``<BAO_KV_MOUNT>/data/<name>``
  (mount default ``secret``), field ``BAO_FIELD`` (default ``value``), and from nowhere else: a
  stray ``HNX_SECRET_*`` variable cannot shadow it.  ``BAO_ADDR`` must be ``https://``;
  ``BAO_CACERT`` names the internal CA (verification is never turned off) and redirects are
  never followed, so the token reaches the configured address only.  The token is
  ``BAO_TOKEN``, else an AppRole login with ``BAO_ROLE_ID`` and ``BAO_SECRET_ID`` made for this
  one lookup and revoked (``auth/token/revoke-self``) as soon as its values are read; a failed
  revoke is a warning and the token lapses at the role's (short) TTL.
* **Environment or directory** (lab-in-a-box and the conformance lab): the environment variable
  the registry delivers it in (``HNX_SECRET_<NAME>``:
  ``homelabnext.registry.model.secret_env_name``), else the file ``<hnx_secrets_dir>/<name>``
  (inventory variable).  That mapping folds every non-alphanumeric to ``_``, so ``a/b``, ``a-b``
  and ``a.b`` share one variable: two such references in one lookup, or in one controller
  process, are refused instead of silently handing one the other's value.

Either way an empty or missing secret fails the lookup, never reads as "no secret", and errors
name the reference, the variable or the HTTP status, never a value or a token.  A task that uses
the value must carry ``no_log: true`` (tools/role_lint.py RL011).  This stand-in is meant to be
replaced by the secrets capability's resolver behind the same lookup name and arguments.
"""

from __future__ import annotations

import json
import os
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Mapping
from pathlib import Path

from ansible.errors import AnsibleLookupError
from ansible.utils.display import Display

from ansible.plugins.lookup import LookupBase

DOCUMENTATION = r"""
name: hnx_secret
short_description: Resolve a secret reference (secret:<name>) to its value on the controller
options:
  _terms:
    description: Secret references, each secret:<name>.
    required: true
"""

NAME = re.compile(r"^[a-z0-9][a-z0-9._-]*(?:/[a-z0-9][a-z0-9._-]*)*$")
MOUNT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]*$")
TIMEOUT = 10.0
MAX_BYTES = 1 << 20
#: env name -> the reference first read through it in this controller process
_SEEN: dict[str, str] = {}

display = Display()


def env_name(ref: str) -> str:
    """``secret:siem/enrollment-password`` -> ``HNX_SECRET_SIEM_ENROLLMENT_PASSWORD`` (the rule
    of ``homelabnext.registry.model.secret_env_name``)."""
    return "HNX_SECRET_" + re.sub(r"[^A-Za-z0-9]", "_", ref.removeprefix("secret:")).upper()


def _name(ref: object) -> str:
    name = ref.removeprefix("secret:") if isinstance(ref, str) else ""
    if not isinstance(ref, str) or not ref.startswith("secret:") or not NAME.match(name):
        raise AnsibleLookupError(f"hnx_secret: {ref!r} is not a secret reference (secret:<name>)")
    return name


def _refuse_collisions(refs: list[str], seen: dict[str, str]) -> None:
    for ref in refs:
        env = env_name(ref)
        first = seen.setdefault(env, ref)
        if first != ref:
            raise AnsibleLookupError(
                f"hnx_secret: {ref} and {first} are both delivered in {env}; rename one "
                "(or read them from OpenBao by name, BAO_ADDR)"
            )


# ---- OpenBao (KV v2, AppRole) -----------------------------------------------------------------


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse every redirect: urllib would replay X-Vault-Token to any Location, http included."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[override]
        return None  # urllib then raises HTTPError for the 3xx itself


class OpenBao:
    """The three calls this lookup makes, with errors that name the path and status only."""

    def __init__(self, env: Mapping[str, str]):
        self.addr = env.get("BAO_ADDR", "").rstrip("/")
        if not self.addr.startswith("https://"):
            raise AnsibleLookupError("hnx_secret: BAO_ADDR must be an https:// address")
        self.mount = env.get("BAO_KV_MOUNT") or "secret"
        if not MOUNT.match(self.mount):
            raise AnsibleLookupError("hnx_secret: BAO_KV_MOUNT is not a mount name")
        self.field = env.get("BAO_FIELD") or "value"
        self.env = env
        ctx = ssl.create_default_context(cafile=env.get("BAO_CACERT") or None)
        self._opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=ctx), _NoRedirect()
        )

    def _call(self, path: str, *, token: str | None, body: dict | None = None) -> dict:
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(
            self.addr + path, data=data, method="POST" if data is not None else "GET"
        )
        req.add_header("Accept", "application/json")
        if data is not None:
            req.add_header("Content-Type", "application/json")
        if token:
            req.add_header("X-Vault-Token", token)
        shown = urllib.parse.urlsplit(self.addr + path).path
        try:
            with self._opener.open(req, timeout=TIMEOUT) as resp:
                raw = resp.read(MAX_BYTES + 1)
        except urllib.error.HTTPError as exc:
            moved = " (redirects are refused)" if 300 <= exc.code < 400 else ""
            raise AnsibleLookupError(
                f"hnx_secret: OpenBao answered HTTP {exc.code} for {shown}{moved}"
            ) from None
        except (urllib.error.URLError, OSError) as exc:
            raise AnsibleLookupError(
                f"hnx_secret: OpenBao unreachable for {shown}: {exc.__class__.__name__}"
            ) from None
        if len(raw) > MAX_BYTES:
            raise AnsibleLookupError(f"hnx_secret: OpenBao answer too large for {shown}")
        if not raw.strip():
            return {}
        try:
            got = json.loads(raw.decode("utf-8"))
        except ValueError:
            raise AnsibleLookupError(f"hnx_secret: OpenBao returned no JSON for {shown}") from None
        return got if isinstance(got, dict) else {}

    def login(self) -> tuple[str, bool]:
        """``(token, minted)``: ``BAO_TOKEN`` as given, else a fresh AppRole token."""
        token = self.env.get("BAO_TOKEN")
        if token:
            return token, False
        role, secret_id = self.env.get("BAO_ROLE_ID"), self.env.get("BAO_SECRET_ID")
        if not (role and secret_id):
            raise AnsibleLookupError(
                "hnx_secret: BAO_ADDR is set: set BAO_TOKEN, or BAO_ROLE_ID and BAO_SECRET_ID "
                "(AppRole)"
            )
        got = self._call(
            "/v1/auth/approle/login", token=None, body={"role_id": role, "secret_id": secret_id}
        )
        token = (got.get("auth") or {}).get("client_token")
        if not isinstance(token, str) or not token:
            raise AnsibleLookupError("hnx_secret: the AppRole login returned no token")
        return token, True

    def read(self, token: str, ref: str, name: str) -> str:
        quoted = "/".join(urllib.parse.quote(part, safe="") for part in name.split("/"))
        got = self._call(f"/v1/{self.mount}/data/{quoted}", token=token)
        data = (got.get("data") or {}).get("data") or {}
        value = data.get(self.field) if isinstance(data, dict) else None
        if not isinstance(value, str) or not value:
            raise AnsibleLookupError(f"hnx_secret: {ref} has no non-empty field {self.field!r}")
        return value

    def revoke(self, token: str) -> None:
        try:
            self._call("/v1/auth/token/revoke-self", token=token, body={})
        except AnsibleLookupError as exc:
            why = str(exc).removeprefix("hnx_secret: ")
            display.warning(
                f"hnx_secret: could not revoke the AppRole token ({why}); it lapses at its TTL"
            )


def from_openbao(refs: list[str], env: Mapping[str, str]) -> list[str]:
    bao = OpenBao(env)
    token, minted = bao.login()
    try:
        return [bao.read(token, ref, _name(ref)) for ref in refs]
    finally:
        if minted:
            bao.revoke(token)


# ---- environment or directory ------------------------------------------------------------------


def from_env_or_dir(refs: list[str], secrets_dir: str | None) -> list[str]:
    _refuse_collisions(refs, {})  # within this lookup
    _refuse_collisions(refs, _SEEN)  # and across lookups in this controller process
    out = []
    for ref in refs:
        name = _name(ref)
        value = os.environ.get(env_name(ref), "")
        if not value and secrets_dir:
            p = Path(secrets_dir) / name
            try:
                value = p.read_text(encoding="utf-8").strip() if p.is_file() else ""
            except OSError as exc:
                raise AnsibleLookupError(f"hnx_secret: cannot read {ref}: {exc}") from exc
        if not value:
            raise AnsibleLookupError(
                f"hnx_secret: {ref} is not set ({env_name(ref)} or hnx_secrets_dir/{name})"
            )
        out.append(value)
    return out


class LookupModule(LookupBase):
    def run(self, terms, variables=None, **kwargs):
        refs = list(terms)
        for ref in refs:
            _name(ref)
        if os.environ.get("BAO_ADDR"):
            return from_openbao(refs, os.environ)
        return from_env_or_dir(refs, (variables or {}).get("hnx_secrets_dir"))
