#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# hnx-script:
#   id: overlay-vault-pass-client
#   kind: tool
#   purpose: Print the ansible-vault password of a private overlay from the environment or OpenBao, never from a file.
#   owner: maintainers
#   trigger: [manual]
#   inputs: "--vault-id ID (passed by Ansible); env HNX_VAULT_PASSWORD, or HNX_VAULT_PASSWORD_REF plus BAO_ADDR and a token or AppRole"
#   outputs: the password on stdout, nothing else
#   exit:
#     "0": password printed
#     "1": OpenBao refused or returned no value
#     "2": not configured
"""Ansible vault password client for a private overlay (template; docs/private-overlay.md).

Ansible runs a vault identity list entry whose file name ends in ``-client`` as a client
script with ``--vault-id <id>`` and reads the password from its stdout.  This one never reads a
password file.  In order:

1. ``HNX_VAULT_PASSWORD``: the protected Actions Environment injects it into the deploy step
   (``secrets.ANSIBLE_VAULT_PASSWORD``), or an operator exports it for one command.
2. ``HNX_VAULT_PASSWORD_REF=secret:<name>``: read from OpenBao's KV v2 engine by name, the same
   ``secret:`` reference the registry and the ``hnx_secret`` lookup use.  ``BAO_ADDR`` must be
   ``https://``; ``BAO_CACERT`` names the internal CA (verification is never turned off).  The
   token is ``BAO_TOKEN``, else an AppRole login with ``BAO_ROLE_ID`` and ``BAO_SECRET_ID``.
   ``BAO_KV_MOUNT`` (default ``secret``) and ``BAO_FIELD`` (default ``value``) locate the value.

Nothing secret is ever written to stderr: errors name variables and HTTP statuses only.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Mapping

ENV_PASSWORD = "HNX_VAULT_PASSWORD"
ENV_REF = "HNX_VAULT_PASSWORD_REF"
TIMEOUT = 10.0
NAME = re.compile(r"^[a-z0-9][a-z0-9._-]*(?:/[a-z0-9][a-z0-9._-]*)*$")  # as the hnx_secret lookup
MOUNT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]*$")

Opener = Callable[..., object]


class ClientError(Exception):
    def __init__(self, message: str, code: int = 1):
        super().__init__(message)
        self.code = code


def _request(opener: Opener, url: str, *, token: str | None, body: dict | None, ctx) -> dict:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method="POST" if data else "GET")
    req.add_header("Accept", "application/json")
    if data is not None:
        req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("X-Vault-Token", token)
    path = urllib.parse.urlsplit(url).path
    try:
        with opener(req, timeout=TIMEOUT, context=ctx) as resp:  # type: ignore[attr-defined]
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raise ClientError(f"OpenBao answered HTTP {exc.code} for {path}") from None
    except (urllib.error.URLError, OSError) as exc:
        raise ClientError(f"OpenBao unreachable for {path}: {exc.__class__.__name__}") from None
    except ValueError:
        raise ClientError(f"OpenBao returned no JSON for {path}") from None


def from_openbao(ref: str, env: Mapping[str, str], opener: Opener) -> str:
    name = ref.removeprefix("secret:")
    if not ref.startswith("secret:") or not NAME.match(name):
        raise ClientError(f"{ENV_REF} is not a secret reference (secret:<name>)", 2)
    addr = env.get("BAO_ADDR", "").rstrip("/")
    if not addr.startswith("https://"):
        raise ClientError("BAO_ADDR must be an https:// address", 2)
    mount = env.get("BAO_KV_MOUNT") or "secret"
    if not MOUNT.match(mount):
        raise ClientError("BAO_KV_MOUNT is not a mount name", 2)
    ctx = ssl.create_default_context(cafile=env.get("BAO_CACERT") or None)
    token = env.get("BAO_TOKEN")
    if not token:
        role, secret_id = env.get("BAO_ROLE_ID"), env.get("BAO_SECRET_ID")
        if not (role and secret_id):
            raise ClientError("set BAO_TOKEN, or BAO_ROLE_ID and BAO_SECRET_ID (AppRole)", 2)
        got = _request(
            opener,
            f"{addr}/v1/auth/approle/login",
            token=None,
            body={"role_id": role, "secret_id": secret_id},
            ctx=ctx,
        )
        token = ((got.get("auth") or {}) if isinstance(got, dict) else {}).get("client_token")
        if not token:
            raise ClientError("the AppRole login returned no token")
    quoted = "/".join(urllib.parse.quote(part, safe="") for part in name.split("/"))
    got = _request(opener, f"{addr}/v1/{mount}/data/{quoted}", token=token, body=None, ctx=ctx)
    field = env.get("BAO_FIELD") or "value"
    data = ((got.get("data") or {}).get("data") or {}) if isinstance(got, dict) else {}
    value = data.get(field) if isinstance(data, dict) else None
    if not isinstance(value, str) or not value:
        raise ClientError(f"{ref} has no non-empty field {field!r}")
    return value


def password(env: Mapping[str, str], opener: Opener = urllib.request.urlopen) -> str:
    value = env.get(ENV_PASSWORD, "")
    if value:
        return value
    ref = env.get(ENV_REF, "")
    if ref:
        return from_openbao(ref, env, opener)
    raise ClientError(
        f"no vault password: set {ENV_PASSWORD} (Actions Environment secret) or {ENV_REF} "
        "(OpenBao); this client never reads a password file",
        2,
    )


def main(argv: list[str] | None = None, env: Mapping[str, str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="ansible-vault password client (env or OpenBao)")
    ap.add_argument("--vault-id", default="default", help="passed by Ansible; one id is served")
    ap.parse_args(argv)
    try:
        value = password(os.environ if env is None else env)
    except ClientError as exc:
        print(f"vault-pass-client: {exc}", file=sys.stderr)
        return exc.code
    sys.stdout.write(value + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
