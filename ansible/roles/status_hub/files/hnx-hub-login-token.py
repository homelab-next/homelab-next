#!/usr/bin/python3 -I
# SPDX-License-Identifier: Apache-2.0
# hnx-script:
#   id: hub-login-token
#   kind: tool
#   purpose: Refresh the short-lived bearer tokens the status hub's collector sends to products that only issue them for a login (a form post of a user name and password), so no expired token leaves a source unreadable.
#   owner: platform
#   trigger: [role:status_hub]
#   inputs: "--config FILE: JSON {entries: [{name, url, username, password_file, out}], ca_file?: PATH}"
#   outputs: one line per entry on stdout (name, ok or the error class); each token is written to its entry's out file (0640, group kept) by rename; the token is never printed
#   exit:
#     "0": every entry refreshed
#     "1": at least one entry failed (its previous token file is left as it was)
#     "2": usage or configuration error
"""Refresh login-issued bearer tokens for the status hub (docs/status.md, "Login-issued tokens").

The product's token endpoint takes ``username`` and ``password`` as a form and answers the token
as the body.  The password is read from a root-only file, never from the command line or the
environment; the token is written next to the collector's other file-form secrets and read by
``hnx status collect`` at run time (``--secrets-dir``).  The connection is verified against the
lab's CA bundle (``ca_file``); a redirect, a proxy from the environment and a non-https url are
refused, because the form carries the password.
"""

from __future__ import annotations

import json
import os
import re
import ssl
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request

TOKEN_RE = re.compile(r"\A[A-Za-z0-9._~+/=-]{8,8192}\Z")
NAME_RE = re.compile(r"\A[a-z0-9][a-z0-9_-]{0,62}\Z")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):  # a redirect would send the password elsewhere
        return None


def _read_password(path: str) -> str:
    st = os.stat(path)
    if st.st_mode & 0o077:
        raise ValueError("password file is readable by group or other")
    with open(path, encoding="utf-8") as fh:
        value = fh.read().rstrip("\n")
    if not value:
        raise ValueError("password file is empty")
    return value


def fetch_token(entry: dict, ctx: ssl.SSLContext, timeout: float = 20.0) -> str:
    url = entry["url"]
    if urllib.parse.urlsplit(url).scheme != "https":
        raise ValueError("token url must be https")
    body = urllib.parse.urlencode(
        {"username": entry["username"], "password": _read_password(entry["password_file"])}
    ).encode()
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),  # no proxy from the environment: it would see the form
        _NoRedirect(),
        urllib.request.HTTPSHandler(context=ctx),
    )
    req = urllib.request.Request(
        url, data=body, method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded", "Accept": "text/plain"},
    )  # fmt: skip
    with opener.open(req, timeout=timeout) as resp:
        if resp.status not in (200, 201):
            raise ValueError(f"status {resp.status}")
        token = resp.read(16384).decode("ascii", "strict").strip()
    if not TOKEN_RE.match(token):
        raise ValueError("the answer is not a bearer token")
    return token


def write_atomic(path: str, token: str) -> None:
    directory = os.path.dirname(path)
    fd, tmp = tempfile.mkstemp(prefix=".tok-", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="ascii") as fh:
            fh.write(token + "\n")
        os.chmod(tmp, 0o640)
        try:  # keep the group of the directory the collector reads from
            os.chown(tmp, -1, os.stat(directory).st_gid)
        except PermissionError:
            pass
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def main(argv: list[str]) -> int:
    if len(argv) != 3 or argv[1] != "--config":
        print("usage: hnx-hub-login-token --config FILE", file=sys.stderr)
        return 2
    try:
        with open(argv[2], encoding="utf-8") as fh:
            cfg = json.load(fh)
        entries = cfg["entries"]
        assert isinstance(entries, list) and entries
        for e in entries:
            assert NAME_RE.match(e["name"])
    except (OSError, ValueError, KeyError, AssertionError, TypeError):
        print("hnx-hub-login-token: unreadable configuration", file=sys.stderr)
        return 2
    ctx = ssl.create_default_context(cafile=cfg.get("ca_file"))
    failed = 0
    for e in entries:
        try:
            write_atomic(e["out"], fetch_token(e, ctx))
            print(f"{e['name']}: ok")
        except Exception as exc:  # one entry never blocks the others; the class, never a value
            failed += 1
            print(f"{e['name']}: failed ({type(exc).__name__})")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
