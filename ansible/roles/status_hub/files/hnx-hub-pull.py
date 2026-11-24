#!/usr/bin/python3 -I
# SPDX-License-Identifier: Apache-2.0
# hnx-script:
#   id: hub-pull
#   kind: tool
#   purpose: Pull each producer host's status file (for example the invariants runner's results document) over SSH to a restricted account whose forced command streams that one file read-only, and file it under the status root at the path the hub's own configuration names, so a poll-file source has something to read.
#   owner: platform
#   trigger: [role:status_hub, timer:status_hub/hnx-hub-pull]
#   inputs: "--config FILE: JSON {key_file, known_hosts, root, group, ssh?: PATH, entries: [{name, address, user, dest}]}"
#   outputs: one line per entry on stdout (name, ok and the size, or the error class); each document is written to <root>/<dest> (0640, group the collector's) by rename; nothing is written for a document that is not a JSON object
#   installs_to: /usr/local/libexec/hnx-hub/hnx-hub-pull
#   exit:
#     "0": every entry pulled
#     "1": at least one entry failed (its previous file is left as it was)
#     "2": usage or configuration error
"""Pull per-host status files to the status hub (ADR-0049 decision 7, "The results transport").

The hub dials out; the producer never reaches the hub.  The producer's account accepts only a key
restricted to a forced command that prints one file, so the client sends no command and the stream
can name nothing: the hub files what it receives at the ``dest`` ITS configuration gives for the
host it connected to.  The host key is pinned (a known_hosts file the role writes, strict
checking), the key file is root's, and the stream is size-capped and must parse as a JSON object
before it replaces the previous file by rename.
"""

from __future__ import annotations

import grp
import json
import os
import re
import secrets
import subprocess
import sys

NAME_RE = re.compile(r"\A[a-z0-9][a-z0-9_-]{0,62}\Z")
USER_RE = re.compile(r"\A[a-z_][a-z0-9_-]{0,31}\Z")
ADDRESS_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9.:-]{0,252}\Z")
DEST_RE = re.compile(r"\A[a-z0-9][a-z0-9_.-]{0,62}(/[a-z0-9][a-z0-9_.-]{0,62}){0,3}\.json\Z")
MAX_BYTES = 4 * 1024 * 1024


def dest_path(root: str, dest: str) -> str:
    """``dest`` under ``root``, refusing anything that is not a plain relative path inside it."""
    if not DEST_RE.match(dest) or any(p in (".", "..") for p in dest.split("/")):
        raise ValueError("dest is not a plain relative .json path")
    root_real = os.path.realpath(root)
    path = os.path.realpath(os.path.join(root_real, dest))
    if os.path.commonpath([root_real, path]) != root_real or path == root_real:
        raise ValueError("dest escapes the status root")
    return path


def ssh_argv(cfg: dict, entry: dict) -> list[str]:
    return [
        cfg.get("ssh") or "/usr/bin/ssh",
        "-F", "none",
        "-i", cfg["key_file"],
        "-o", "IdentitiesOnly=yes",
        "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=yes",
        "-o", f"UserKnownHostsFile={cfg['known_hosts']}",
        "-o", "GlobalKnownHostsFile=/dev/null",
        "-o", "UpdateHostKeys=no",
        "-o", "ConnectTimeout=10",
        "-o", "ServerAliveInterval=10",
        "-o", "ServerAliveCountMax=2",
        "-o", "ForwardAgent=no",
        "-o", "ClearAllForwardings=yes",
        "-T",
        "-l", entry["user"],
        "--",
        entry["address"],
    ]  # fmt: skip


def fetch(cfg: dict, entry: dict, timeout: float = 60.0) -> bytes:
    """The stream the forced command prints (the client asks for no command), capped and checked."""
    proc = subprocess.run(
        ssh_argv(cfg, entry),
        stdin=subprocess.DEVNULL,
        capture_output=True,
        timeout=timeout,
        check=False,
    )
    if proc.returncode != 0:
        raise ConnectionError(f"ssh exited {proc.returncode}")
    data = proc.stdout
    if len(data) > MAX_BYTES:
        raise ValueError("the stream is larger than the cap")
    doc = json.loads(data.decode("utf-8", "strict"))
    if not isinstance(doc, dict) or not doc:
        raise ValueError("the stream is not a JSON object")
    return data


def write_atomic(path: str, data: bytes, group: str | None) -> None:
    """The document by rename at mode 0640, group the collector's: a reader never sees half a file."""
    directory = os.path.dirname(path)
    gid = grp.getgrnam(group).gr_gid if group else -1
    if not os.path.isdir(
        directory
    ):  # a new dest's directory: the collector's group may traverse it
        os.makedirs(directory, mode=0o750)
        os.chown(directory, -1, gid)
    tmp = os.path.join(directory, f".pull-{secrets.token_hex(8)}")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o640)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            if gid != -1:
                os.fchown(fh.fileno(), -1, gid)
            os.fchmod(fh.fileno(), 0o640)
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def load_config(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        cfg = json.load(fh)
    entries = cfg["entries"]
    assert isinstance(entries, list) and entries
    for key in ("key_file", "known_hosts", "root"):
        assert isinstance(cfg[key], str) and cfg[key].startswith("/")
    assert cfg.get("group") is None or NAME_RE.match(cfg["group"])
    assert cfg.get("ssh") is None or str(cfg["ssh"]).startswith("/")
    names = set()
    for e in entries:
        assert NAME_RE.match(e["name"]) and e["name"] not in names
        names.add(e["name"])
        assert USER_RE.match(e["user"]) and ADDRESS_RE.match(e["address"])
        dest_path(cfg["root"], e["dest"])
    return cfg


def main(argv: list[str]) -> int:
    if len(argv) != 3 or argv[1] != "--config":
        print("usage: hnx-hub-pull --config FILE", file=sys.stderr)
        return 2
    try:
        cfg = load_config(argv[2])
    except (OSError, ValueError, KeyError, AssertionError, TypeError):
        print("hnx-hub-pull: unreadable configuration", file=sys.stderr)
        return 2
    failed = 0
    for e in cfg["entries"]:
        try:
            data = fetch(cfg, e)
            write_atomic(dest_path(cfg["root"], e["dest"]), data, cfg.get("group"))
            print(f"{e['name']}: ok ({len(data)} bytes)")
        except Exception as exc:  # one entry never blocks the others; the class, never the content
            failed += 1
            print(f"{e['name']}: failed ({type(exc).__name__}: {str(exc)[:80]})")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
