# SPDX-License-Identifier: Apache-2.0
"""The commands the misp role runs on the guest that need a pipe or an archive: ``dump``, ``verify``,
``load`` and ``files``. One JSON object on standard input names the paths; the database's root
password travels in the environment (``MYSQL_PWD``) of the docker client and is never read here.
Every command prints one line of JSON on success and exits 1 with a one-line reason on standard
error (which never holds a credential) on failure. Nothing here shells out: every command is an
argument vector, every pipe a pair of processes whose exit statuses are both checked.
"""

from __future__ import annotations

import json
import os
import re
import stat
import subprocess
import sys
import tarfile

COMPLETION = b"-- Dump completed"
#: a member the files command may extract: a plain name under files/<digits>/
MEMBER = re.compile(r"^files/[0-9]+(/[A-Za-z0-9_.-]+)*/?\Z")
CHUNK = 1 << 20


class Refusal(Exception):
    """Something the command refuses to do, with the reason."""


def _abs(path: object, what: str) -> str:
    if not isinstance(path, str) or not path.startswith("/") or "\0" in path:
        raise Refusal(f"{what} must be an absolute path")
    if any(part in ("", ".", "..") for part in path.split("/")[1:]):
        raise Refusal(f"{what} must be a canonical path")
    return path


def _pipe(first: list[str], second: list[str], *, sink_out: int | None = None) -> None:
    """Run ``first | second``; both must exit 0."""
    a = subprocess.Popen(first, stdout=subprocess.PIPE)
    try:
        b = subprocess.Popen(second, stdin=a.stdout, stdout=sink_out)
    except BaseException:
        a.kill()
        a.wait()
        raise
    assert a.stdout is not None
    a.stdout.close()
    rc_b = b.wait()
    rc_a = a.wait()
    if rc_a != 0 or rc_b != 0:
        raise Refusal(f"the pipeline failed (producer {rc_a}, consumer {rc_b})")


def dump(cfg: dict) -> dict:
    compose, out = _abs(cfg.get("compose"), "compose"), _abs(cfg.get("out"), "out")
    if os.path.lexists(out):
        raise Refusal("the output file exists; a dump never overwrites")
    first = [
        "docker", "compose", "-f", compose, "exec", "-T", "-e", "MYSQL_PWD", "db",
        "mariadb-dump", "--user=root", "--single-transaction", "--quick", "--routines",
        "--triggers", "--events", "--ignore-table=misp.audit_logs", "misp",
    ]  # fmt: skip
    _pipe(first, ["zstd", "-q", "-T0", "-3", "-o", out])
    return verify({"path": out})


def verify(cfg: dict) -> dict:
    """The file decompresses whole and its last kilobyte holds the dump's completion line."""
    path = _abs(cfg.get("path"), "path")
    st = os.lstat(path)
    if not stat.S_ISREG(st.st_mode):
        raise Refusal("not a regular file")
    tail = b""
    p = subprocess.Popen(["zstd", "-dc", "--", path], stdout=subprocess.PIPE)
    assert p.stdout is not None
    total = 0
    while chunk := p.stdout.read(CHUNK):
        total += len(chunk)
        tail = (tail + chunk)[-1024:]
    if p.wait() != 0:
        raise Refusal("the dump does not decompress")
    if COMPLETION not in tail:
        raise Refusal("the dump does not end with the dump's completion line")
    return {"ok": True, "size": st.st_size, "logical": total}


def load(cfg: dict) -> dict:
    compose, dump_path = _abs(cfg.get("compose"), "compose"), _abs(cfg.get("dump"), "dump")
    st = os.lstat(dump_path)
    if not stat.S_ISREG(st.st_mode):
        raise Refusal("the dump is not a regular file")
    second = ["docker", "compose", "-f", compose, "exec", "-T", "-e", "MYSQL_PWD", "db",
              "mariadb", "--user=root", "misp"]  # fmt: skip
    _pipe(["zstd", "-dc", "--", dump_path], second)
    return {"ok": True}


def files(cfg: dict) -> dict:
    """List, check and extract the event directories of the old instance's files tarball."""
    src, dest = _abs(cfg.get("tar"), "tar"), _abs(cfg.get("dest"), "dest")
    if not stat.S_ISDIR(os.lstat(dest).st_mode):
        raise Refusal("the destination is not a directory")
    wanted = []
    with tarfile.open(src, "r:") as tar:
        for m in tar:
            if not (m.name.startswith("files/") and m.name[6:7].isdigit()):
                continue
            if not MEMBER.match(m.name) or ".." in m.name.split("/"):
                raise Refusal("a member under files/ has an unexpected name")
            if not (m.isreg() or m.isdir()):
                raise Refusal("a member under files/ is a link or a device")
            wanted.append(m)
        listed = sum(1 for m in wanted if m.isreg())
        for m in wanted:
            rel = m.name[len("files/") :].rstrip("/")
            target = os.path.join(dest, rel)
            if m.isdir():
                os.makedirs(target, mode=0o750, exist_ok=True)
                continue
            os.makedirs(os.path.dirname(target), mode=0o750, exist_ok=True)
            # a file already there is never replaced and a link is never followed; the modes are
            # the owner's alone (the application's entrypoint takes the directory over at its next
            # start and gives it the web server's user and its own modes)
            fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "wb") as out:
                src_f = tar.extractfile(m)
                assert src_f is not None
                while chunk := src_f.read(CHUNK):
                    out.write(chunk)
    found = 0
    for name in os.listdir(dest):
        if name.isdigit():
            for _root, _dirs, fs in os.walk(os.path.join(dest, name)):
                found += len(fs)
    if found < listed:
        raise Refusal(f"{found} files after extraction, {listed} listed")
    return {"listed": listed, "found": found}


COMMANDS = {"dump": dump, "verify": verify, "load": load, "files": files}


def main(argv: list[str]) -> int:
    if len(argv) != 2 or argv[1] not in COMMANDS:
        sys.stderr.write("usage: hnx_misp.py dump|verify|load|files < settings.json\n")
        return 2
    try:
        cfg = json.loads(sys.stdin.read())
        if not isinstance(cfg, dict):
            raise Refusal("the settings are not an object")
        sys.stdout.write(json.dumps(COMMANDS[argv[1]](cfg), sort_keys=True) + "\n")
        return 0
    except (Refusal, OSError, tarfile.TarError, ValueError) as e:
        sys.stderr.write(f"{argv[1]}: {e}\n")
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
