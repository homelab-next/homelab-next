# SPDX-License-Identifier: Apache-2.0
# hnx-script:
#   id: lakekeeper-backup
#   kind: tool
#   purpose: List the lakekeeper role's export, and check an export (and stage its dump through the checked descriptor) before a restore.
#   owner: platform
#   trigger: [role:lakekeeper]
#   inputs: "listing EXPORT_DIR | check SOURCE DB_UID | stage SOURCE DEST DB_UID DB_GID"
#   outputs: the dump's key, size and sha256 as JSON on stdout; stage also writes DEST (0600, the database's user)
#   exit:
#     "0": listed, checked or staged
#     "1": the export or the source is refused (the reason on stderr)
#     "2": usage error
"""The lakekeeper role's export listing and restore check (modules/lakekeeper/README.md).

    python3 -I lakekeeper_backup.py listing EXPORT_DIR
    python3 -I lakekeeper_backup.py check SOURCE_DIR DB_UID
    python3 -I lakekeeper_backup.py stage SOURCE_DIR DEST DB_UID DB_GID

An export (object-tree) is ``db/lakekeeper.dump``, PostgreSQL's custom-format dump of the catalog
database, named with its size and sha256 in ``listing.jsonl``. ``listing`` prints the dump's row (the
role writes ``listing.jsonl``, 0600). ``check`` reads a source and writes nothing: the directories
and both files are opened without following a link, are single-link regular files, belong to root
or the database's user and are writable by no one else, nothing else is in the source, and the dump
has the listed size and sha256. ``stage`` is ``check`` plus a copy of the dump to DEST (new, 0600,
the database's user), written from the descriptor that was hashed, so what is restored is what was
checked.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
import sys

KEY = "db/lakekeeper.dump"
NOFOLLOW = os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)


def refuse(why: str) -> None:
    sys.exit("lakekeeper restore refused: " + why)


def sha256_of(fd: int, copy_to: int | None = None) -> str:
    digest = hashlib.sha256()
    while block := os.read(fd, 1 << 20):
        digest.update(block)
        if copy_to is not None:
            view = memoryview(block)
            while view:
                view = view[os.write(copy_to, view) :]
    return digest.hexdigest()


def open_dir(name: str, parent: int | None = None) -> int:
    try:
        return os.open(name, os.O_RDONLY | os.O_DIRECTORY | NOFOLLOW, dir_fd=parent)
    except OSError:
        refuse(f"{name}: not a directory (or a link)")
        raise


def trusted(info: os.stat_result, what: str, db_uid: int) -> None:
    if info.st_uid not in (0, db_uid) or info.st_mode & 0o022:
        refuse(f"{what} must belong to root or the database's user and be writable by no one else")


def open_file(parent: int, name: str, db_uid: int | None) -> tuple[int, os.stat_result]:
    try:
        fd = os.open(name, os.O_RDONLY | NOFOLLOW, dir_fd=parent)
    except OSError:
        refuse(f"{name}: cannot be opened (missing, or a link)")
        raise
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        refuse(f"{name}: not a single-link regular file")
    if (
        db_uid is not None
    ):  # a listing reads what this host's database just wrote; a restore trusts nothing
        trusted(info, name, db_uid)
    return fd, info


def listing(export: str) -> None:
    top = open_dir(export)
    fd, info = open_file(open_dir("db", top), "lakekeeper.dump", None)
    row = {"key": KEY, "sha256": sha256_of(fd), "size": info.st_size}
    print(json.dumps([row], sort_keys=True))


def check(source: str, db_uid: int, dest: str | None = None, db_gid: int | None = None) -> None:
    top = open_dir(source)
    trusted(os.fstat(top), "the source directory", db_uid)
    sub = open_dir("db", top)
    trusted(os.fstat(sub), "db/", db_uid)
    if set(os.listdir(top)) != {"db", "listing.jsonl"} or set(os.listdir(sub)) != {
        "lakekeeper.dump"
    }:
        refuse("the source holds files the listing does not name, or misses one")
    lfd, _ = open_file(top, "listing.jsonl", db_uid)
    with os.fdopen(lfd, encoding="utf-8") as handle:
        rows = [json.loads(line) for line in handle.read(1 << 16).splitlines() if line.strip()]
    if len(rows) != 1 or rows[0].get("key") != KEY:
        refuse("the listing must name exactly " + KEY)
    fd, info = open_file(sub, "lakekeeper.dump", db_uid)
    if info.st_size != rows[0].get("size"):
        refuse(KEY + ": not the listed size")
    out = None
    try:
        if dest is not None:
            if os.path.lexists(dest):
                os.unlink(dest)
            out = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL | NOFOLLOW, 0o600)
        got = sha256_of(fd, out)
        if out is not None:
            os.fsync(out)
            os.fchown(out, db_uid, db_gid if db_gid is not None else db_uid)
    finally:
        os.close(fd)
        if out is not None:
            os.close(out)
    if got != rows[0].get("sha256"):
        if dest is not None:
            os.unlink(dest)
        refuse(KEY + ": sha256 differs from the listing")
    print(json.dumps({KEY: {"sha256": got, "size": info.st_size}}, sort_keys=True))


def main(argv: list[str]) -> int:
    commands = {"listing": (1, lambda a: listing(a[0])),
                "check": (2, lambda a: check(a[0], int(a[1]))),
                "stage": (4, lambda a: check(a[0], int(a[2]), dest=a[1], db_gid=int(a[3])))}  # fmt: skip
    if len(argv) < 2 or argv[1] not in commands or len(argv) - 2 != commands[argv[1]][0]:
        print("usage: lakekeeper_backup.py listing DIR | check SRC DB_UID | stage SRC DEST DB_UID DB_GID",
              file=sys.stderr)  # fmt: skip
        return 2
    commands[argv[1]][1](argv[2:])
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
