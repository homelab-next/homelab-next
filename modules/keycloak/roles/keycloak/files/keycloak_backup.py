# SPDX-License-Identifier: Apache-2.0
# hnx-script:
#   id: keycloak-backup
#   kind: tool
#   purpose: List the keycloak role's export, and check an export (and stage its dump through the checked descriptor) before a restore.
#   owner: platform
#   trigger: [role:keycloak]
#   inputs: "listing EXPORT_DIR | check SOURCE DB_UID | stage SOURCE DEST DB_UID DB_GID"
#   outputs: the listing's rows, or the checked files' size and sha256, as JSON on stdout; stage also writes DEST (0600, the database's user)
#   exit:
#     "0": listed, checked or staged
#     "1": the export or the source is refused (the reason on stderr)
#     "2": usage error
"""The keycloak role's export listing and restore check (modules/keycloak/README.md).

    python3 -I keycloak_backup.py listing EXPORT_DIR
    python3 -I keycloak_backup.py check SOURCE_DIR DB_UID

An export (object-tree) is ``db/keycloak.dump`` (PostgreSQL's custom-format dump of the whole
database: the realm, its users and their credentials) and ``realm.json`` (the realm's partial
export: clients, groups, roles, flows and settings; client secrets masked, no users), listed in
``listing.jsonl`` (key, size, sha256).

``listing`` prints that listing's rows (the role writes ``listing.jsonl``, 0600).  ``check`` reads a source and writes
nothing: the directory and every file are opened without following a link, belong to root or
the database's user and are writable by no one else; the listing names exactly the two files
and each is a single-link regular file of its listed size and sha256.  ``stage`` runs the same
check and copies the dump to DEST (created new, 0600, the database's user) through the
descriptor it checked, hashing the bytes it writes, so what is restored is what was hashed.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
import sys

DUMP = "db/keycloak.dump"
FILES = (DUMP, "realm.json")
NF = os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)


def fail(why: str) -> None:
    sys.exit("keycloak restore refused: " + why)


def _digest(fd: int, out: int | None = None) -> tuple[str, int]:
    h, n = hashlib.sha256(), 0
    while True:
        chunk = os.read(fd, 1 << 20)
        if not chunk:
            return h.hexdigest(), n
        h.update(chunk)
        n += len(chunk)
        if out is not None:
            view = memoryview(chunk)
            while view:
                view = view[os.write(out, view) :]


def listing(export: str) -> None:
    rows = []
    for key in FILES:
        path = os.path.join(export, key)
        fd = os.open(path, os.O_RDONLY | NF)
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                fail(key + " is not a regular file")
            sha, size = _digest(fd)
        finally:
            os.close(fd)
        rows.append({"key": key, "sha256": sha, "size": size})
    print(json.dumps(rows, sort_keys=True))


def check(src: str, uid: int, stage: str | None = None, gid: int | None = None) -> None:
    def trusted(st: os.stat_result, what: str) -> None:
        if st.st_uid not in (0, uid) or st.st_mode & 0o022:
            fail(
                what + " must belong to root or the database's user and be writable by no one else"
            )

    try:
        top = os.open(src, os.O_RDONLY | os.O_DIRECTORY | NF)
    except OSError:
        fail("the source is not a directory (or is a link)")
    trusted(os.fstat(top), "the source directory")
    try:
        sub = os.open("db", os.O_RDONLY | os.O_DIRECTORY | NF, dir_fd=top)
    except OSError:
        fail("the source has no db/ directory (or it is a link)")
    trusted(os.fstat(sub), "db/")
    if set(os.listdir(top)) != {"db", "realm.json", "listing.jsonl"}:
        fail("the source holds files the listing does not name, or misses one")
    if set(os.listdir(sub)) != {"keycloak.dump"}:
        fail("db/ holds files the listing does not name, or misses the dump")

    def opened(key: str) -> tuple[int, os.stat_result]:
        parent, name = (sub, key.split("/", 1)[1]) if key.startswith("db/") else (top, key)
        try:
            fd = os.open(name, os.O_RDONLY | NF, dir_fd=parent)
        except OSError:
            fail(key + ": cannot be opened (missing, or a link)")
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
            fail(key + ": not a single-link regular file")
        trusted(st, key)
        return fd, st

    fd, _ = opened("listing.jsonl")
    with os.fdopen(fd, encoding="utf-8") as f:
        text = f.read(1 << 16)
    listed: dict[str, dict] = {}
    for line in text.splitlines():
        if line.strip():
            r = json.loads(line)
            if r.get("key") not in FILES or r["key"] in listed:
                fail("the listing names an unknown or repeated file")
            listed[r["key"]] = r
    if set(listed) != set(FILES):
        fail("the listing does not name both files")
    out = {}
    for key in FILES:
        fd, st = opened(key)
        dest = None
        try:
            if st.st_size != listed[key].get("size"):
                fail(key + ": not the listed size")
            if stage is not None and key == DUMP:
                # copy through the descriptor that was checked, hashing what is written: what
                # is restored is what was hashed, whatever happens to the path meanwhile
                if os.path.lexists(stage):
                    os.unlink(stage)
                dest = os.open(stage, os.O_WRONLY | os.O_CREAT | os.O_EXCL | NF, 0o600)
                sha, _ = _digest(fd, dest)
                os.fsync(dest)
                os.fchown(dest, uid, gid if gid is not None else uid)
            else:
                sha, _ = _digest(fd)
        finally:
            os.close(fd)
            if dest is not None:
                os.close(dest)
        if sha != listed[key].get("sha256"):
            if stage is not None and key == DUMP:
                os.unlink(stage)
            fail(key + ": sha256 differs from the listing")
        out[key] = {"sha256": sha, "size": st.st_size}
    print(json.dumps(out, sort_keys=True))


def main(argv: list[str]) -> int:
    if len(argv) == 3 and argv[1] == "listing":
        listing(argv[2])
        return 0
    if len(argv) == 4 and argv[1] == "check":
        check(argv[2], int(argv[3]))
        return 0
    if len(argv) == 6 and argv[1] == "stage":
        check(argv[2], int(argv[4]), stage=argv[3], gid=int(argv[5]))
        return 0
    print(
        "usage: keycloak_backup.py listing DIR | check SRC DB_UID | stage SRC DEST DB_UID DB_GID",
        file=sys.stderr,
    )
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
