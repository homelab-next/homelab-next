#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# hnx-script:
#   id: forge-restore
#   kind: tool
#   purpose: Place a forge dump into the module's data directory beside what is there (renamed, never deleted), taking only the repositories and the data directories the role does not own.
#   owner: platform
#   trigger: [role:gitea]
#   inputs: "the data directory, the dump, the container's ids and a stamp as JSON on standard input"
#   outputs: JSON of what was placed, what was set aside and the restored database's counts
#   exit:
#     "0": placed
#     "1": refused or failed (the reason on stderr; the live paths are as they were)
"""Place a Gitea dump (``gitea dump``, a zip) into the module's data directory (run as root on the
guest, with the service STOPPED: ``python3 -I gitea_restore.py`` and its settings as JSON on
standard input).

Settings: ``data`` (the directory mounted as the container's application data path), ``zip``
(the dump), ``uid``/``gid`` (the container's user), ``allow_empty`` and ``stamp`` (a suffix that
names this restore, e.g. ``20261116T120000Z``).

What it does, in order, and nothing before the checks have passed:

1. the data directory must be an absolute canonical path of at least three components, a real
   directory (no symbolic link in it), and no ``.restore-stage`` may be left from an earlier run;
2. the zip is read member by member: an absolute name, ``..``, a backslash, a NUL or a symbolic
   link is refused, and only ``repos/`` and ``data/<avatars|repo-avatars|attachments|packages|jwt|
   custom>/`` are taken (the SSH host keys, the configuration and the logs are not: the role owns
   them); everything is written into the stage directory, never into a live path;
3. the database is rebuilt from ``gitea-db.sql`` into a new SQLite file in the stage and must pass
   ``PRAGMA integrity_check`` and :func:`hnx_gitea.db_facts` (an unrecognised schema, or no account,
   is an error); a dump with no repository is an error unless ``allow_empty``;
4. the stage is given to the container's user (``lchown``: links are never followed);
5. each live path that exists is renamed to ``<name>.before-restore.<stamp>`` (never deleted: that
   is the operator's to remove once the restore is proved) and the stage's item takes its place by
   rename.  If a rename fails the ones already made are undone.

Nothing is removed except the stage directory this run created, and only after its contents have
all been renamed out or the run failed before the swap.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import stat
import sys
import zipfile
from pathlib import Path, PurePosixPath

sys.dont_write_bytecode = True  # the helper beside this file is imported, never compiled to disk
sys.path.insert(0, str(Path(__file__).resolve().parent))
import hnx_gitea  # noqa: E402  (the helper beside this file)

DATA_DIRS = ("avatars", "repo-avatars", "attachments", "packages", "jwt", "custom")
STAGE = ".restore-stage"
SIDECARS = ("-wal", "-shm", "-journal")
MAX_MEMBERS = 5_000_000
MAX_BYTES = 64 << 30
_STAMP = re.compile(r"[0-9A-Za-z]{8,32}\Z")


class RestoreError(RuntimeError):
    pass


def guard_data(path: str) -> Path:
    p = PurePosixPath(path)
    if not path.startswith("/") or str(p) != path or ".." in p.parts or "." in p.parts:
        raise RestoreError(f"{path!r}: not an absolute canonical path")
    if len(p.parts) < 4:
        raise RestoreError(
            f"{path!r}: refusing to restore into a path of fewer than three components"
        )
    real = Path(os.path.realpath(path))
    if str(real) != path or not real.is_dir():
        raise RestoreError(f"{path!r}: not a real directory (a symbolic link in the path?)")
    return real


def member_target(name: str) -> tuple[str, str] | None:
    """(kind, relative path inside the stage) for a member that is taken, None for one that is
    not; raises for a name that must never be extracted."""
    if "\\" in name or "\0" in name or name.startswith("/"):
        raise RestoreError(f"refusing the member {name!r}")
    parts = PurePosixPath(name).parts
    if ".." in parts or "." in parts:
        raise RestoreError(f"refusing the member {name!r}")
    if not parts:
        return None
    if parts[0] == "repos" and len(parts) >= 2:
        return "repos", str(PurePosixPath("git/repositories", *parts[1:]))
    if parts[0] == "data" and len(parts) >= 3 and parts[1] in DATA_DIRS:
        return "data", str(PurePosixPath(*parts[1:]))
    return None


def extract(zpath: str, stage: Path) -> dict:
    taken = {"repos": 0, "data": 0, "bytes": 0}
    with zipfile.ZipFile(zpath) as z:
        infos = z.infolist()
        if len(infos) > MAX_MEMBERS:
            raise RestoreError("the dump has too many members")
        for info in infos:
            mode = info.external_attr >> 16
            if stat.S_ISLNK(mode):
                raise RestoreError(f"refusing the symbolic link {info.filename!r}")
            target = member_target(info.filename)
            if target is None:
                continue
            kind, rel = target
            dest = stage / rel
            if info.is_dir():
                dest.mkdir(parents=True, exist_ok=True, mode=0o750)
                continue
            taken[kind] += 1
            taken["bytes"] += info.file_size
            if taken["bytes"] > MAX_BYTES:
                raise RestoreError("the dump is larger than the restore accepts")
            dest.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
            perm = (mode & 0o700) | 0o600  # the container's user only: nothing here is for a group
            with (
                z.open(info) as src,
                os.fdopen(os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL, perm), "wb") as out,
            ):
                shutil.copyfileobj(src, out, 1 << 20)
            os.chmod(dest, perm)
    return taken


def build_db(zpath: str, dest: Path) -> dict:
    with zipfile.ZipFile(zpath) as z:
        try:
            sql = z.read("gitea-db.sql").decode("utf-8")
        except KeyError:
            raise RestoreError(
                "the dump has no gitea-db.sql (a dump of another database type?)"
            ) from None
    conn = hnx_gitea.sql_connection(str(dest))
    try:
        hnx_gitea.load_sql(conn, sql)
        conn.set_authorizer(None)
        conn.commit()
        if conn.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
            raise RestoreError("the rebuilt database fails its integrity check")
        return hnx_gitea.db_facts(conn)
    finally:
        conn.close()
    # (the file is the stage's: no journal is left because the connection is closed)


def chown_tree(root: Path, uid: int, gid: int) -> None:
    os.lchown(root, uid, gid)
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        for n in (*dirnames, *filenames):
            os.lchown(os.path.join(dirpath, n), uid, gid)


def restore(cfg: dict) -> dict:
    data = guard_data(cfg["data"])
    stamp = str(cfg["stamp"])
    if not _STAMP.fullmatch(stamp):
        raise RestoreError("stamp: 8 to 32 letters and digits")
    zpath = cfg["zip"]
    if not os.path.isfile(zpath) or os.path.islink(zpath):
        raise RestoreError(f"{zpath!r}: not a regular file")
    stage = data / STAGE
    if os.path.lexists(stage):
        raise RestoreError(f"{stage}: left by an earlier restore; inspect it and remove it first")
    stage.mkdir(mode=0o700)
    swapped: list[tuple[Path, Path]] = []
    try:
        taken = extract(zpath, stage)
        if taken["repos"] == 0 and not cfg.get("allow_empty"):
            raise RestoreError("the dump holds no repository file: refusing a vacuous restore")
        facts = build_db(zpath, stage / "gitea.db")
        if facts["counts"]["repos"] == 0 and not cfg.get("allow_empty"):
            raise RestoreError(
                "the dump's database lists no repository: refusing a vacuous restore"
            )
        chown_tree(stage, int(cfg["uid"]), int(cfg["gid"]))
        items = ["gitea.db"]
        items += ["git/repositories"] if (stage / "git" / "repositories").is_dir() else []
        items += [d for d in DATA_DIRS if (stage / d).is_dir()]
        aside = []
        for rel in items:
            live = data / rel
            if os.path.islink(live):
                raise RestoreError(f"{live}: is a symbolic link")
            names = [live] + ([Path(str(live) + s) for s in SIDECARS] if rel == "gitea.db" else [])
            for old in names:
                if os.path.lexists(old):
                    moved = Path(f"{old}.before-restore.{stamp}")
                    if os.path.lexists(moved):
                        raise RestoreError(f"{moved}: already exists")
                    os.rename(old, moved)
                    swapped.append((moved, old))
                    aside.append(str(moved))
            live.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
            os.rename(stage / rel, live)
            swapped.append((live, stage / rel))
        # the stage now holds empty directories only; rmdir (never a recursive delete) proves it
        leftover = []
        for dirpath, _dirs, _files in os.walk(stage, topdown=False):
            try:
                os.rmdir(dirpath)
            except OSError:
                leftover.append(dirpath)
        # git/ may have been created by the rename's mkdir: it must be the container's too
        if os.path.isdir(data / "git") and not os.path.islink(data / "git"):
            os.lchown(data / "git", int(cfg["uid"]), int(cfg["gid"]))
        return {"restored": items, "aside": aside, "leftover": leftover, "taken": taken, **facts}
    except BaseException:
        undone = True
        for src, dst in reversed(swapped):
            try:
                os.rename(src, dst)
            except OSError:
                undone = False
        # the only recursive delete: the stage this run created (a real directory named STAGE in
        # the data directory), and only when every swap it made was undone
        if undone and os.path.isdir(stage) and not os.path.islink(stage) and stage.parent == data:
            shutil.rmtree(stage, ignore_errors=True)
        raise


def main() -> int:
    try:
        print(json.dumps(restore(json.load(sys.stdin)), sort_keys=True))
    except (
        RestoreError,
        hnx_gitea.HelperError,
        OSError,
        KeyError,
        ValueError,
        *hnx_gitea.SQLITE_ERRORS,
        zipfile.BadZipFile,
    ) as exc:
        print(f"{type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
