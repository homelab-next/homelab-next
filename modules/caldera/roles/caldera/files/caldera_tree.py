#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Export, check and restore the server's data as an object tree (modules/caldera README, "Data").

    caldera_tree.py export  <source tree> <export root>
    caldera_tree.py check   <snapshot>
    caldera_tree.py restore <snapshot> <source tree>

A snapshot is ``<export root>/<stamp>/`` holding ``files/<key>`` and ``listing.jsonl`` (one JSON
object per file: key, size, sha256, dataset). It is staged in a sibling directory and renamed into
place; an earlier snapshot is never touched. Only the dataset roots below are read or written, only
regular files are followed (a link or special file is skipped and counted), and the generated
configuration (conf/local.yml, which holds the passwords) is not among them. ``check`` and
``restore`` refuse, before changing anything: a key that traverses or leaves a dataset root, a link
or special file or a file with a second hard link in the snapshot, an unlisted file, a size or
sha256 that differs, a duplicate key (also case-insensitively) and an empty listing (a snapshot of
nothing proves nothing). Exit 0 on success, 2 on a refusal, with the reason on stderr.
"""

from __future__ import annotations

import datetime
import hashlib
import json
import os
import shutil
import stat
import sys
import unicodedata

# dataset id -> the paths (relative to the source tree) it owns. The object store holds both the
# operations and the agents; it is listed once, under operations.
DATASETS = {
    "operations": ["data/object_store", "data/results"],
    "adversaries": ["data/adversaries", "data/abilities", "data/objectives"],
    "agents": ["conf/agents.yml", "conf/payloads.yml"],
    "artifacts": ["data/payloads", "data/sources", "data/facts", "data/fact_store"],
}
SKIP_NAMES = {".gitkeep"}
CHUNK = 1 << 20


class Refused(Exception):
    pass


def _roots() -> list[tuple[str, str]]:
    return [(root, ds) for ds, roots in DATASETS.items() for root in roots]


def dataset_of(key: str) -> str | None:
    for root, ds in _roots():
        if key == root or key.startswith(root + "/"):
            return ds
    return None


def _safe_key(key: object) -> str:
    if not isinstance(key, str) or not key or key != unicodedata.normalize("NFC", key):
        raise Refused(f"bad key {key!r}")
    if key.startswith("/") or "\\" in key or any(ord(c) < 32 or ord(c) == 127 for c in key):
        raise Refused(f"bad key {key!r}")
    if any(p in ("", ".", "..") for p in key.split("/")):
        raise Refused(f"bad key {key!r}")
    if dataset_of(key) is None:
        raise Refused(f"key {key!r} is outside every dataset root")
    return key


def _absolute_dir(path: str, what: str) -> str:
    real = os.path.abspath(path)
    parts = [p for p in real.split(os.sep) if p]
    if path != real or len(parts) < 3:
        raise Refused(f"{what} {path!r} must be a canonical absolute path of three or more parts")
    if os.path.islink(real) or not os.path.isdir(real):
        raise Refused(f"{what} {path!r} is not a directory (or is a link)")
    return real


def _hash_copy(src_fd: int, dst_fd: int | None) -> tuple[int, str]:
    h = hashlib.sha256()
    size = 0
    while True:
        chunk = os.read(src_fd, CHUNK)
        if not chunk:
            break
        h.update(chunk)
        size += len(chunk)
        if dst_fd is not None:
            os.write(dst_fd, chunk)
    return size, h.hexdigest()


def _open_regular(path: str) -> int:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    st = os.fstat(fd)
    if not stat.S_ISREG(st.st_mode):
        os.close(fd)
        raise Refused(f"{path} is not a regular file")
    return fd


def _walk(source: str):
    """Yield (key, dataset, abs path) of the regular files under the dataset roots; count the rest."""
    skipped = 0
    found = []
    for root, ds in _roots():
        top = os.path.join(source, root)
        try:
            st = os.lstat(top)
        except FileNotFoundError:
            continue
        if stat.S_ISREG(st.st_mode):
            found.append((root, ds, top))
            continue
        if not stat.S_ISDIR(st.st_mode):
            skipped += 1
            continue
        for dirpath, dirnames, filenames in os.walk(top, followlinks=False):
            keep = []
            for d in dirnames:
                if os.path.islink(os.path.join(dirpath, d)):
                    skipped += 1
                else:
                    keep.append(d)
            dirnames[:] = keep
            for name in filenames:
                path = os.path.join(dirpath, name)
                if name in SKIP_NAMES:
                    continue
                if not stat.S_ISREG(os.lstat(path).st_mode):
                    skipped += 1
                    continue
                found.append((os.path.relpath(path, source).replace(os.sep, "/"), ds, path))
    return sorted(found), skipped


def export(source: str, export_root: str) -> dict:
    source = _absolute_dir(source, "source tree")
    export_root = _absolute_dir(export_root, "export root")
    stamp = datetime.datetime.now(datetime.UTC).strftime("%Y%m%dT%H%M%S%fZ")
    final = os.path.join(export_root, stamp)
    stage = os.path.join(export_root, f".{stamp}.tmp")
    if os.path.lexists(final) or os.path.lexists(stage):
        raise Refused(f"{final} or its staging directory exists")
    files, skipped = _walk(source)
    os.mkdir(stage, 0o700)
    try:
        rows = []
        total = 0
        for key, ds, path in files:
            _safe_key(key)
            dest = os.path.join(stage, "files", key)
            os.makedirs(os.path.dirname(dest), mode=0o700, exist_ok=True)
            src_fd = _open_regular(path)
            try:
                dst_fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                try:
                    size, digest = _hash_copy(src_fd, dst_fd)
                    os.fsync(dst_fd)
                finally:
                    os.close(dst_fd)
            finally:
                os.close(src_fd)
            rows.append({"key": key, "size": size, "sha256": digest, "dataset": ds})
            total += size
        with open(os.path.join(stage, "listing.jsonl"), "w", encoding="utf-8") as f:
            for row in rows:
                f.write(json.dumps(row, sort_keys=True) + "\n")
            f.flush()
            os.fsync(f.fileno())
        os.rename(stage, final)
    except BaseException:
        _remove_own_stage(stage, export_root)
        raise
    return {
        "snapshot": final,
        "files": len(rows),
        "bytes": total,
        "skipped": skipped,
        "empty": not rows,
    }


def _remove_own_stage(stage: str, export_root: str) -> None:
    """Remove a half-written staging directory this run made, and nothing else."""
    parent, name = os.path.split(stage)
    if parent != export_root or not (name.startswith(".") and name.endswith(".tmp")):
        return
    if os.path.islink(stage) or not os.path.isdir(stage):
        return
    shutil.rmtree(stage)


def _listing(snapshot: str) -> list[dict]:
    path = os.path.join(snapshot, "listing.jsonl")
    try:
        fd = _open_regular(path)
    except OSError as exc:
        raise Refused(f"no readable listing.jsonl in {snapshot}: {exc.strerror}") from None
    with os.fdopen(fd, encoding="utf-8") as f:
        text = f.read()
    rows = []
    for n, line in enumerate(text.splitlines(), 1):
        try:
            row = json.loads(line)
        except ValueError:
            raise Refused(f"listing.jsonl line {n} is not JSON") from None
        if (
            not isinstance(row, dict)
            or set(row) != {"key", "size", "sha256", "dataset"}
            or not isinstance(row["size"], int)
            or isinstance(row["size"], bool)
            or row["size"] < 0
            or not isinstance(row["sha256"], str)
        ):
            raise Refused(f"listing.jsonl line {n} is not a listing row")
        _safe_key(row["key"])
        if dataset_of(row["key"]) != row["dataset"]:
            raise Refused(
                f"listing.jsonl line {n}: {row['key']} is not in dataset {row['dataset']}"
            )
        rows.append(row)
    if not rows:
        raise Refused("the listing is empty: a snapshot of nothing is not restorable")
    folded = [r["key"].casefold() for r in rows]
    if len(set(folded)) != len(folded):
        raise Refused("the listing repeats a key (compared case-insensitively)")
    return rows


def check(snapshot: str) -> dict:
    snapshot = _absolute_dir(snapshot, "snapshot")
    rows = _listing(snapshot)
    base = os.path.join(snapshot, "files")
    if os.path.islink(base) or not os.path.isdir(base):
        raise Refused("the snapshot has no files/ directory")
    listed = {r["key"] for r in rows}
    for dirpath, dirnames, filenames in os.walk(base, followlinks=False):
        for name in dirnames + filenames:
            p = os.path.join(dirpath, name)
            st = os.lstat(p)
            if stat.S_ISLNK(st.st_mode) or not (
                stat.S_ISREG(st.st_mode) or stat.S_ISDIR(st.st_mode)
            ):
                raise Refused(f"{p} is a link or a special file")
            if stat.S_ISREG(st.st_mode):
                if st.st_nlink != 1:
                    raise Refused(f"{p} has a second hard link")
                key = os.path.relpath(p, base).replace(os.sep, "/")
                if key not in listed:
                    raise Refused(f"{key} is in the snapshot but not in its listing")
    total = 0
    for row in rows:
        path = os.path.join(base, row["key"])
        try:
            fd = _open_regular(path)
        except FileNotFoundError:
            raise Refused(f"{row['key']} is listed but missing") from None
        except OSError as exc:
            raise Refused(f"{row['key']} cannot be opened safely: {exc.strerror}") from None
        try:
            size, digest = _hash_copy(fd, None)
        finally:
            os.close(fd)
        if size != row["size"] or digest != row["sha256"]:
            raise Refused(f"{row['key']} differs from its listing (size or sha256)")
        total += size
    return {"snapshot": snapshot, "files": len(rows), "bytes": total}


def _no_link_in(source: str, key: str) -> None:
    cur = source
    for part in key.split("/")[:-1]:
        cur = os.path.join(cur, part)
        if os.path.islink(cur):
            raise Refused(f"{cur} is a link")


def restore(snapshot: str, source: str) -> dict:
    source = _absolute_dir(source, "source tree")
    summary = check(snapshot)
    rows = _listing(summary["snapshot"])
    base = os.path.join(summary["snapshot"], "files")
    for row in rows:  # judge every target before writing one
        _no_link_in(source, row["key"])
        target = os.path.join(source, row["key"])
        if os.path.lexists(target) and not stat.S_ISREG(os.lstat(target).st_mode):
            raise Refused(f"{target} exists and is not a regular file")
    for row in rows:
        target = os.path.join(source, row["key"])
        os.makedirs(os.path.dirname(target), exist_ok=True)
        tmp = target + ".hnx-restore.tmp"
        if os.path.lexists(tmp):
            raise Refused(f"{tmp} exists (an earlier restore stopped half way)")
        src_fd = _open_regular(os.path.join(base, row["key"]))
        try:
            dst_fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            try:
                size, digest = _hash_copy(src_fd, dst_fd)
                os.fsync(dst_fd)
            finally:
                os.close(dst_fd)
        finally:
            os.close(src_fd)
        if size != row["size"] or digest != row["sha256"]:
            os.unlink(tmp)
            raise Refused(f"{row['key']} changed while it was being copied")
        os.replace(tmp, target)
    return {"restored": len(rows), "bytes": summary["bytes"]}


def main(argv: list[str]) -> int:
    usage = "usage: caldera_tree.py export <source> <root> | check <snapshot> | restore <snapshot> <source>"
    try:
        if len(argv) == 4 and argv[1] == "export":
            out = export(argv[2], argv[3])
        elif len(argv) == 3 and argv[1] == "check":
            out = check(argv[2])
        elif len(argv) == 4 and argv[1] == "restore":
            out = restore(argv[2], argv[3])
        else:
            print(usage, file=sys.stderr)
            return 2
    except Refused as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(out, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
