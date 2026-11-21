# SPDX-License-Identifier: Apache-2.0
# hnx-script:
#   id: synapse-cortex-backup
#   kind: tool
#   purpose: Seal, check, stage and prune the synapse_cortex role's backups (a backup made by Synapse's own backup machinery), refusing a copy that is not exactly what its listing says.
#   owner: platform
#   trigger: [role:synapse_cortex]
#   inputs: "seal BACKUP_DIR (manifest JSON on stdin) | check BACKUP_DIR | stage SOURCE DEST | prune BACKUPS_DIR KEEP"
#   outputs: the manifest (check, stage) or the names removed (prune) as JSON on stdout; seal writes hnx-manifest.json and hnx-listing.jsonl (0600) into BACKUP_DIR; stage writes DEST (0700, files 0600)
#   exit:
#     "0": sealed, checked, staged or pruned
#     "1": the backup, the destination or the request is refused (the reason on stderr)
#     "2": usage error
"""The synapse_cortex role's backup seal, check, stage and prune (modules/synapse-cortex/README.md).

    python3 -I synapse_cortex_backup.py seal BACKUP_DIR < manifest.json
    python3 -I synapse_cortex_backup.py check BACKUP_DIR
    python3 -I synapse_cortex_backup.py stage SOURCE_DIR DEST_DIR
    python3 -I synapse_cortex_backup.py prune BACKUPS_DIR KEEP

A backup is a directory the service's own backup machinery wrote (``cell.guid`` and the LMDB
slabs, a runnable service directory).  ``seal`` adds ``hnx-manifest.json`` (what the role
measured: the node count of every form before and after the backup, the version, the image) and
``hnx-listing.jsonl`` (every file's key, size and sha256).  ``check`` reads and writes nothing:
no link, no special file, exactly the listed files and no others, each of its listed size and
sha256, the manifest's format known, the two counts equal (a backup taken while the graph was
changing is not a proof of anything) and not empty (zero nodes where nodes are expected is an
error, never a pass), and a ``cell.guid`` and at least one ``data.mdb`` present.  ``stage`` checks
the source, then copies the listed files (not the manifest or the listing) into DEST, which must
not exist, hashing what it writes, and re-reads DEST against the listing before it reports; it
never deletes anything.  ``prune`` removes the oldest sealed backups beyond KEEP and nothing else.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import sys

FORMAT = "synapse-cortex-export-1"
MANIFEST = "hnx-manifest.json"
LISTING = "hnx-listing.jsonl"
NAME = re.compile(r"\Ahnx-[0-9]{8}T[0-9]{6}Z\Z")
NF = os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)


def fail(why: str) -> None:
    sys.exit("synapse-cortex backup refused: " + why)


def safe_dir(path: str, what: str) -> str:
    """An absolute, canonical path of at least three components that is not, and does not pass through,
    a link: the only kind of path this tool reads from or writes under."""
    if not path.startswith("/") or os.path.normpath(path) != path:
        fail(f"{what} {path!r} is not an absolute canonical path")
    if len([p for p in path.split("/") if p]) < 3:
        fail(f"{what} {path!r} is too shallow")
    if os.path.realpath(path) != path:
        fail(f"{what} {path!r} is, or passes through, a link")
    return path


def walk(root: str) -> list[tuple[str, str]]:
    """(key, path) of every file under ``root``: refuses a link, a special file or a hard-linked one."""
    out = []
    for cur, dirs, files in os.walk(root, followlinks=False):
        for d in dirs:
            if os.path.islink(os.path.join(cur, d)):
                fail(f"{os.path.join(cur, d)} is a link")
        for f in files:
            p = os.path.join(cur, f)
            st = os.lstat(p)
            if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
                fail(f"{p} is not a plain single-link file")
            out.append((os.path.relpath(p, root).replace(os.sep, "/"), p))
    return sorted(out)


def digest(path: str, out_path: str | None = None) -> tuple[str, int]:
    fd = os.open(path, os.O_RDONLY | NF)
    ofd = None
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            fail(f"{path} is not a regular file")
        if out_path is not None:
            ofd = os.open(out_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | NF, 0o600)
        h, n = hashlib.sha256(), 0
        while chunk := os.read(fd, 1 << 20):
            h.update(chunk)
            n += len(chunk)
            if ofd is not None:
                view = memoryview(chunk)
                while view:
                    view = view[os.write(ofd, view) :]
        return h.hexdigest(), n
    finally:
        os.close(fd)
        if ofd is not None:
            os.close(ofd)


def rows_of(root: str, skip: tuple[str, ...] = ()) -> list[dict]:
    rows = []
    for key, p in walk(root):
        if key in skip:
            continue
        sha, size = digest(p)
        rows.append({"key": key, "size": size, "sha256": sha})
    return rows


def total_nodes(counts: object) -> int:
    if not isinstance(counts, dict) or not counts:
        return 0
    if not all(
        isinstance(k, str) and isinstance(v, int) and not isinstance(v, bool) and v >= 0
        for k, v in counts.items()
    ):
        fail("a form count is not a non-negative integer")
    return sum(counts.values())


def read_manifest(path: str) -> dict:
    try:
        with open(path, "rb") as fh:
            doc = json.loads(fh.read(1 << 22))
    except (OSError, ValueError) as e:
        fail(f"{path} is not readable JSON ({type(e).__name__})")
    if not isinstance(doc, dict) or doc.get("format") != FORMAT:
        fail(f"{path} is not a {FORMAT} manifest")
    return doc


def read_listing(path: str) -> list[dict]:
    try:
        with open(path, encoding="utf-8") as fh:
            return [json.loads(x) for x in fh.read().splitlines() if x]
    except ValueError:
        fail(f"{path} is not JSON lines")


def check(src: str) -> dict:
    src = safe_dir(src, "the backup")
    if not os.path.isdir(src):
        fail(f"{src} is not a directory")
    listing_path = os.path.join(src, LISTING)
    manifest_path = os.path.join(src, MANIFEST)
    for p in (listing_path, manifest_path):
        if not os.path.isfile(p) or os.path.islink(p):
            fail(f"{p} is missing: the backup was never sealed (an unsealed one is not a backup)")
    manifest = read_manifest(manifest_path)
    before, after = manifest.get("counts_before"), manifest.get("counts_after")
    if total_nodes(before) == 0 or total_nodes(after) == 0:
        fail("the manifest holds no node counts (an empty graph is not a backup to restore)")
    if before != after:
        fail(
            "the graph changed while the backup was taken (counts_before differs from counts_after): take it again with the writers stopped"
        )
    listed = read_listing(listing_path)
    keys = [r.get("key") for r in listed]
    if not listed or len(set(keys)) != len(keys) or not all(isinstance(k, str) for k in keys):
        fail("the listing is empty, repeats a key or names a non-string")
    if any(k.startswith("/") or ".." in k.split("/") or k in (MANIFEST, LISTING) for k in keys):
        fail("the listing names a path outside the backup, or the manifest or listing itself")
    if "cell.guid" not in keys or not any(k.endswith("data.mdb") for k in keys):
        fail("the listing has no cell.guid or no LMDB slab: this is not a service directory")
    actual = rows_of(src, skip=(MANIFEST, LISTING))
    if actual != sorted(listed, key=lambda r: r["key"]):
        want, have = {r["key"] for r in listed}, {r["key"] for r in actual}
        fail(
            "the directory is not exactly what its listing says "
            f"(missing {sorted(want - have)[:5]}, extra {sorted(have - want)[:5]}, or a size or sha256 differs)"
        )
    return manifest


def seal(dest: str) -> None:
    dest = safe_dir(dest, "the backup")
    if not os.path.isdir(dest):
        fail(f"{dest} is not a directory")
    try:
        manifest = json.loads(sys.stdin.read(1 << 22))
    except ValueError:
        fail("the manifest on stdin is not JSON")
    if not isinstance(manifest, dict):
        fail("the manifest on stdin is not an object")
    manifest["format"] = FORMAT
    for p in (MANIFEST, LISTING):
        if os.path.lexists(os.path.join(dest, p)):
            fail(f"{p} exists: a backup is sealed once")
    rows = rows_of(dest)
    with open(os.path.join(dest, MANIFEST), "x") as fh:
        fh.write(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    os.chmod(os.path.join(dest, MANIFEST), 0o600)
    with open(os.path.join(dest, LISTING), "x") as fh:
        fh.write("".join(json.dumps(r, sort_keys=True) + "\n" for r in rows))
    os.chmod(os.path.join(dest, LISTING), 0o600)
    check(dest)  # what was just written must pass the check the restore will run


def stage(src: str, dest: str) -> dict:
    manifest = check(src)
    src = os.path.realpath(src)
    parent = safe_dir(os.path.dirname(dest), "the destination's parent")
    if not os.path.isdir(parent):
        fail(f"{parent} is not a directory")
    if (
        dest != os.path.join(parent, os.path.basename(dest))
        or not os.path.basename(dest)
        or os.path.lexists(dest)
    ):
        fail(f"the destination {dest!r} exists or is not a plain name under its parent")
    if dest == src or dest.startswith(src + "/") or src.startswith(dest + "/"):
        fail("the destination and the source are the same or nested")
    listed = read_listing(os.path.join(src, LISTING))
    os.mkdir(dest, 0o700)
    for row in listed:
        target = os.path.join(dest, row["key"])
        os.makedirs(os.path.dirname(target), mode=0o700, exist_ok=True)
        sha, size = digest(os.path.join(src, row["key"]), target)
        if (sha, size) != (row["sha256"], row["size"]):
            fail(
                f"{row['key']} changed while it was copied; {dest} is left for inspection, not removed"
            )
    if rows_of(dest) != sorted(listed, key=lambda r: r["key"]):
        fail(
            f"{dest} is not exactly the listed files after the copy; it is left for inspection, not removed"
        )
    return manifest


def prune(backups: str, keep: int) -> list[str]:
    backups = safe_dir(backups, "the backups directory")
    if keep < 1:
        fail("keep at least one backup")
    sealed = []
    for name in sorted(os.listdir(backups)):
        p = os.path.join(backups, name)
        if (
            NAME.match(name)
            and os.path.isdir(p)
            and not os.path.islink(p)
            and os.path.isfile(os.path.join(p, MANIFEST))
        ):
            sealed.append(name)
    removed = []
    for name in sealed[: max(0, len(sealed) - keep)]:
        p = os.path.join(backups, name)
        if os.path.dirname(os.path.realpath(p)) != backups or os.path.realpath(p) != p:
            fail(f"{p} is not a direct child of {backups}")
        shutil.rmtree(p)
        removed.append(name)
    return removed


def main(argv: list[str]) -> int:
    try:
        if len(argv) == 3 and argv[1] == "seal":
            seal(argv[2])
        elif len(argv) == 3 and argv[1] == "check":
            print(json.dumps(check(argv[2]), sort_keys=True))
        elif len(argv) == 4 and argv[1] == "stage":
            print(json.dumps(stage(argv[2], argv[3]), sort_keys=True))
        elif len(argv) == 4 and argv[1] == "prune":
            print(json.dumps(prune(argv[2], int(argv[3]))))
        else:
            print(__doc__, file=sys.stderr)
            return 2
    except OSError as e:
        fail(f"{type(e).__name__}: {e.filename or ''}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
