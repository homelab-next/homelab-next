#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Import an existing media-server config/data directory into a new one, keeping its identity.

A client (a TV app, a set-top box) remembers a server by its id and its signed-in device tokens.
A new id, or a lost device row, makes it treat the server as a stranger and drop the login. So the
import carries, unchanged: the server id (``data/device.txt``), the server name and settings
(``config/*.xml``), the users, the devices and their tokens, and the watch state (the databases).
It changes only what the new host forces, and says so in the report:

* **library paths**, old prefix to new (``--map /media=/srv/media``), in the databases (through
  SQL, parameterised, one column value at a time: never a byte substitution, which corrupts the
  length prefixes of a SQLite record) and in the library definitions (``root/``, ``config/*.xml``);
* **hardware acceleration** is set to ``none`` (the new host may have no GPU; the old
  ``encoding.xml`` named one) unless ``hardware_accel=None`` leaves it as it was;
* **Quick Connect** is kept enabled (TV apps sign in with it).

Everything is verified after the copy: the server id is byte-identical and the counts of users,
devices, libraries, items and watch-state rows read from the target equal those read from the
source (``ImportError`` otherwise, the target left in place for inspection).

``counts(data_dir)`` reads a config/data directory read-only and returns ``{users, devices,
libraries, items, watch_state}``; the id is ``server_id(data_dir)``.

    python3 tools/migrate/jellyfin.py counts DIR
    python3 tools/migrate/jellyfin.py import SRC DST --map /old=/new [--map ...] [--no-accel-reset]

Stop the source server before copying (or point SRC at a snapshot): a database copied while it is
written is the SQLite online backup of one moment, but the files around it are not.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import sqlite3
import sys
from pathlib import Path

# Not carried: caches the server rebuilds, logs, transcodes in flight.
SKIP_DIRS = ("cache", "log", "logs", "transcodes", "transcoding-temp")
TEXT_SUFFIXES = (".xml", ".mblink", ".json")
# table names by schema generation: the 10.11 layout (one EF database) and the earlier two-database one
USER_TABLES = ("Users",)
DEVICE_TABLES = ("Devices",)
ITEM_TABLES = ("BaseItems", "TypedBaseItems")
WATCH_TABLES = ("UserData", "UserDatas")


class ImportFailed(Exception):
    """The import cannot go on, or its result does not match its source."""


def server_id(data_dir: Path) -> str:
    """The server id: the content of ``data/device.txt`` (what a client remembers)."""
    f = Path(data_dir) / "data" / "device.txt"
    if not f.is_file():
        raise ImportFailed(f"{f}: no server id (is this a config/data directory?)")
    return f.read_text(encoding="utf-8").strip()


def _ro(path: Path) -> sqlite3.Connection:
    # immutable=1 reads a database that sits on a read-only snapshot; refuse it when a write-ahead
    # log is present, because immutable ignores the log and would read stale pages
    wal = Path(str(path) + "-wal")
    if wal.exists() and wal.stat().st_size > 0:
        return sqlite3.connect(f"{path.as_uri()}?mode=ro", uri=True)
    return sqlite3.connect(f"{path.as_uri()}?mode=ro&immutable=1", uri=True)


def _count(db_dir: Path, tables: tuple[str, ...]) -> int:
    total = 0
    for db in sorted(db_dir.glob("*.db")):
        c = _ro(db)
        try:
            have = {r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            for t in tables:
                if t in have:
                    total += c.execute(f'SELECT COUNT(*) FROM "{t}"').fetchone()[0]
        finally:
            c.close()
    return total


def libraries(data_dir: Path) -> list[str]:
    """The library (virtual folder) names: one directory each under ``root/default``."""
    root = Path(data_dir) / "root" / "default"
    return sorted(p.name for p in root.iterdir() if p.is_dir()) if root.is_dir() else []


def counts(data_dir: Path) -> dict[str, int]:
    """Users, devices, libraries, items and watch-state rows of a config/data directory, read-only."""
    data_dir = Path(data_dir)
    db_dir = data_dir / "data"
    if not db_dir.is_dir():
        raise ImportFailed(f"{db_dir}: not a config/data directory")
    return {
        "users": _count(db_dir, USER_TABLES),
        "devices": _count(db_dir, DEVICE_TABLES),
        "libraries": len(libraries(data_dir)),
        "items": _count(db_dir, ITEM_TABLES),
        "watch_state": _count(db_dir, WATCH_TABLES),
    }


# ----------------------------------------------------------------------------- path mapping


def _pattern(old: str) -> re.Pattern[str]:
    old = old.rstrip("/") or "/"
    # a real path boundary on both sides: the prefix is not the tail of a longer name
    # (``/data`` inside ``/mydata``) and not the head of one (``/media`` in ``/media2``)
    return re.compile(r"(?<![A-Za-z0-9_.\-/])" + re.escape(old) + r"(?=/|\Z|[<\"'\s,;\\])")


def _rewriter(path_map: dict[str, str]):
    rules = [
        (_pattern(o), n.rstrip("/") or "/")
        for o, n in sorted(path_map.items(), key=lambda kv: -len(kv[0]))
    ]

    def rewrite(text: str) -> str:
        for pat, new in rules:
            text = pat.sub(lambda _m, new=new: new, text)
        return text

    return rewrite


def _rewrite_db(path: Path, rewrite) -> int:
    """Rewrite library paths in every text column of one database; returns the values changed."""
    c = sqlite3.connect(path)
    changed = 0
    try:
        tables = [r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table'")]
        for t in tables:
            cols = [
                r[1]
                for r in c.execute(f'PRAGMA table_info("{t}")')
                if "CHAR" in r[2].upper() or "TEXT" in r[2].upper() or "CLOB" in r[2].upper()
            ]
            for col in cols:
                rows = c.execute(
                    f'SELECT rowid, "{col}" FROM "{t}" WHERE typeof("{col}") = ? AND "{col}" LIKE ?',
                    ("text", "%/%"),
                ).fetchall()
                for rowid, value in rows:
                    new = rewrite(value)
                    if new != value:
                        c.execute(f'UPDATE "{t}" SET "{col}" = ? WHERE rowid = ?', (new, rowid))
                        changed += 1
        c.commit()
        c.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        ok = c.execute("PRAGMA integrity_check").fetchone()[0]
        if ok != "ok":
            raise ImportFailed(f"{path.name}: integrity_check failed after the path rewrite: {ok}")
    finally:
        c.close()
    return changed


# ----------------------------------------------------------------------------- the copy


def _copy_db(src: Path, dst: Path) -> None:
    a = _ro(src)
    b = sqlite3.connect(dst)
    try:
        a.backup(b)
    finally:
        a.close()
        b.close()


def _copy_tree(src: Path, dst: Path) -> None:
    for root, dirs, files in os.walk(src):
        rel = Path(root).relative_to(src)
        dirs[:] = sorted(d for d in dirs if not (rel == Path(".") and d in SKIP_DIRS))
        (dst / rel).mkdir(parents=True, exist_ok=True)
        for name in sorted(files):
            s, d = Path(root) / name, dst / rel / name
            if s.is_symlink():
                continue  # a link in a config tree is not followed into the target
            if name.endswith(("-wal", "-shm")):
                continue  # folded in by the online backup of the database itself
            if name.endswith(".db") and rel == Path("data"):
                _copy_db(s, d)
            else:
                shutil.copy2(s, d)


def _set_xml_value(path: Path, tag: str, value: str, *, create_root: str | None = None) -> bool:
    """Set ``<tag>value</tag>`` in a flat settings file; returns whether the file changed."""
    if path.is_file():
        text = path.read_text(encoding="utf-8")
    elif create_root:
        text = f'<?xml version="1.0" encoding="utf-8"?>\n<{create_root} />\n'
    else:
        return False
    new, n = re.subn(rf"<{tag}>[^<]*</{tag}>", f"<{tag}>{value}</{tag}>", text)
    if n == 0:
        if re.search(rf"<{tag}\s*/>", text):
            new = re.sub(rf"<{tag}\s*/>", f"<{tag}>{value}</{tag}>", text)
        elif re.search(r"<(\w+)\s*/>", text) and "</" not in text.split("?>", 1)[-1]:
            new = re.sub(r"<(\w+)\s*/>", rf"<\1>\n  <{tag}>{value}</{tag}>\n</\1>", text, count=1)
        else:
            new = re.sub(r"(</\w+>\s*)\Z", f"  <{tag}>{value}</{tag}>\n\\1", text, count=1)
    if new == text and path.is_file():
        return False
    path.write_text(new, encoding="utf-8")
    return True


def _rewrite_text_files(root: Path, rewrite) -> int:
    changed = 0
    for p in sorted(root.rglob("*")):
        if p.is_file() and not p.is_symlink() and p.suffix in TEXT_SUFFIXES:
            try:
                text = p.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                continue
            new = rewrite(text)
            if new != text:
                p.write_text(new, encoding="utf-8")
                changed += 1
    return changed


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def import_config(
    source: Path,
    target: Path,
    path_map: dict[str, str] | None = None,
    *,
    hardware_accel: str | None = "none",
    quick_connect: bool = True,
    replace: bool = False,
    owner: tuple[int, int] | None = None,
) -> dict:
    """Copy a config/data directory into ``target`` with its identity, mapping library paths.

    ``source`` is read only. ``target`` must be empty (or hold no database, or ``replace=True``);
    the new server must be stopped. Returns a report: the counts at the source and the target,
    the server id, and every change made beyond the copy.
    """
    source, target = Path(source), Path(target)
    path_map = path_map or {}
    sid = server_id(source)
    before = counts(source)
    if (target / "data").is_dir() and any((target / "data").glob("*.db")) and not replace:
        raise ImportFailed(f"{target}: already holds a database (replace=True to overwrite it)")
    if replace and target.exists():
        for child in target.iterdir():
            if child.name in SKIP_DIRS:
                continue
            shutil.rmtree(child) if child.is_dir() and not child.is_symlink() else child.unlink()
    target.mkdir(parents=True, exist_ok=True)
    _copy_tree(source, target)

    rewrite = _rewriter(path_map)
    report: dict = {"server_id": sid, "source": before, "changes": {}}
    if path_map:
        rows = sum(_rewrite_db(db, rewrite) for db in sorted((target / "data").glob("*.db")))
        files = _rewrite_text_files(target, rewrite)
        report["changes"]["path_map"] = {"map": path_map, "db_values": rows, "files": files}
    if hardware_accel is not None and _set_xml_value(
        target / "config" / "encoding.xml", "HardwareAccelerationType", hardware_accel
    ):
        report["changes"]["hardware_accel"] = hardware_accel
    if quick_connect:
        sysxml = target / "config" / "system.xml"
        if _set_xml_value(
            sysxml, "QuickConnectAvailable", "true", create_root="ServerConfiguration"
        ):
            report["changes"]["quick_connect"] = True
    if owner is not None:
        for root, dirs, files in os.walk(target):
            for n in dirs + files:
                os.chown(Path(root) / n, *owner, follow_symlinks=False)
        os.chown(target, *owner)

    after = counts(target)
    report["target"] = after
    if after != before:
        raise ImportFailed(f"counts differ after the copy: source {before}, target {after}")
    if server_id(target) != sid or _sha(target / "data" / "device.txt") != _sha(
        source / "data" / "device.txt"
    ):
        raise ImportFailed("the server id changed in the copy")
    return report


def _parse_map(items: list[str]) -> dict[str, str]:
    out = {}
    for it in items:
        old, sep, new = it.partition("=")
        if not sep or not old.startswith("/") or not new.startswith("/"):
            raise SystemExit(f"--map wants /old=/new (absolute paths), got {it!r}")
        out[old] = new
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser(
        "counts", help="print users/devices/libraries/items/watch_state and the server id"
    )
    c.add_argument("dir", type=Path)
    i = sub.add_parser(
        "import", help="import SRC into DST keeping the server id, users, devices, watch state"
    )
    i.add_argument("src", type=Path)
    i.add_argument("dst", type=Path)
    i.add_argument("--map", action="append", default=[], metavar="/old=/new")
    i.add_argument(
        "--no-accel-reset", action="store_true", help="keep the old hardware acceleration setting"
    )
    i.add_argument("--replace", action="store_true")
    i.add_argument("--chown", metavar="UID:GID")
    a = ap.parse_args(argv)
    try:
        if a.cmd == "counts":
            print(json.dumps({"server_id": server_id(a.dir), **counts(a.dir)}, indent=2))
            return 0
        owner = tuple(int(x) for x in a.chown.split(":")) if a.chown else None
        rep = import_config(
            a.src, a.dst, _parse_map(a.map),
            hardware_accel=None if a.no_accel_reset else "none", replace=a.replace, owner=owner,
        )  # fmt: skip
        print(json.dumps(rep, indent=2))
        return 0
    except ImportFailed as e:
        print(f"media import: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
