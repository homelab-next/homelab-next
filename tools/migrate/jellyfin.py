#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# hnx-script:
#   id: media-config-import
#   kind: tool
#   purpose: Import a media server's config/data directory into a new one, keeping its server id, users, devices and watch state, mapping library paths and checking the counts.
#   owner: maintainers
#   trigger: [manual]
#   inputs: a stopped (or snapshotted) source config/data directory and an empty target; --map old=new library path prefixes
#   outputs: a JSON report of the counts at both ends and every change made beyond the copy; counts prints the server id and counts of one directory
#   exit:
#     "0": imported and verified, or counts printed
#     "1": the import failed or its counts differ from the source (the target is kept for inspection)
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
source (``ImportFailed`` otherwise). Nothing is ever deleted: the new tree is built in a sibling
directory (``DST.partial``) and renamed into place only after it verified; an existing DST that
is empty or already a data root is renamed to ``DST.before-import`` first. A failed import leaves
the previous DST untouched and the partial tree for inspection.

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
# settings that name a path on the old host; blanked (the server then uses its default under
# /config or /cache, or its bundled encoder) when they point outside what the new host has
HOST_PATH_TAGS = {
    "system.xml": ("MetadataPath", "CachePath"),
    "encoding.xml": ("TranscodingTempPath", "EncoderAppPath"),
}
# directories every container has; paths under them are fine
CONTAINER_PREFIXES = ("/config", "/cache")
MIN_COMPONENTS = 3  # a target shallower than /a/b/c is refused


class ImportFailed(Exception):
    """The import cannot go on, or its result does not match its source."""


def _abs(path: Path | str) -> Path:
    return Path(path).expanduser().resolve()


def server_id(data_dir: Path) -> str:
    """The server id: the content of ``data/device.txt`` (what a client remembers)."""
    f = _abs(data_dir) / "data" / "device.txt"
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


def _count(db_dir: Path, tables: tuple[str, ...]) -> tuple[int, bool]:
    """Rows in the named tables over every database in ``db_dir``, and whether any table was found."""
    total, found = 0, False
    for db in sorted(db_dir.glob("*.db")):
        c = _ro(db)
        try:
            have = {r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            for t in tables:
                if t in have:
                    found = True
                    total += c.execute(f'SELECT COUNT(*) FROM "{t}"').fetchone()[0]
        finally:
            c.close()
    return total, found


def libraries(data_dir: Path) -> list[str]:
    """The library (virtual folder) names: one directory each under ``root/default``."""
    root = _abs(data_dir) / "root" / "default"
    return sorted(p.name for p in root.iterdir() if p.is_dir()) if root.is_dir() else []


def counts(data_dir: Path) -> dict[str, int]:
    """Users, devices, libraries, items and watch-state rows of a config/data directory, read-only."""
    data_dir = _abs(data_dir)
    db_dir = data_dir / "data"
    if not db_dir.is_dir():
        raise ImportFailed(f"{db_dir}: not a config/data directory")
    return {
        "users": _count(db_dir, USER_TABLES)[0],
        "devices": _count(db_dir, DEVICE_TABLES)[0],
        "libraries": len(libraries(data_dir)),
        "items": _count(db_dir, ITEM_TABLES)[0],
        "watch_state": _count(db_dir, WATCH_TABLES)[0],
    }


def _require_understood(data_dir: Path, allow_empty: bool) -> None:
    """Refuse a source whose schema was not recognised, or that holds no user: equal counts of
    nothing would otherwise verify."""
    db_dir = data_dir / "data"
    users, has_users = _count(db_dir, USER_TABLES)
    _, has_devices = _count(db_dir, DEVICE_TABLES)
    if not (has_users and has_devices):
        raise ImportFailed(
            f"{db_dir}: no users table and devices table in any database (an unrecognised "
            "schema or the wrong directory): refusing to call an empty count verified"
        )
    if users == 0 and not allow_empty:
        raise ImportFailed(f"{db_dir}: the source has no users (--allow-empty to import it anyway)")


def _device_tokens(data_dir: Path) -> list[str]:
    out: list[str] = []
    for db in sorted((data_dir / "data").glob("*.db")):
        c = _ro(db)
        try:
            for t in DEVICE_TABLES:
                cols = [r[1] for r in c.execute(f'PRAGMA table_info("{t}")')]
                if "AccessToken" in cols:
                    out += [str(r[0]) for r in c.execute(f'SELECT AccessToken FROM "{t}"')]
        finally:
            c.close()
    return sorted(out)


# ----------------------------------------------------------------------------- path mapping

_BEFORE = r"(?<![A-Za-z0-9_.\-/])"
_AFTER = r"(?=/|\Z|[<\"'\s,;\\])"


def _clean_map(path_map: dict[str, str]) -> dict[str, str]:
    out = {}
    for old, new in path_map.items():
        o, n = old.rstrip("/"), new.rstrip("/")
        if not o.startswith("/") or o == "" or not n.startswith("/"):
            raise ImportFailed(
                f"--map {old!r}={new!r}: absolute paths below the root are required (a root prefix is refused)"
            )
        out[o] = n or "/"
    return out


def _rewriter(path_map: dict[str, str]):
    """One pass over the text: every old prefix is looked for at once (longest first), so a
    rewritten path is never rewritten again by a later rule."""
    rules = _clean_map(path_map)
    if not rules:
        return lambda text: text
    alt = "|".join(re.escape(o) for o in sorted(rules, key=len, reverse=True))
    pat = re.compile(_BEFORE + "(" + alt + ")" + _AFTER)
    return lambda text: pat.sub(lambda m: rules[m.group(1)], text)


def _old_pattern(path_map: dict[str, str]) -> re.Pattern[str]:
    rules = _clean_map(path_map)
    alt = "|".join(re.escape(o) for o in sorted(rules, key=len, reverse=True))
    return re.compile(_BEFORE + "(" + alt + ")" + _AFTER)


def _rewrite_db(path: Path, rewrite, unhandled: list[str]) -> int:
    """Rewrite library paths in every text column (and every UTF-8 JSON blob) of one database;
    returns the values changed. A blob that holds an old path but is not JSON is listed in
    ``unhandled`` (a binary format's length prefixes would be corrupted by editing it)."""
    c = sqlite3.connect(path)
    changed = 0
    try:
        tables = [r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table'")]
        for t in tables:
            cols = [(r[1], r[2].upper()) for r in c.execute(f'PRAGMA table_info("{t}")')]
            for col, _decl in cols:
                for kind in ("text", "blob"):
                    rows = c.execute(
                        f'SELECT rowid, "{col}" FROM "{t}" WHERE typeof("{col}") = ?', (kind,)
                    ).fetchall()
                    for rowid, value in rows:
                        if kind == "blob":
                            try:
                                text = bytes(value).decode("utf-8")
                            except UnicodeDecodeError:
                                continue
                            if "/" not in text:
                                continue
                            new = rewrite(text)
                            if new == text:
                                continue
                            try:
                                json.loads(text)
                            except ValueError:
                                unhandled.append(f"{path.name}:{t}.{col}")
                                continue
                            c.execute(
                                f'UPDATE "{t}" SET "{col}" = ? WHERE rowid = ?',
                                (new.encode("utf-8"), rowid),
                            )
                            changed += 1
                        elif "/" in value:
                            new = rewrite(value)
                            if new != value:
                                c.execute(
                                    f'UPDATE "{t}" SET "{col}" = ? WHERE rowid = ?', (new, rowid)
                                )
                                changed += 1
        c.commit()
        c.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        ok = c.execute("PRAGMA integrity_check").fetchone()[0]
        if ok != "ok":
            raise ImportFailed(f"{path.name}: integrity_check failed after the path rewrite: {ok}")
    finally:
        c.close()
    return changed


def _leftovers(db_dir: Path, pat: re.Pattern[str]) -> list[str]:
    """Places where an old prefix still occurs (text columns and blobs that decode as UTF-8)."""
    left: list[str] = []
    for db in sorted(db_dir.glob("*.db")):
        c = sqlite3.connect(db)
        try:
            for (t,) in c.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall():
                for col in [r[1] for r in c.execute(f'PRAGMA table_info("{t}")')]:
                    for (v,) in c.execute(
                        f'SELECT "{col}" FROM "{t}" WHERE typeof("{col}") IN (?, ?)',
                        ("text", "blob"),
                    ):
                        if isinstance(v, bytes):
                            try:
                                v = v.decode("utf-8")
                            except UnicodeDecodeError:
                                continue
                        if "/" in v and pat.search(v):
                            left.append(f"{db.name}:{t}.{col}")
                            break
        finally:
            c.close()
    return left


def _missing_item_paths(db_dir: Path, roots: list[str]) -> int:
    """Item paths under the new library roots that do not exist on this host (a warning only)."""
    missing = 0
    for db in sorted(db_dir.glob("*.db")):
        c = _ro(db)
        try:
            names = {r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            for t in ITEM_TABLES:
                if t in names and "Path" in [r[1] for r in c.execute(f'PRAGMA table_info("{t}")')]:
                    for (p,) in c.execute(
                        f'SELECT Path FROM "{t}" WHERE typeof(Path) = ?', ("text",)
                    ):
                        if any(
                            p == r or p.startswith(r + "/") for r in roots
                        ) and not os.path.exists(p):
                            missing += 1
        finally:
            c.close()
    return missing


# ----------------------------------------------------------------------------- the copy


def _copy_db(src: Path, dst: Path) -> None:
    a = _ro(src)
    b = sqlite3.connect(dst)
    try:
        a.backup(b)
    finally:
        a.close()
        b.close()


def _copy_tree(src: Path, dst: Path, skipped: list[str]) -> None:
    for root, dirs, files in os.walk(src):
        rel = Path(root).relative_to(src)
        keep = []
        for d in sorted(dirs):
            if rel == Path(".") and d in SKIP_DIRS:
                continue
            if (Path(root) / d).is_symlink():
                skipped.append(str(rel / d))  # a linked directory is not followed into the target
                continue
            keep.append(d)
        dirs[:] = keep
        (dst / rel).mkdir(parents=True, exist_ok=True)
        for name in sorted(files):
            s, d = Path(root) / name, dst / rel / name
            if s.is_symlink():
                skipped.append(str(rel / name))
                continue
            if name.endswith(("-wal", "-shm")):
                continue  # folded in by the online backup of the database itself
            if name.endswith(".db") and rel == Path("data"):
                _copy_db(s, d)
            else:
                shutil.copy2(s, d)


def _read(path: Path) -> str:
    with open(path, encoding="utf-8", newline="") as f:  # newline="": CRLF survives
        return f.read()


def _write(path: Path, text: str) -> None:
    with open(path, "w", encoding="utf-8", newline="") as f:
        f.write(text)


def _set_xml_value(path: Path, tag: str, value: str, *, create_root: str | None = None) -> bool:
    """Set ``<tag>value</tag>`` in a flat settings file; returns whether the file changed."""
    if path.is_file():
        text = _read(path)
    elif create_root:
        path.parent.mkdir(parents=True, exist_ok=True)
        text = f'<?xml version="1.0" encoding="utf-8"?>\n<{create_root} />\n'
    else:
        return False
    nl = "\r\n" if "\r\n" in text else "\n"
    new, n = re.subn(rf"<{tag}>[^<]*</{tag}>", f"<{tag}>{value}</{tag}>", text)
    if n == 0:
        if re.search(rf"<{tag}\s*/>", text):
            new = re.sub(rf"<{tag}\s*/>", f"<{tag}>{value}</{tag}>", text)
        elif re.search(r"<(\w+)\s*/>", text) and "</" not in text.split("?>", 1)[-1]:
            new = re.sub(
                r"<(\w+)\s*/>", rf"<\1>{nl}  <{tag}>{value}</{tag}>{nl}</\1>", text, count=1
            )
        else:
            new = re.sub(r"(</\w+>\s*)\Z", f"  <{tag}>{value}</{tag}>{nl}\\1", text, count=1)
    if new == text and path.is_file():
        return False
    _write(path, new)
    return True


def _rewrite_text_files(root: Path, rewrite) -> int:
    changed = 0
    for p in sorted(root.rglob("*")):
        if p.is_file() and not p.is_symlink() and p.suffix in TEXT_SUFFIXES:
            try:
                text = _read(p)
            except UnicodeDecodeError:
                continue
            new = rewrite(text)
            if new != text:
                _write(p, new)
                changed += 1
    return changed


_ELEMENT_PATH = re.compile(r"<(\w+)>(/[^<]*)</\1>")


def _host_paths(config_dir: Path, allowed: list[str]) -> list[tuple[str, str, str]]:
    """(file, tag, path) for every absolute path in config/*.xml outside what the new host has."""
    out = []
    for f in sorted(config_dir.glob("*.xml")):
        for tag, val in _ELEMENT_PATH.findall(_read(f)):
            if not any(val == a or val.startswith(a.rstrip("/") + "/") for a in allowed):
                out.append((f.name, tag, val))
    return out


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _is_empty_dir(p: Path) -> bool:
    return p.is_dir() and not any(p.iterdir())


def _nested(a: Path, b: Path) -> bool:
    return a == b or a in b.parents or b in a.parents


def _guard_target(
    source: Path, target: Path, new_prefixes: list[str], replace: bool, data_root: Path | None
) -> None:
    """Every refusal that has to hold before anything is created or moved."""
    if len(target.parts) - 1 < MIN_COMPONENTS or target == Path(target.anchor):
        raise ImportFailed(
            f"{target}: too shallow a target (at least {MIN_COMPONENTS} path components)"
        )
    if _nested(source, target):
        raise ImportFailed(f"{target}: the target is the source, or inside or around it ({source})")
    if data_root is not None and not (target == data_root or data_root in target.parents):
        raise ImportFailed(f"{target}: outside the module's data root {data_root}")
    for pre in new_prefixes:
        pp = Path(pre)
        if target == pp or target in pp.parents:
            raise ImportFailed(f"{target}: the target is, or contains, the library root {pre}")
    if target.exists() or target.is_symlink():
        if not target.is_dir():
            raise ImportFailed(f"{target}: exists and is not a directory")
        if os.path.ismount(target):
            raise ImportFailed(f"{target}: is a mount point")
        if not _is_empty_dir(target):
            if not (target / "data" / "device.txt").is_file():
                raise ImportFailed(
                    f"{target}: not empty and not a media server data root (no data/device.txt); refusing to replace it"
                )
            if not replace:
                raise ImportFailed(
                    f"{target}: already holds a data root (replace=True moves it aside to {target.name}.before-import)"
                )


def import_config(
    source: Path,
    target: Path,
    path_map: dict[str, str] | None = None,
    *,
    hardware_accel: str | None = "none",
    quick_connect: bool = True,
    replace: bool = False,
    owner: tuple[int, int] | None = None,
    allow_empty: bool = False,
    strict: bool = False,
    data_root: Path | None = None,
) -> dict:
    """Copy a config/data directory into ``target`` with its identity, mapping library paths.

    ``source`` is read only and nothing is deleted. The new tree is built in ``<target>.partial``
    and, once verified, renamed into place; an existing ``target`` that is empty or a data root
    (with ``replace=True``) is first renamed to ``<target>.before-import``. The new server must
    be stopped. Returns a report: the counts at both ends, the server id, every change beyond the
    copy, the symlinks not carried, host paths found in the settings, and warnings.
    """
    source, target = _abs(source), _abs(target)
    data_root = _abs(data_root) if data_root else None
    rules = _clean_map(path_map or {})
    sid = server_id(source)
    _require_understood(source, allow_empty)
    _guard_target(source, target, list(rules.values()), replace, data_root)
    partial = target.with_name(target.name + ".partial")
    aside = target.with_name(target.name + ".before-import")
    if partial.exists() or partial.is_symlink():
        raise ImportFailed(f"{partial}: left by an earlier import; inspect it and move it away")
    if target.exists() and not _is_empty_dir(target) and (aside.exists() or aside.is_symlink()):
        raise ImportFailed(f"{aside}: exists; move it away first")

    before = counts(source)
    tokens = _device_tokens(source)
    skipped: list[str] = []
    partial.mkdir(parents=True)
    _copy_tree(source, partial, skipped)

    rewrite = _rewriter(rules)
    report: dict = {"server_id": sid, "source": before, "changes": {}, "warnings": []}
    if rules:
        unhandled: list[str] = []
        rows = sum(
            _rewrite_db(db, rewrite, unhandled) for db in sorted((partial / "data").glob("*.db"))
        )
        if unhandled:
            raise ImportFailed(
                "old library paths inside binary (non-JSON) blobs that cannot be edited safely: "
                + ", ".join(sorted(set(unhandled)))
            )
        files = _rewrite_text_files(partial, rewrite)
        report["changes"]["path_map"] = {"map": rules, "db_values": rows, "files": files}
        if not any(n == o or n.startswith(o + "/") for o in rules for n in rules.values()):
            left = _leftovers(partial / "data", _old_pattern(rules))
            if left:
                raise ImportFailed(
                    "an old library prefix remains after the rewrite in: " + ", ".join(left)
                )
        gone = _missing_item_paths(partial / "data", list(rules.values()))
        if gone:
            report["warnings"].append(
                f"{gone} item path(s) under the new library roots do not exist on this host"
            )

    cfg = partial / "config"
    allowed = [*CONTAINER_PREFIXES, *rules.values()]
    blanked = []
    for fname, tags in HOST_PATH_TAGS.items():
        f = cfg / fname
        if f.is_file():
            for tag in tags:
                m = re.search(rf"<{tag}>(/[^<]*)</{tag}>", _read(f))
                if m and not any(
                    m.group(1) == a or m.group(1).startswith(a + "/") for a in allowed
                ):
                    _set_xml_value(f, tag, "")
                    blanked.append(f"{fname}:{tag}={m.group(1)}")
    if blanked:
        report["changes"]["host_paths_blanked"] = blanked
    if hardware_accel is not None and _set_xml_value(
        cfg / "encoding.xml", "HardwareAccelerationType", hardware_accel
    ):
        report["changes"]["hardware_accel"] = hardware_accel
    if quick_connect and _set_xml_value(
        cfg / "system.xml", "QuickConnectAvailable", "true", create_root="ServerConfiguration"
    ):
        report["changes"]["quick_connect"] = True
    foreign = _host_paths(cfg, allowed)
    if foreign:
        report["host_paths"] = [f"{f}:{t}={v}" for f, t, v in foreign]
        if strict:
            raise ImportFailed(
                "settings name paths this host may not have: " + ", ".join(report["host_paths"])
            )
    if skipped:
        report["skipped_symlinks"] = skipped
    if owner is not None:
        for root, dirs, files in os.walk(partial):
            for n in dirs + files:
                os.chown(Path(root) / n, *owner, follow_symlinks=False)
        os.chown(partial, *owner)

    after = counts(partial)
    report["target"] = after
    if after != before:
        raise ImportFailed(
            f"counts differ after the copy: source {before}, new tree {after}; kept at {partial}, {target} untouched"
        )
    if server_id(partial) != sid or _sha(partial / "data" / "device.txt") != _sha(
        source / "data" / "device.txt"
    ):
        raise ImportFailed(
            f"the server id changed in the copy; kept at {partial}, {target} untouched"
        )
    if _device_tokens(partial) != tokens:
        raise ImportFailed(
            f"device tokens differ after the copy; kept at {partial}, {target} untouched"
        )

    # only now does anything of the previous target move, and it is renamed, never deleted
    if target.exists():
        if _is_empty_dir(target):
            target.rmdir()  # an empty directory: nothing to lose
        else:
            os.rename(target, aside)
            report["previous_target"] = str(aside)
    os.rename(partial, target)
    report["target_path"] = str(target)
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
    i.add_argument(
        "--replace",
        action="store_true",
        help="move an existing data root at DST aside (never deleted)",
    )
    i.add_argument("--allow-empty", action="store_true", help="accept a source with no users")
    i.add_argument(
        "--strict", action="store_true", help="fail when settings name paths this host may not have"
    )
    i.add_argument("--data-root", type=Path, help="DST must lie inside this directory")
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
            allow_empty=a.allow_empty, strict=a.strict, data_root=a.data_root,
        )  # fmt: skip
        print(json.dumps(rep, indent=2))
        return 0
    except ImportFailed as e:
        print(f"media import: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
