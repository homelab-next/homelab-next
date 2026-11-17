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
is empty or already a data root is renamed to ``DST.before-import`` first (or, when that name is
taken by an earlier import, the first free ``DST.before-import.N``, N from 2: nothing is ever
overwritten). A failed import leaves
the previous DST untouched and the partial tree for inspection.

**No downgrade.** A server cannot open a database a newer server has migrated: it fails to start
("no such column"), and a health check that only asks ``/health`` may still say Healthy. So both
``counts`` and ``import`` first read the source's migration history (``__EFMigrationsHistory``) and
refuse a source that holds a migration the target does not know, or that a newer server version
wrote, naming each. What the target knows is ``modules/media/known-migrations.json``: every
migration id of every release up to the module's pinned version, generated from the product's
source (``known-migrations``) and checked against the pin (``product.version`` in
``modules/media/module.yml``) whenever it is read. A source with no history at all is refused
too: nothing proves the target understands it.

``counts(data_dir)`` reads a config/data directory read-only and returns ``{users, devices,
libraries, items, watch_state}``; the id is ``server_id(data_dir)`` (without the byte order mark
the server writes); the history check is ``check_schema(data_dir)``.

    python3 tools/migrate/jellyfin.py counts DIR
    python3 tools/migrate/jellyfin.py import SRC DST --map /old=/new [--map ...] [--no-accel-reset]
    python3 tools/migrate/jellyfin.py known-migrations --repo CLONE --version V [--out FILE]

Stop the source server before copying (or point SRC at a snapshot): a database copied while it is
written is the SQLite online backup of one moment, but the files around it are not.
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import re
import shutil
import sqlite3
import subprocess
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
ASIDE_MAX = 99  # DST.before-import, then .2 to .99: the first free name
# the module this tool imports for: its pinned product version and the migrations that version knows
MODULE_DIR = Path(__file__).resolve().parents[2] / "modules" / "media"
KNOWN_MIGRATIONS = MODULE_DIR / "known-migrations.json"
HISTORY_TABLE = "__EFMigrationsHistory"
BOM = "\ufeff"
_MIGRATION_ID = re.compile(r"\d{14}_[A-Za-z0-9_]+")


class ImportFailed(Exception):
    """The import cannot go on, or its result does not match its source."""


def _abs(path: Path | str) -> Path:
    return Path(path).expanduser().resolve()


def server_id(data_dir: Path) -> str:
    """The server id: the content of ``data/device.txt`` (what a client remembers)."""
    f = _abs(data_dir) / "data" / "device.txt"
    if not f.is_file():
        raise ImportFailed(f"{f}: no server id (is this a config/data directory?)")
    # the server writes the file with a UTF-8 byte order mark; the id is what follows it
    return f.read_text(encoding="utf-8-sig").strip()


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


# ----------------------------------------------------------------------------- no downgrade


def _version_key(text: str) -> tuple[int, ...] | None:
    """``12.1`` (or with up to four parts, as the history records it) -> ``(12, 1, 0, 0)``; None
    for anything that is not dotted digits."""
    parts = text.strip().split(".")
    if not 1 <= len(parts) <= 4 or not all(p.isdigit() for p in parts):
        return None
    return tuple(int(p) for p in parts) + (0,) * (4 - len(parts))


def pinned_version(module_dir: Path = MODULE_DIR) -> str:
    """``product.version`` of the module's manifest (the version its image pin carries)."""
    lines = (module_dir / "module.yml").read_text(encoding="utf-8").splitlines()
    inside = False
    for line in lines:  # a line scan of the top-level product: block (no YAML dependency)
        if not line[:1].isspace():
            inside = line.rstrip() == "product:"
            continue
        key, sep, value = line.strip().partition(":")
        if inside and sep and key == "version":
            version = value.strip().strip("\"'")
            if _version_key(version) is not None:
                return version
    raise ImportFailed(f"{module_dir / 'module.yml'}: no product.version")


def load_known(path: Path | None = None, *, expect_version: str | None = None) -> dict:
    """The migration ids the target server knows (``known-migrations.json``). Read from the module,
    it must be for the module's pinned version: a list for another version proves nothing."""
    path = path or KNOWN_MIGRATIONS
    try:
        known = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        raise ImportFailed(f"{path}: cannot read the target's known migrations ({e})") from e
    version = str(known.get("product_version", ""))
    if _version_key(version) is None or not known.get("database") or not known.get("code"):
        raise ImportFailed(f"{path}: not a known-migrations list (product_version, database, code)")
    # stored as [time, name] pairs (one id is "<time>_<name>"): a joined id reads to a secret
    # scanner like a random token
    for kind in ("database", "code"):
        ids = [
            "_".join(x) if isinstance(x, list) and all(isinstance(y, str) for y in x) else repr(x)
            for x in known[kind]
        ]
        bad = [i for i in ids if not _MIGRATION_ID.fullmatch(i)]
        if bad:
            raise ImportFailed(f"{path}: malformed migration ids: {', '.join(bad[:5])}")
        known[kind] = ids
    if expect_version is None and path == KNOWN_MIGRATIONS:
        expect_version = pinned_version()
    if expect_version is not None and _version_key(version) != _version_key(expect_version):
        raise ImportFailed(
            f"{path} lists the migrations of {version} but the module pins {expect_version}: "
            "regenerate it (known-migrations --version <pinned>) with the pin"
        )
    return known


def migration_history(data_dir: Path) -> list[tuple[str, str, str]]:
    """``(database, MigrationId, ProductVersion)`` of every row of every migration history."""
    rows: list[tuple[str, str, str]] = []
    for db in sorted((_abs(data_dir) / "data").glob("*.db")):
        c = _ro(db)
        try:
            have = {r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            if HISTORY_TABLE in have:
                rows += [
                    (db.name, str(i), str(v or ""))
                    for i, v in c.execute(
                        f'SELECT MigrationId, ProductVersion FROM "{HISTORY_TABLE}"'
                    )
                ]
        finally:
            c.close()
    return rows


def check_schema(
    data_dir: Path, known: dict | None = None, *, source_version: str | None = None
) -> dict:
    """Refuse a source the target server cannot open: one whose history holds a migration the
    target does not know, or that a newer server version wrote (``ImportFailed``, naming them).
    Returns what was read: the number of migrations, the newest, and the newest server version
    that wrote one."""
    known = known if known is not None else load_known()
    target = str(known["product_version"])
    tkey = _version_key(target)
    db_dir = _abs(data_dir) / "data"
    rows = migration_history(data_dir)
    if not rows:
        raise ImportFailed(
            f"{db_dir}: no {HISTORY_TABLE} rows in any database: nothing proves the target server "
            f"({target}) can open it; refusing"
        )
    code, database = set(known["code"]), set(known["database"])
    unknown = sorted({(i, v) for _, i, v in rows if i not in code and i not in database})
    # a code migration's row carries the server version that ran it; a schema migration's row
    # carries the database library's version instead, so only the former says which server wrote it
    written = [(v, i) for _, i, v in rows if i in code and _version_key(v) is not None]
    newer = sorted({(v, i) for v, i in written if _version_key(v) > tkey})
    newest_server = max((v for v, _ in written), key=_version_key, default="")
    if source_version is not None:
        if _version_key(source_version) is None:
            raise ImportFailed(f"--source-version {source_version!r}: not a version")
        if _version_key(source_version) > tkey:
            raise ImportFailed(
                f"{db_dir}: the source server is {source_version}, newer than the target {target}: "
                "importing it would be a downgrade; pin the module to the source's version or newer"
            )
    if unknown or newer:
        # an unknown row's version is the server's or the database library's: shown, not judged
        named = [f"{i} (recorded as {v or 'no version'})" for i, v in unknown]
        named += [f"{i} (written by {v})" for v, i in newer if (i, v) not in unknown]
        raise ImportFailed(
            f"{db_dir}: the source database was migrated by a newer server than the target "
            f"{target}: {len(unknown)} migration(s) the target does not know"
            + (f" and {len(newer)} written by a newer version" if newer else "")
            + ": "
            + ", ".join(named)
            + ". The target server would fail to start on it (a downgrade). Pin the module to "
            f"the source's version or newer (newest seen: {newest_server or 'unknown'}), "
            "regenerate known-migrations.json, and import again"
        )
    return {
        "target_version": target,
        "migrations": len(rows),
        "newest_migration": max(i for _, i, _ in rows),
        "newest_server_version": newest_server,
    }


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), *args], check=True, capture_output=True, text=True
    ).stdout


def _git_origin(repo: Path) -> str:
    try:
        return _git(repo, "config", "--get", "remote.origin.url").strip()
    except subprocess.CalledProcessError:
        return ""


_TAG = re.compile(r"v(\d+)\.(\d+)(?:\.(\d+))?(?:-(alpha|beta|rc)(\d+))?")
_PRE = {"alpha": 0, "beta": 1, "rc": 2, None: 3}
_EF_ATTR = re.compile(r"\[Migration\(\s*\"(\d{14}_[A-Za-z0-9_]+)\"\s*\)\]")
_CODE_ATTR = re.compile(
    r"\[JellyfinMigration\(\s*\"([0-9T:\-]+)\"\s*,\s*(?:nameof\(\s*(\w+)\s*\)|\"(\w+)\")"
)


def _tag_key(tag: str) -> tuple[int, ...] | None:
    m = _TAG.fullmatch(tag)
    if not m:
        return None
    major, minor, patch, pre, n = m.groups()
    return (int(major), int(minor), int(patch or 0), _PRE[pre], int(n or 0))


def known_migrations(repo: Path, version: str) -> dict:
    """Every migration id of every release up to ``version`` (``v<version>``), read from a clone of
    the product's source: schema migrations by their ``[Migration("<id>")]`` attribute, code
    migrations by ``[JellyfinMigration("<time>", nameof(<Name>))]`` as the server records them
    (``yyyyMMddHHmmss_<Name>``). A release counts when its version is not above ``version`` and it
    was tagged no later (a later patch of an older line may know migrations ``version`` does not).
    A migration later removed from the source stays known: a database that ran it is still one
    ``version`` opens."""
    want = "v" + version
    refs = {}
    for line in _git(
        repo, "for-each-ref", "--format=%(refname:short) %(creatordate:unix)", "refs/tags"
    ).splitlines():
        name, _, when = line.partition(" ")
        if _tag_key(name) is not None:
            refs[name] = int(when)
    if want not in refs:
        raise ImportFailed(f"{repo}: no release tag {want}")
    releases = sorted(
        (t for t, when in refs.items() if _tag_key(t) <= _tag_key(want) and when <= refs[want]),
        key=_tag_key,
    )
    database: set[str] = set()
    code: set[str] = set()
    seen: set[str] = set()
    for tag in releases:
        for line in _git(repo, "ls-tree", "-r", tag).splitlines():
            meta, _, path = line.partition("\t")
            oid = meta.split()[2]
            if (
                not path.endswith(".cs")
                or "/Migrations/" not in "/" + path
                or path.startswith("tests/")
                or oid in seen
            ):
                continue
            seen.add(oid)
            text = _git(repo, "cat-file", "blob", oid)
            database.update(_EF_ATTR.findall(text))
            for when, n1, n2 in _CODE_ATTR.findall(text):
                stamp = datetime.datetime.fromisoformat(when).strftime("%Y%m%d%H%M%S")
                code.add(f"{stamp}_{n1 or n2}")
    if not database or not code:
        raise ImportFailed(
            f"{repo}: no migrations found up to {want}; is this the product's source?"
        )
    return {
        "product_version": version,
        "source": {
            "repository": _git_origin(repo),
            "tag": want,
            "commit": _git(repo, "rev-parse", want + "^{commit}").strip(),
            "releases": releases,
        },
        "database": sorted(database),
        "code": sorted(code),
    }


def dump_known(known: dict) -> str:
    """The list as stored: ids as ``[time, name]`` pairs, one per line (see ``load_known``)."""
    head = {k: v for k, v in known.items() if k not in ("database", "code")}
    text = json.dumps(head, indent=2)[: -len("\n}")]
    for kind in ("database", "code"):
        pairs = [json.dumps(i.split("_", 1)) for i in known[kind]]
        text += f',\n  "{kind}": [\n    ' + ",\n    ".join(pairs) + "\n  ]"
    return text + "\n}\n"


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
                    f"{target}: already holds a data root (replace=True moves it aside to "
                    f"{target.name}.before-import, or the first free {target.name}.before-import.N)"
                )


def _aside_path(target: Path) -> Path:
    """Where a previous target is moved: ``<target>.before-import``, or when an earlier import
    already took that name, the first free ``<target>.before-import.N`` (N = 2..99). A name that
    exists in any form (a directory, a file, a dangling link) is taken; nothing is overwritten."""
    for n in range(1, ASIDE_MAX + 1):
        p = target.with_name(target.name + ".before-import" + ("" if n == 1 else f".{n}"))
        if not (p.exists() or p.is_symlink()):
            return p
    raise ImportFailed(
        f"{target}.before-import through .{ASIDE_MAX} all exist; inspect them and move some away"
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
    known: dict | None = None,
    source_version: str | None = None,
) -> dict:
    """Copy a config/data directory into ``target`` with its identity, mapping library paths.

    ``source`` is read only and nothing is deleted. The new tree is built in ``<target>.partial``
    and, once verified, renamed into place; an existing ``target`` that is empty or a data root
    (with ``replace=True``) is first renamed to ``<target>.before-import`` (the first free
    ``.before-import.N`` when that is taken). A source the target server cannot open (its history
    holds migrations ``known`` lacks, or a newer server wrote it: ``check_schema``) is refused
    before anything is created. The new server must be stopped. Returns a report: the counts at both ends, the server id, every change beyond the
    copy, the symlinks not carried, host paths found in the settings, and warnings.
    """
    source, target = _abs(source), _abs(target)
    data_root = _abs(data_root) if data_root else None
    rules = _clean_map(path_map or {})
    sid = server_id(source)
    _require_understood(source, allow_empty)
    schema = check_schema(source, known, source_version=source_version)
    _guard_target(source, target, list(rules.values()), replace, data_root)
    partial = target.with_name(target.name + ".partial")
    replacing = target.exists() and not _is_empty_dir(target)
    if replacing:
        _aside_path(target)  # refuse now, before any copy, when every aside name is taken
    if partial.exists() or partial.is_symlink():
        raise ImportFailed(f"{partial}: left by an earlier import; inspect it and move it away")

    before = counts(source)
    tokens = _device_tokens(source)
    skipped: list[str] = []
    partial.mkdir(parents=True)
    _copy_tree(source, partial, skipped)

    rewrite = _rewriter(rules)
    report: dict = {
        "server_id": sid,
        "schema": schema,
        "source": before,
        "changes": {},
        "warnings": [],
    }
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
            aside = _aside_path(target)  # chosen again just before the move: never an existing name
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
    c.add_argument(
        "--known", type=Path, help="the target's known-migrations list (default: the module's)"
    )
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
    i.add_argument(
        "--known", type=Path, help="the target's known-migrations list (default: the module's)"
    )
    i.add_argument(
        "--source-version",
        metavar="V",
        help="the source server's version, when known (its image tag): refused when newer than the target",
    )
    g = sub.add_parser(
        "known-migrations",
        help="list every migration id up to a release, from a clone of the product's source",
    )
    g.add_argument(
        "--repo", type=Path, required=True, help="a clone of the product's source, with its tags"
    )
    g.add_argument(
        "--version", required=True, help="the release, as the image tag names it (e.g. 12.1)"
    )
    g.add_argument("--out", type=Path, help="write here instead of standard output")
    a = ap.parse_args(argv)
    try:
        if a.cmd == "known-migrations":
            text = dump_known(known_migrations(a.repo, a.version))
            if a.out:
                a.out.write_text(text, encoding="utf-8")
            else:
                sys.stdout.write(text)
            return 0
        known = load_known(a.known) if a.known else None
        if a.cmd == "counts":
            sid = server_id(a.dir)
            out = {"server_id": sid, **counts(a.dir), "schema": check_schema(a.dir, known)}
            print(json.dumps(out, indent=2))
            return 0
        owner = tuple(int(x) for x in a.chown.split(":")) if a.chown else None
        rep = import_config(
            a.src, a.dst, _parse_map(a.map),
            hardware_accel=None if a.no_accel_reset else "none", replace=a.replace, owner=owner,
            allow_empty=a.allow_empty, strict=a.strict, data_root=a.data_root,
            known=known, source_version=a.source_version,
        )  # fmt: skip
        print(json.dumps(rep, indent=2))
        return 0
    except ImportFailed as e:
        print(f"media import: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
