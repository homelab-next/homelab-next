#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# hnx-script:
#   id: media-automation-config-import
#   kind: tool
#   purpose: Import the media automation stack's per-app config directories (library managers, indexer manager, torrent and usenet clients, request app, transcode server) into the module's config root, keeping API keys and settings, mapping library paths and host names, and checking the counts.
#   owner: maintainers
#   trigger: [manual]
#   inputs: a read-only source holding each app's config directory (a copy of the old volumes or an export) and an absent or empty target; --map old=new library path prefixes; --host-map old=new service host names
#   outputs: a JSON report of the counts at both ends and every change made beyond the copy (never a key, a password or a token); counts prints the counts of one source or one module config root
#   exit:
#     "0": imported and verified, or counts printed
#     "1": the import failed or its counts differ from the source (the partial tree is kept for inspection, the target untouched)
"""Import the old media automation stack's app state into the module's config root.

The library managers (TV, films, music) and the indexer manager keep everything in one SQLite
database plus a ``config.xml`` that carries the application's own API key; the other apps in
settings files. The API keys, indexer definitions, download-client entries, history and quality
profiles must arrive **unchanged** or every app has to be wired to the others again; the keys
travel host to host through this tool, never through a repository or a command line. It changes
only what the new host forces, and says so in the report:

* **library paths**, old prefix to new (``--map /media=/srv/media``) in every database (through SQL,
  parameterised, one column value at a time: never a byte substitution, which corrupts the length
  prefixes of a SQLite record), in the settings files (``*.conf``, ``*.json``, ``*.xml``) and, with a
  real bencode reader and writer, in the torrent client's resume files (a length-prefixed format,
  too). One pass over the text, the longest old prefix first, so a rewritten path is never rewritten
  again;
* **host names**, old to new (``--host-map media-core-gluetun=gluetun`` or ``--strip-host-prefix
  media-core-``): the apps address each other, and the download clients, by container name, and the
  new stack's names are the service names. A host written as an IP address is never right (a
  container behind the VPN client has no address of its own that stays put) and is reported, and
  refused with ``--strict``.

Everything is verified after the copy, with counts read from the new tree and compared to the
source: the series, films, artists, files, indexers, download clients, applications, root folders,
the request app's users and requests, the torrent resume files; a source with no recognised schema,
or none of the four library/indexer apps, or an empty primary table, is an error (equal counts of
nothing would otherwise verify). The API keys are compared by hash and never printed.

Nothing is ever deleted: the new tree is built in a sibling directory (``DST.partial``) and renamed
into place only after it verified; an existing DST that is empty or already a config root is
renamed to ``DST.before-import`` first (``--replace``). A failed import leaves the previous DST
untouched and the partial tree for inspection.

    python3 tools/migrate/media_automation.py counts DIR [--prefix media-core_]
    python3 tools/migrate/media_automation.py import SRC DST --map /old=/new [--map ...] \\
        [--host-map old=new ...] [--strip-host-prefix PFX] [--prefix media-core_] [--replace] \\
        [--data-root DIR] [--owner UID:GID] [--seerr-owner UID:GID] [--strict]

SRC is read only: either a directory with one ``<app>/`` per app (the module's own config root) or
the old host's volumes directory (``<prefix><app>_config/_data``). Stop the old stack before the
final copy (or point SRC at a snapshot).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import sqlite3
import stat
import sys
from pathlib import Path

MIN_COMPONENTS = 3  # a target shallower than /a/b/c is refused
SQL_APPS = {
    # app: (database file, tables that must exist, tables that count, tables whose rows must be > 0)
    "sonarr": (
        "sonarr.db",
        ("VersionInfo", "Series", "EpisodeFiles", "RootFolders", "Indexers", "DownloadClients"),
        ("Series", "EpisodeFiles", "RootFolders", "Indexers", "DownloadClients"),
        ("Series",),
    ),
    "radarr": (
        "radarr.db",
        ("VersionInfo", "Movies", "MovieFiles", "RootFolders", "Indexers", "DownloadClients"),
        ("Movies", "MovieFiles", "RootFolders", "Indexers", "DownloadClients"),
        ("Movies",),
    ),
    "lidarr": (
        "lidarr.db",
        (
            "VersionInfo",
            "Artists",
            "Albums",
            "TrackFiles",
            "RootFolders",
            "Indexers",
            "DownloadClients",
        ),
        ("Artists", "Albums", "TrackFiles", "RootFolders", "Indexers", "DownloadClients"),
        ("Artists",),
    ),
    "prowlarr": (
        "prowlarr.db",
        ("VersionInfo", "Indexers", "Applications", "DownloadClients", "IndexerProxies"),
        ("Indexers", "Applications", "DownloadClients", "IndexerProxies"),
        ("Indexers",),
    ),
}
REQUEST_TABLES = ("user", "media", "media_request")
REQUIRED_APPS = ("sonarr", "radarr", "lidarr", "prowlarr", "qbittorrent")
ALL_APPS = (*REQUIRED_APPS, "nzbget", "seerr", "tdarr")
# the old volume names (<prefix><name>_config) per app; the request app was renamed upstream
SOURCE_NAMES = {"seerr": ("seerr", "jellyseerr")}
# the names the apps are reached by in the new stack: the service names
HOST_SERVICES = (
    "gluetun",
    "prowlarr",
    "sonarr",
    "radarr",
    "lidarr",
    "flaresolverr",
    "qbittorrent",
    "nzbget",
    "seerr",
    "tdarr",
)
# never carried: logs, process ids, crash-report state, caches the apps rebuild, dated database
# copies the apps made of themselves, the old stack's own VPN server list
SKIP_DIRS = {"logs", "log", "asp", "Sentry", ".cache", "cache"}
SKIP_FILE_RE = re.compile(r"(\.pid|\.bak-\d+|-wal|-shm)\Z|^logs\.db$|^nzbget\.log$|^Last_Run_")
TEXT_SUFFIXES = (".xml", ".json", ".conf")
IPV4 = re.compile(
    r"(?<![0-9.])(?:(?:25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])(?![0-9.])"
)


class ImportFailed(Exception):
    """The import cannot go on, or its result does not match its source."""


def _abs(path: Path | str) -> Path:
    return Path(path).expanduser().resolve()


# ----------------------------------------------------------------------------- locating the source


def find_app_dir(src: Path, app: str, prefix: str) -> Path | None:
    """The app's config directory under ``src``: ``<app>/`` (the module layout) or the old host's
    ``<prefix><name>_config/_data`` (a volume), whichever exists as a real directory."""
    for name in SOURCE_NAMES.get(app, (app,)):
        for cand in (
            src / name,
            src / f"{prefix}{name}_config" / "_data",
            src / f"{prefix}{name}_config",
        ):
            if cand.is_dir() and not cand.is_symlink():
                return cand
    return None


def _app_root(base: Path, app: str) -> Path:
    """Where the tree keeps an app's own files inside its directory (tdarr: configs/)."""
    return base / "configs" if app == "tdarr" and (base / "configs").is_dir() else base


# ----------------------------------------------------------------------------- reading


def _ro(path: Path) -> sqlite3.Connection:
    # immutable=1 reads a database on a read-only snapshot, but ignores a write-ahead log: when a
    # log holds data the plain read-only open (which reads it) is used instead
    wal = Path(str(path) + "-wal")
    if wal.exists() and wal.stat().st_size > 0:
        return sqlite3.connect(f"{path.as_uri()}?mode=ro", uri=True)
    return sqlite3.connect(f"{path.as_uri()}?mode=ro&immutable=1", uri=True)


def _tables(c: sqlite3.Connection) -> set[str]:
    return {r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table'")}


def _db_counts(
    db: Path, app: str, tables: tuple[str, ...], counting: tuple[str, ...]
) -> dict[str, int]:
    if not db.is_file():
        raise ImportFailed(f"{app}: {db}: no database (is this the app's config directory?)")
    c = _ro(db)
    try:
        have = _tables(c)
        missing = [t for t in tables if t not in have]
        if missing:
            raise ImportFailed(
                f"{app}: {db.name}: unrecognised schema, no table {', '.join(missing)} (refusing to guess)"
            )
        out = {t.lower(): c.execute(f'SELECT COUNT(*) FROM "{t}"').fetchone()[0] for t in counting}
        out["schema_version"] = (
            c.execute('SELECT MAX("Version") FROM "VersionInfo"').fetchone()[0]
            if "VersionInfo" in have
            else 0
        )
        return out
    finally:
        c.close()


def app_counts(app: str, base: Path) -> dict[str, int]:
    """The counts of one app's config directory (read-only); an unrecognised layout is an error."""
    if app in SQL_APPS:
        dbname, need, counting, _nonzero = SQL_APPS[app]
        if not (base / "config.xml").is_file():
            raise ImportFailed(f"{app}: {base}: no config.xml (the app's identity and API key)")
        return _db_counts(base / dbname, app, need, counting)
    if app == "seerr":
        db = base / "db" / "db.sqlite3"
        if not (base / "settings.json").is_file():
            raise ImportFailed(f"seerr: {base}: no settings.json")
        if not db.is_file():
            raise ImportFailed(f"seerr: {db}: no database")
        c = _ro(db)
        try:
            have = _tables(c)
            missing = [t for t in REQUEST_TABLES if t not in have]
            if missing:
                raise ImportFailed(
                    f"seerr: db.sqlite3: unrecognised schema, no table {', '.join(missing)}"
                )
            return {
                t: c.execute(f'SELECT COUNT(*) FROM "{t}"').fetchone()[0] for t in REQUEST_TABLES
            }
        finally:
            c.close()
    if app == "qbittorrent":
        conf = base / "qBittorrent" / "qBittorrent.conf"
        if not conf.is_file():
            raise ImportFailed(f"qbittorrent: {conf}: no settings file")
        bt = base / "qBittorrent" / "BT_backup"
        return {
            "resume_files": len(list(bt.glob("*.fastresume"))) if bt.is_dir() else 0,
            "torrent_files": len(list(bt.glob("*.torrent"))) if bt.is_dir() else 0,
        }
    if app == "nzbget":
        conf = base / "nzbget.conf"
        if not conf.is_file():
            raise ImportFailed(f"nzbget: {conf}: no nzbget.conf")
        text = conf.read_text(encoding="utf-8", errors="replace")
        return {
            "categories": len(re.findall(r"(?m)^Category\d+\.Name=.+$", text)),
            "servers": len(re.findall(r"(?m)^Server\d+\.Host=.+$", text)),
        }
    if app == "tdarr":
        root = _app_root(
            base, "tdarr"
        )  # the module layout keeps it under configs/, the old volume at the top
        if not (root / "Tdarr_Server_Config.json").is_file():
            raise ImportFailed(f"tdarr: {root}: no Tdarr_Server_Config.json")
        return {"config_files": len(list(root.glob("Tdarr_*_Config.json")))}
    raise ImportFailed(f"unknown app {app!r}")


def _key_hash(base: Path, app: str) -> str | None:
    """sha256 of the app's config.xml (it holds the API key): compared, never printed."""
    if app in SQL_APPS:
        return hashlib.sha256((base / "config.xml").read_bytes()).hexdigest()
    return None


def counts(
    src: Path, prefix: str = "", only: tuple[str, ...] | None = None
) -> dict[str, dict[str, int]]:
    """Per-app counts of a source (or of the module's config root), read-only."""
    src = _abs(src)
    out: dict[str, dict[str, int]] = {}
    for app in only or ALL_APPS:
        base = find_app_dir(src, app, prefix)
        if base is None:
            continue
        out[app] = app_counts(app, base)
    if not out:
        raise ImportFailed(
            f"{src}: no app config directory found (is this the volumes directory, and the prefix right?)"
        )
    return out


def _require_understood(
    per_app: dict[str, dict[str, int]],
    present: set[str],
    allow_empty: bool,
    only: tuple[str, ...] | None,
) -> None:
    """Refuse a source that lacks a required app or whose primary tables are empty."""
    missing = [a for a in REQUIRED_APPS if a not in present]
    if missing and only is None:
        raise ImportFailed(
            f"the source has no config directory for {', '.join(missing)} (--only to import some apps, "
            "knowingly)"
        )
    if allow_empty:
        return
    for app, (_db, _need, _count, nonzero) in SQL_APPS.items():
        if app in per_app:
            for t in nonzero:
                if per_app[app].get(t.lower(), 0) == 0:
                    raise ImportFailed(
                        f"{app}: the source has no rows in {t} (an empty database; --allow-empty to import it anyway)"
                    )


# ----------------------------------------------------------------------------- path and host mapping

_BEFORE = r"(?<![A-Za-z0-9_.\-/])"
_AFTER = r"(?=/|\Z|[<\"'\s,;\\])"
_HOST_BEFORE = r"(?<![A-Za-z0-9_.-])"
_HOST_AFTER = r"(?![A-Za-z0-9_-])"


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


def _rewriter(path_map: dict[str, str], host_map: dict[str, str]):
    """One pass for the paths (every old prefix looked for at once, longest first, so a rewritten
    path is never rewritten again), then one pass for the host names (whole tokens only)."""
    rules = _clean_map(path_map)
    pat = None
    if rules:
        alt = "|".join(re.escape(o) for o in sorted(rules, key=len, reverse=True))
        pat = re.compile(_BEFORE + "(" + alt + ")" + _AFTER)
    hpat = None
    if host_map:
        halt = "|".join(re.escape(o) for o in sorted(host_map, key=len, reverse=True))
        hpat = re.compile(_HOST_BEFORE + "(" + halt + ")" + _HOST_AFTER)

    def rewrite(text: str) -> str:
        if pat is not None:
            text = pat.sub(lambda m: rules[m.group(1)], text)
        if hpat is not None:
            text = hpat.sub(lambda m: host_map[m.group(1)], text)
        return text

    return rewrite


def _old_patterns(path_map: dict[str, str], host_map: dict[str, str]) -> list[re.Pattern[str]]:
    out = []
    if path_map:
        rules = _clean_map(path_map)
        alt = "|".join(re.escape(o) for o in sorted(rules, key=len, reverse=True))
        out.append(re.compile(_BEFORE + "(" + alt + ")" + _AFTER))
    if host_map:
        halt = "|".join(re.escape(o) for o in sorted(host_map, key=len, reverse=True))
        out.append(re.compile(_HOST_BEFORE + "(" + halt + ")" + _HOST_AFTER))
    return out


def _rewrite_db(path: Path, rewrite, unhandled: list[str]) -> int:
    """Rewrite paths and host names in every text column (and every UTF-8 JSON blob) of one
    database; returns the values changed. A blob that holds an old value but is not JSON is listed
    in ``unhandled`` (a binary format's length prefixes would be corrupted by editing it)."""
    c = sqlite3.connect(path)
    changed = 0
    try:
        for t in sorted(_tables(c)):
            for col in [r[1] for r in c.execute(f'PRAGMA table_info("{t}")')]:
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
                        else:
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
            raise ImportFailed(f"{path.name}: integrity_check failed after the rewrite: {ok}")
    finally:
        c.close()
    return changed


def _leftovers(db: Path, pats: list[re.Pattern[str]]) -> list[str]:
    left: list[str] = []
    c = sqlite3.connect(db)
    try:
        for t in sorted(_tables(c)):
            for col in [r[1] for r in c.execute(f'PRAGMA table_info("{t}")')]:
                for (v,) in c.execute(
                    f'SELECT "{col}" FROM "{t}" WHERE typeof("{col}") IN (?, ?)', ("text", "blob")
                ):
                    if isinstance(v, bytes):
                        try:
                            v = v.decode("utf-8")
                        except UnicodeDecodeError:
                            continue
                    if any(p.search(v) for p in pats):
                        left.append(f"{db.name}:{t}.{col}")
                        break
    finally:
        c.close()
    return left


def _ip_hosts(db: Path) -> list[str]:
    """Download-client, indexer and application rows whose settings name a host as an IP address."""
    found: list[str] = []
    c = sqlite3.connect(db)
    try:
        for t in sorted(_tables(c)):
            cols = [r[1] for r in c.execute(f'PRAGMA table_info("{t}")')]
            if "Settings" not in cols:
                continue
            for rowid, v in c.execute(
                f'SELECT rowid, "Settings" FROM "{t}" WHERE typeof("Settings") = ?', ("text",)
            ):
                try:
                    doc = json.loads(v)
                except ValueError:
                    continue
                for k in ("host", "hostname", "baseUrl", "prowlarrUrl"):
                    val = doc.get(k) if isinstance(doc, dict) else None
                    if isinstance(val, str) and IPV4.search(val):
                        found.append(f"{db.name}:{t}#{rowid}.{k}")
    finally:
        c.close()
    return found


# ----------------------------------------------------------------------------- bencode (the resume files)


class _Bad(ValueError):
    pass


def _bdecode(data: bytes, i: int = 0):
    ch = data[i : i + 1]
    if ch == b"i":
        end = data.index(b"e", i)
        return int(data[i + 1 : end]), end + 1
    if ch == b"l":
        i += 1
        out = []
        while data[i : i + 1] != b"e":
            v, i = _bdecode(data, i)
            out.append(v)
        return out, i + 1
    if ch == b"d":
        i += 1
        out = {}
        while data[i : i + 1] != b"e":
            k, i = _bdecode(data, i)
            if not isinstance(k, bytes):
                raise _Bad("a dictionary key that is not a string")
            v, i = _bdecode(data, i)
            out[k] = v
        return out, i + 1
    if ch.isdigit():
        colon = data.index(b":", i)
        n = int(data[i:colon])
        start = colon + 1
        if start + n > len(data):
            raise _Bad("a string past the end")
        return data[start : start + n], start + n
    raise _Bad(f"unexpected byte at {i}")


def _bencode(v) -> bytes:
    if isinstance(v, int):
        return b"i%de" % v
    if isinstance(v, bytes):
        return b"%d:" % len(v) + v
    if isinstance(v, list):
        return b"l" + b"".join(_bencode(x) for x in v) + b"e"
    if isinstance(v, dict):
        return b"d" + b"".join(_bencode(k) + _bencode(v[k]) for k in sorted(v)) + b"e"
    raise _Bad(f"cannot encode {type(v)}")


def _map_bytes(v, rewrite) -> tuple[object, int]:
    """Rewrite every string value that is a path (or holds a host), never a key; returns (value, changes)."""
    if isinstance(v, bytes):
        try:
            text = v.decode("utf-8")
        except UnicodeDecodeError:
            return v, 0
        new = rewrite(text)
        return (new.encode("utf-8"), 1) if new != text else (v, 0)
    if isinstance(v, list):
        out, n = [], 0
        for x in v:
            y, k = _map_bytes(x, rewrite)
            out.append(y)
            n += k
        return out, n
    if isinstance(v, dict):
        out, n = {}, 0
        for k2, x in v.items():
            if k2 == b"pieces":
                out[k2] = x
                continue
            y, k = _map_bytes(x, rewrite)
            out[k2] = y
            n += k
        return out, n
    return v, 0


def _rewrite_resume(path: Path, rewrite) -> int:
    raw = path.read_bytes()
    try:
        doc, end = _bdecode(raw)
    except (ValueError, IndexError) as e:
        raise ImportFailed(f"{path.name}: not a valid resume file ({e}); refusing to guess") from e
    if end != len(raw) or _bencode(doc) != raw:
        raise ImportFailed(
            f"{path.name}: a resume file that does not re-encode byte for byte; refusing to rewrite it"
        )
    new, n = _map_bytes(doc, rewrite)
    if n:
        path.write_bytes(_bencode(new))
    return n


# ----------------------------------------------------------------------------- the copy


def _copy_db(src: Path, dst: Path) -> None:
    a = _ro(src)
    b = sqlite3.connect(dst)
    try:
        a.backup(b)
    finally:
        a.close()
        b.close()


def _copy_tree(src: Path, dst: Path, skipped: list[str], skip_covers: bool) -> None:
    for root, dirs, files in os.walk(src):
        rel = Path(root).relative_to(src)
        keep = []
        for d in sorted(dirs):
            if d in SKIP_DIRS or (skip_covers and d == "MediaCover" and rel == Path(".")):
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
            if SKIP_FILE_RE.search(name):
                continue
            if not stat.S_ISREG(os.lstat(s).st_mode):
                skipped.append(str(rel / name))  # a fifo or a socket would hang the copy
                continue
            if name.endswith((".db", ".sqlite3")) and (rel == Path(".") or rel == Path("db")):
                _copy_db(s, d)
            else:
                shutil.copy2(s, d)


def _read(path: Path) -> str:
    with open(path, encoding="utf-8", newline="") as f:  # newline="": CRLF survives
        return f.read()


def _write(path: Path, text: str) -> None:
    with open(path, "w", encoding="utf-8", newline="") as f:
        f.write(text)


def _rewrite_text_files(root: Path, rewrite) -> int:
    changed = 0
    for p in sorted(root.rglob("*")):
        if (
            p.is_file()
            and not p.is_symlink()
            and p.suffix in TEXT_SUFFIXES
            and p.name != "config.xml"
        ):
            try:
                text = _read(p)
            except UnicodeDecodeError:
                continue
            new = rewrite(text)
            if new != text:
                _write(p, new)
                changed += 1
    return changed


def _is_empty_dir(p: Path) -> bool:
    return p.is_dir() and not any(p.iterdir())


def _nested(a: Path, b: Path) -> bool:
    return a == b or a in b.parents or b in a.parents


def _is_config_root(p: Path) -> bool:
    return any((p / app / "config.xml").is_file() for app in SQL_APPS)


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
        if target == pp or target in pp.parents or pp in target.parents:
            raise ImportFailed(
                f"{target}: the target is, or contains or lies inside, the library root {pre}"
            )
    if target.is_symlink():
        raise ImportFailed(f"{target}: is a symbolic link")
    if target.exists():
        if not target.is_dir():
            raise ImportFailed(f"{target}: exists and is not a directory")
        if os.path.ismount(target):
            raise ImportFailed(f"{target}: is a mount point")
        if not _is_empty_dir(target):
            if not _is_config_root(target):
                raise ImportFailed(
                    f"{target}: not empty and not an app config root (no <app>/config.xml); refusing to replace it"
                )
            if not replace:
                raise ImportFailed(
                    f"{target}: already holds a config root (replace=True moves it aside to {target.name}.before-import)"
                )


def import_config(
    source: Path,
    target: Path,
    path_map: dict[str, str] | None = None,
    *,
    host_map: dict[str, str] | None = None,
    strip_host_prefix: str = "",
    prefix: str = "",
    only: tuple[str, ...] | None = None,
    replace: bool = False,
    owner: tuple[int, int] | None = None,
    seerr_owner: tuple[int, int] | None = None,
    allow_empty: bool = False,
    strict: bool = False,
    skip_covers: bool = False,
    data_root: Path | None = None,
) -> dict:
    """Copy each app's config directory into ``target`` (``target/<app>``), mapping library paths
    and host names; verified against the source before it is renamed into place."""
    if Path(target).expanduser().is_symlink():  # judged before resolve() follows it away
        raise ImportFailed(f"{target}: is a symbolic link")
    source, target = _abs(source), _abs(target)
    data_root = _abs(data_root) if data_root else None
    rules = _clean_map(path_map or {})
    hosts = dict(host_map or {})
    if strip_host_prefix:
        hosts.update({f"{strip_host_prefix}{h}": h for h in HOST_SERVICES} | hosts)
    for old, new in hosts.items():
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]*", old) or not re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9.-]*", new
        ):
            raise ImportFailed(f"--host-map {old!r}={new!r}: plain host names only")
    apps = {}
    for app in only or ALL_APPS:
        base = find_app_dir(source, app, prefix)
        if base is not None:
            apps[app] = base
    if not apps:
        raise ImportFailed(
            f"{source}: no app config directory found (the volumes directory, and the --prefix?)"
        )
    before = {app: app_counts(app, base) for app, base in apps.items()}
    _require_understood(before, set(apps), allow_empty, only)
    _guard_target(source, target, list(rules.values()), replace, data_root)
    if (owner is not None or seerr_owner is not None) and os.geteuid() != 0:
        raise ImportFailed("--owner and --seerr-owner need root (chown); nothing was written")
    partial = target.with_name(target.name + ".partial")
    aside = target.with_name(target.name + ".before-import")
    if partial.exists() or partial.is_symlink():
        raise ImportFailed(f"{partial}: left by an earlier import; inspect it and move it away")
    if target.exists() and not _is_empty_dir(target) and (aside.exists() or aside.is_symlink()):
        raise ImportFailed(f"{aside}: exists; move it away first")

    keyhash = {app: _key_hash(base, app) for app, base in apps.items()}
    skipped: list[str] = []
    partial.mkdir(parents=True)
    for app, base in apps.items():
        dst = partial / app
        if app == "tdarr":
            dst = partial / "tdarr" / "configs"
        dst.mkdir(parents=True, exist_ok=True)
        _copy_tree(base, dst, skipped, skip_covers)

    rewrite = _rewriter(rules, hosts)
    report: dict = {"source": before, "changes": {}, "warnings": []}
    if rules or hosts:
        unhandled: list[str] = []
        rows = 0
        for p in sorted(partial.rglob("*")):
            if p.is_file() and not p.is_symlink() and p.suffix in (".db", ".sqlite3"):
                rows += _rewrite_db(p, rewrite, unhandled)
        resumes = 0
        for p in (
            sorted((partial / "qbittorrent").rglob("*.fastresume"))
            if (partial / "qbittorrent").is_dir()
            else []
        ):
            resumes += _rewrite_resume(p, rewrite)
        if unhandled:
            raise ImportFailed(
                "old library paths or host names inside binary (non-JSON) blobs that cannot be edited safely: "
                + ", ".join(sorted(set(unhandled)))
            )
        files = _rewrite_text_files(partial, rewrite)
        report["changes"]["rewrite"] = {
            "path_map": rules,
            "host_map": hosts,
            "db_values": rows,
            "resume_values": resumes,
            "files": files,
        }
        nested = any(n == o or n.startswith(o + "/") for o in rules for n in rules.values())
        if not nested:
            pats = _old_patterns(rules, hosts)
            left: list[str] = []
            for p in sorted(partial.rglob("*")):
                if p.is_file() and not p.is_symlink() and p.suffix in (".db", ".sqlite3"):
                    left += _leftovers(p, pats)
            if left:
                raise ImportFailed(
                    "an old library prefix or host name remains after the rewrite in: "
                    + ", ".join(left)
                )
    ips: list[str] = []
    for app in SQL_APPS:
        db = partial / app / SQL_APPS[app][0]
        if db.is_file():
            ips += _ip_hosts(db)
    if ips:
        report["ip_hosts"] = ips
        report["warnings"].append(
            f"{len(ips)} setting(s) name a host as an IP address (a container behind the VPN client has none that stays put); set the service name"
        )
        if strict:
            raise ImportFailed("settings name an IP address as a host: " + ", ".join(ips))
    if skipped:
        report["skipped_symlinks"] = skipped
    if owner is not None:
        for root, dirs, files in os.walk(partial):
            for n in dirs + files:
                os.chown(Path(root) / n, *owner, follow_symlinks=False)
        os.chown(partial, *owner)
        if seerr_owner is not None and (partial / "seerr").is_dir():
            for root, dirs, files in os.walk(partial / "seerr"):
                for n in dirs + files:
                    os.chown(Path(root) / n, *seerr_owner, follow_symlinks=False)
            os.chown(partial / "seerr", *seerr_owner)

    after = {}
    for app in apps:
        base = partial / app
        after[app] = app_counts(app, base)
    report["target"] = after
    if after != before:
        raise ImportFailed(
            f"counts differ after the copy: source {before}, new tree {after}; kept at {partial}, {target} untouched"
        )
    for app, h in keyhash.items():
        if h is not None and _key_hash(partial / app, app) != h:
            raise ImportFailed(
                f"{app}: config.xml (its API key) changed in the copy; kept at {partial}, {target} untouched"
            )
    if not any(v for c in after.values() for k, v in c.items() if k != "schema_version"):
        raise ImportFailed("every count is zero: refusing to call an empty import verified")

    # only now does anything of the previous target move, and it is renamed, never deleted
    if target.exists():
        if _is_empty_dir(target):
            target.rmdir()  # an empty directory: nothing to lose
        else:
            os.rename(target, aside)
            report["previous_target"] = str(aside)
    os.rename(partial, target)
    report["target_path"] = str(target)
    report["apps"] = sorted(apps)
    return report


def _parse_map(items: list[str], what: str, absolute: bool) -> dict[str, str]:
    out = {}
    for it in items:
        old, sep, new = it.partition("=")
        if (
            not sep
            or not old
            or not new
            or (absolute and not (old.startswith("/") and new.startswith("/")))
        ):
            raise SystemExit(
                f"{what} wants old=new{' (absolute paths)' if absolute else ''}, got {it!r}"
            )
        out[old] = new
    return out


def _parse_owner(v: str | None) -> tuple[int, int] | None:
    if not v:
        return None
    m = re.fullmatch(r"(\d+):(\d+)", v)
    if not m:
        raise SystemExit(f"owner wants UID:GID, got {v!r}")
    return int(m.group(1)), int(m.group(2))


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("counts", help="print the counts of each app found under DIR")
    c.add_argument("dir", type=Path)
    c.add_argument("--prefix", default="")
    i = sub.add_parser("import", help="import SRC's app config directories into DST")
    i.add_argument("src", type=Path)
    i.add_argument("dst", type=Path)
    i.add_argument("--map", action="append", default=[], metavar="/old=/new")
    i.add_argument("--host-map", action="append", default=[], metavar="old=new")
    i.add_argument("--strip-host-prefix", default="", metavar="PFX")
    i.add_argument("--prefix", default="", help="the old volumes' name prefix, e.g. media-core_")
    i.add_argument("--only", help="comma separated apps (knowingly leaves the rest)")
    i.add_argument(
        "--replace",
        action="store_true",
        help="move an existing config root at DST aside (never deleted)",
    )
    i.add_argument(
        "--allow-empty", action="store_true", help="accept a source whose primary tables are empty"
    )
    i.add_argument(
        "--strict", action="store_true", help="fail when a setting names an IP address as a host"
    )
    i.add_argument(
        "--skip-covers",
        action="store_true",
        help="do not carry the cover art caches (the apps re-download them)",
    )
    i.add_argument("--data-root", type=Path, help="DST must lie inside this directory")
    i.add_argument("--owner", help="UID:GID for everything copied")
    i.add_argument("--seerr-owner", help="UID:GID for the request app's directory")
    a = ap.parse_args(argv)
    try:
        if a.cmd == "counts":
            print(json.dumps(counts(a.dir, a.prefix), indent=2))
            return 0
        only = tuple(x for x in (a.only or "").split(",") if x) or None
        if only and any(x not in ALL_APPS for x in only):
            raise SystemExit(f"--only names apps of {', '.join(ALL_APPS)}")
        rep = import_config(
            a.src,
            a.dst,
            _parse_map(a.map, "--map", True),
            host_map=_parse_map(a.host_map, "--host-map", False),
            strip_host_prefix=a.strip_host_prefix,
            prefix=a.prefix,
            only=only,
            replace=a.replace,
            owner=_parse_owner(a.owner),
            seerr_owner=_parse_owner(a.seerr_owner),
            allow_empty=a.allow_empty,
            strict=a.strict,
            skip_covers=a.skip_covers,
            data_root=a.data_root,
        )
        print(json.dumps(rep, indent=2))
        return 0
    except ImportFailed as e:
        print(f"media-automation import: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
