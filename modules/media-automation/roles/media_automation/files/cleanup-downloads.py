#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Carried by the media-automation module (modules/media-automation/roles/media_automation/files): do not edit on the host.

Replaces cleanuparr (the user reported it never worked reliably) for the
one specific job asked for: cleaning up qBittorrent's completed-downloads
folder, but ONLY once a file's data is confirmed to already be safely
present in one of the real library folders (movies/shows/music/books/
audiobooks/workouts).

Also unconditionally deletes anything matching the community-maintained
ojwc/filetype-blacklist (nosubs variant — subtitle extensions are
deliberately NOT blocked) found in the completed-downloads folder, on
sight, with no hardlink check — there is no legitimate reason for an
executable/script/archive/office-doc/sample file to ever be in a movie/
show/music/book pipeline, unlike real media files which need the hardlink
safety check below. The same pattern file is also loaded into qBittorrent
itself (excluded_file_names) so these are refused at download time, not
just cleaned up after — this script is the backstop for anything that
slips through. `*.torrent` is deliberately REMOVED from the upstream list
before use here — qBittorrent needs its own .torrent metadata files to
function, confirmed the hard way this would have broken it. Scoped to
completed/ only, NOT incomplete/, so it never interferes with
qBittorrent's own tracking of an in-progress download's files.

Safety model for everything else — this is the whole point of the script, not an afterthought:
  - The *arr suite imports completed downloads via HARDLINK (the standard,
    recommended TRaSH-guides approach when source and destination share a
    filesystem, which they do here — everything lives under one NFS
    mount). A hardlinked file has the SAME (device, inode) as its
    counterpart in the library; it isn't a copy.
  - Before deleting anything from downloads/completed, this script builds
    an index of every (device, inode) pair under the real library folders,
    then only removes a file from downloads/completed if its (device,
    inode) is found in that index — i.e., its data is confirmed to still
    exist via a hardlink in the library. If a download hasn't been
    imported yet (no matching inode anywhere in the library), it is left
    alone completely, no matter how old it is.
  - libtorrent's own `<40-hex-infohash>.parts` control file (a "partfile":
    piece data for a torrent whose real files aren't fully written yet) is
    a DIFFERENT case from the above — it never gets hardlinked into the
    library (the *arr suite only ever imports the real media file), so the
    hardlink test above can never make one eligible, and by design it would
    otherwise sit in completed/ forever. Found live 2026-09-28
    (TASK-20260928-06): a `.parts` file for a torrent whose real file had
    already been reclaimed survived 3+ consecutive downloads_audit runs
    because nothing in this script's hardlink-based logic could ever match
    it. remove_stale_partfiles() below closes that gap with its own,
    narrower safety model: eligible only once (a) it is NOT held by any
    currently-loaded qBittorrent torrent (the identical seeding gate used
    for real media below — a `.parts` file for a torrent still genuinely
    downloading must never be touched) and (b) it has been stable
    (unmodified) for at least MIN_AGE_HOURS, the same margin already used
    before removing an empty directory.
  - Only after safe-to-remove files are deleted does it clean up
    directories that are now empty (and only ones older than
    MIN_AGE_HOURS, so it never races an import still in progress).
  - Run with --dry-run to preview every action with no deletions at all.
"""

import argparse
import fnmatch
import http.cookiejar
import json
import logging
import os
import time
import urllib.parse
import urllib.request

# qBittorrent, for the seeding check added 2026-07-23. Reached on localhost
# because this script runs on the guest itself, against the address the vpn
# container publishes the WebUI on (qBittorrent shares its network namespace and has
# no identity of its own: `gluetun` from inside the compose network).
QBIT_URL = os.environ.get(
    "QBIT_URL", ""
)  # the unit sets it to the published address; empty fails closed
QBIT_USER = os.environ.get("QBIT_USER", "admin")
QBIT_PASS = os.environ.get("QBIT_PASS", "")

MEDIA_ROOT = os.environ.get("MEDIA_ROOT", "/srv/media")
COMPLETED_ROOT = os.environ.get(
    "COMPLETED_ROOT", os.path.join(MEDIA_ROOT, "downloads", "qbittorrent", "completed")
)
# The real library folders to check for a hardlinked copy before deleting
# anything from downloads — deliberately NOT including `downloads` itself.
LIBRARY_DIRS = ["movies", "shows", "music", "books", "audiobooks", "workouts"]
MIN_AGE_HOURS = 6
BLACKLIST_FILE = os.environ.get(
    "BLACKLIST_FILE",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "qbittorrent-excluded-file-names.txt"),
)


def load_blacklist_patterns(path: str) -> list[str]:
    if not os.path.isfile(path):
        logging.warning("blacklist file not found, skipping blocked-file cleanup: %s", path)
        return []
    with open(path) as f:
        return [line.strip() for line in f if line.strip()]


def remove_blacklisted_files(completed_root: str, patterns: list[str], dry_run: bool) -> None:
    if not patterns:
        return
    for dirpath, _dirnames, filenames in os.walk(completed_root):
        for name in filenames:
            name_lower = name.lower()
            if any(fnmatch.fnmatch(name_lower, p.lower()) for p in patterns):
                path = os.path.join(dirpath, name)
                if dry_run:
                    logging.info("[dry-run] would remove (blacklisted filename): %s", path)
                else:
                    try:
                        os.remove(path)
                        logging.info("removed (blacklisted filename): %s", path)
                    except OSError as exc:
                        logging.warning("failed to remove blacklisted file %s: %s", path, exc)


def build_library_inode_index(media_root: str, library_dirs: list[str]) -> set[tuple[int, int]]:
    index: set[tuple[int, int]] = set()
    for library_dir in library_dirs:
        root = os.path.join(media_root, library_dir)
        if not os.path.isdir(root):
            continue
        for dirpath, _dirnames, filenames in os.walk(root):
            for name in filenames:
                try:
                    st = os.stat(os.path.join(dirpath, name))
                except OSError:
                    continue
                index.add((st.st_dev, st.st_ino))
    return index


def build_qbittorrent_path_index(url: str, user: str, password: str) -> set[str] | None:
    """Every filesystem path currently referenced by a torrent loaded in qBittorrent.

    Returns None when qBittorrent cannot be reached or authenticated. The caller
    treats None as "unknown" and SKIPS hardlink-based deletion entirely. Failing
    closed is deliberate: a transient API error must never be the reason a
    seeding torrent has its files deleted out from under it.
    """
    if not password:
        logging.error("QBIT_PASS is empty — cannot check seeding state, skipping cleanup")
        return None
    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())
    )
    try:
        data = urllib.parse.urlencode({"username": user, "password": password}).encode()
        login = urllib.request.Request(
            f"{url}/api/v2/auth/login", data=data, headers={"Referer": url}
        )
        with opener.open(login, timeout=30) as r:
            # qBittorrent signals a successful login as 200 with the body "Ok."
            # on some builds and as a bare 204 with an EMPTY body on others
            # (this deployment does the latter). Requiring the "Ok." string
            # therefore rejected perfectly good logins. Bad credentials are a
            # 401, which urllib raises as HTTPError and the except below turns
            # into a fail-closed None — so any 2xx that doesn't say "Fails" is
            # a success.
            body = r.read().decode("utf-8", "replace").strip()
            if r.status not in (200, 204) or "fails" in body.lower():
                logging.error(
                    "qBittorrent login rejected (HTTP %s, body %r) — skipping cleanup",
                    r.status,
                    body[:60],
                )
                return None
        with opener.open(f"{url}/api/v2/torrents/info", timeout=30) as r:
            torrents = json.loads(r.read().decode("utf-8", "replace"))
    except Exception as exc:
        logging.error("qBittorrent unreachable (%s) — skipping cleanup", exc)
        return None
    paths: set[str] = set()
    for t in torrents:
        for key in ("content_path", "save_path"):
            if t.get(key):
                paths.add(os.path.normpath(t[key]))
    logging.info("qBittorrent reports %d torrent(s) holding %d path(s)", len(torrents), len(paths))
    return paths


def _is_held_by_torrent(path: str, torrent_paths: set[str]) -> bool:
    """True if this file is, or lives under, a path a loaded torrent references."""
    p = os.path.normpath(path)
    if p in torrent_paths:
        return True
    return any(p.startswith(tp + os.sep) for tp in torrent_paths)


def remove_safe_files(
    completed_root: str, library_index: set[tuple[int, int]], torrent_paths: set[str], dry_run: bool
) -> None:
    for dirpath, _dirnames, filenames in os.walk(completed_root):
        for name in filenames:
            path = os.path.join(dirpath, name)
            try:
                st = os.stat(path)
            except OSError:
                continue
            if (st.st_dev, st.st_ino) in library_index:
                # Imported, but qBittorrent is still seeding it. Deleting this
                # hardlink leaves the library copy intact, but qBittorrent sees
                # the file as missing, errors the torrent, and stops seeding.
                # Remove the torrent in qBittorrent to make it eligible here —
                # that removal is the operator's intent signal.
                if _is_held_by_torrent(path, torrent_paths):
                    logging.info("leaving alone (still loaded in qBittorrent): %s", path)
                    continue
                if dry_run:
                    logging.info(
                        "[dry-run] would remove (confirmed hardlinked in library): %s", path
                    )
                else:
                    try:
                        os.remove(path)
                        logging.info("removed (confirmed hardlinked in library): %s", path)
                    except OSError as exc:
                        logging.warning("failed to remove %s: %s", path, exc)
            else:
                logging.debug("leaving alone (no matching library copy found): %s", path)


def remove_stale_partfiles(
    completed_root: str, torrent_paths: set[str], min_age_seconds: float, dry_run: bool
) -> None:
    """Reclaim orphaned libtorrent `.parts` control files — see the module docstring for why
    the hardlink test in remove_safe_files() can never match one. `torrent_paths` is the same
    qBittorrent-loaded-path index built for the seeding gate above; a `.parts` file still held
    by a loaded torrent is left alone regardless of age (it may be genuinely mid-download).
    Only a `.parts` file that is BOTH unheld and stable for `min_age_seconds` is removed."""
    now = time.time()
    for dirpath, _dirnames, filenames in os.walk(completed_root):
        for name in filenames:
            if not name.lower().endswith(".parts"):
                continue
            path = os.path.join(dirpath, name)
            if _is_held_by_torrent(path, torrent_paths):
                logging.info("leaving alone (still loaded in qBittorrent): %s", path)
                continue
            try:
                st = os.stat(path)
            except OSError:
                continue
            age = now - st.st_mtime
            if age < min_age_seconds:
                logging.debug("leaving alone (too recent, age=%.0fs): %s", age, path)
                continue
            if dry_run:
                logging.info("[dry-run] would remove (orphaned libtorrent partfile): %s", path)
            else:
                try:
                    os.remove(path)
                    logging.info("removed (orphaned libtorrent partfile): %s", path)
                except OSError as exc:
                    logging.warning("failed to remove %s: %s", path, exc)


def find_empty_dirs(root: str, min_age_seconds: float) -> list[str]:
    now = time.time()
    empty_dirs = []
    for dirpath, dirnames, filenames in os.walk(root, topdown=False):
        if dirpath == root or filenames:
            continue
        if any(os.path.isfile(os.path.join(dirpath, d)) for d in dirnames):
            continue
        try:
            age = now - os.path.getmtime(dirpath)
        except OSError:
            continue
        if age < min_age_seconds:
            continue
        empty_dirs.append(dirpath)
    return empty_dirs


def remove_empty_dirs(empty_dirs: list[str], dry_run: bool) -> None:
    for d in empty_dirs:
        if dry_run:
            logging.info("[dry-run] would remove empty directory: %s", d)
        else:
            try:
                os.rmdir(d)
                logging.info("removed empty directory: %s", d)
            except OSError as exc:
                logging.warning("failed to remove %s: %s", d, exc)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--dry-run", action="store_true", help="Log every action without deleting anything"
    )
    parser.add_argument(
        "--media-root", default=MEDIA_ROOT, help="Media mount root (default: %(default)s)"
    )
    parser.add_argument(
        "--completed-root",
        default=COMPLETED_ROOT,
        help="qBittorrent completed-downloads folder (default: %(default)s)",
    )
    parser.add_argument(
        "--min-age-hours",
        type=float,
        default=MIN_AGE_HOURS,
        help="Minimum directory age before an empty one is removed (default: %(default)s)",
    )
    parser.add_argument(
        "--blacklist-file",
        default=BLACKLIST_FILE,
        help="Path to the filename-pattern blacklist (default: %(default)s)",
    )
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    if not os.path.isdir(args.completed_root):
        logging.error("completed-downloads root does not exist: %s", args.completed_root)
        return

    blacklist_patterns = load_blacklist_patterns(args.blacklist_file)
    remove_blacklisted_files(args.completed_root, blacklist_patterns, args.dry_run)

    library_index = build_library_inode_index(args.media_root, LIBRARY_DIRS)
    logging.info(
        "indexed %d files across library folders: %s", len(library_index), ", ".join(LIBRARY_DIRS)
    )

    # Seeding gate: only files no longer held by any loaded torrent are
    # eligible. None means qBittorrent's state is unknown — skip rather than
    # guess, since guessing wrong kills seeding on the whole backlog.
    torrent_paths = build_qbittorrent_path_index(QBIT_URL, QBIT_USER, QBIT_PASS)
    if torrent_paths is None:
        logging.error("skipping hardlink-based cleanup this run (qBittorrent state unknown)")
        logging.error("skipping orphaned-partfile cleanup this run (qBittorrent state unknown)")
    else:
        remove_safe_files(args.completed_root, library_index, torrent_paths, args.dry_run)
        remove_stale_partfiles(
            args.completed_root, torrent_paths, args.min_age_hours * 3600, args.dry_run
        )

    empty_dirs = find_empty_dirs(args.completed_root, args.min_age_hours * 3600)
    remove_empty_dirs(empty_dirs, args.dry_run)


if __name__ == "__main__":
    main()
