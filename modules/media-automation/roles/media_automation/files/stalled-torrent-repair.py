#!/usr/bin/env python3
"""Carried by the media-automation module (modules/media-automation/roles/media_automation/files): do not edit on the host.

Remove + re-search any torrent whose download progress has not moved in >=24h (operator
request 2026-08-27, generalizing a manual cleanup pass that hand-fixed 17 torrents
stuck at 0% with "missingFiles" state -- the operator's own framing: "allow it to remove and
find new for any torrent that is same progress across a 24 hour period... a simple memory of
name and progress percentage and date timestamp").

METHOD
  A small JSON state file remembers, per torrent hash, the progress last observed and the
  timestamp that progress was FIRST seen at (not the last check time -- progress changing at
  all resets the clock; only genuinely FROZEN progress accumulates age). A torrent whose
  progress is identical to the last observation, and that observation is >= STALL_HOURS old,
  is stalled: delete it from qBittorrent (deleteFiles=true -- its partial data cannot resume
  a fresh grab anyway), then resolve its release title to a Sonarr episode / Radarr movie via
  each app's own /parse endpoint (same mechanism confirmed live during the manual cleanup this
  generalizes) and trigger a search for a replacement.

  Paused/queued/checking states are exempt entirely -- a torrent qBittorrent is deliberately
  not feeding is not "stalled", it is doing exactly what it was told; only states where the
  app IS actively trying to progress (downloading, stalledDL, missingFiles, error, ...)
  accumulate stall age.

SAFETY
  Read-only by default in the sense that matters: only ever deletes a torrent that has been
  observed making zero progress for a FULL STALL_HOURS window, keyed by its own hash (never
  guesses from title similarity). A torrent this script has never seen before always gets one
  full stall-hours window of grace before it is eligible for removal, even if it happens to be
  stuck at 0% the very first time it's observed.
"""
from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger("stalled-torrent-repair")

QBIT_URL = os.environ.get("QBIT_URL", "")
QBIT_USER = os.environ.get("QBIT_USER", "admin")
QBIT_PASS = os.environ.get("QBIT_PASS", "")
SONARR_URL = os.environ.get("SONARR_URL", "")
RADARR_URL = os.environ.get("RADARR_URL", "")
STATE_FILE = Path(os.environ.get("STALLED_TORRENT_STATE",
                                  "/var/lib/hnx-modules/media-automation/state/stalled-torrents.json"))
STALL_HOURS = float(os.environ.get("STALLED_TORRENT_HOURS", "24"))
NOTIFY = os.environ.get("STALLED_TORRENT_NOTIFY", "")  # empty: no notification

# Paused/queued/checking states are BY DESIGN not progressing -- never accumulate stall age.
EXEMPT_STATES = {"pausedDL", "pausedUP", "queuedDL", "queuedUP", "checkingDL", "checkingUP",
                  "checkingResumeData", "moving", "allocating", "metaDL"}
# Completed/seeding states -- "is this download progressing" doesn't apply once it's done.
DONE_STATES = {"uploading", "stalledUP", "queuedUP", "pausedUP", "forcedUP"}

CATEGORY_APP = {"tv-sonarr": "sonarr", "radarr": "radarr"}

# --- Already-imported torrents stuck in missingFiles (2026-09-07) ------------------------
# A THIRD distinct shape, different again from both checks below: qBittorrent's own
# `missingFiles` state means "the file(s) this torrent tracks are no longer at their expected
# path" -- which the EXISTING progress-stall pass above already treats as stall-worthy (it is
# not in EXEMPT_STATES/DONE_STATES), but that pass's action (delete + trigger a FRESH *arr
# search) is WRONG for the common, benign cause: the *arr app already successfully imported
# this exact download (its own history shows a `downloadFolderImported` event for this
# torrent's hash) and the source copy is gone because import MOVED or hardlink-then-pruned it,
# not because the download failed. Confirmed live 2026-09-07 for the real case that surfaced
# this ("Colin from Accounts S03E08"): Sonarr's own /api/v3/history shows `downloadFolderImported`
# at 2026-09-07T03:40:28Z for the exact torrent hash still sitting in qBittorrent's queue at
# 0%/missingFiles hours later. Triggering a fresh episode/movie search for already-owned
# content wastes indexer/bandwidth budget and would re-grab a DUPLICATE of something already in
# the library -- the correct action here is simply removing the stale qBittorrent entry (there
# is nothing left to delete on disk; the file already lives in the library under a different
# path), with NO re-search.
#
# Runs BEFORE the progress-stall pass for exactly this reason: a torrent this check removes
# must never also reach find_stalled()'s stall-then-research action on some later run.
IMPORTED_EVENT_TYPES = ("downloadFolderImported",)


def find_imported_missing_files(torrents: list[dict], imported_hashes: set[str]) -> list[dict]:
    """Pure function. `imported_hashes` is a set of LOWERCASE torrent hashes drawn from *arr
    history downloadId fields for IMPORTED_EVENT_TYPES events. Matches only torrents currently
    in qBittorrent's `missingFiles` state whose hash appears in that set -- a torrent that is
    missingFiles but was NEVER actually imported (e.g. a genuinely broken/incomplete download)
    is correctly left for the progress-stall pass instead, which will eventually re-search it."""
    matched = []
    for t in torrents:
        h = (t.get("hash") or "").lower()
        if t.get("state") == "missingFiles" and h in imported_hashes:
            matched.append(t)
    return matched


def fetch_imported_hashes(base: str, key: str, page_size: int = 200) -> set[str]:
    """GET /api/v3/history (most recent `page_size` records — currently-tracked qBittorrent
    torrents are inherently recent, so this does not need to page through the whole history)
    and return the lowercased downloadId of every IMPORTED_EVENT_TYPES record."""
    hist = arr_get(base, key,
                    f"/api/v3/history?pageSize={page_size}&sortKey=date&sortDirection=descending")
    records = (hist or {}).get("records", []) if isinstance(hist, dict) else []
    return {
        r["downloadId"].lower()
        for r in records
        if r.get("eventType") in IMPORTED_EVENT_TYPES and r.get("downloadId")
    }


# --- Structurally-unimportable *arr queue items (2026-09-07) ------------------------------
# A DIFFERENT failure shape from the progress-stall repair above, and the one this file's own
# DONE_STATES exemption cannot see: a fake/poisoned release whose real payload is a *.exe (or
# any other extension on qBittorrent's ExcludedFileNamesEnabled list, LL-200) downloads to
# 0 excluded bytes almost instantly -- qBittorrent correctly reports it COMPLETE and moves it
# to a seeding state (uploading/stalledUP/queuedUP), which is exactly what DONE_STATES exists
# to exempt from stall-tracking, because a genuinely finished download SHOULD stop
# accumulating stall age. But Sonarr/Radarr then can never import it ("No files found are
# eligible for import") and the item sits in the *arr app's own queue in importPending/warning
# forever -- a torrent-level "done" and an app-level "stuck" at the same time. Found live
# 2026-09-07: 4 such releases (Lioness/Star Trek/South Park) had sat unremoved for 3+ days
# despite media-monitor correctly detecting and reporting them on 3 separate scheduled runs
# (2026-09-04, -05, -07) -- its own finding notes claimed a removal task was filed each time,
# but media-monitor is READ-ONLY by charter (agents/media-monitor.md) and no such task was
# ever actually created via tasking_queue_tool.py (confirmed: grepped tasking/queue.md and
# archive.md for the exact referenced ID and for the release titles -- neither exists). The
# recommendation was correct and the escalation text was accurate; nothing ever executed it.
#
# This check is deliberately NARROW, matching only the one unambiguous, structurally-safe
# signal: the *arr app's own message that no file in the download could ever be imported. It
# does NOT touch a generically slow/stuck item for any other reason (wrong file structure,
# missing codec, corrupt archive, etc.) -- those still need a human or the broader stall-repair
# pass above, because "will never import" for THOSE reasons is a judgment call this script
# should not make unattended. A real, unambiguous case is worth automating; a fuzzy one is not.
UNIMPORTABLE_MESSAGE_MARKERS = ("No files found are eligible for import",)

# Prowlarr is an indexer manager with no import queue of its own (mirrors the media MCP
# server's own arr_health.py skip list). Lidarr deliberately NOT included: tried it live
# 2026-09-07 (it shares the identical queue/import shape on paper) and both
# /api/v3/queue and /api/v3/system/status 404 against this deployment even with its own
# correct API key -- something about this Lidarr instance's API surface or URL base differs
# from Sonarr/Radarr's, not investigated further since no live case has ever needed it. Add it
# back once that's actually understood, not by guessing at a second endpoint shape blind.
UNIMPORTABLE_QUEUE_APPS = {
    "sonarr": ("SONARR_URL", "", "sonarr"),
    "radarr": ("RADARR_URL", "", "radarr"),
}


def find_unimportable_queue_items(records: list[dict]) -> list[dict]:
    """Pure function -- the actual decision logic for this check. A record matches only if one
    of its statusMessages (or its top-level errorMessage) contains one of
    UNIMPORTABLE_MESSAGE_MARKERS verbatim. Returns the matching records unchanged (caller reads
    `id`/`title` off them)."""
    matched = []
    for r in records:
        texts = [r.get("errorMessage") or ""]
        for sm in r.get("statusMessages", []) or []:
            texts.extend(str(m) for m in (sm.get("messages") or []))
        if any(marker in t for t in texts for marker in UNIMPORTABLE_MESSAGE_MARKERS):
            matched.append(r)
    return matched


def remove_unimportable(base: str, key: str, item_id) -> None:
    """DELETE .../queue/<id> with removeFromClient+blocklist+skipRedownload=true -- the exact
    procedure LL-200 proved necessary: skipRedownload=false re-grabs the SAME poisoned release
    (or another fake for the same episode) within seconds, because the *arr app's own
    immediate re-search hits the same flooded indexer listing that produced the stuck item."""
    req = urllib.request.Request(
        base + f"/api/v3/queue/{item_id}?removeFromClient=true&blocklist=true&skipRedownload=true",
        method="DELETE", headers={"X-Api-Key": key})
    urllib.request.urlopen(req, timeout=20)


def _api_key_from_container(app: str) -> str:
    """Reads the app's own auto-generated API key from its config.xml in the module's data root
    (APP_CONFIG_ROOT/<app>/config.xml, read-only to this unit): deliberately not duplicated in the
    secret store, it is an internal self-generated key, and reading it live is correct even if it
    is ever regenerated. The name is kept (the callers pass the app's name)."""
    import re
    root = os.environ.get("APP_CONFIG_ROOT", "/var/lib/hnx-modules/media-automation/config")
    try:
        text = (Path(root) / app / "config.xml").read_text(encoding="utf-8")
        m = re.search(r"<ApiKey>([^<]+)</ApiKey>", text)
        return m.group(1) if m else ""
    except Exception as exc:  # noqa: BLE001 — a missing key degrades to "can't re-search", not a crash
        logger.warning("could not read API key of %s: %s", app, exc)
        return ""


def qbit_login() -> str:
    req = urllib.request.Request(
        QBIT_URL + "/api/v2/auth/login",
        data=urllib.parse.urlencode({"username": QBIT_USER, "password": QBIT_PASS}).encode(),
        method="POST")
    resp = urllib.request.urlopen(req, timeout=15)
    return resp.headers.get("Set-Cookie", "").split(";")[0]


def qbit_torrents(cookie: str) -> list[dict]:
    req = urllib.request.Request(QBIT_URL + "/api/v2/torrents/info", headers={"Cookie": cookie})
    return json.loads(urllib.request.urlopen(req, timeout=20).read())


def qbit_delete(cookie: str, torrent_hash: str) -> None:
    req = urllib.request.Request(
        QBIT_URL + "/api/v2/torrents/delete",
        data=f"hashes={torrent_hash}&deleteFiles=true".encode(), method="POST",
        headers={"Cookie": cookie})
    urllib.request.urlopen(req, timeout=15)


def arr_get(base: str, key: str, path: str):
    req = urllib.request.Request(base + path, headers={"X-Api-Key": key})
    return json.loads(urllib.request.urlopen(req, timeout=20).read())


def arr_post(base: str, key: str, path: str, payload: dict):
    req = urllib.request.Request(
        base + path, data=json.dumps(payload).encode(), method="POST",
        headers={"X-Api-Key": key, "Content-Type": "application/json"})
    return json.loads(urllib.request.urlopen(req, timeout=20).read())


def load_state() -> dict:
    if not STATE_FILE.exists():
        return {}
    try:
        return json.loads(STATE_FILE.read_text())
    except (OSError, json.JSONDecodeError):
        return {}


def save_state(state: dict) -> None:
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = STATE_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(state))
    tmp.replace(STATE_FILE)  # atomic — a killed run must never leave a half-written state file


def find_stalled(torrents: list[dict], prior_state: dict, now: float,
                  stall_hours: float = STALL_HOURS) -> tuple[list[dict], dict]:
    """Pure function, the actual decision logic -- see module docstring. Returns
    (stalled_torrents, next_state). `next_state` already excludes stalled torrents (they're
    about to be deleted; if deletion fails for some reason, the NEXT run will just see them as
    "new" again and give them a fresh grace window, which is the safe direction to fail in)."""
    next_state: dict = {}
    stalled: list[dict] = []
    for t in torrents:
        h = t.get("hash")
        state = t.get("state")
        if not h or state in EXEMPT_STATES or state in DONE_STATES:
            continue  # not tracked -- no stale clock accumulates while paused/queued/done
        progress = t.get("progress")
        prev = prior_state.get(h)
        if prev is None or prev.get("progress") != progress:
            next_state[h] = {"name": t.get("name"), "progress": progress, "since": now}
            continue
        age_hours = (now - prev["since"]) / 3600.0
        if age_hours >= stall_hours:
            stalled.append(t)
        else:
            next_state[h] = prev  # unchanged — keep the ORIGINAL since-timestamp
    return stalled, next_state


def repair_one(cookie: str, torrent: dict, sonarr_key: str, radarr_key: str) -> dict:
    """Delete one stalled torrent and trigger a replacement search. Returns a result dict for
    logging; never raises -- one bad torrent must not abort the whole run."""
    name = torrent.get("name", "")
    category = torrent.get("category", "")
    result = {"name": name, "hash": torrent.get("hash"), "deleted": False, "researched": False}
    try:
        qbit_delete(cookie, torrent["hash"])
        result["deleted"] = True
    except Exception as exc:  # noqa: BLE001
        result["error"] = f"delete failed: {exc}"
        return result

    app = CATEGORY_APP.get(category)
    if app is None:
        result["error"] = f"no re-search: unrecognized category {category!r}"
        return result
    try:
        if app == "sonarr":
            if not sonarr_key:
                result["error"] = "no re-search: the library manager API key is unavailable"
                return result
            parsed = arr_get(SONARR_URL, sonarr_key, "/api/v3/parse?title=" + urllib.parse.quote(name))
            eps = parsed.get("episodes") or []
            if not eps:
                result["error"] = "no re-search: sonarr could not parse release title"
                return result
            arr_post(SONARR_URL, sonarr_key, "/api/v3/command",
                     {"name": "EpisodeSearch", "episodeIds": [e["id"] for e in eps]})
            result["researched"] = True
        else:
            if not radarr_key:
                result["error"] = "no re-search: the library manager API key is unavailable"
                return result
            parsed = arr_get(RADARR_URL, radarr_key, "/api/v3/parse?title=" + urllib.parse.quote(name))
            movie = parsed.get("movie")
            if not movie:
                result["error"] = "no re-search: radarr could not parse release title"
                return result
            arr_post(RADARR_URL, radarr_key, "/api/v3/command",
                     {"name": "MoviesSearch", "movieIds": [movie["id"]]})
            result["researched"] = True
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError) as exc:
        result["error"] = f"re-search failed: {exc}"
    return result


def notify(title: str, body: str) -> None:
    if not NOTIFY:
        return
    try:
        urllib.request.urlopen(urllib.request.Request(
            NOTIFY, data=body.encode(),
            headers={"Title": title, "Tags": "recycle,robot"}), timeout=10)
    except Exception as exc:  # noqa: BLE001
        logger.warning("notification failed: %s", exc)


def main() -> int:
    import argparse
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dry-run", action="store_true",
                     help="Log what would be removed/researched; touch no state, delete nothing.")
    args = ap.parse_args()

    try:
        cookie = qbit_login()
        torrents = qbit_torrents(cookie)
    except Exception as exc:  # noqa: BLE001
        logger.error("could not reach qBittorrent: %s", exc)
        return 2

    # --- First pass: already-imported torrents stuck in missingFiles ----------------------
    # Runs before find_stalled() so a torrent this removes never also reaches the
    # stall-then-research action on this or a later run (see the module-level comment above
    # find_imported_missing_files for why that combination would be wrong).
    sonarr_key_early = _api_key_from_container("sonarr")
    radarr_key_early = _api_key_from_container("radarr")
    imported_hashes: set[str] = set()
    for app_base, app_key in ((SONARR_URL, sonarr_key_early), (RADARR_URL, radarr_key_early)):
        if not app_key:
            continue
        try:
            imported_hashes |= fetch_imported_hashes(app_base, app_key)
        except Exception as exc:  # noqa: BLE001
            logger.warning("imported-missing-files check: could not read history from %s: %s",
                            app_base, exc)

    already_imported = find_imported_missing_files(torrents, imported_hashes)
    removed_imported = []
    for t in already_imported:
        name = t.get("name", "?")
        if args.dry_run:
            logger.info("DRY RUN would remove already-imported missingFiles torrent: %s", name)
            continue
        try:
            qbit_delete(cookie, t["hash"])
            removed_imported.append(name)
            logger.info("ALREADY-IMPORTED MISSINGFILES REMOVED: %s", name)
        except Exception as exc:  # noqa: BLE001
            logger.warning("imported-missing-files check: failed to remove %s: %s", name, exc)
    if removed_imported and not args.dry_run:
        notify("stalled-torrent-repair: already-imported torrent(s) removed",
             f"{len(removed_imported)} torrent(s) removed -- content was already successfully "
             f"imported (confirmed via *arr history), the qBittorrent entry was just stale:\n\n"
             + "\n".join(f"- {n}" for n in removed_imported))
    # Never re-process an already-imported torrent as a progress-stall candidate this run.
    removed_hash_set = {t["hash"] for t in already_imported} if not args.dry_run else set()
    torrents = [t for t in torrents if t.get("hash") not in removed_hash_set]

    prior_state = load_state()
    now = time.time()
    stalled, next_state = find_stalled(torrents, prior_state, now)

    if not stalled:
        if not args.dry_run:
            save_state(next_state)
        logger.info("no stalled torrents (checked %d, %d tracked)", len(torrents), len(next_state))
    else:
        # NOTE: this branch used to `return 0` when `stalled` was empty, which meant the
        # unimportable-queue-item pass below NEVER RAN on the (common) case of "no
        # progress-stalled torrents this hour" -- caught in this same change, before it ever
        # shipped, by a live test run whose log showed only "no stalled torrents" with no trace
        # of the second pass at all.
        sonarr_key = _api_key_from_container("sonarr")
        radarr_key = _api_key_from_container("radarr")

        results = []
        for t in stalled:
            if args.dry_run:
                logger.info("DRY RUN would remove+research: %s (%.0f%%, category=%s)",
                            t.get("name"), (t.get("progress") or 0) * 100, t.get("category"))
                continue
            r = repair_one(cookie, t, sonarr_key, radarr_key)
            results.append(r)
            tag = "OK" if r["researched"] else ("DELETED, NO RESEARCH" if r["deleted"] else "FAILED")
            logger.info("%s: %s%s", tag, r["name"], f" ({r.get('error')})" if r.get("error") else "")

        if not args.dry_run:
            save_state(next_state)
            researched = sum(1 for r in results if r["researched"])
            problems = [r for r in results if r.get("error")]
            # Constant title, counts in the body (LL-208): this is a one-shot "action taken"
            # report, and a count in the title made every run its own permanent status.json row.
            notify("stalled-torrent-repair: stalled torrent(s) removed",
                 f"{len(stalled)} removed; {researched}/{len(stalled)} re-searched "
                 f"successfully.\n\n" +
                 "\n".join(f"- {r['name']}: {r.get('error', 'ok')}" for r in results))
            if problems:
                logger.warning("%d/%d had a problem (see log above)", len(problems), len(stalled))

    # --- Second, independent pass: structurally-unimportable *arr queue items -------------
    # ALWAYS runs, regardless of the progress-stall pass's own outcome above (see the NOTE in
    # the `if not stalled` branch for why that matters). Deliberately separate from the
    # progress-stall pass (own try/except per app, same fail-open-per-item shape as
    # repair_one) -- a bug in one pass must never block the other.
    removed_unimportable = []
    for app, (env_var, default_url, container) in UNIMPORTABLE_QUEUE_APPS.items():
        base = os.environ.get(env_var, default_url)
        if not base:
            logger.warning("unimportable-check: %s is not set, skipping %s", env_var, app)
            continue
        try:
            key = _api_key_from_container(container)
            if not key:
                logger.warning("unimportable-check: no API key for %s, skipping", app)
                continue
            queue = arr_get(base, key, "/api/v3/queue?pageSize=100")
            records = (queue or {}).get("records", []) if isinstance(queue, dict) else []
        except Exception as exc:  # noqa: BLE001
            logger.warning("unimportable-check: could not reach %s: %s", app, exc)
            continue
        for item in find_unimportable_queue_items(records):
            title = item.get("title", "?")
            if args.dry_run:
                logger.info("DRY RUN would remove unimportable %s item: %s", app, title)
                continue
            try:
                remove_unimportable(base, key, item["id"])
                removed_unimportable.append(f"{app}: {title}")
                logger.info("UNIMPORTABLE REMOVED (%s): %s", app, title)
            except Exception as exc:  # noqa: BLE001
                logger.warning("unimportable-check: failed to remove %s item %s: %s",
                                app, title, exc)

    if removed_unimportable and not args.dry_run:
        notify("stalled-torrent-repair: unimportable release(s) removed",
             f"{len(removed_unimportable)} structurally-unimportable release(s) blocklisted "
             f"and removed (LL-200):\n\n" + "\n".join(f"- {r}" for r in removed_unimportable))
    elif not removed_unimportable:
        # Symmetric with the progress-stall pass's own "no stalled torrents" line -- a clean
        # pass should say so explicitly, not just be silence indistinguishable from "never ran".
        logger.info("no unimportable queue items (checked %d app(s))", len(UNIMPORTABLE_QUEUE_APPS))

    return 0


if __name__ == "__main__":
    sys.exit(main())
