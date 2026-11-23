#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# hnx-script:
#   id: restore-drill
#   kind: job
#   purpose: Restore the latest backup of one guest (rotating, alternating the primary and the second copy) to scratch space, check the image and the application exports inside it, destroy the scratch and record pass or fail (ADR-0042 decision 3, ADR-0008 decision 2).
#   owner: platform
#   trigger: [role:restore_drill, timer:restore_drill/drill]
#   inputs: the config the role renders (--config) and its env file (the backup server's API token secret, its certificate fingerprint, the notifier token)
#   outputs: the records file (drills.json, with a guests and a services mapping), one notifier message per change of a guest's state
#   installs_to: /usr/local/sbin/hnx-restore-drill
#   exit:
#     "0": the drill verified
#     "1": the drill failed or did not verify (recorded; the teardown still ran)
#     "2": bad arguments, an unreadable config or nothing to drill
"""Managed by homelabnext (role restore_drill); local changes are overwritten.

Two ways in, one drill:

    hnx-restore-drill <guest id> <guest name>    the role's contract (one guest, the primary copy);
                                                 prints {"snapshot": ..., "verified": ...}
    hnx-restore-drill --config C rotate          the timer's: the most overdue guest, from the
                                                 copy that was drilled the longest ago

A drill is more than the backup product's checksum (ADR-0042 context: "the drill checks bytes,
not service"): the newest snapshot must exist, be younger than ``max_snapshot_age_h`` and carry a
passing verification; its image is restored into scratch space, attached read-only (a loop
device; the journal is never replayed), the root filesystem must be a guest (``etc/os-release``),
and every application export under ``var/backups`` must be fresh, internally consistent (the
sha256 listing matches every dump; a custom-format dump carries its header) and restorable: the
smallest dump is copied to scratch and compared again.  Teardown (unmount, detach, delete) is part
of the verdict: a drill that leaves scratch behind fails.  A record never carries dumped content."""

import argparse
import datetime
import glob
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import urllib.request

SCHEMA = "homelabnext.restore-drill/1"
NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z")
GUEST_ID = re.compile(r"^(?:guest:)?[a-z0-9][a-z0-9-]*\Z")
LOOP = re.compile(r"^/dev/loop\d+\Z")


class Drill(Exception):
    """A verdict: the drill failed, with the reason that goes into the record."""


def now(ts=None):
    utc = datetime.timezone.utc  # noqa: UP017 - the host's own Python 3
    t = datetime.datetime.fromtimestamp(ts, utc) if ts is not None else datetime.datetime.now(utc)
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_ts(text):
    return datetime.datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.UTC)


def load_env(path):
    out = {}
    if path and os.path.exists(path):
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, _, v = line.partition("=")
                    out[k.strip()] = v.strip().strip("'\"")
    return out


def run(argv, env=None, check=True):
    proc = subprocess.run(argv, capture_output=True, text=True, env=env, check=False)
    if check and proc.returncode != 0:
        tail = (proc.stderr.strip().splitlines() or [""])[-1][:200]
        raise Drill(f"{os.path.basename(argv[0])} exited {proc.returncode}: {tail}")
    return proc


# ---------------------------------------------------------------- config and records
def load_config(path):
    with open(path, encoding="utf-8") as fh:
        cfg = json.load(fh)
    for key in (
        "client_cli",
        "authid",
        "stores",
        "namespace",
        "guests",
        "state_file",
        "scratch_dir",
    ):
        if key not in cfg:
            raise ValueError(f"config lacks {key!r}")
    if not cfg["stores"] or not cfg["guests"]:
        raise ValueError("config lists no store or no guest")
    for g in cfg["guests"]:
        if (
            not GUEST_ID.match(str(g.get("id", "")))
            or not NAME.match(str(g.get("name", "")))
            or not isinstance(g.get("vmid"), int)
        ):
            raise ValueError(
                f"guest {g!r}: an id (guest:<name>), a plain name and a numeric vmid are required"
            )
    scratch = cfg["scratch_dir"]
    if (
        not scratch.startswith("/")
        or ".." in scratch.split("/")
        or len([p for p in scratch.split("/") if p]) < 2
    ):
        raise ValueError(
            f"scratch_dir {scratch!r} is not a normalised absolute path of two or more components"
        )
    cfg.setdefault("max_snapshot_age_h", 36)
    cfg.setdefault("max_export_age_h", 36)
    cfg.setdefault("interval_days", 30)
    cfg.setdefault("host", "localhost")
    cfg.setdefault("disk", "drive-scsi0.img")
    cfg.setdefault("min_free_gb", 0)
    return cfg


def load_records(path):
    try:
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
    except FileNotFoundError:
        doc = {}
    doc.setdefault("guests", {})
    doc.setdefault("services", {})
    doc.setdefault("notified", {})
    doc.setdefault("runs", 0)
    return doc


def atomic_write(path, text):
    """Write text to path through a sibling temp file created at its final mode, then rename.
    A file that exists keeps its mode (the role sets who may read the records); a new one is 0600."""
    try:
        mode = stat.S_IMODE(os.stat(path).st_mode)
    except FileNotFoundError:
        mode = 0o600
    tmp = os.path.join(os.path.dirname(path), f".drills-{os.getpid()}-{os.urandom(4).hex()}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def save_records(path, doc):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    atomic_write(path, json.dumps(doc, indent=2, sort_keys=True) + "\n")


# ---------------------------------------------------------------- the backup server
def client_env(cfg, secrets):
    env = dict(os.environ)
    env["PBS_PASSWORD"] = secrets.get("PBS_PASSWORD", env.get("PBS_PASSWORD", ""))
    if secrets.get("PBS_FINGERPRINT"):
        env["PBS_FINGERPRINT"] = secrets["PBS_FINGERPRINT"]
    return env


def client_cli(cfg):
    return cfg["client_cli"]


def repository(cfg, store):
    return f"{cfg['authid']}@{cfg['host']}:{store}"


def newest_snapshot(cfg, guest, store, env, at):
    out = run(
        [
            client_cli(cfg),
            "snapshot",
            "list",
            "--repository",
            repository(cfg, store),
            "--ns",
            cfg["namespace"],
            "--output-format",
            "json",
        ],
        env=env,
    ).stdout
    try:
        rows = json.loads(out)
    except ValueError as exc:
        raise Drill("the snapshot list is not JSON") from exc
    mine = [
        r
        for r in rows
        if r.get("backup-type") == "vm" and str(r.get("backup-id")) == str(guest["vmid"])
    ]
    if not mine:
        raise Drill(f"no snapshot of vm/{guest['vmid']} in {store}")
    snap = max(mine, key=lambda r: r["backup-time"])
    age_h = (at - snap["backup-time"]) / 3600
    if age_h > float(cfg["max_snapshot_age_h"]):
        raise Drill(
            f"newest snapshot of vm/{guest['vmid']} in {store} is {age_h:.0f} h old (limit {cfg['max_snapshot_age_h']})"
        )
    state = (snap.get("verification") or {}).get("state")
    if state != "ok":
        raise Drill(
            f"newest snapshot of vm/{guest['vmid']} in {store} is not verified (state {state!r})"
        )
    return f"vm/{guest['vmid']}/{now(snap['backup-time'])}"


# ---------------------------------------------------------------- the checks inside the image
def sha256_of(path):
    with open(path, "rb") as fh:
        return hashlib.file_digest(fh, "sha256").hexdigest()


def find_exports(root):
    return sorted(glob.glob(os.path.join(root, "var/backups/**/db/manifest.json"), recursive=True))


def check_export(manifest_path, cfg, scratch, at):
    """Verify one application's dump directory; return its record."""
    base = os.path.dirname(manifest_path)
    with open(manifest_path, encoding="utf-8") as fh:
        meta = json.load(fh)
    app = str(meta.get("app", ""))
    if not NAME.match(app):
        raise Drill(f"{manifest_path}: no application name")
    age_h = (at - parse_ts(meta["created"]).timestamp()) / 3600
    if age_h > float(cfg["max_export_age_h"]):
        raise Drill(f"export of {app} is {age_h:.0f} h old (limit {cfg['max_export_age_h']})")
    stale = [s for s, j in (meta.get("jobs") or {}).items() if j.get("stale")]
    if stale:
        raise Drill(
            f"export of {app}: the last run failed for {', '.join(sorted(stale))} (stale dump)"
        )
    listing = os.path.join(base, "listing.sha256")
    entries = []
    with open(listing, encoding="utf-8") as fh:
        for line in fh:
            digest, _, rel = line.rstrip("\n").partition("  ")
            if (
                not re.fullmatch(r"[0-9a-f]{64}", digest)
                or not rel
                or rel.startswith("/")
                or ".." in rel.split("/")
            ):
                raise Drill(f"export of {app}: a malformed listing line")
            entries.append((digest, rel))
    if not entries:
        raise Drill(f"export of {app}: an empty listing")
    smallest = None
    for digest, rel in entries:
        path = os.path.join(base, rel)
        if not os.path.isfile(path):
            raise Drill(f"export of {app}: {rel} is listed and missing")
        if sha256_of(path) != digest:
            raise Drill(f"export of {app}: {rel} does not match its checksum")
        if rel.endswith(".dump"):
            with open(path, "rb") as fh:
                if fh.read(5) != b"PGDMP":
                    raise Drill(f"export of {app}: {rel} is not a custom-format dump")
        if smallest is None or os.path.getsize(path) < smallest[0]:
            smallest = (os.path.getsize(path), path, digest)
    # restore the smallest dump into scratch and compare once more (the copy is what a restore reads)
    copy = os.path.join(scratch, f"export-{app}")
    shutil.copyfile(smallest[1], copy)
    ok = sha256_of(copy) == smallest[2]
    os.unlink(copy)
    if not ok:
        raise Drill(f"export of {app}: the copy in scratch differs from the listing")
    return {
        "app": app,
        "created": meta["created"],
        "files": len(entries),
        "fingerprint_match": True,
    }


# ---------------------------------------------------------------- one guest
def partitions(loop):
    return sorted(glob.glob(loop + "p*"), key=lambda p: int(re.sub(r"\D", "", p[len(loop) :]) or 0))


def drill_guest(cfg, guest, store, secrets, at=None):
    """Run one drill; return (record, services).  Raises Drill on a failed verdict after teardown."""
    at = time.time() if at is None else at
    env = client_env(cfg, secrets)
    started = time.monotonic()
    snapshot = newest_snapshot(cfg, guest, store, env, at)
    os.makedirs(cfg["scratch_dir"], exist_ok=True)
    if (
        cfg["min_free_gb"]
        and shutil.disk_usage(cfg["scratch_dir"]).free < int(cfg["min_free_gb"]) * 1024**3
    ):
        raise Drill(f"scratch space has less than {cfg['min_free_gb']} GiB free")
    work = tempfile.mkdtemp(prefix="drill-", dir=cfg["scratch_dir"])
    loop = mnt = None
    problems = []
    services = {}
    try:
        image = os.path.join(work, "disk.img")
        disk = guest.get("disk") or cfg["disk"]
        run(
            [
                client_cli(cfg),
                "restore",
                snapshot,
                disk,
                image,
                "--repository",
                repository(cfg, store),
                "--ns",
                cfg["namespace"],
            ],
            env=env,
        )
        out = run(
            ["losetup", "--find", "--show", "--read-only", "--partscan", image]
        ).stdout.strip()
        if not LOOP.match(out):
            raise Drill(f"losetup answered {out!r}")
        loop = out
        mnt = os.path.join(work, "mnt")
        os.mkdir(mnt)
        mounted = False
        for part in partitions(loop) or [loop]:
            if run(["mount", "-o", "ro,noload", part, mnt], check=False).returncode == 0:
                if os.path.exists(os.path.join(mnt, "etc/os-release")):
                    mounted = True
                    break
                run(["umount", mnt], check=False)
        if not mounted:
            raise Drill("no partition of the restored image is a root filesystem (etc/os-release)")
        exports = find_exports(mnt)
        if guest.get("expect_export") and not exports:
            raise Drill(
                "the guest should carry an application export under var/backups and has none"
            )
        for mf in exports:
            try:
                rec = check_export(mf, cfg, work, at)
                services[rec["app"]] = {
                    "kind": "export",
                    "source": "export",
                    "snapshot": snapshot,
                    "verified": True,
                    "fingerprint_match": rec["fingerprint_match"],
                    "export_created": rec["created"],
                    "files": rec["files"],
                }
            except (Drill, OSError, ValueError, KeyError) as exc:
                problems.append(str(exc))
    except Drill as exc:
        problems.append(str(exc))
    finally:
        for argv in (
            ["umount", mnt] if mnt and os.path.ismount(mnt) else None,
            ["losetup", "--detach", loop] if loop else None,
        ):
            if argv:
                run(argv, check=False)
        shutil.rmtree(work, ignore_errors=True)
        if os.path.exists(work):
            problems.append("teardown failed: scratch space is still there")
        if loop and os.path.exists(loop) and run(["losetup", loop], check=False).returncode == 0:
            problems.append(f"teardown failed: {loop} is still attached")
    if problems:
        raise Drill("; ".join(problems))
    return {
        "kind": "image",
        "snapshot": snapshot,
        "store": store,
        "verified": True,
        "duration_s": round(time.monotonic() - started),
        "exports": sorted(services),
    }, services


# ---------------------------------------------------------------- records, choice, alerts
def due_order(cfg, records):
    def key(g):
        row = records["guests"].get(g["id"], {})
        return row.get("last_verified") or ""  # never drilled first, then the oldest

    return sorted(cfg["guests"], key=lambda g: (key(g), g["id"]))


def apply_result(records, guest, store, result, services, failure, at_text):
    row = dict(records["guests"].get(guest["id"], {}))
    row["name"] = guest["name"]
    if failure is None:
        row.update(
            {
                "last_verified": at_text,
                "snapshot": result["snapshot"],
                "store": store,
                "duration_s": result["duration_s"],
            }
        )
        row.pop("failure", None)
        row.pop("last_failure", None)
        for app, rec in services.items():
            prev = dict(records["services"].get(app, {}))
            prev.update(rec)
            prev["last_verified"] = at_text
            prev["guest"] = guest["id"]
            records["services"][app] = prev
    else:
        row.update({"last_failure": at_text, "failure": failure[:400], "store": store})
    records["guests"][guest["id"]] = row


def notify(cfg, secrets, title, message):
    cfg_n = cfg.get("notify") or {}
    if not cfg_n.get("url") or not cfg_n.get("topic"):
        return
    req = urllib.request.Request(
        cfg_n["url"].rstrip("/") + "/" + cfg_n["topic"], data=message.encode(), method="POST"
    )
    req.add_header("Title", title)
    token = secrets.get("NOTIFY_TOKEN")
    if token:
        req.add_header("Authorization", "Bearer " + token)
    try:
        urllib.request.urlopen(req, timeout=15).read()
    except OSError as exc:
        print(f"hnx-restore-drill: the notifier did not answer: {exc}", file=sys.stderr)


def settle(cfg, secrets, records, guest, failure):
    state = "ok" if failure is None else "fail"
    if records["notified"].get(guest["id"], "ok") != state:
        if failure is None:
            notify(
                cfg,
                secrets,
                f"restore drill recovered: {guest['name']}",
                "The restore drill of this guest verified again.",
            )
        else:
            notify(cfg, secrets, f"restore drill FAILED: {guest['name']}", failure[:400])
    records["notified"][guest["id"]] = state


def one(cfg, guest, store, secrets, records, at):
    at_text = now(at)
    failure = result = None
    services = {}
    try:
        result, services = drill_guest(cfg, guest, store, secrets, at)
    except (Drill, OSError, ValueError) as exc:
        failure = str(exc) or exc.__class__.__name__
    apply_result(records, guest, store, result, services, failure, at_text)
    records["runs"] = int(records.get("runs", 0)) + 1
    settle(cfg, secrets, records, guest, failure)
    return result, failure


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--config", default="/etc/hnx/restore-drill.json")
    ap.add_argument("--at", type=float, help="the evaluation time (epoch seconds), for a replay")
    ap.add_argument("args", nargs="*", help="rotate, or: <guest id> <guest name>")
    args = ap.parse_args(argv)
    try:
        cfg = load_config(args.config)
    except (OSError, ValueError) as exc:
        print(f"hnx-restore-drill: {exc}", file=sys.stderr)
        return 2
    secrets = load_env(cfg.get("env_file"))
    at = time.time() if args.at is None else args.at
    records = load_records(cfg["state_file"])
    if args.args == ["rotate"]:
        guest = due_order(cfg, records)[0]
        store = cfg["stores"][int(records.get("runs", 0)) % len(cfg["stores"])]
    elif len(args.args) == 2:
        found = [g for g in cfg["guests"] if g["id"] == args.args[0]]
        if not found:
            print(
                f"hnx-restore-drill: guest {args.args[0]!r} is not in the config", file=sys.stderr
            )
            return 2
        guest, store = found[0], cfg["stores"][0]
    else:
        print("hnx-restore-drill: say `rotate` or `<guest id> <guest name>`", file=sys.stderr)
        return 2
    result, failure = one(cfg, guest, store, secrets, records, at)
    save_records(cfg["state_file"], records)
    doc = {"schema": SCHEMA, "guest": guest["id"], "store": store, "verified": failure is None}
    if result:
        doc["snapshot"] = result["snapshot"]
    if failure:
        doc["failure"] = failure[:400]
    print(json.dumps(doc, sort_keys=True))
    return 0 if failure is None else 1


if __name__ == "__main__":
    sys.exit(main())
