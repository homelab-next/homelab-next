# SPDX-License-Identifier: Apache-2.0
# hnx-script:
#   id: cti-pipeline-state
#   kind: tool
#   purpose: Export, check and restore a cti-pipeline lane's store and state files; judge each job's last-run freshness; probe the gateway with a real-sized request.
#   owner: platform
#   trigger: [role:cti_pipeline]
#   inputs: "export SRC_ROOT DEST [--include DIR]... | prune-exports EXPORT_DIR LANE KEEP | check SOURCE [--expect-counts FILE] | restore SOURCE LANE_ROOT UID GID [--expect-counts FILE] | freshness RUNS_DIR JOB=MAX_AGE_S... [--now EPOCH] | probe-gateway URL MODEL MAX_TOKENS TIMEOUT_S [--ca FILE] (key on stdin)"
#   outputs: one JSON object on stdout; export writes DEST (created new), restore moves the replaced directories aside and renames the restored ones into the lane root
#   exit:
#     "0": exported, checked, restored, fresh, or the gateway answered with content
#     "1": refused, stale, or the probe failed (the reason in the JSON and on stderr)
#     "2": usage error
"""The cti-pipeline role's state tool (modules/cti-pipeline/README.md, "Backup, export, restore").

An export (format ``hnx-cti-state/1``) is a directory::

    cti.db          a consistent copy of the lane's store (the database's own backup API)
    counts.json     {"<table>": <rows>, ...} of that copy, every table
    files/<rel>     every regular file under the included directories of the source root (the
                    store and its -wal/-shm/-journal excluded: the copy above replaces them)
    listing.jsonl   one {"path", "size", "sha256"} per file above
    manifest.json   {"format", "store", "tables", "rows", "files"}

``export`` reads a lane root (or a copy of the old lab's working tree, the same layout:
``data/cti.db``, ``data/*.json``, ``state/``, ``podcast/``...) and writes DEST, which must not
exist: it is built as ``.<name>.incoming`` beside it and renamed when complete.  A symbolic link
or special file anywhere in an included directory is refused, never followed.

``check`` reads an export and writes nothing: every listed file is a single-link regular file of
its size and sha256 and every file is listed; the store passes its integrity check; its row
counts equal counts.json exactly (and the counts in ``--expect-counts`` when given, the source's
own at copy time); it holds at least one table.  A zero-table or zero-file export is an error,
never a pass.

``restore`` runs the check, stages the store and the files into ``LANE_ROOT/.restore-<stamp>/``
(owned by UID:GID), moves each replaced top-level directory aside as
``<dir>.before-restore-<stamp>`` (refused when that name exists) and renames the staged one in.
Nothing is deleted.

``freshness`` reads each job's last-run record (``<runs dir>/<job>.json``, written by
the job wrapper) and is fresh when the last run ended ok within its max age.

``probe-gateway`` posts one chat completion of MAX_TOKENS (the size a real job asks for: a
reasoning model spends a small budget on thought and returns nothing) and passes only when the
answer carries non-empty content.
"""

from __future__ import annotations

import argparse
import calendar
import hashlib
import json
import os
import re
import shutil
import sqlite3
import ssl
import stat
import sys
import time
import unicodedata
import urllib.error
import urllib.request

FORMAT = "hnx-cti-state/1"
STORE = "data/cti.db"
STORE_SIDE = ("-wal", "-shm", "-journal")
NF = os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
TABLE_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}\Z")
JOB_RE = re.compile(r"^[a-z][a-z0-9]*(-[a-z0-9]+)*\Z")
INCLUDE_RE = re.compile(r"^[A-Za-z0-9_.-]+(/[A-Za-z0-9_.-]+)*\Z")
MAX_FILES = 200_000
MAX_LISTING = 64 << 20


class Refused(Exception):
    """Refused, stale or failed: exit 1."""


# ----------------------------------------------------------------------------- paths


def deep_dir(path: str, what: str) -> str:
    """``path`` as given, which must be an existing directory (not a link) three components deep
    whose resolution is itself."""
    if not path.startswith("/") or os.path.islink(path) or not os.path.isdir(path):
        raise Refused(f"{what} {path} is not an absolute directory (or is a link)")
    resolved = os.path.realpath(path)
    if resolved != os.path.normpath(path) or len([p for p in resolved.split("/") if p]) < 3:
        raise Refused(
            f"{what} {path} resolves elsewhere or is too shallow (three components or more)"
        )
    return resolved


def rel_ok(rel: str) -> bool:
    if (
        not rel
        or rel.startswith("/")
        or "\\" in rel
        or any(ord(c) < 32 or ord(c) == 127 for c in rel)
    ):
        return False
    if unicodedata.normalize("NFC", rel) != rel:
        return False
    return all(p not in ("", ".", "..") for p in rel.split("/"))


def sha256_fd(fd: int, out=None) -> tuple[str, int]:
    """The sha256 and size of what ``fd`` holds from its offset on, copied to ``out`` when given."""
    h = hashlib.sha256()
    with os.fdopen(os.dup(fd), "rb", closefd=True) as src:
        for chunk in iter(lambda: src.read(1 << 20), b""):
            h.update(chunk)
            if out is not None:
                out.write(chunk)
        return h.hexdigest(), src.tell()


def walk_files(root: str, rel_dir: str):
    """(rel path, abs path) of every regular file under root/rel_dir; Refused on a link or a
    special file."""
    top = os.path.join(root, rel_dir)
    if os.path.islink(top):
        raise Refused(f"{rel_dir} is a link")
    if not os.path.exists(top):
        return
    if not os.path.isdir(top):
        raise Refused(f"{rel_dir} is not a directory")
    for dirpath, dirs, files in os.walk(top, followlinks=False):
        for d in dirs:
            if os.path.islink(os.path.join(dirpath, d)):
                raise Refused(f"{os.path.relpath(os.path.join(dirpath, d), root)} is a link")
        for name in sorted(files):
            full = os.path.join(dirpath, name)
            st = os.lstat(full)
            rel = os.path.relpath(full, root)
            if not stat.S_ISREG(st.st_mode):
                raise Refused(f"{rel} is a link or a special file")
            yield rel, full


# ----------------------------------------------------------------------------- the store


def table_counts(db_path: str) -> dict[str, int]:
    con = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    try:
        names = [r[0] for r in con.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")]  # fmt: skip
        out = {}
        for name in names:
            if not TABLE_RE.match(name):
                raise Refused(f"table {name!r} has a name this tool does not quote")
            out[name] = con.execute(f'SELECT count(*) FROM "{name}"').fetchone()[0]
        return out
    finally:
        con.close()


def integrity(db_path: str) -> str:
    con = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    try:
        return con.execute("PRAGMA integrity_check").fetchone()[0]
    finally:
        con.close()


def copy_store(src: str, dest: str) -> None:
    source = sqlite3.connect(f"file:{src}?mode=ro", uri=True)
    target = sqlite3.connect(dest)
    try:
        source.backup(target)
    finally:
        target.close()
        source.close()
    os.chmod(dest, 0o600)


# ----------------------------------------------------------------------------- export


def write_new(path: str, text: str) -> None:
    """A new file of an export being built (never an existing one: O_EXCL, owner-only)."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | NF, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(text)


def export(src_root: str, dest: str, includes: list[str]) -> dict:
    src_root = deep_dir(src_root, "the source root")
    if not dest.startswith("/") or os.path.lexists(dest):
        raise Refused(f"the destination {dest} must be an absolute path that does not exist yet")
    parent = deep_dir(os.path.dirname(dest.rstrip("/")) or "/", "the destination's parent")
    if (parent + "/").startswith(src_root + "/"):
        raise Refused("the destination is inside the source root")
    for inc in includes:
        if not INCLUDE_RE.match(inc) or not rel_ok(inc):
            raise Refused(f"--include {inc!r} is not a relative directory inside the source")
    store = os.path.join(src_root, STORE)
    if os.path.islink(store) or not os.path.isfile(store):
        raise Refused(f"the source has no store at {STORE}")
    stage = os.path.join(parent, "." + os.path.basename(dest.rstrip("/")) + ".incoming")
    if os.path.lexists(stage):
        raise Refused(f"{stage} exists (an interrupted export): move it aside first")
    os.mkdir(stage, 0o700)
    try:
        copy_store(store, os.path.join(stage, "cti.db"))
        counts = table_counts(os.path.join(stage, "cti.db"))
        if not counts:
            raise Refused("the store holds no table")
        write_new(os.path.join(stage, "counts.json"), json.dumps(counts, sort_keys=True, indent=1))
        skip = {STORE, *(STORE + s for s in STORE_SIDE)}
        listing = []
        for inc in sorted(set(includes)):
            for rel, full in walk_files(src_root, inc):
                if rel in skip:
                    continue
                out_path = os.path.join(stage, "files", rel)
                os.makedirs(os.path.dirname(out_path), mode=0o700, exist_ok=True)
                fd = os.open(full, os.O_RDONLY | NF)
                try:
                    with open(out_path, "xb") as out:
                        digest, size = sha256_fd(fd, out)
                finally:
                    os.close(fd)
                listing.append({"path": "files/" + rel, "size": size, "sha256": digest})
                if len(listing) > MAX_FILES:
                    raise Refused(f"more than {MAX_FILES} files")
        for name in ("cti.db", "counts.json"):
            fd = os.open(os.path.join(stage, name), os.O_RDONLY | NF)
            try:
                digest, size = sha256_fd(fd)
            finally:
                os.close(fd)
            listing.append({"path": name, "size": size, "sha256": digest})
        listing.sort(key=lambda r: r["path"])
        write_new(
            os.path.join(stage, "listing.jsonl"),
            "".join(json.dumps(r, sort_keys=True) + "\n" for r in listing),
        )
        manifest = {"format": FORMAT, "store": STORE, "tables": len(counts),
                    "rows": sum(counts.values()), "files": len(listing)}  # fmt: skip
        write_new(
            os.path.join(stage, "manifest.json"), json.dumps(manifest, sort_keys=True, indent=1)
        )
        os.rename(stage, dest)
    except BaseException:
        if os.path.isdir(stage) and not os.path.islink(stage) and os.path.dirname(stage) == parent:
            shutil.rmtree(stage)
        raise
    return {**manifest, "export": dest, "counts": counts}


# ----------------------------------------------------------------------------- check


def load_json(path: str):
    fd = os.open(path, os.O_RDONLY | NF)
    with os.fdopen(fd, "rb") as f:
        if not stat.S_ISREG(os.fstat(f.fileno()).st_mode):
            raise Refused(f"{path} is not a regular file")
        return json.loads(f.read(MAX_LISTING))


def check(source: str, expect_counts: str | None = None) -> dict:
    source = deep_dir(source, "the export")
    try:
        manifest = load_json(os.path.join(source, "manifest.json"))
        counts = load_json(os.path.join(source, "counts.json"))
    except (OSError, ValueError) as e:
        raise Refused(f"the export has no readable manifest.json or counts.json ({e})") from e
    if not isinstance(manifest, dict) or manifest.get("format") != FORMAT:
        raise Refused(f"the export is not {FORMAT}")
    if (
        not isinstance(counts, dict)
        or not counts
        or not all(isinstance(k, str) and isinstance(v, int) and v >= 0 for k, v in counts.items())
    ):
        raise Refused("counts.json is empty or not {table: rows}")
    listed: dict[str, dict] = {}
    with open(os.path.join(source, "listing.jsonl"), "rb") as f:
        raw = f.read(MAX_LISTING + 1)
    if len(raw) > MAX_LISTING:
        raise Refused("listing.jsonl is too large")
    for line in raw.decode("utf-8").splitlines():
        row = json.loads(line)
        path = row.get("path") if isinstance(row, dict) else None
        if (
            not isinstance(path, str)
            or not rel_ok(path)
            or path.casefold() in {p.casefold() for p in listed}
        ):
            raise Refused(f"listing entry {path!r} traverses, is malformed or repeats")
        listed[path] = row
    if "cti.db" not in listed or "counts.json" not in listed:
        raise Refused("the listing does not name cti.db and counts.json")
    present = set()
    for dirpath, dirs, files in os.walk(source, followlinks=False):
        for d in dirs:
            if os.path.islink(os.path.join(dirpath, d)):
                raise Refused(f"{os.path.relpath(os.path.join(dirpath, d), source)} is a link")
        for name in files:
            rel = os.path.relpath(os.path.join(dirpath, name), source)
            if rel not in ("listing.jsonl", "manifest.json"):
                present.add(rel)
    if present != set(listed):
        raise Refused(f"files and listing differ: unlisted {sorted(present - set(listed))[:5]}, "
                      f"missing {sorted(set(listed) - present)[:5]}")  # fmt: skip
    for rel, row in listed.items():
        fd = os.open(os.path.join(source, rel), os.O_RDONLY | NF)
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
                raise Refused(f"{rel} is not a single-link regular file")
            digest, size = sha256_fd(fd)
        finally:
            os.close(fd)
        if size != row.get("size") or digest != row.get("sha256"):
            raise Refused(f"{rel}: size or sha256 differs from the listing")
    db = os.path.join(source, "cti.db")
    verdict = integrity(db)
    if verdict != "ok":
        raise Refused(f"the store fails its integrity check: {verdict[:200]}")
    actual = table_counts(db)
    if actual != counts:
        diff = {
            t: (counts.get(t), actual.get(t))
            for t in sorted(set(counts) | set(actual))
            if counts.get(t) != actual.get(t)
        }
        raise Refused(f"the store's row counts differ from counts.json (expected, found): {diff}")
    if expect_counts:
        expected = load_json(expect_counts)
        if not isinstance(expected, dict) or not expected:
            raise Refused("--expect-counts is empty or not {table: rows}")
        diff = {
            t: (expected.get(t), actual.get(t))
            for t in sorted(expected)
            if expected[t] != actual.get(t)
        }
        if diff:
            raise Refused(
                f"the store's row counts differ from the source's (expected, found): {diff}"
            )
    return {
        "ok": True,
        "tables": len(actual),
        "rows": sum(actual.values()),
        "files": len(listed),
        "counts": actual,
    }


# ----------------------------------------------------------------------------- restore


def restore(
    source: str, lane_root: str, uid: int, gid: int, expect_counts: str | None = None
) -> dict:
    verdict = check(source, expect_counts)
    source = deep_dir(source, "the export")
    lane_root = deep_dir(lane_root, "the lane root")
    if (lane_root + "/").startswith(source + "/") or (source + "/").startswith(lane_root + "/"):
        raise Refused("the export and the lane root are nested")
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    stage = os.path.join(lane_root, f".restore-{stamp}")
    if os.path.lexists(stage):
        raise Refused(f"{stage} exists")
    os.mkdir(stage, 0o700)
    tops: set[str] = {STORE.split("/")[0]}
    for rel in [r for r in os_listing(source) if r.startswith("files/")]:
        inner = rel[len("files/") :]
        tops.add(inner.split("/")[0])
        dest = os.path.join(stage, inner)
        os.makedirs(os.path.dirname(dest), mode=0o700, exist_ok=True)
        shutil.copyfile(os.path.join(source, rel), dest, follow_symlinks=False)
    os.makedirs(os.path.join(stage, os.path.dirname(STORE)), mode=0o700, exist_ok=True)
    shutil.copyfile(
        os.path.join(source, "cti.db"), os.path.join(stage, STORE), follow_symlinks=False
    )
    staged_counts = table_counts(os.path.join(stage, STORE))
    if staged_counts != verdict["counts"]:
        raise Refused("the staged store's row counts differ from the checked export")
    for dirpath, dirs, files in os.walk(stage):
        for name in dirs + files:
            os.lchown(os.path.join(dirpath, name), uid, gid)
    os.lchown(stage, uid, gid)
    for top in sorted(tops):
        aside = os.path.join(lane_root, f"{top}.before-restore-{stamp}")
        if os.path.lexists(aside):
            raise Refused(f"{aside} exists")
    moved = []
    for top in sorted(tops):
        live = os.path.join(lane_root, top)
        if os.path.lexists(live):
            os.rename(live, os.path.join(lane_root, f"{top}.before-restore-{stamp}"))
            moved.append(top)
        os.rename(os.path.join(stage, top), live)
    os.rmdir(stage)
    return {**verdict, "restored": sorted(tops), "moved_aside": moved, "stamp": stamp}


def os_listing(source: str) -> list[str]:
    with open(os.path.join(source, "listing.jsonl"), encoding="utf-8") as f:
        return [json.loads(line)["path"] for line in f if line.strip()]


def prune_exports(export_dir: str, lane: str, keep: int) -> dict:
    """Remove ``<lane>-<stamp>`` export directories past the ``keep`` newest (by name: the stamp
    sorts in time order); never a link, never anything else in the directory."""
    export_dir = deep_dir(export_dir, "the export directory")
    if lane not in ("real", "shadow") or keep < 1:
        raise Refused("prune-exports takes a lane (real, shadow) and keep >= 1")
    pattern = re.compile(rf"^{lane}-[0-9]{{8}}T[0-9]{{6}}Z\Z")
    names = sorted(
        (
            e.name
            for e in os.scandir(export_dir)
            if pattern.match(e.name) and e.is_dir(follow_symlinks=False)
        ),
        reverse=True,
    )
    removed = []
    for name in names[keep:]:
        path = os.path.join(export_dir, name)
        if os.path.islink(path) or os.path.dirname(os.path.realpath(path)) != export_dir:
            raise Refused(f"{path} is not directly inside {export_dir}")
        shutil.rmtree(path)
        removed.append(name)
    return {"ok": True, "changed": bool(removed), "removed": removed, "kept": names[:keep]}


# ----------------------------------------------------------------------------- freshness


def freshness(runs_dir: str, jobs: dict[str, int], now: float) -> dict:
    out = {}
    for job, max_age in sorted(jobs.items()):
        path = os.path.join(runs_dir, job + ".json")
        try:
            rec = load_json(path)
        except (OSError, ValueError):
            out[job] = {"fresh": False, "why": "never ran (no record)"}
            continue
        finished = rec.get("finished_at") if isinstance(rec, dict) else None
        if not rec.get("ok") or not isinstance(finished, str):
            out[job] = {
                "fresh": False,
                "why": f"the last run did not succeed (exit {rec.get('exit')}, {rec.get('state')})",
            }
            continue
        try:
            at = calendar.timegm(time.strptime(finished, "%Y-%m-%dT%H:%M:%SZ"))
        except ValueError:
            out[job] = {"fresh": False, "why": f"unreadable finished_at {finished!r}"}
            continue
        age = int(now - at)
        out[job] = {
            "fresh": age <= max_age,
            "age_s": age,
            "max_age_s": max_age,
            "run_id": rec.get("run_id"),
        }
        if age > max_age:
            out[job]["why"] = f"the last success is {age} s old, over {max_age} s"
    return {"ok": all(v["fresh"] for v in out.values()), "jobs": out}


# ----------------------------------------------------------------------------- the gateway


def completion_verdict(status: int, body: bytes) -> dict:
    """A chat completion that counts: HTTP 200, a choice, and non-empty content."""
    if status != 200:
        return {"ok": False, "why": f"HTTP {status}"}
    try:
        doc = json.loads(body)
        msg = doc["choices"][0]["message"]
    except (ValueError, KeyError, IndexError, TypeError):
        return {"ok": False, "why": "the answer is not a chat completion"}
    content = msg.get("content") if isinstance(msg, dict) else None
    if not isinstance(content, str) or not content.strip():
        reason = doc["choices"][0].get("finish_reason")
        return {
            "ok": False,
            "why": f"empty content (finish_reason {reason!r}): the budget went to reasoning",
        }
    return {"ok": True, "chars": len(content.strip())}


def probe_gateway(
    url: str, model: str, max_tokens: int, timeout: int, ca: str | None, key: str
) -> dict:
    if not url.startswith(("https://", "http://")):
        raise Refused("the gateway URL is not http(s)")
    body = json.dumps({"model": model, "max_tokens": max_tokens,
                       "messages": [{"role": "user", "content": "Reply with one short sentence: what is a CVE?"}]}).encode()  # fmt: skip
    req = urllib.request.Request(url, data=body, method="POST", headers={
        "Content-Type": "application/json", "Authorization": f"Bearer {key}"})  # fmt: skip
    ctx = ssl.create_default_context(cafile=ca) if url.startswith("https://") else None
    try:
        with urllib.request.urlopen(
            req, timeout=timeout, context=ctx
        ) as r:  # the scheme is checked above
            return completion_verdict(r.status, r.read(4 << 20))
    except urllib.error.HTTPError as e:
        return completion_verdict(e.code, b"")
    except (urllib.error.URLError, OSError) as e:
        return {"ok": False, "why": f"the gateway did not answer: {e}"}


# ----------------------------------------------------------------------------- main


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(prog="cti_state.py")
    sub = ap.add_subparsers(dest="cmd", required=True)
    e = sub.add_parser("export")
    e.add_argument("src_root")
    e.add_argument("dest")
    e.add_argument("--include", action="append", default=[])
    c = sub.add_parser("check")
    c.add_argument("source")
    c.add_argument("--expect-counts")
    r = sub.add_parser("restore")
    r.add_argument("source")
    r.add_argument("lane_root")
    r.add_argument("uid", type=int)
    r.add_argument("gid", type=int)
    r.add_argument("--expect-counts")
    p = sub.add_parser("prune-exports")
    p.add_argument("export_dir")
    p.add_argument("lane")
    p.add_argument("keep", type=int)
    f = sub.add_parser("freshness")
    f.add_argument("runs_dir")
    f.add_argument("jobs", nargs="+")
    f.add_argument("--now", type=float)
    g = sub.add_parser("probe-gateway")
    g.add_argument("url")
    g.add_argument("model")
    g.add_argument("max_tokens", type=int)
    g.add_argument("timeout", type=int)
    g.add_argument("--ca")
    try:
        args = ap.parse_args(argv)
    except SystemExit:
        return 2
    try:
        if args.cmd == "export":
            out = export(args.src_root, args.dest, args.include)
        elif args.cmd == "check":
            out = check(args.source, args.expect_counts)
        elif args.cmd == "restore":
            out = restore(args.source, args.lane_root, args.uid, args.gid, args.expect_counts)
        elif args.cmd == "prune-exports":
            out = prune_exports(args.export_dir, args.lane, args.keep)
        elif args.cmd == "freshness":
            jobs = {}
            for item in args.jobs:
                job, sep, age = item.partition("=")
                if not sep or not JOB_RE.match(job) or not age.isdigit():
                    print(f"freshness: {item!r} is not JOB=MAX_AGE_S", file=sys.stderr)
                    return 2
                jobs[job] = int(age)
            out = freshness(args.runs_dir, jobs, args.now if args.now is not None else time.time())
        else:
            key = sys.stdin.read().strip()
            if not key:
                print("probe-gateway: no key on stdin", file=sys.stderr)
                return 2
            out = probe_gateway(args.url, args.model, args.max_tokens, args.timeout, args.ca, key)
    except (Refused, OSError, sqlite3.Error, ValueError) as err:
        print(json.dumps({"ok": False, "why": str(err)}))
        print(f"cti-pipeline state: refused: {err}", file=sys.stderr)
        return 1
    print(json.dumps(out, sort_keys=True))
    return 0 if out.get("ok", True) else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
