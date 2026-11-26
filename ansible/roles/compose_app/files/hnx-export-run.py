#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# hnx-script:
#   id: compose-app-export-run
#   kind: job
#   purpose: Take the application-consistent dump of every database engine a compose application runs, and a consistent copy of its SQLite files and state trees (ADR-0042 decision 2, ADR-0008 decision 1), into the application's export directory, where the guest's image backup picks it up.
#   owner: platform
#   trigger: [role:compose_app, timer:compose_app/export]
#   inputs: the manifest the role renders (--manifest)
#   outputs: <export dir>/<service>/<database>.dump or all-databases.sql (for a sqlite job <name>/<file>.sqlite, for a tree job <name>/<name>.tar.gz), <export dir>/listing.sha256 and manifest.json (mode 0600, directories 0700); the previous dump of a service is kept once as <service>.prev
#   installs_to: /usr/local/libexec/homelabnext/hnx-export-run
#   exit:
#     "0": every job dumped and verified (or the manifest lists no supported engine)
#     "1": at least one job failed; the last good dump of that service is untouched
#     "2": bad arguments or a refused path
"""Managed by homelabnext (role compose_app); local changes are overwritten.

The dump runs *inside* the engine's own container (``docker compose exec -T``), so the engine's
credentials never leave it and never appear on this script's command line: PostgreSQL over its
socket as the container's own ``POSTGRES_USER``, MariaDB/MySQL with ``MYSQL_PWD`` taken from the
container's own environment.  Every dump is written to a temporary file in the service's export
directory, checked (a custom-format dump starts with ``PGDMP``; an SQL dump ends with the engine's
completion trailer) and only then renamed into place, so a failed or interrupted run leaves the
last good dump alone.  What the dump does not carry (bind-mounted files, uploads, a cache) is
written into ``manifest.json`` (ADR-0008 decision 4); those travel in the guest's image backup.

Two more job kinds need no container: ``sqlite`` copies every file a glob matches through SQLite's
online backup API (a consistent snapshot of a live database, read-only on the source), and checks
the copy (``PRAGMA integrity_check`` is ``ok`` and it holds a table); ``tree`` writes a gzip tar of a
directory, minus the listed exclusions, and checks it reads back.  A glob that matches nothing or a
tree that is empty is a failure, not an empty success."""

import argparse
import contextlib
import datetime
import fnmatch
import glob
import hashlib
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import tarfile
import tempfile

SCHEMA = "homelabnext.compose-app.export/1"
NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z")
ENGINES = ("postgres", "mysql")
FILE_KINDS = ("sqlite", "tree")
NOT_CARRIED = (
    "anything the jobs above do not name (bind-mounted files, uploads, caches): it is in the guest's image backup; "
    "a sqlite or tree job is a copy of live files, not a quiesced dump of the application"
)


class Refused(Exception):
    pass


def now():
    utc = datetime.timezone.utc  # noqa: UP017 - the guest's own Python 3
    return datetime.datetime.now(utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def safe_export_dir(path):
    """Refuse a path the script must never write under (shallow, relative, traversing)."""
    if not isinstance(path, str) or not path.startswith("/") or ".." in path.split("/"):
        raise Refused(f"export dir {path!r} is not a normalised absolute path")
    if len([p for p in path.split("/") if p]) < 3:
        raise Refused(f"export dir {path!r} is too shallow")
    real = os.path.realpath(path)
    if real != os.path.normpath(path):
        raise Refused(f"export dir {path!r} resolves elsewhere ({real!r}): a symlink")
    return path


def safe_source(path):
    """Refuse a source path that is relative, traversing or shallow (the source is read, never written)."""
    if not isinstance(path, str) or not path.startswith("/") or ".." in path.split("/"):
        raise Refused(f"source {path!r} is not a normalised absolute path")
    if len([p for p in path.split("/") if p]) < 3:
        raise Refused(f"source {path!r} is too shallow")
    return path


def load_manifest(path):
    with open(path, encoding="utf-8") as fh:
        doc = json.load(fh)
    for key in ("app", "export_dir", "jobs"):
        if key not in doc:
            raise Refused(f"manifest lacks {key!r}")
    if not NAME.match(str(doc["app"])):
        raise Refused("manifest app name is not a plain name")
    safe_export_dir(doc["export_dir"])
    names = set()
    for job in doc["jobs"]:
        name, kind = str(job.get("service", "")), job.get("engine")
        if not NAME.match(name) or name in names or kind not in ENGINES + FILE_KINDS:
            raise Refused(
                f"job {job!r}: a unique plain name and one of {ENGINES + FILE_KINDS} are required"
            )
        names.add(name)
        if kind in ENGINES and "compose_file" not in doc:
            raise Refused(f"manifest lacks 'compose_file' for job {name!r}")
        if kind == "sqlite":
            safe_source(job.get("glob"))
        elif kind == "tree":
            safe_source(job.get("path"))
            if not all(isinstance(x, str) and x for x in job.get("exclude", [])):
                raise Refused(f"job {name!r}: exclude is a list of patterns")
    return doc


def compose(doc, service, remote_argv, stdout):
    """Run remote_argv in the service's container, streaming stdout to the open file."""
    argv = ["docker", "compose", "-f", doc["compose_file"], "exec", "-T", service, *remote_argv]
    proc = subprocess.run(argv, stdout=stdout, stderr=subprocess.PIPE, check=False)
    if proc.returncode != 0:
        tail = proc.stderr.decode("utf-8", "replace").strip().splitlines()[-1:] or [""]
        raise RuntimeError(f"{service}: exit {proc.returncode}: {tail[0][:200]}")


def compose_text(doc, service, remote_argv):
    argv = ["docker", "compose", "-f", doc["compose_file"], "exec", "-T", service, *remote_argv]
    proc = subprocess.run(argv, capture_output=True, check=False)
    if proc.returncode != 0:
        raise RuntimeError(f"{service}: exit {proc.returncode}")
    return proc.stdout.decode("utf-8", "replace")


PG_USER = '"${POSTGRES_USER:-postgres}"'
MY_DUMP = (
    'MYSQL_PWD="$MYSQL_ROOT_PASSWORD" exec "$(command -v mariadb-dump || command -v mysqldump)"'
    " --all-databases --single-transaction --routines --events -uroot"
)


def check_file(path, kind):
    size = os.path.getsize(path)
    if size == 0:
        raise RuntimeError(f"{os.path.basename(path)}: empty dump")
    with open(path, "rb") as fh:
        head = fh.read(5)
        fh.seek(max(0, size - 4096))
        tail = fh.read().decode("utf-8", "replace")
    if kind == "custom" and head != b"PGDMP":
        raise RuntimeError(f"{os.path.basename(path)}: not a custom-format dump")
    if kind == "pg-sql" and "PostgreSQL database cluster dump complete" not in tail:
        raise RuntimeError(f"{os.path.basename(path)}: no completion trailer")
    if kind == "mysql-sql" and "Dump completed" not in tail:
        raise RuntimeError(f"{os.path.basename(path)}: no completion trailer")


def dump_to(doc, service, remote_argv, dest_dir, name, kind):
    fd, tmp = tempfile.mkstemp(prefix=".tmp-", dir=dest_dir)
    try:
        with os.fdopen(fd, "wb") as fh:
            compose(doc, service, remote_argv, fh)
        check_file(tmp, kind)
        os.chmod(tmp, 0o600)
        os.replace(tmp, os.path.join(dest_dir, name))
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)
    return name


def copy_sqlite(src, dest):
    """Online backup of a live SQLite file, then prove the copy: integrity_check ok and a table in it."""
    tmp = dest + ".tmp"
    with contextlib.suppress(FileNotFoundError):
        os.unlink(tmp)
    source = sqlite3.connect(f"file:{src}?mode=ro", uri=True, timeout=30)
    try:
        target = sqlite3.connect(tmp)
        try:
            source.backup(target)
            verdict = target.execute("PRAGMA integrity_check").fetchone()[0]
            tables = target.execute(
                "select count(*) from sqlite_master where type = 'table'"
            ).fetchone()[0]
        finally:
            target.close()
    finally:
        source.close()
    if verdict != "ok" or tables == 0:
        os.unlink(tmp)
        raise RuntimeError(
            f"{os.path.basename(src)}: copy is not sound (integrity {verdict!r}, {tables} tables)"
        )
    os.chmod(tmp, 0o600)
    os.replace(tmp, dest)


def sqlite_job(job, out):
    pattern = job["glob"]
    base = os.path.dirname(pattern)  # the directory part; walk up past any wildcard in it
    while any(c in base for c in "*?["):
        base = os.path.dirname(base)
    matches = sorted(glob.glob(pattern))
    if not matches:
        raise RuntimeError(f"{job['service']}: {pattern} matches no file")
    files = []
    for src in matches:
        name = os.path.relpath(src, base).replace("/", "__")
        if not NAME.match(name):
            raise RuntimeError(f"{job['service']}: {src}: not a plain file name once flattened")
        copy_sqlite(src, os.path.join(out, name))
        files.append(name)
    return files


def tree_job(job, out):
    root, exclude = job["path"].rstrip("/"), job.get("exclude", [])
    if not os.path.isdir(root):
        raise RuntimeError(f"{job['service']}: {root} is not a directory")

    def keep(info):
        rel = info.name.split("/", 1)[1] if "/" in info.name else ""
        if any(
            fnmatch.fnmatch(rel, pat) or fnmatch.fnmatch(os.path.basename(rel), pat)
            for pat in exclude
        ):
            return None
        return info

    name = f"{job['service']}.tar.gz"
    tmp = os.path.join(out, "." + name + ".tmp")
    with contextlib.suppress(FileNotFoundError):
        os.unlink(tmp)
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as raw, tarfile.open(fileobj=raw, mode="w:gz") as tar:
        tar.add(root, arcname="tree", filter=keep)
    with tarfile.open(tmp, "r:gz") as tar:
        members = sum(1 for m in tar if m.isfile())
    if members == 0:
        os.unlink(tmp)
        raise RuntimeError(f"{job['service']}: {root} holds no file to keep")
    os.replace(tmp, os.path.join(out, name))
    return [name]


def run_job(doc, job, stage):
    service, engine = job["service"], job["engine"]
    out = os.path.join(stage, service)
    os.makedirs(out, mode=0o700, exist_ok=True)
    files = []
    if engine == "sqlite":
        return sqlite_job(job, out)
    if engine == "tree":
        return tree_job(job, out)
    if engine == "postgres":
        listing = compose_text(
            doc,
            service,
            [
                "sh",
                "-c",
                f'psql -U {PG_USER} -Atc "select datname from pg_database where not datistemplate"',
            ],
        )
        dbs = [d.strip() for d in listing.splitlines() if NAME.match(d.strip())]
        if not dbs:
            raise RuntimeError(f"{service}: no database listed")
        for db in dbs:
            files.append(
                dump_to(
                    doc,
                    service,
                    ["sh", "-c", f'pg_dump -Fc -U {PG_USER} -d "{db}"'],
                    out,
                    f"{db}.dump",
                    "custom",
                )
            )
        files.append(
            dump_to(
                doc,
                service,
                ["sh", "-c", f"pg_dumpall --globals-only -U {PG_USER}"],
                out,
                "globals.sql",
                "pg-sql",
            )
        )
    else:
        files.append(
            dump_to(doc, service, ["sh", "-c", MY_DUMP], out, "all-databases.sql", "mysql-sql")
        )
    return files


def sha256_of(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def publish(export_dir, stage, service):
    """Replace <export>/<service> by the staged one, keeping the previous one once as <service>.prev."""
    final = os.path.join(export_dir, service)
    prev = final + ".prev"
    if os.path.isdir(final):
        if os.path.isdir(prev):
            shutil.rmtree(prev)  # only ever our own .prev, under the checked export dir
        os.rename(final, prev)
    os.rename(os.path.join(stage, service), final)


def atomic_write(path, text, mode=0o600):
    """Write text to path through a sibling temp file created at its final mode, then rename."""
    tmp = os.path.join(os.path.dirname(path), "." + os.path.basename(path) + ".tmp")
    with contextlib.suppress(FileNotFoundError):
        os.unlink(tmp)
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(text)
    os.replace(tmp, path)


def write_listing(export_dir, doc, results):
    lines = []
    for service in sorted(results):
        base = os.path.join(export_dir, service)
        for name in sorted(os.listdir(base)):
            if not name.startswith("."):
                lines.append(f"{sha256_of(os.path.join(base, name))}  {service}/{name}\n")
    atomic_write(os.path.join(export_dir, "listing.sha256"), "".join(lines))
    meta = {
        "schema": SCHEMA,
        "app": doc["app"],
        "created": now(),
        "jobs": {s: results[s] for s in sorted(results)},
        "images": doc.get("images", {}),
        "does_not_carry": NOT_CARRIED,
    }
    atomic_write(
        os.path.join(export_dir, "manifest.json"), json.dumps(meta, indent=2, sort_keys=True) + "\n"
    )


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--manifest", required=True)
    args = ap.parse_args(argv)
    try:
        doc = load_manifest(args.manifest)
    except (OSError, ValueError, Refused) as exc:
        print(f"hnx-export-run: {exc}", file=sys.stderr)
        return 2
    export_dir = doc["export_dir"]
    if not doc["jobs"]:
        print(
            "hnx-export-run: no supported engine or file job in this application: nothing to dump"
        )
        return 0
    os.makedirs(export_dir, mode=0o700, exist_ok=True)
    os.chmod(export_dir, 0o700)
    stage = tempfile.mkdtemp(prefix=".stage-", dir=export_dir)
    results, failed = {}, []
    try:
        for job in doc["jobs"]:
            try:
                files = run_job(doc, job, stage)
            except (RuntimeError, OSError, sqlite3.Error, tarfile.TarError) as exc:
                failed.append(job["service"])
                print(f"hnx-export-run: {job['service']}: FAILED: {exc}", file=sys.stderr)
                continue
            publish(export_dir, stage, job["service"])
            results[job["service"]] = {"engine": job["engine"], "files": files}
            print(f"hnx-export-run: {job['service']}: {len(files)} dump(s) verified")
        if results:
            # a failed service keeps its last good dump, so it stays in the listing
            for job in doc["jobs"]:
                svc = job["service"]
                if svc not in results and os.path.isdir(os.path.join(export_dir, svc)):
                    results[svc] = {
                        "engine": job["engine"],
                        "files": sorted(os.listdir(os.path.join(export_dir, svc))),
                        "stale": True,
                    }
            write_listing(export_dir, doc, results)
    finally:
        shutil.rmtree(stage, ignore_errors=True)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
