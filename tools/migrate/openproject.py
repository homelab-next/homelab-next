#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# hnx-script:
#   id: projects-migrate
#   kind: tool
#   purpose: Copy a projects instance (database and attachments) from one place to another over ssh pipes, count both sides, and freeze or unfreeze the source for a final delta.
#   owner: maintainers
#   trigger: [manual]
#   inputs: two endpoints named on the command line (an ssh destination and container names, never a literal in this file); for restore, a dump directory written by dump
#   outputs: a dump directory (db.dump, attachments.tar, manifest.json) for dump; the four counts as JSON for counts and restore
#   exit:
#     "0": done (for restore, the target counts equal the manifest counts)
#     "1": a count differs or the dump is not intact
#     "2": usage error or a command on an endpoint failed
"""Migrate a projects instance by dump, freeze, final delta and re-count (docs of the provider:
``modules/openproject/README.md``, "Migrating in").

Generic: an *endpoint* is an ssh destination (or ``None`` for this host) plus the names of the
containers that hold the database, the attachments and every process that writes; nothing here
names a host, an address or a lab.

* :func:`dump` -- **read-only on the source**: ``pg_dump`` and a tar of the attachments are run in
  the source's containers and streamed over the ssh pipe into files of a directory the caller
  names (never a temporary directory: the dump holds every account's password hash), then
  ``manifest.json`` records their sizes and sha256, the row counts of nine tables, a content
  fingerprint of those tables, the number and sha256 digest of the attachment files, and whether
  every writer container was stopped (``frozen``).  ``quiescent`` is true only when the source was
  frozen and neither the counts nor the fingerprint moved while it was dumped.
* :func:`restore` -- onto a target: checks the manifest (and, with ``expect_counts``, that the
  dump is the frozen state ``freeze`` reported), stops the target's writers, restores the
  database in one transaction (``--clean`` replaces everything a previous restore wrote), empties
  and unpacks the attachments, then **verifies the target against the manifest** (counts,
  fingerprint, every attachment file's sha256) before running the product's migrations and
  starting it.  A failed restore leaves the target stopped.
* :func:`counts` -- row counts of an endpoint (a read).
* :func:`freeze` / :func:`unfreeze` -- stop / start **every** writer of the endpoint (a *write*,
  done only in the cutover window, only to stop and start): the database keeps running so it can
  still be dumped.  ``freeze`` returns the counts read after they stopped.

**The final delta.** A copy taken while people work is already stale, and a *delta* of a database
is the database again: the restore is idempotent, so the cutover is ``freeze(source)``,
``dump(source, final_dir)`` again, ``restore(target, final_dir, expect_counts=<what freeze
returned>, require_quiescent=True)``: the target equals the frozen source by counts, content
fingerprint and attachment files.

**Destructive paths.** The only recursive deletes (``find -delete`` and ``chown -R``) act on the
attachments directory, which must be an absolute canonical path of at least three components with
no ``..``, resolve to itself on the endpoint (no symlink anywhere in it) and, for a host path,
lie strictly inside the named data root.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shlex
import subprocess
import sys
import tarfile
import tempfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import BinaryIO, Protocol

__all__ = [
    "COUNT_KEYS",
    "COUNT_SQL",
    "CountMismatch",
    "Endpoint",
    "MigrateError",
    "VerifyMismatch",
    "counts",
    "dump",
    "freeze",
    "restore",
    "unfreeze",
]

#: the first four are the contract's; the rest are what the inventory lists beside them
COUNT_TABLES = {
    "projects": "projects",
    "work_packages": "work_packages",
    "users": "users",
    "attachments": "attachments",
    "journals": "journals",
    "time_entries": "time_entries",
    "members": "members",
    "versions": "versions",
    "custom_fields": "custom_fields",
}
COUNT_KEYS = tuple(COUNT_TABLES)
#: real accounts only: the product also keeps an anonymous user, a deleted-user placeholder and
#: system users in the same table
_WHERE = {"users": " WHERE type = 'User'"}
COUNT_SQL = "SELECT " + ", ".join(
    f"(SELECT count(*) FROM {t}{_WHERE.get(k, '')})" for k, t in COUNT_TABLES.items()
)
#: a content fingerprint: the hash of every row of the data tables in id order, so an edit, a
#: comment or a changed password that moves no count still moves it
FINGERPRINT_TABLES = tuple(COUNT_TABLES.values())
FINGERPRINT_SQL = (
    "SELECT md5("
    + " || ".join(
        f"coalesce((SELECT md5(string_agg(md5(x::text), '' ORDER BY x.id)) FROM {t} x), '')"
        for t in FINGERPRINT_TABLES
    )
    + ")"
)
DB_FILE, ATTACHMENTS_FILE, MANIFEST = "db.dump", "attachments.tar", "manifest.json"
#: places a dump must never be staged: world-writable scratch space (the dump holds every
#: account's password hash)
SCRATCH_DIRS = ("/tmp", "/var/tmp", "/dev/shm")
_CHUNK = 1 << 20


class MigrateError(RuntimeError):
    """A command on an endpoint failed, or an input is not usable."""


class VerifyMismatch(MigrateError):
    """The target is not what the manifest (or the frozen source) says."""


class CountMismatch(VerifyMismatch):
    """Row counts differ."""

    def __init__(self, expected: Mapping[str, int], got: Mapping[str, int]):
        self.expected, self.got = dict(expected), dict(got)
        diff = {
            k: (self.expected.get(k), self.got.get(k))
            for k in COUNT_KEYS
            if self.expected.get(k) != self.got.get(k)
        }
        super().__init__(f"counts differ (expected, got): {diff}")


def guard_dir(path: str, *, root: str | None = None, min_components: int = 3) -> str:
    """Lexical checks for a directory something recursive acts on; returns it unchanged.

    Absolute, canonical (no ``..``, ``.``, ``//`` or trailing ``/``), at least three components
    (``/var/x/y``: never ``/``, ``/var``, ``/var/lib``), and strictly inside ``root`` when given.
    """
    p = PurePosixPath(path)
    if not path.startswith("/") or str(p) != path or ".." in p.parts or "." in p.parts:
        raise MigrateError(f"{path!r}: not an absolute canonical path")
    if len(p.parts) < min_components + 1:  # "/" counts as a part
        raise MigrateError(
            f"{path!r}: refusing a recursive action on a path of fewer than {min_components} components"
        )
    if root is not None:
        r = PurePosixPath(guard_dir(root, min_components=2))
        if r not in p.parents:
            raise MigrateError(f"{path!r}: not inside the data root {root!r}")
    return path


@dataclass(frozen=True)
class Endpoint:
    """Where an instance runs.  ``ssh`` is a destination (``user@host``) or ``None`` for this
    host; commands run as ``[ssh dest] [sudo -n] docker ...``.

    ``db_container`` runs the database.  The attachments are read through ``assets_container``
    (a running container that mounts them at ``assets_path``) or through ``assets_host_path``
    (the directory on the host, which must lie inside ``data_root``): a restore uses the host
    path, because it stops the containers.  ``writers`` are **every** container that writes (the
    web app, the worker, any scheduler): freeze stops all of them.  ``compose_file`` (on the
    host) lets restore run the migrations and start the services; without it restore starts
    ``writers`` with ``docker start`` and does not migrate.
    """

    db_container: str
    db_user: str
    db_name: str
    ssh: str | None = None
    sudo: bool = True
    assets_container: str | None = None
    assets_path: str = "/var/openproject/assets"
    assets_host_path: str | None = None
    data_root: str | None = None
    assets_owner: str = "1000:1000"
    writers: tuple[str, ...] = ()
    compose_file: str | None = None
    compose_web_services: tuple[str, ...] = ("web", "worker")
    compose_seed_service: str = "web"
    compose_seed_command: str = "./docker/prod/seeder"
    compose_infra_services: tuple[str, ...] = ("postgres", "cache")

    def __post_init__(self) -> None:
        if bool(self.assets_container) == bool(self.assets_host_path):
            raise MigrateError("name exactly one of assets_container and assets_host_path")
        if self.assets_host_path:
            if not self.data_root:
                raise MigrateError("assets_host_path needs data_root: the directory it must lie in")
            guard_dir(self.assets_host_path, root=self.data_root)
        else:
            guard_dir(self.assets_path)

    @property
    def assets_dir(self) -> str:
        return str(self.assets_host_path or self.assets_path)


class Runner(Protocol):
    def __call__(
        self,
        argv: Sequence[str],
        *,
        stdin: BinaryIO | None = None,
        stdout: BinaryIO | None = None,
    ) -> tuple[int, bytes, bytes]:
        """Run argv; stdout goes to ``stdout`` if given, else is returned.  -> (rc, out, err)."""


def _subprocess_runner(argv, *, stdin=None, stdout=None):
    p = subprocess.run(
        list(argv),
        stdin=stdin if stdin is not None else subprocess.DEVNULL,
        stdout=stdout if stdout is not None else subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    return p.returncode, p.stdout or b"", p.stderr or b""


@dataclass
class _Ctx:
    runner: Runner | None = None
    log: list[list[str]] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.runner is None:  # looked up at call time, so a test can replace the module's
            self.runner = _subprocess_runner


def _wrap(ep: Endpoint, inner: Sequence[str], *, has_stdin: bool = False) -> list[str]:
    """The argv that runs ``inner`` on the endpoint: through ssh (one quoted command string, as
    ssh joins it; ``-n`` when nothing is piped in, so ssh never reads the caller's stdin) and
    sudo when asked."""
    cmd = (["sudo", "-n"] if ep.sudo else []) + list(inner)
    if ep.ssh is None:
        return cmd
    return ["ssh", *([] if has_stdin else ["-n"]), "-o", "BatchMode=yes", ep.ssh, shlex.join(cmd)]


def _run(ctx: _Ctx, ep: Endpoint, inner: Sequence[str], *, stdin=None, stdout=None) -> bytes:
    argv = _wrap(ep, inner, has_stdin=stdin is not None)
    ctx.log.append(list(argv))
    rc, out, err = ctx.runner(argv, stdin=stdin, stdout=stdout)
    if rc != 0:
        tail = err.decode("utf-8", "replace").strip().splitlines()[-3:]
        raise MigrateError(f"{' '.join(inner[:6])} ... failed ({rc}): {' | '.join(tail)}")
    return out


def _psql(ep: Endpoint, sql: str) -> list[str]:
    return [
        "docker", "exec", ep.db_container, "psql", "-U", ep.db_user, "-d", ep.db_name,
        "-At", "-F", "|", "-v", "ON_ERROR_STOP=1", "-c", sql,
    ]  # fmt: skip


def counts(ep: Endpoint, *, _ctx: _Ctx | None = None) -> dict[str, int]:
    """Row counts of the endpoint, ``COUNT_KEYS`` in order (a read: one SELECT)."""
    ctx = _ctx or _Ctx()
    out = _run(ctx, ep, _psql(ep, COUNT_SQL)).decode().strip().splitlines()
    try:
        values = [int(v) for v in out[-1].split("|")]
    except (IndexError, ValueError) as e:
        raise MigrateError(f"unreadable counts: {out!r}") from e
    if len(values) != len(COUNT_KEYS):
        raise MigrateError(f"expected {len(COUNT_KEYS)} counts, got {out[-1]!r}")
    return dict(zip(COUNT_KEYS, values, strict=True))


def fingerprint(ep: Endpoint, *, _ctx: _Ctx | None = None) -> str:
    """The content fingerprint of the data tables (a read: one SELECT)."""
    ctx = _ctx or _Ctx()
    out = _run(ctx, ep, _psql(ep, FINGERPRINT_SQL)).decode().strip().splitlines()
    if not out or len(out[-1]) != 32:
        raise MigrateError(f"unreadable fingerprint: {out!r}")
    return out[-1]


def _assets_read(ep: Endpoint) -> list[str]:
    if ep.assets_container:
        return ["docker", "exec", ep.assets_container, "tar", "--create", "--file", "-",
                "--directory", ep.assets_path, "."]  # fmt: skip
    return ["tar", "--create", "--file", "-", "--directory", ep.assets_dir, "."]


def _sha256(path: Path) -> tuple[int, str]:
    h, n = hashlib.sha256(), 0
    with path.open("rb") as f:
        while chunk := f.read(_CHUNK):
            h.update(chunk)
            n += len(chunk)
    return n, h.hexdigest()


def _files_digest(entries: Mapping[str, str]) -> dict:
    """``{count, sha256}`` of {relative path: sha256 of the content}."""
    h = hashlib.sha256()
    for name in sorted(entries):
        h.update(f"{name}\0{entries[name]}\n".encode())
    return {"count": len(entries), "sha256": h.hexdigest()}


def _norm(name: str) -> str:
    return name[2:] if name.startswith("./") else name


def tar_files(archive: Path) -> dict:
    """The attachment files of a tar: ``{count, sha256}`` over every regular member's path and
    content hash (what :func:`endpoint_files` computes on a live tree)."""
    entries: dict[str, str] = {}
    with tarfile.open(archive, "r") as t:
        for m in t:
            if m.isreg():
                h, f = hashlib.sha256(), t.extractfile(m)
                while chunk := f.read(_CHUNK):
                    h.update(chunk)
                entries[_norm(m.name)] = h.hexdigest()
    return _files_digest(entries)


def endpoint_files(ep: Endpoint, *, _ctx: _Ctx | None = None) -> dict:
    """``{count, sha256}`` of the regular files under the endpoint's attachments directory
    (a read: ``find ... -exec sha256sum``)."""
    ctx = _ctx or _Ctx()
    script = f"cd {shlex.quote(ep.assets_dir)} && find . -type f -exec sha256sum -- {{}} +"
    inner = ["sh", "-c", script]
    if ep.assets_container:
        inner = ["docker", "exec", ep.assets_container, *inner]
    entries: dict[str, str] = {}
    for line in _run(ctx, ep, inner).decode().splitlines():
        digest, _, name = line.partition("  ")
        if len(digest) == 64:
            entries[_norm(name)] = digest
    return _files_digest(entries)


def _refuse_scratch(out_dir: Path, scratch_dirs: Sequence[str]) -> None:
    here = out_dir.resolve()
    for bad in {Path(d).resolve() for d in scratch_dirs}:
        if here == bad or bad in here.parents:
            raise MigrateError(
                f"{out_dir}: refusing to stage a dump under {bad}; name a private directory"
            )


def _writers_running(ctx: _Ctx, ep: Endpoint) -> dict[str, bool]:
    """Which of the endpoint's writers are running (a read: ``docker inspect``)."""
    state = {}
    for name in ep.writers:
        out = _run(ctx, ep, ["docker", "inspect", "--format", "{{.State.Running}}", name])
        state[name] = out.decode().strip() == "true"
    return state


def dump(
    source: Endpoint,
    out_dir: str | os.PathLike,
    *,
    scratch_dirs: Sequence[str] = (*SCRATCH_DIRS, tempfile.gettempdir()),
    _ctx: _Ctx | None = None,
) -> dict:
    """Dump ``source`` into ``out_dir`` (created, mode 0700, must be empty) and return the manifest.

    Read-only on the source: ``docker inspect``, SELECTs, ``pg_dump`` and ``tar --create``.
    """
    ctx = _ctx or _Ctx()
    out = Path(out_dir)
    _refuse_scratch(out, scratch_dirs)
    out.mkdir(mode=0o700, parents=True, exist_ok=True)
    out.chmod(0o700)
    if any(out.iterdir()):
        raise MigrateError(f"{out}: not empty")
    running = _writers_running(ctx, source)
    before = (counts(source, _ctx=ctx), fingerprint(source, _ctx=ctx))
    files = {
        DB_FILE: ["docker", "exec", source.db_container, "pg_dump", "-U", source.db_user,
                  "-d", source.db_name, "-Fc", "--no-owner", "--no-acl"],
        ATTACHMENTS_FILE: _assets_read(source),
    }  # fmt: skip
    meta: dict[str, dict] = {}
    for name, inner in files.items():
        path = out / name
        try:
            with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as f:
                _run(ctx, source, inner, stdout=f)
        except BaseException:
            path.unlink(missing_ok=True)
            raise
        size, digest = _sha256(path)
        meta[name] = {"size": size, "sha256": digest}
    after = (counts(source, _ctx=ctx), fingerprint(source, _ctx=ctx))
    frozen = (
        bool(source.writers)
        and not any(_writers_running(ctx, source).values())
        and not any(running.values())
    )
    manifest = {
        "format": 2,
        "files": meta,
        "attachment_files": tar_files(out / ATTACHMENTS_FILE),
        "counts": after[0],
        "counts_before": before[0],
        "fingerprint": after[1],
        "writers": running,
        "frozen": frozen,
        "quiescent": frozen and before == after,
    }
    (out / MANIFEST).write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    return manifest


def _read_manifest(dump_dir: Path) -> dict:
    try:
        manifest = json.loads((dump_dir / MANIFEST).read_text())
    except (OSError, ValueError) as e:
        raise MigrateError(f"{dump_dir}: no readable {MANIFEST}") from e
    for name in (DB_FILE, ATTACHMENTS_FILE):
        want = (manifest.get("files") or {}).get(name)
        path = dump_dir / name
        if not want or path.is_symlink() or not path.is_file():
            raise MigrateError(f"{dump_dir}: {name} is missing from the manifest or the directory")
        size, digest = _sha256(path)
        if (size, digest) != (want.get("size"), want.get("sha256")):
            raise MigrateError(
                f"{dump_dir}: {name} is not what the manifest recorded (size or sha256)"
            )
    if set(manifest.get("counts") or ()) != set(COUNT_KEYS):
        raise MigrateError(f"{dump_dir}: the manifest has no counts")
    if not manifest.get("fingerprint") or not manifest.get("attachment_files"):
        raise MigrateError(f"{dump_dir}: the manifest has no fingerprint or file digest")
    return manifest


def _compose(ep: Endpoint, *args: str) -> list[str]:
    return ["docker", "compose", "-f", str(ep.compose_file), *args]


def _stop(ctx: _Ctx, ep: Endpoint) -> None:
    if ep.writers:
        _run(ctx, ep, ["docker", "stop", *ep.writers])
    elif ep.compose_file:
        _run(ctx, ep, _compose(ep, "stop", *ep.compose_web_services))


def _start(ctx: _Ctx, ep: Endpoint) -> None:
    if ep.compose_file:
        _run(ctx, ep, _compose(ep, "up", "-d", *ep.compose_web_services))
    elif ep.writers:
        _run(ctx, ep, ["docker", "start", *ep.writers])


def restore(
    target: Endpoint,
    dump_dir: str | os.PathLike,
    *,
    expect_counts: Mapping[str, int] | None = None,
    require_quiescent: bool = False,
    _ctx: _Ctx | None = None,
) -> dict[str, int]:
    """Restore a dump onto ``target``, verify it, start it, and return the target's counts.

    ``expect_counts`` is what :func:`freeze` returned: the dump must equal it before anything is
    written and the target must equal it after.  ``require_quiescent`` demands a dump taken from
    a frozen source and an ``expect_counts``.  Verification compares the target with the
    manifest (counts, content fingerprint, every attachment file) right after the restore, before
    the migrations run; a mismatch, like any failure, leaves the target **stopped**.  Run again
    with a newer dump for the final delta: the database is replaced and the attachments directory
    emptied and unpacked again.
    """
    ctx = _ctx or _Ctx()
    src = Path(dump_dir)
    manifest = _read_manifest(src)
    if require_quiescent:
        if expect_counts is None:
            raise MigrateError("require_quiescent needs expect_counts: the counts freeze reported")
        if not (manifest.get("frozen") and manifest.get("quiescent")):
            raise MigrateError(
                f"{src}: not dumped from a frozen source (a writer was running or the data moved "
                "while it was dumped); freeze the source and dump again"
            )
    if expect_counts is not None and dict(expect_counts) != manifest["counts"]:
        raise CountMismatch(expect_counts, manifest["counts"])
    if target.assets_container:
        raise MigrateError("a restore stops the containers: name assets_host_path for the target")
    assets = _guarded_assets(ctx, target)
    _stop(ctx, target)
    try:
        with (src / DB_FILE).open("rb") as f:
            _run(ctx, target,
                 ["docker", "exec", "-i", target.db_container, "pg_restore", "-U", target.db_user,
                  "-d", target.db_name, "--clean", "--if-exists", "--no-owner", "--no-acl",
                  "--single-transaction", "--exit-on-error"],
                 stdin=f)  # fmt: skip
        _run(ctx, target, ["find", assets, "-xdev", "-mindepth", "1", "-delete"])
        with (src / ATTACHMENTS_FILE).open("rb") as f:
            _run(ctx, target, ["tar", "--extract", "--no-same-owner", "--no-same-permissions",
                               "--file", "-", "--directory", assets], stdin=f)  # fmt: skip
        _run(ctx, target, ["chown", "-R", "-h", target.assets_owner, assets])
        wanted = dict(expect_counts) if expect_counts is not None else manifest["counts"]
        got = counts(target, _ctx=ctx)
        if got != wanted:
            raise CountMismatch(wanted, got)
        if fingerprint(target, _ctx=ctx) != manifest["fingerprint"]:
            raise VerifyMismatch("the target's content fingerprint differs from the dump's")
        if endpoint_files(target, _ctx=ctx) != manifest["attachment_files"]:
            raise VerifyMismatch(
                "the target's attachment files differ from the dump's (count or sha256)"
            )
        if target.compose_file:
            _run(
                ctx, target, _compose(target, "up", "-d", "--wait", *target.compose_infra_services)
            )
            _run(ctx, target, _compose(target, "run", "--rm", "-T", "--no-deps",
                                       target.compose_seed_service, target.compose_seed_command))  # fmt: skip
    except BaseException as e:
        e.add_note("the target's writers are left stopped; fix the cause and restore again")
        raise
    _start(ctx, target)
    return counts(target, _ctx=ctx)


def _guarded_assets(ctx: _Ctx, ep: Endpoint) -> str:
    """The attachments directory, after the endpoint itself says it resolves to the same path
    (no symlink anywhere in it) and, for a host path, inside the data root."""
    path = ep.assets_dir
    guard_dir(path, root=ep.data_root if ep.assets_host_path else None)
    real = _run(ctx, ep, ["readlink", "-f", "--", path]).decode().strip()
    if real != path:
        raise MigrateError(
            f"{path!r} resolves to {real!r}: refusing a recursive action through a link"
        )
    return path


def freeze(source: Endpoint, *, _ctx: _Ctx | None = None) -> dict[str, int]:
    """Stop **every** writer of the source (the only write this tool makes to a source), check that
    none runs, and return its counts read after they stopped: the figures the target must equal."""
    ctx = _ctx or _Ctx()
    if not source.writers:
        raise MigrateError(
            "freeze needs writers: every container that writes (web, worker, scheduler)"
        )
    _run(ctx, source, ["docker", "stop", *source.writers])
    still = [n for n, up in _writers_running(ctx, source).items() if up]
    if still:
        raise MigrateError(f"still running after the stop: {', '.join(still)}")
    return counts(source, _ctx=ctx)


def unfreeze(source: Endpoint, *, _ctx: _Ctx | None = None) -> None:
    """Start the source's writers again (the rollback of a cutover)."""
    ctx = _ctx or _Ctx()
    if not source.writers:
        raise MigrateError("unfreeze needs writers")
    _run(ctx, source, ["docker", "start", *source.writers])


# ----------------------------------------------------------------------------- command line


def _endpoint(a: argparse.Namespace) -> Endpoint:
    return Endpoint(
        db_container=a.db_container, db_user=a.db_user, db_name=a.db_name, ssh=a.ssh,
        sudo=not a.no_sudo, assets_container=a.assets_container, assets_path=a.assets_path,
        assets_host_path=a.assets_host_path, data_root=a.data_root, assets_owner=a.assets_owner,
        writers=tuple(a.writer or ()), compose_file=a.compose_file,
    )  # fmt: skip


def _expect(text: str | None) -> dict | None:
    if text is None:
        return None
    try:
        doc = json.loads(Path(text[1:]).read_text() if text.startswith("@") else text)
    except (OSError, ValueError) as e:
        raise MigrateError(f"--expect-counts: not JSON or a readable @file: {e}") from e
    if not isinstance(doc, dict):
        raise MigrateError("--expect-counts: a JSON object of counts")
    return doc


def _parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("command", choices=["dump", "restore", "counts", "freeze", "unfreeze"])
    ap.add_argument("--ssh", help="user@host (default: this host)")
    ap.add_argument("--no-sudo", action="store_true")
    ap.add_argument("--db-container", required=True)
    ap.add_argument("--db-user", required=True)
    ap.add_argument("--db-name", required=True)
    ap.add_argument("--assets-container")
    ap.add_argument("--assets-host-path")
    ap.add_argument("--data-root", help="with --assets-host-path: the directory it must lie in")
    ap.add_argument("--assets-path", default="/var/openproject/assets")
    ap.add_argument("--assets-owner", default="1000:1000")
    ap.add_argument("--writer", action="append", help="every container that writes; repeatable")
    ap.add_argument("--compose-file", help="on the endpoint's host: lets restore migrate and start")
    ap.add_argument("--dir", help="dump: the (empty) directory to write; restore: the one to read")
    ap.add_argument("--expect-counts", help="restore: what freeze printed (JSON or @file)")
    ap.add_argument("--require-quiescent", action="store_true",
                    help="restore: refuse a dump not taken from a frozen source (needs --expect-counts)")  # fmt: skip
    return ap


def main(argv: Sequence[str] | None = None) -> int:
    a = _parser().parse_args(argv)
    try:
        ep = _endpoint(a)
        if a.command in ("dump", "restore") and not a.dir:
            raise MigrateError(f"{a.command} needs --dir")
        if a.command == "dump":
            result = dump(ep, a.dir)
        elif a.command == "restore":
            result = restore(ep, a.dir, expect_counts=_expect(a.expect_counts),
                             require_quiescent=a.require_quiescent)  # fmt: skip
        elif a.command == "counts":
            result = counts(ep)
        elif a.command == "freeze":
            result = freeze(ep)
        else:
            unfreeze(ep)
            result = {"started": list(ep.writers)}
    except VerifyMismatch as e:
        print(f"projects-migrate: {e}", file=sys.stderr)
        return 1
    except MigrateError as e:
        print(f"projects-migrate: {e}", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
