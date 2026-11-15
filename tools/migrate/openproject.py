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
``modules/projects/README.md``, "Migrating in").

Generic: an *endpoint* is an ssh destination (or ``None`` for this host) plus the names of the
containers that hold the database, the attachments and the web processes; nothing here names a
host, an address or a lab.

* :func:`dump` -- **read-only on the source**: ``pg_dump`` and a tar of the attachments are run in
  the source's containers and streamed over the ssh pipe into files of a directory the caller
  names (never a temporary directory: the dump holds every account's password hash), then
  ``manifest.json`` records their sizes and sha256 and the four counts, taken before and after
  (``quiescent`` is true when nothing changed between them).
* :func:`restore` -- onto a target: checks the manifest, stops the target's web processes, restores
  the database in one transaction (``--clean`` replaces everything a previous restore wrote), empties
  and unpacks the attachments, runs the product's migrations and starts the web processes again,
  then **counts the target and compares with the manifest**.
* :func:`counts` -- ``{projects, work_packages, users, attachments}`` of an endpoint (a read).
* :func:`freeze` / :func:`unfreeze` -- stop / start the endpoint's web processes (a *write*, done
  only in the cutover window, only to stop and start): the database keeps running so it can still
  be dumped.

**The final delta.** A copy taken while people work is already stale, and a *delta* of a database
is the database again: the restore is idempotent, so the cutover is ``freeze(source)``,
``dump(source, final_dir)`` again, ``restore(target, final_dir)`` again, and
``counts(target) == counts(source)`` read after the freeze.  ``restore(..., require_quiescent=True)``
refuses a dump whose counts moved while it was taken.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shlex
import subprocess
import sys
import tempfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO, Protocol

__all__ = [
    "COUNT_KEYS",
    "COUNT_SQL",
    "CountMismatch",
    "Endpoint",
    "MigrateError",
    "counts",
    "dump",
    "freeze",
    "restore",
    "unfreeze",
]

COUNT_KEYS = ("projects", "work_packages", "users", "attachments")
#: real accounts only: the product also keeps an anonymous user, a deleted-user placeholder and
#: system users in the same table
COUNT_SQL = (
    "SELECT (SELECT count(*) FROM projects), (SELECT count(*) FROM work_packages), "
    "(SELECT count(*) FROM users WHERE type = 'User'), (SELECT count(*) FROM attachments)"
)
DB_FILE, ATTACHMENTS_FILE, MANIFEST = "db.dump", "attachments.tar", "manifest.json"
_CHUNK = 1 << 20


class MigrateError(RuntimeError):
    """A command on an endpoint failed, or an input is not usable."""


class CountMismatch(MigrateError):
    """The target's counts are not the manifest's."""

    def __init__(self, expected: Mapping[str, int], got: Mapping[str, int]):
        self.expected, self.got = dict(expected), dict(got)
        diff = {
            k: (self.expected.get(k), self.got.get(k))
            for k in COUNT_KEYS
            if self.expected.get(k) != self.got.get(k)
        }
        super().__init__(f"counts differ (expected, got): {diff}")


@dataclass(frozen=True)
class Endpoint:
    """Where an instance runs.  ``ssh`` is a destination (``user@host``) or ``None`` for this
    host; commands run as ``[ssh dest] [sudo -n] docker ...``.

    ``db_container`` runs the database; the attachments are read through ``assets_container`` (a
    running container that mounts them at ``assets_path``) or, when the web processes are
    stopped, through ``assets_host_path`` (the directory on the host).  ``web_containers`` are
    the processes freeze stops.  ``compose_file`` (on the host) lets restore run the migrations
    and start the web services; without it restore starts ``web_containers`` with ``docker start``
    and does not migrate.
    """

    db_container: str
    db_user: str
    db_name: str
    ssh: str | None = None
    sudo: bool = True
    assets_container: str | None = None
    assets_path: str = "/var/openproject/assets"
    assets_host_path: str | None = None
    assets_owner: str = "1000:1000"
    web_containers: tuple[str, ...] = ()
    compose_file: str | None = None
    compose_web_services: tuple[str, ...] = ("web", "worker")
    compose_seed_service: str = "web"
    compose_seed_command: str = "./docker/prod/seeder"
    compose_infra_services: tuple[str, ...] = ("postgres", "cache")

    def __post_init__(self) -> None:
        if bool(self.assets_container) == bool(self.assets_host_path):
            raise MigrateError("name exactly one of assets_container and assets_host_path")
        if self.assets_host_path and not self.assets_host_path.startswith("/"):
            raise MigrateError("assets_host_path must be absolute")


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
        stdin=stdin,
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


def _wrap(ep: Endpoint, inner: Sequence[str]) -> list[str]:
    """The argv that runs ``inner`` on the endpoint: through ssh (one quoted command string, as
    ssh joins it) and sudo when asked."""
    cmd = (["sudo", "-n"] if ep.sudo else []) + list(inner)
    if ep.ssh is None:
        return cmd
    return ["ssh", "-o", "BatchMode=yes", ep.ssh, shlex.join(cmd)]


def _run(ctx: _Ctx, ep: Endpoint, inner: Sequence[str], *, stdin=None, stdout=None) -> bytes:
    argv = _wrap(ep, inner)
    ctx.log.append(list(argv))
    rc, out, err = ctx.runner(argv, stdin=stdin, stdout=stdout)
    if rc != 0:
        tail = err.decode("utf-8", "replace").strip().splitlines()[-3:]
        raise MigrateError(f"{' '.join(inner[:6])} ... failed ({rc}): {' | '.join(tail)}")
    return out


def _psql(ep: Endpoint, sql: str) -> list[str]:
    return [
        "docker",
        "exec",
        ep.db_container,
        "psql",
        "-U",
        ep.db_user,
        "-d",
        ep.db_name,
        "-At",
        "-F",
        "|",
        "-v",
        "ON_ERROR_STOP=1",
        "-c",
        sql,
    ]


def counts(ep: Endpoint, *, _ctx: _Ctx | None = None) -> dict[str, int]:
    """``{projects, work_packages, users, attachments}`` of the endpoint (a read: one SELECT)."""
    ctx = _ctx or _Ctx()
    out = _run(ctx, ep, _psql(ep, COUNT_SQL)).decode().strip().splitlines()
    try:
        values = [int(v) for v in out[-1].split("|")]
    except (IndexError, ValueError) as e:
        raise MigrateError(f"unreadable counts: {out!r}") from e
    if len(values) != len(COUNT_KEYS):
        raise MigrateError(f"expected {len(COUNT_KEYS)} counts, got {out[-1]!r}")
    return dict(zip(COUNT_KEYS, values, strict=True))


def _assets_read(ep: Endpoint) -> list[str]:
    if ep.assets_container:
        return [
            "docker",
            "exec",
            ep.assets_container,
            "tar",
            "--create",
            "--file",
            "-",
            "--directory",
            ep.assets_path,
            ".",
        ]
    return ["tar", "--create", "--file", "-", "--directory", str(ep.assets_host_path), "."]


def _sha256(path: Path) -> tuple[int, str]:
    h, n = hashlib.sha256(), 0
    with path.open("rb") as f:
        while chunk := f.read(_CHUNK):
            h.update(chunk)
            n += len(chunk)
    return n, h.hexdigest()


#: places a dump must never be staged: world-writable scratch space (the dump holds every
#: account's password hash)
SCRATCH_DIRS = ("/tmp", "/var/tmp", "/dev/shm")


def _refuse_scratch(out_dir: Path) -> None:
    here = out_dir.resolve()
    bad_dirs = {
        Path(d).resolve()
        for d in (*SCRATCH_DIRS, *([tempfile.gettempdir()] if SCRATCH_DIRS else []))
    }
    for bad in bad_dirs:
        if here == bad or bad in here.parents:
            raise MigrateError(
                f"{out_dir}: refusing to stage a dump under {bad}; name a private directory"
            )


def dump(source: Endpoint, out_dir: str | os.PathLike, *, _ctx: _Ctx | None = None) -> dict:
    """Dump ``source`` into ``out_dir`` (created, mode 0700, must be empty) and return the manifest.

    Read-only on the source: a ``SELECT``, ``pg_dump`` and a ``tar --create``.
    """
    ctx = _ctx or _Ctx()
    out = Path(out_dir)
    _refuse_scratch(out)
    out.mkdir(mode=0o700, parents=True, exist_ok=True)
    if any(out.iterdir()):
        raise MigrateError(f"{out}: not empty")
    before = counts(source, _ctx=ctx)
    files = {
        DB_FILE: [
            "docker",
            "exec",
            source.db_container,
            "pg_dump",
            "-U",
            source.db_user,
            "-d",
            source.db_name,
            "-Fc",
            "--no-owner",
            "--no-acl",
        ],
        ATTACHMENTS_FILE: _assets_read(source),
    }
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
    after = counts(source, _ctx=ctx)
    manifest = {
        "format": 1,
        "files": meta,
        "counts": after,
        "counts_before": before,
        "quiescent": before == after,
    }
    (out / MANIFEST).write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    return manifest


def _read_manifest(dump_dir: Path, *, require_quiescent: bool) -> dict:
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
    if require_quiescent and not manifest.get("quiescent"):
        raise MigrateError(
            f"{dump_dir}: the source changed while it was dumped (counts moved); freeze it and dump again"
        )
    return manifest


def _compose(ep: Endpoint, *args: str) -> list[str]:
    return ["docker", "compose", "-f", str(ep.compose_file), *args]


def restore(
    target: Endpoint,
    dump_dir: str | os.PathLike,
    *,
    require_quiescent: bool = False,
    _ctx: _Ctx | None = None,
) -> dict[str, int]:
    """Restore a dump onto ``target`` and return the target's counts, equal to the manifest's.

    Raises :class:`CountMismatch` (after the target is started again) when they differ.  Run again
    with a newer dump for the final delta: the database is replaced and the attachments directory
    emptied and unpacked again.
    """
    ctx = _ctx or _Ctx()
    src = Path(dump_dir)
    manifest = _read_manifest(src, require_quiescent=require_quiescent)
    if target.assets_container and target.assets_container in target.web_containers:
        raise MigrateError(
            "the attachments are reached through a container restore stops: "
            "name assets_host_path for the target"
        )
    if target.web_containers:
        _run(ctx, target, ["docker", "stop", *target.web_containers])
    elif target.compose_file:
        _run(ctx, target, _compose(target, "stop", *target.compose_web_services))
    try:
        with (src / DB_FILE).open("rb") as f:
            _run(
                ctx,
                target,
                [
                    "docker",
                    "exec",
                    "-i",
                    target.db_container,
                    "pg_restore",
                    "-U",
                    target.db_user,
                    "-d",
                    target.db_name,
                    "--clean",
                    "--if-exists",
                    "--no-owner",
                    "--no-acl",
                    "--single-transaction",
                    "--exit-on-error",
                ],
                stdin=f,
            )
        _restore_assets(ctx, target, src / ATTACHMENTS_FILE)
        if target.compose_file:
            _run(
                ctx, target, _compose(target, "up", "-d", "--wait", *target.compose_infra_services)
            )
            _run(
                ctx,
                target,
                _compose(
                    target,
                    "run",
                    "--rm",
                    "-T",
                    "--no-deps",
                    target.compose_seed_service,
                    target.compose_seed_command,
                ),
            )
    finally:
        _start(ctx, target)
    got = counts(target, _ctx=ctx)
    if got != manifest["counts"]:
        raise CountMismatch(manifest["counts"], got)
    return got


def _restore_assets(ctx: _Ctx, target: Endpoint, archive: Path) -> None:
    if target.assets_host_path:
        path = target.assets_host_path
        _run(ctx, target, ["find", path, "-mindepth", "1", "-delete"])
        with archive.open("rb") as f:
            _run(
                ctx,
                target,
                [
                    "tar",
                    "--extract",
                    "--no-same-owner",
                    "--no-same-permissions",
                    "--file",
                    "-",
                    "--directory",
                    path,
                ],
                stdin=f,
            )
        _run(ctx, target, ["chown", "-R", target.assets_owner, path])
        return
    box = str(target.assets_container)
    _run(
        ctx,
        target,
        ["docker", "exec", box, "find", target.assets_path, "-mindepth", "1", "-delete"],
    )
    with archive.open("rb") as f:
        _run(
            ctx,
            target,
            [
                "docker",
                "exec",
                "-i",
                box,
                "tar",
                "--extract",
                "--no-same-owner",
                "--file",
                "-",
                "--directory",
                target.assets_path,
            ],
            stdin=f,
        )


def _start(ctx: _Ctx, ep: Endpoint) -> None:
    if ep.compose_file:
        _run(ctx, ep, _compose(ep, "up", "-d", *ep.compose_web_services))
    elif ep.web_containers:
        _run(ctx, ep, ["docker", "start", *ep.web_containers])


def freeze(source: Endpoint, *, _ctx: _Ctx | None = None) -> dict[str, int]:
    """Stop the source's web processes (the only write this tool makes to a source) and return its
    counts, read after they stopped: the figures the target must equal."""
    ctx = _ctx or _Ctx()
    if not source.web_containers:
        raise MigrateError("freeze needs web_containers: the processes that write")
    _run(ctx, source, ["docker", "stop", *source.web_containers])
    return counts(source, _ctx=ctx)


def unfreeze(source: Endpoint, *, _ctx: _Ctx | None = None) -> None:
    """Start the source's web processes again (the rollback of a cutover)."""
    ctx = _ctx or _Ctx()
    if not source.web_containers:
        raise MigrateError("unfreeze needs web_containers")
    _run(ctx, source, ["docker", "start", *source.web_containers])


# ----------------------------------------------------------------------------- command line


def _endpoint(a: argparse.Namespace) -> Endpoint:
    return Endpoint(
        db_container=a.db_container,
        db_user=a.db_user,
        db_name=a.db_name,
        ssh=a.ssh,
        sudo=not a.no_sudo,
        assets_container=a.assets_container,
        assets_path=a.assets_path,
        assets_host_path=a.assets_host_path,
        assets_owner=a.assets_owner,
        web_containers=tuple(a.web_container or ()),
        compose_file=a.compose_file,
    )


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
    ap.add_argument("--assets-path", default="/var/openproject/assets")
    ap.add_argument("--assets-owner", default="1000:1000")
    ap.add_argument("--web-container", action="append", help="repeatable")
    ap.add_argument("--compose-file", help="on the endpoint's host: lets restore migrate and start")
    ap.add_argument("--dir", help="dump: the (empty) directory to write; restore: the one to read")
    ap.add_argument(
        "--require-quiescent",
        action="store_true",
        help="restore: refuse a dump taken while the source changed",
    )
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
            result = restore(ep, a.dir, require_quiescent=a.require_quiescent)
        elif a.command == "counts":
            result = counts(ep)
        elif a.command == "freeze":
            result = freeze(ep)
        else:
            unfreeze(ep)
            result = {"started": list(ep.web_containers)}
    except CountMismatch as e:
        print(f"projects-migrate: {e}", file=sys.stderr)
        return 1
    except MigrateError as e:
        print(f"projects-migrate: {e}", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
