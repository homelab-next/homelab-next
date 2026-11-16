#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# hnx-script:
#   id: documents-migrate
#   kind: tool
#   purpose: Copy a document library (every document with its archive copy and thumbnail, tags, correspondents, document types, custom fields, notes and accounts) from one instance to another with the product's own exporter and importer, and prove the copy by counts and by the checksum of every file.
#   owner: maintainers
#   trigger: [manual]
#   inputs: two endpoints named on the command line (an ssh destination and the application container, never a literal in this file); for restore, a dump directory written by dump
#   outputs: a dump directory (export.tar, dump-manifest.json) for dump; the counts as JSON for counts, the verification report for restore
#   exit:
#     "0": done (for restore, the target equals the manifest by counts and by every file's checksum)
#     "1": a count or a checksum differs, or the dump is not intact
#     "2": usage error, a refused target or a command on an endpoint failed
"""Migrate a document library by the product's exporter and importer (docs of the provider:
``modules/documents/README.md``, "Migrating in").

Generic: an *endpoint* is an ssh destination (or ``None`` for this host) plus the application
container, the directory of its ``manage.py`` and, for a source started as root, the account its
commands run as; nothing here names a host, an address, a path of the product or a lab.

* :func:`counts` -- **read-only**: documents (the trash included), tags, correspondents, document
  types, custom fields and their values, notes, storage paths and accounts, and a fingerprint (the
  newest modification time and the highest id).
* :func:`dump` -- **read-only on the source's data**: the product's exporter writes into a scratch
  directory *inside the container* (``<scratch>/<12 hex>``, removed afterwards), which is streamed
  over the ssh pipe into ``export.tar`` of a private directory the caller names.  The tar is then
  read once: every member's name and type are checked, every document's original and archive copy
  is hashed and compared with the checksum the export's own ``manifest.json`` records for it, every
  record the manifest holds is counted, and the counts must equal the live database's (a source
  that changed during the export is refused).  ``dump-manifest.json`` records the counts, the
  digest of every document's checksums and whether the source stood still (``quiescent``).
* :func:`restore` -- onto an **empty** target (no document, no account: the importer upserts by id
  and refuses to overwrite a file, so it is not a delta tool): the tar is re-scanned and compared
  with the manifest, streamed into a staging directory in the target's export volume, imported by
  the product's importer, and the target is then read: the counts equal the manifest's and the
  checksum of *every file on disk* equals what the export recorded.  A passing run that proved
  nothing (no documents, nothing hashed) is an error.
* :func:`stop` / :func:`start` -- stop (or start) the named containers of an endpoint; the only write
  this tool makes to a source, done in the cutover window after the final dump.

**The final copy.** The importer does not merge, so a rehearsal and the cutover are separate
restores onto separate empty targets: ``dump`` (callers of the source disabled), ``dump`` again,
``restore(require_quiescent=True, expect_counts=<what counts printed>)``, then ``stop`` the source.

**Destructive paths.** The only recursive deletes remove the scratch directory this tool made in the
source container and the staging directory it made in the target's export volume; each must be an
absolute canonical path of at least three components with a generated 12-hex last component, sit
directly under the directory the caller named, and resolve to itself inside the container (no
symlink anywhere in it).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import secrets
import shlex
import subprocess
import sys
import tarfile
import tempfile
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

__all__ = [
    "COUNT_KEYS",
    "CountMismatch",
    "Endpoint",
    "MigrateError",
    "VerifyMismatch",
    "counts",
    "dump",
    "restore",
    "scan_export",
    "start",
    "stop",
]

#: the manifest's model label for each counted table
MODEL_KEYS = {
    "documents.document": "documents",
    "documents.tag": "tags",
    "documents.correspondent": "correspondents",
    "documents.documenttype": "document_types",
    "documents.customfield": "custom_fields",
    "documents.customfieldinstance": "custom_field_instances",
    "documents.note": "notes",
    "documents.storagepath": "storage_paths",
    "auth.user": "users",
}
COUNT_KEYS = tuple(MODEL_KEYS.values())
#: what restore refuses to find in a target that is to receive an import
TARGET_MUST_BE_EMPTY = COUNT_KEYS
TAR_FILE, MANIFEST = "export.tar", "dump-manifest.json"
EXPORT_MANIFEST, EXPORT_METADATA = "manifest.json", "metadata.json"
FILE_KEY, THUMB_KEY, ARCHIVE_KEY = (
    "__exported_file_name__",
    "__exported_thumbnail_name__",
    "__exported_archive_name__",
)
#: places a dump must never be staged: world-writable scratch space (it holds every account's
#: password hash and every document)
SCRATCH_DIRS = ("/tmp", "/var/tmp", "/dev/shm")
_HEX12 = re.compile(r"[0-9a-f]{12}\Z")
_CHUNK = 1 << 20
_PREFIX = "HNX-JSON "

#: run in the application's own interpreter (``manage.py shell -c``); the models are the
#: product's, the trash included for the tables that have one
COUNTS_CODE = """
import json
from django.contrib.auth.models import User
from django.db.models import Max
from documents.models import (Correspondent, CustomField, CustomFieldInstance, Document,
    DocumentType, Note, StoragePath, Tag)
mx = Document.global_objects.aggregate(m=Max("modified"), i=Max("id"))
print("HNX-JSON " + json.dumps({
    "counts": {
        "documents": Document.global_objects.count(),
        "tags": Tag.objects.count(),
        "correspondents": Correspondent.objects.count(),
        "document_types": DocumentType.objects.count(),
        "custom_fields": CustomField.objects.count(),
        "custom_field_instances": CustomFieldInstance.global_objects.count(),
        "notes": Note.global_objects.count(),
        "storage_paths": StoragePath.objects.count(),
        "users": User.objects.exclude(username__in=["consumer", "AnonymousUser"]).count(),
    },
    "fingerprint": {"modified": mx["m"].isoformat() if mx["m"] else "", "max_id": mx["i"] or 0},
}, sort_keys=True))
"""
#: hashes every document file on disk (by the length of the checksum the database holds for it)
FILES_CODE = """
import hashlib, json, os
from documents.models import Document
def digest(path, want):
    algo = {32: "md5", 64: "sha256"}.get(len(want or ""))
    if algo is None or path is None or not os.path.isfile(path):
        return None
    h = hashlib.new(algo)
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()
lines, bad = [], []
for d in Document.global_objects.order_by("pk"):
    o = digest(d.source_path, d.checksum)
    a = digest(d.archive_path, d.archive_checksum) if d.archive_filename else ""
    if o is None or o != d.checksum or (d.archive_filename and a != d.archive_checksum):
        bad.append(d.pk)
    lines.append(f"{d.pk}:{o or ''}:{a or ''}")
print("HNX-JSON " + json.dumps({
    "documents": len(lines), "bad": bad,
    "digest": hashlib.sha256("\\n".join(lines).encode()).hexdigest(),
}, sort_keys=True))
"""


class MigrateError(RuntimeError):
    """A command on an endpoint failed, or an input is not usable."""


class VerifyMismatch(MigrateError):
    """What was written is not what the manifest says."""


def _count_difference(expected: Mapping[str, int], got: Mapping[str, int]) -> str:
    apart = [k for k in COUNT_KEYS if expected.get(k) != got.get(k)]
    return "counts differ (expected, got): " + ", ".join(
        f"{k} ({expected.get(k)}, {got.get(k)})" for k in apart
    )


class CountMismatch(VerifyMismatch):
    """Counts differ; ``expected`` and ``got`` are kept, the message lists the tables that do."""

    def __init__(self, expected: Mapping[str, int], got: Mapping[str, int]):
        super().__init__(_count_difference(expected, got))
        self.expected, self.got = dict(expected), dict(got)


def _canonical(path: str) -> bool:
    """An absolute path written the one way the kernel reads it: no ``..``, ``.``, ``//`` or trailing ``/``."""
    parts = PurePosixPath(path).parts
    return (
        path.startswith("/") and str(PurePosixPath(path)) == path and not {"..", "."} & set(parts)
    )


def guard_dir(path: str, *, parent: str | None = None, min_components: int = 3) -> str:
    """The checks a directory must pass before something recursive acts on it; returns it unchanged.

    Canonical, at least ``min_components`` components (``/tmp/x/y``: never ``/``, ``/tmp`` or
    ``/var/lib``), a last component this tool generated (``<12 hex>``) and, when ``parent`` is
    given, directly under it.
    """
    if not _canonical(path):
        raise MigrateError(f"{path!r}: not an absolute canonical path")
    p = PurePosixPath(path)
    if len(p.parts) <= min_components:  # the root counts as a part
        raise MigrateError(
            f"{path!r}: refusing a recursive action on a path of fewer than {min_components} components"
        )
    if not _HEX12.match(p.name):
        raise MigrateError(f"{path!r}: not a directory this tool generated")
    if parent is not None and str(p.parent) != parent:
        raise MigrateError(f"{path!r}: not directly under {parent!r}")
    return path


@dataclass(frozen=True)
class Endpoint:
    """Where an instance runs.  ``ssh`` is a destination (``user@host``) or ``None`` for this host;
    commands run as ``[ssh dest] [sudo -n] docker exec ...``.

    ``container`` runs the application; ``src_dir`` is the directory of its ``manage.py`` inside it;
    ``exec_user`` is the account its commands run as (a source started as root must not run them as
    root: the files it writes would be root's); ``scratch_dir`` is where a dump's scratch directory
    goes (a dump) and ``staging_dir`` where an import's is made (a restore: a directory the
    application's user can write, in the volume that holds its exports); ``containers`` are what
    ``stop`` and ``start`` act on.
    """

    container: str
    src_dir: str
    ssh: str | None = None
    sudo: bool = True
    exec_user: str | None = None
    scratch_dir: str = "/tmp/hnx-dump"
    staging_dir: str | None = None
    containers: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        named = [self.src_dir, self.scratch_dir, *([self.staging_dir] if self.staging_dir else [])]
        for path in named:
            if path == "/" or not _canonical(path):
                raise MigrateError(f"{path!r}: not an absolute canonical path")

    def argv(self, inner: Sequence[str], *, piped: bool = False) -> list[str]:
        """What runs ``inner`` on this endpoint: sudo when asked, and through ssh as one quoted
        command string (``-n`` unless something is piped in, so ssh never reads the caller's stdin)."""
        cmd = [*(("sudo", "-n") if self.sudo else ()), *inner]
        if self.ssh is None:
            return cmd
        return [
            "ssh",
            *(() if piped else ("-n",)),
            "-o",
            "BatchMode=yes",
            self.ssh,
            shlex.join(cmd),
        ]


#: ``(argv, *, stdin, stdout) -> (return code, stdout, stderr)``; stdout goes to the file when one
#: is given, else it is returned
Runner = Callable[..., tuple[int, bytes, bytes]]


def _subprocess_runner(argv, *, stdin=None, stdout=None):
    done = subprocess.run(
        list(argv),
        stdin=stdin or subprocess.DEVNULL,
        stdout=stdout or subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    return done.returncode, done.stdout or b"", done.stderr or b""


@dataclass
class _Ctx:
    runner: Runner | None = None
    log: list[list[str]] = field(default_factory=list)

    def run(self, ep: Endpoint, inner: Sequence[str], *, stdin=None, stdout=None) -> bytes:
        argv = ep.argv(inner, piped=stdin is not None)
        self.log.append(argv)
        # the module's own runner is looked up at call time, so a test can replace it
        code, out, err = (self.runner or _subprocess_runner)(argv, stdin=stdin, stdout=stdout)
        if code:
            tail = " | ".join(err.decode("utf-8", "replace").strip().splitlines()[-3:])
            raise MigrateError(f"{' '.join(inner[:8])} ... failed ({code}): {tail}")
        return out


def _run(ctx: _Ctx, ep: Endpoint, inner: Sequence[str], *, stdin=None, stdout=None) -> bytes:
    return ctx.run(ep, inner, stdin=stdin, stdout=stdout)


def _exec(
    ep: Endpoint, args: Sequence[str], *, stdin: bool = False, cwd: str | None = None
) -> list[str]:
    """``docker exec`` in the application container, as its configured account."""
    return [
        "docker", "exec", *(["-i"] if stdin else []),
        *(["-u", ep.exec_user] if ep.exec_user else []),
        *(["-w", cwd] if cwd else []), ep.container, *args,
    ]  # fmt: skip


def _manage(ep: Endpoint, *args: str) -> list[str]:
    return _exec(ep, ["python3", "manage.py", *args], cwd=ep.src_dir)


def _json_line(out: bytes, what: str) -> dict:
    for line in reversed(out.decode("utf-8", "replace").splitlines()):
        if line.startswith(_PREFIX):
            try:
                doc = json.loads(line[len(_PREFIX) :])
            except ValueError as e:
                raise MigrateError(f"{what}: unreadable answer: {e}") from e
            if isinstance(doc, dict):
                return doc
    raise MigrateError(f"{what}: the application printed no answer (wrong container or schema?)")


def _state(ctx: _Ctx, ep: Endpoint) -> dict:
    doc = _json_line(_run(ctx, ep, _manage(ep, "shell", "-c", COUNTS_CODE)), "counts")
    c = doc.get("counts")
    if (
        not isinstance(c, dict)
        or set(c) != set(COUNT_KEYS)
        or not all(isinstance(v, int) and not isinstance(v, bool) and v >= 0 for v in c.values())
    ):
        raise MigrateError(f"counts: not the expected tables {COUNT_KEYS}: {doc!r}")
    return {"counts": c, "fingerprint": doc.get("fingerprint", {})}


def counts(ep: Endpoint, *, _ctx: _Ctx | None = None) -> dict[str, int]:
    """Counts of the endpoint, ``COUNT_KEYS`` in order (a read)."""
    return _state(_ctx or _Ctx(), ep)["counts"]


def _sha256(path: Path) -> tuple[int, str]:
    h, n = hashlib.sha256(), 0
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(_CHUNK), b""):
            h.update(chunk)
            n += len(chunk)
    return n, h.hexdigest()


def _private_empty_dir(path: str | os.PathLike, scratch_dirs: Sequence[str]) -> Path:
    """``path`` as a directory only its owner can enter, empty, and not in scratch space."""
    out = Path(path)
    here = out.resolve()
    for scratch in map(Path, scratch_dirs):
        root = scratch.resolve()
        if root == here or root in here.parents:
            raise MigrateError(
                f"{out}: refusing to stage a dump under {root}; name a private directory"
            )
    out.mkdir(mode=0o700, parents=True, exist_ok=True)
    out.chmod(0o700)
    if next(out.iterdir(), None) is not None:
        raise MigrateError(f"{out}: not empty")
    return out


# ----------------------------------------------------------------------------- reading an export


def _member_name(name: str) -> str:
    p = PurePosixPath(name)
    if name.startswith("/") or ".." in p.parts or "\\" in name or name == "":
        raise MigrateError(f"the export holds a member that leaves its directory: {name!r}")
    return "/".join(x for x in p.parts if x != ".")


def scan_export(path: str | os.PathLike) -> dict:
    """Read an export tar once and say what it holds, refusing what is not safe or not whole.

    Every member must be a regular file or a directory with a name inside the tree; ``manifest.json``
    must parse; each document's original and archive copy must be present and hash to the
    checksum the manifest records (32 hex = md5, 64 = sha256); its thumbnail must be present.
    Returns ``{counts, digest, documents, archives, thumbnails, files, version}``.
    """
    hashes: dict[str, tuple[str, str]] = {}
    manifest_raw: bytes | None = None
    metadata_raw: bytes | None = None
    with tarfile.open(path, mode="r|") as tf:
        for m in tf:
            name = _member_name(m.name)
            if m.isdir():
                continue
            if not m.isreg():
                raise MigrateError(f"the export holds a link or special file: {m.name!r}")
            if not name:
                raise MigrateError("the export holds an unnamed file")
            if name in hashes:
                raise MigrateError(f"the export holds {name!r} twice")
            f = tf.extractfile(m)
            md, sh = hashlib.md5(usedforsecurity=False), hashlib.sha256()
            keep = bytearray() if name in (EXPORT_MANIFEST, EXPORT_METADATA) else None
            for chunk in iter(lambda f=f: f.read(_CHUNK), b""):
                md.update(chunk)
                sh.update(chunk)
                if keep is not None:
                    keep += chunk
            hashes[name] = (md.hexdigest(), sh.hexdigest())
            if name == EXPORT_MANIFEST:
                manifest_raw = bytes(keep)
            elif name == EXPORT_METADATA:
                metadata_raw = bytes(keep)
    if manifest_raw is None:
        raise MigrateError(f"{path}: the export holds no {EXPORT_MANIFEST}")
    try:
        records = json.loads(manifest_raw)
    except ValueError as e:
        raise MigrateError(f"{path}: {EXPORT_MANIFEST} does not parse: {e}") from e
    if not isinstance(records, list) or not all(isinstance(r, dict) for r in records):
        raise MigrateError(f"{path}: {EXPORT_MANIFEST} is not a list of records")
    counted = dict.fromkeys(COUNT_KEYS, 0)
    rows: list[tuple[int, str, str]] = []
    archives = thumbnails = 0
    for r in records:
        key = MODEL_KEYS.get(r.get("model"))
        if key is None:
            continue
        counted[key] += 1
        if key != "documents":
            continue
        fields = r.get("fields") or {}
        pk = r.get("pk")
        if not isinstance(pk, int):
            raise MigrateError(f"a document record has no integer id: {pk!r}")
        entries = [(r.get(FILE_KEY), fields.get("checksum"), "original")]
        if r.get(ARCHIVE_KEY):
            entries.append((r[ARCHIVE_KEY], fields.get("archive_checksum"), "archive"))
            archives += 1
        for fname, want, kind in entries:
            seen = hashes.get(_member_name(fname)) if isinstance(fname, str) else None
            algo = {32: 0, 64: 1}.get(len(want) if isinstance(want, str) else -1)
            if seen is None or algo is None:
                raise MigrateError(f"document {pk}: its {kind} file {fname!r} is not in the export")
            if seen[algo] != want:
                raise VerifyMismatch(
                    f"document {pk}: the {kind} file {fname!r} hashes to {seen[algo]}, "
                    f"the manifest records {want}"
                )
        thumb = r.get(THUMB_KEY)
        if thumb:
            if _member_name(thumb) not in hashes:
                raise MigrateError(f"document {pk}: its thumbnail {thumb!r} is not in the export")
            thumbnails += 1
        rows.append((pk, fields["checksum"], fields.get("archive_checksum") or ""))
    rows.sort()
    digest = hashlib.sha256("\n".join(f"{p}:{c}:{a}" for p, c, a in rows).encode()).hexdigest()
    version = ""
    if metadata_raw:
        try:
            version = str(json.loads(metadata_raw).get("version", ""))
        except ValueError:
            version = ""
    return {
        "counts": counted,
        "digest": digest,
        "documents": len(rows),
        "archives": archives,
        "thumbnails": thumbnails,
        "files": len(hashes),
        "version": version,
    }


# ----------------------------------------------------------------------------- dump


def _remove_dir(ctx: _Ctx, ep: Endpoint, path: str, parent: str) -> None:
    """Delete a directory this tool made (generated name, directly under ``parent``, no link)."""
    guard_dir(path, parent=parent)
    real = _run(ctx, ep, _exec(ep, ["readlink", "-f", "--", path])).decode().strip()
    if real != path:
        raise MigrateError(
            f"{path!r} resolves to {real!r}: refusing a recursive action through a link"
        )
    _run(ctx, ep, _exec(ep, ["rm", "-rf", "--", path]))


def dump(
    source: Endpoint,
    out_dir: str | os.PathLike,
    *,
    scratch_dirs: Sequence[str] = (*SCRATCH_DIRS, tempfile.gettempdir()),
    allow_empty: bool = False,
    _ctx: _Ctx | None = None,
) -> dict:
    """Export ``source`` into a private, empty ``out_dir`` and return the dump manifest.

    Nothing of the source's is written: its data is read (queries and the exporter) and a scratch
    directory is made inside the container and removed afterwards.
    """
    ctx = _ctx or _Ctx()
    out = _private_empty_dir(out_dir, scratch_dirs)
    before = _state(ctx, source)
    scratch = f"{source.scratch_dir}/{secrets.token_hex(6)}"
    guard_dir(scratch, parent=source.scratch_dir)
    tar_path = out / TAR_FILE
    _run(ctx, source, _exec(source, ["mkdir", "-p", "-m", "700", "--", source.scratch_dir]))
    _run(ctx, source, _exec(source, ["mkdir", "-m", "700", "--", scratch]))
    try:
        _run(ctx, source, _manage(source, "document_exporter", scratch, "--no-progress-bar"))
        try:
            with os.fdopen(
                os.open(tar_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb"
            ) as f:
                _run(ctx, source, _exec(source, ["tar", "-C", scratch, "-cf", "-", "."]), stdout=f)
        except BaseException:
            tar_path.unlink(missing_ok=True)
            raise
    finally:
        _remove_dir(ctx, source, scratch, source.scratch_dir)
    after = _state(ctx, source)
    scan = scan_export(tar_path)
    if scan["counts"] != after["counts"]:
        raise CountMismatch(after["counts"], scan["counts"])
    if not allow_empty and (scan["documents"] == 0 or scan["counts"]["users"] == 0):
        raise MigrateError(
            f"the source has {scan['documents']} documents and {scan['counts']['users']} accounts: "
            "refusing a vacuous dump (wrong container? --allow-empty if it is empty)"
        )
    size, digest = _sha256(tar_path)
    manifest = {
        "format": 1,
        "files": {TAR_FILE: {"size": size, "sha256": digest}},
        "counts": after["counts"],
        "counts_before": before["counts"],
        "fingerprint": after["fingerprint"],
        "documents_digest": scan["digest"],
        "archives": scan["archives"],
        "thumbnails": scan["thumbnails"],
        "version": scan["version"],
        "quiescent": before == after,
    }
    (out / MANIFEST).write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    return manifest


# ----------------------------------------------------------------------------- restore


def _json_object(raw: bytes, label: str) -> dict:
    """The JSON object ``raw`` holds, or a MigrateError naming ``label``."""
    try:
        doc = json.loads(raw)
    except ValueError as e:
        raise MigrateError(f"{label}: not JSON ({e})") from e
    if not isinstance(doc, dict):
        raise MigrateError(f"{label}: not a JSON object")
    return doc


def _json_file(path: Path) -> dict:
    """The JSON object a file holds, or a MigrateError."""
    try:
        raw = path.read_bytes()
    except OSError as e:
        raise MigrateError(f"{path}: not readable ({e})") from e
    return _json_object(raw, str(path))


def _read_manifest(dump_dir: Path) -> dict:
    try:
        manifest = _json_file(dump_dir / MANIFEST)
    except MigrateError as e:
        raise MigrateError(f"{dump_dir}: no readable {MANIFEST}") from e
    want = (manifest.get("files") or {}).get(TAR_FILE)
    path = dump_dir / TAR_FILE
    if not want or path.is_symlink() or not path.is_file():
        raise MigrateError(f"{dump_dir}: {TAR_FILE} is missing or not a plain file")
    size, digest = _sha256(path)
    if (size, digest) != (want.get("size"), want.get("sha256")):
        raise VerifyMismatch(f"{path}: not what {MANIFEST} recorded (size or sha256 differ)")
    c = manifest.get("counts")
    if not isinstance(c, dict) or set(c) != set(COUNT_KEYS):
        raise MigrateError(f"{dump_dir}: {MANIFEST} holds no usable counts")
    return manifest


def restore(
    target: Endpoint,
    dump_dir: str | os.PathLike,
    *,
    expect_counts: Mapping[str, int] | None = None,
    require_quiescent: bool = False,
    _ctx: _Ctx | None = None,
) -> dict:
    """Import ``dump_dir`` into an empty ``target`` and verify it; return the report.

    Refused before anything is written: a dump whose tar is not what its manifest says, or not
    whole; a dump not taken from a source that stood still (``require_quiescent``); one that is not
    the state ``expect_counts`` names; a target that holds any document or account.  After the
    import the counts and the checksum of every file on disk must equal the dump's.  A failure
    leaves the staging directory (and a half-filled target) for inspection and says so.
    """
    ctx = _ctx or _Ctx()
    root = Path(dump_dir)
    manifest = _read_manifest(root)
    if not target.staging_dir:
        raise MigrateError("restore needs a staging directory in the target's export volume")
    scan = scan_export(root / TAR_FILE)
    if scan["counts"] != manifest["counts"] or scan["digest"] != manifest.get("documents_digest"):
        raise VerifyMismatch(f"{root / TAR_FILE}: its contents are not what {MANIFEST} recorded")
    if require_quiescent and not manifest.get("quiescent"):
        raise MigrateError("the dump was not taken from a source that stood still")
    if expect_counts is not None and dict(expect_counts) != manifest["counts"]:
        raise CountMismatch(expect_counts, manifest["counts"])
    if scan["documents"] == 0:
        raise MigrateError("the dump holds no document: refusing a vacuous restore")
    now = counts(target, _ctx=ctx)
    held = {k: v for k, v in now.items() if v}
    if held:
        raise MigrateError(
            f"the target is not empty ({held}): the importer is not a merge. Move its data root "
            "aside and redeploy it empty (admin bootstrap off), then restore again"
        )
    staging = f"{target.staging_dir}/{secrets.token_hex(6)}"
    guard_dir(staging, parent=target.staging_dir)
    try:
        _run(ctx, target, _exec(target, ["mkdir", "-m", "700", "--", staging]))
        with (root / TAR_FILE).open("rb") as f:
            _run(
                ctx, target,
                _exec(target, ["tar", "-x", "-C", staging, "--no-same-owner", "--no-same-permissions", "-f", "-"], stdin=True),
                stdin=f,
            )  # fmt: skip
        staged = (
            _run(ctx, target, _exec(target, ["find", staging, "-type", "f"])).decode().splitlines()
        )
        if len(staged) != scan["files"]:
            raise VerifyMismatch(f"staged {len(staged)} files, the export holds {scan['files']}")
        _run(ctx, target, _manage(target, "document_importer", staging, "--no-progress-bar"))
        got = counts(target, _ctx=ctx)
        if got != manifest["counts"]:
            raise CountMismatch(manifest["counts"], got)
        empty = [k for k in COUNT_KEYS if manifest["counts"][k] > 0 and got[k] == 0]
        if empty:
            raise VerifyMismatch(
                f"the target has no rows in {', '.join(empty)} where the source has some"
            )
        files = _json_line(
            _run(ctx, target, _manage(target, "shell", "-c", FILES_CODE)), "file check"
        )
        if files.get("documents") != scan["documents"] or files.get("documents", 0) == 0:
            raise VerifyMismatch(
                f"checked {files.get('documents')} documents, expected {scan['documents']}"
            )
        if files.get("bad"):
            raise VerifyMismatch(
                f"documents whose files are missing or differ on the target: {files['bad'][:20]}"
            )
        if files.get("digest") != scan["digest"]:
            raise VerifyMismatch(
                "the checksum of the files on the target differs from the export's"
            )
        try:
            _run(ctx, target, _manage(target, "document_sanity_checker", "--no-progress-bar"))
            sanity = "clean"
        except MigrateError as e:
            sanity = f"reported: {e}"
    except BaseException as e:
        e.add_note(
            f"the staging directory {staging} (in the target container) and anything already "
            "imported were left for inspection; empty the target before restoring again"
        )
        raise
    _remove_dir(ctx, target, staging, target.staging_dir)
    return {
        "counts": got,
        "documents_verified": files["documents"],
        "archives": scan["archives"],
        "thumbnails": scan["thumbnails"],
        "digest": scan["digest"],
        "sanity_checker": sanity,
    }


def _names(ep: Endpoint) -> list[str]:
    if not ep.containers:
        raise MigrateError("name the containers to act on (--container, repeatable)")
    return list(ep.containers)


def stop(ep: Endpoint, *, _ctx: _Ctx | None = None) -> dict:
    """Stop the endpoint's containers and check that none runs (the freeze of a cutover)."""
    ctx = _ctx or _Ctx()
    names = _names(ep)
    _run(ctx, ep, ["docker", "stop", *names])
    running = [
        n for n in names
        if _run(ctx, ep, ["docker", "inspect", "--format", "{{.State.Running}}", n]).decode().strip() == "true"
    ]  # fmt: skip
    if running:
        raise MigrateError(f"still running after the stop: {', '.join(running)}")
    return {"stopped": names}


def start(ep: Endpoint, *, _ctx: _Ctx | None = None) -> dict:
    """Start the endpoint's containers again (the rollback of a cutover)."""
    ctx = _ctx or _Ctx()
    names = _names(ep)
    _run(ctx, ep, ["docker", "start", *names])
    return {"started": names}


# ----------------------------------------------------------------------------- command line


def _endpoint(a: argparse.Namespace) -> Endpoint:
    return Endpoint(
        container=a.app_container, src_dir=a.src_dir, ssh=a.ssh, sudo=not a.no_sudo,
        exec_user=a.exec_user, scratch_dir=a.scratch_dir, staging_dir=a.staging_dir,
        containers=tuple(a.container or ()),
    )  # fmt: skip


def _expect(text: str | None) -> dict | None:
    """The counts ``--expect-counts`` names: inline JSON, or ``@file``."""
    if text is None:
        return None
    return (
        _json_file(Path(text[1:]))
        if text[:1] == "@"
        else _json_object(text.encode(), "--expect-counts")
    )


def _parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("command", choices=["dump", "restore", "counts", "stop", "start"])
    ap.add_argument("--ssh", help="user@host (default: this host)")
    ap.add_argument("--no-sudo", action="store_true")
    ap.add_argument(
        "--app-container", help="the application container (every command but stop/start)"
    )
    ap.add_argument("--src-dir", help="the directory of manage.py inside the application container")
    ap.add_argument(
        "--exec-user", help="the account the commands run as (a source started as root)"
    )
    ap.add_argument(
        "--scratch-dir",
        default="/tmp/hnx-dump",
        help="dump: where the scratch directory goes, in the container",
    )
    ap.add_argument(
        "--staging-dir",
        help="restore: a writable directory in the target's export volume (in the container)",
    )
    ap.add_argument(
        "--container", action="append", help="stop/start: a container to act on; repeatable"
    )
    ap.add_argument("--dir", help="dump: the (empty) directory to write; restore: the one to read")
    ap.add_argument(
        "--expect-counts", help="restore: what counts printed on the frozen source (JSON or @file)"
    )
    ap.add_argument(
        "--allow-empty", action="store_true", help="dump: accept a source with no documents"
    )
    ap.add_argument("--require-quiescent", action="store_true",
                    help="restore: refuse a dump taken while the source changed")  # fmt: skip
    return ap


def _command(a: argparse.Namespace) -> dict:
    """Run the command the arguments name and return what it reports."""
    if a.command in ("stop", "start"):
        ep = Endpoint(
            container=a.app_container or "-", src_dir=a.src_dir or "/-", ssh=a.ssh,
            sudo=not a.no_sudo, containers=tuple(a.container or ()),
        )  # fmt: skip
        return stop(ep) if a.command == "stop" else start(ep)
    if not (a.app_container and a.src_dir):
        raise MigrateError(f"{a.command} needs --app-container and --src-dir")
    ep = _endpoint(a)
    if a.command == "counts":
        return counts(ep)
    if not a.dir:
        raise MigrateError(f"{a.command} needs --dir")
    if a.command == "dump":
        return dump(ep, a.dir, allow_empty=a.allow_empty)
    return restore(
        ep, a.dir, expect_counts=_expect(a.expect_counts), require_quiescent=a.require_quiescent
    )


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        report = _command(args)
    except (
        MigrateError
    ) as e:  # a VerifyMismatch is a difference found (1); the rest could not run (2)
        print(f"documents-migrate: {e}", file=sys.stderr)
        return 1 if isinstance(e, VerifyMismatch) else 2
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
