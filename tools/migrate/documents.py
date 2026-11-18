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

**Duplicates.** The product lets two documents carry the same original (same checksum, each with
its own notes, tags, owner and custom fields; its importer writes every document under its id and
puts no constraint on the checksum).  So a document is identified by its id from dump to restore to
verification, never by its checksum: every one of them is carried and compared on its own, and the
groups that share a checksum are listed (``duplicate_checksums`` in the dump manifest and the restore
report), not merged and not dropped.  Corruption is still caught per document: each file must hash to
the checksum its own record carries.

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
import shutil
import signal
import subprocess
import sys
import tarfile
import tempfile
import threading
from collections import Counter
from collections.abc import Callable, Mapping, Sequence
from contextlib import contextmanager
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
    "duplicate_checksums",
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
VERIFY_TAR = "verify-target.tar"
#: what can reach out of the application by itself once imported (mail fetch, e-mail and webhook
#: workflow actions): counted from the export's manifest
EGRESS_MODELS = {
    "paperless_mail.mailaccount": "mail_accounts",
    "paperless_mail.mailrule": "mail_rules",
    "documents.workflowactionemail": "email_actions",
    "documents.workflowactionwebhook": "webhook_actions",
}
#: a sanity finding below this level (info) is not a problem
SANITY_LEVEL = 30
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


#: what the exporter will copy, in bytes (originals, archive copies, thumbnails)
SIZE_CODE = """
import json, os
from documents.models import Document
n = 0
for d in Document.global_objects.all():
    for p in (d.source_path, d.archive_path, d.thumbnail_path):
        if p is not None and os.path.isfile(p):
            n += os.path.getsize(p)
print("HNX-JSON " + json.dumps({"bytes": n}))
"""
#: the product's own sanity checker, as data: (document id or 0, level, message)
SANITY_CODE = """
import json
from documents.sanity_checker import check_sanity
found = check_sanity()
rows = sorted(
    [pk or 0, int(m["level"]), str(m["message"])]
    for pk, entries in found.iter_messages() for m in entries
)
print("HNX-JSON " + json.dumps({"issues": rows}))
"""
#: reports (and, when DISABLE is true, turns off) what can reach out by itself: mail rules, and the
#: workflows that send e-mail or call a webhook
EGRESS_CODE = """
import json
from documents.models import Workflow
from paperless_mail.models import MailAccount, MailRule
DISABLE = False
flows = Workflow.objects.filter(actions__email__isnull=False) | Workflow.objects.filter(actions__webhook__isnull=False)
flows = flows.distinct()
report = {
    "mail_accounts": MailAccount.objects.count(),
    "mail_rules": list(MailRule.objects.filter(enabled=True).values_list("name", flat=True)),
    "workflows": list(flows.filter(enabled=True).values_list("name", flat=True)),
}
if DISABLE:
    MailRule.objects.update(enabled=False)
    flows.update(enabled=False)
report["disabled"] = DISABLE
print("HNX-JSON " + json.dumps(report, sort_keys=True))
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


def _relations(records: list[dict]) -> dict[int, dict]:
    """Per document, keyed by its **id**, what makes the library worth having: its checksums, title,
    date and text (digested), its owner, tags, correspondent, document type and storage path *by
    name*, its custom field values and its notes, all read out of the export's own manifest.

    By id, not by checksum: the product lets two documents carry the same file (a duplicate it was
    told to keep), each with its own notes, tags and owner, and the importer writes every document
    under the id the export gives it, so the id is the one key that names a document on both sides.
    The checksums are compared as attributes (a document whose file changed differs).  Related rows
    by name, not id: two exports of the same library are equal even if a tag's id moved."""
    named: dict[str, dict[int, dict]] = {}
    per_doc: dict[int, dict[str, list]] = {}
    for r in records:
        model, pk, f = r.get("model"), r.get("pk"), r.get("fields") or {}
        if model in (
            "documents.tag", "documents.correspondent", "documents.documenttype",
            "documents.storagepath", "documents.customfield", "auth.user",
        ):  # fmt: skip
            named.setdefault(model, {})[pk] = f
        elif model in ("documents.customfieldinstance", "documents.note"):
            per_doc.setdefault(f.get("document"), {}).setdefault(model, []).append(f)

    def name(model: str, pk) -> str | None:
        if pk is None:
            return None
        f = named.get(model, {}).get(pk)
        if f is None:
            raise MigrateError(f"the export names {model} {pk}, which it does not hold")
        return json.dumps(
            {k: f[k] for k in ("name", "username", "path", "data_type") if k in f}, sort_keys=True
        )

    out: dict[int, dict] = {}
    for r in records:
        if r.get("model") != "documents.document":
            continue
        f = r["fields"]
        mine = per_doc.get(r["pk"], {})
        rel = {
            "pk": r["pk"],
            "checksum": f.get("checksum"),
            "archive_checksum": f.get("archive_checksum") or "",
            "title": f.get("title"),
            "created": f.get("created"),
            "content": hashlib.sha256((f.get("content") or "").encode()).hexdigest(),
            "owner": name("auth.user", f.get("owner")),
            "tags": sorted(name("documents.tag", t) for t in f.get("tags") or []),
            "correspondent": name("documents.correspondent", f.get("correspondent")),
            "document_type": name("documents.documenttype", f.get("document_type")),
            "storage_path": name("documents.storagepath", f.get("storage_path")),
            "fields": sorted(
                json.dumps(
                    [
                        name("documents.customfield", i.get("field")),
                        {k: v for k, v in i.items() if k.startswith("value")},
                    ],
                    sort_keys=True,
                )
                for i in mine.get("documents.customfieldinstance", [])
            ),
            "notes": sorted(
                json.dumps([n.get("note"), n.get("created")])
                for n in mine.get("documents.note", [])
            ),
        }
        if r["pk"] in out:
            raise MigrateError(f"the export holds document {r['pk']} twice")
        out[r["pk"]] = rel
    return out


def duplicate_checksums(relations: Mapping[int, dict]) -> list[list[int]]:
    """The documents that share an original's checksum, as sorted id groups (sorted by first id):
    what the product allowed to exist and the migration carries as it is, every one of them."""
    by_sum: dict[str, list[int]] = {}
    for pk, rel in relations.items():
        by_sum.setdefault(rel["checksum"], []).append(pk)
    return sorted(sorted(g) for g in by_sum.values() if len(g) > 1)


def _relation_differences(want: Mapping[int, dict], got: Mapping[int, dict]) -> list[str]:
    """Which documents (by id) differ, and in what: a missing or extra document, or the names of
    the attributes that differ."""
    diff = []
    for key in sorted(set(want) | set(got)):
        a, b = want.get(key), got.get(key)
        if a is None or b is None:
            diff.append(f"document {key} is {'missing' if b is None else 'extra'} on the target")
            continue
        apart = [k for k in a if k != "pk" and a[k] != b.get(k)]
        if apart:
            diff.append(f"document {key}: {', '.join(apart)} differ")
    return diff


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
    egress = dict.fromkeys(EGRESS_MODELS.values(), 0)
    for r in records:
        if r.get("model") in EGRESS_MODELS:
            egress[EGRESS_MODELS[r["model"]]] += 1
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
    relations = _relations(records)
    return {
        "counts": counted,
        "digest": digest,
        "documents": len(rows),
        "archives": archives,
        "thumbnails": thumbnails,
        "files": len(hashes),
        "version": version,
        "relations": relations,
        "duplicates": duplicate_checksums(relations),
        "egress": egress,
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


class _Terminated(BaseException):
    """SIGTERM or SIGHUP arrived: unwind (so the ``finally`` blocks run) instead of dying in place."""


@contextmanager
def _terminate_as_exception():
    """Turn SIGTERM and SIGHUP into :class:`_Terminated` for the block (main thread only)."""
    if threading.current_thread() is not threading.main_thread():
        yield
        return

    def handler(signum, frame):
        raise _Terminated(signal.Signals(signum).name)

    old = {sig: signal.signal(sig, handler) for sig in (signal.SIGTERM, signal.SIGHUP)}
    try:
        yield
    finally:
        for sig, previous in old.items():
            signal.signal(sig, previous)


def _sweep_stale(ctx: _Ctx, ep: Endpoint) -> list[str]:
    """Remove scratch directories an earlier, interrupted dump left (generated name, directly under
    the scratch directory, untouched for ten minutes, the same guard as any other delete)."""
    _run(ctx, ep, _exec(ep, ["mkdir", "-p", "-m", "700", "--", ep.scratch_dir]))
    found = _run(ctx, ep, _exec(ep, ["find", ep.scratch_dir, "-mindepth", "1", "-maxdepth", "1", "-type", "d", "-mmin", "+10"]))  # fmt: skip
    swept = []
    for line in found.decode().splitlines():
        try:
            guard_dir(line, parent=ep.scratch_dir)
        except MigrateError:
            continue  # not ours: left alone
        _remove_dir(ctx, ep, line, ep.scratch_dir)
        swept.append(line)
    return swept


def _check_space(ctx: _Ctx, ep: Endpoint, out: Path) -> None:
    """The exporter needs the library's size again in the container, and the tar the same on this
    host: refuse before writing when either has less than that and a margin."""
    need = _json_line(_run(ctx, ep, _manage(ep, "shell", "-c", SIZE_CODE)), "size")["bytes"]
    margin = 64 << 20
    df = _run(ctx, ep, _exec(ep, ["df", "-Pk", "--", ep.scratch_dir])).decode().splitlines()
    try:
        free = int(df[-1].split()[3]) * 1024
    except (IndexError, ValueError) as e:
        raise MigrateError(
            f"cannot read the free space of {ep.scratch_dir} in the container"
        ) from e
    if free < need + margin:
        raise MigrateError(
            f"{ep.scratch_dir} in the container has {free} bytes free; the export needs about {need}"
        )
    here = shutil.disk_usage(out).free
    if here < need + margin:
        raise MigrateError(f"{out} has {here} bytes free; the export needs about {need}")


def _export_tar(ctx: _Ctx, ep: Endpoint, out: Path, tar_path: Path) -> list[str]:
    """Export the endpoint's library with the product's exporter into a scratch directory in its
    container and stream it to ``tar_path``; the scratch directory is removed whatever happens
    (an exception, SIGTERM or SIGHUP).  Returns the stale scratch directories it swept first."""
    with _terminate_as_exception():
        swept = _sweep_stale(ctx, ep)
        _check_space(ctx, ep, out)
        scratch = f"{ep.scratch_dir}/{secrets.token_hex(6)}"
        guard_dir(scratch, parent=ep.scratch_dir)
        try:
            _run(ctx, ep, _exec(ep, ["mkdir", "-m", "700", "--", scratch]))
            _run(ctx, ep, _manage(ep, "document_exporter", scratch, "--no-progress-bar"))
            try:
                fd = os.open(tar_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, "wb") as f:
                    _run(ctx, ep, _exec(ep, ["tar", "-C", scratch, "-cf", "-", "."]), stdout=f)
            except BaseException:
                tar_path.unlink(missing_ok=True)
                raise
        finally:
            _remove_dir(ctx, ep, scratch, ep.scratch_dir)
    return swept


def _sanity(ctx: _Ctx, ep: Endpoint) -> list[tuple[int, int, str]]:
    """The sanity checker's findings of warning level and above, as ``(document, level, message)``."""
    doc = _json_line(_run(ctx, ep, _manage(ep, "shell", "-c", SANITY_CODE)), "sanity check")
    rows = doc.get("issues")
    if not isinstance(rows, list) or not all(isinstance(r, list) and len(r) == 3 for r in rows):
        raise MigrateError(f"sanity check: not the expected answer: {doc!r}")
    return [(int(p), int(lv), str(m)) for p, lv, m in rows if int(lv) >= SANITY_LEVEL]


def dump(
    source: Endpoint,
    out_dir: str | os.PathLike,
    *,
    scratch_dirs: Sequence[str] = (*SCRATCH_DIRS, tempfile.gettempdir()),
    allow_empty: bool = False,
    _ctx: _Ctx | None = None,
) -> dict:
    """Export ``source`` into a private, empty ``out_dir`` and return the dump manifest.

    Nothing of the source's is written: its data is read (queries, the sanity checker and the
    exporter) and a scratch directory is made inside the container and removed afterwards, also
    when the dump is interrupted by SIGTERM or SIGHUP; one an earlier interrupted dump left is
    swept first.  The sanity checker's findings are recorded: a restore fails only on a problem the
    source did not already have.
    """
    ctx = _ctx or _Ctx()
    out = _private_empty_dir(out_dir, scratch_dirs)
    before = _state(ctx, source)
    sanity = _sanity(ctx, source)
    tar_path = out / TAR_FILE
    swept = _export_tar(ctx, source, out, tar_path)
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
        "format": 2,
        "files": {TAR_FILE: {"size": size, "sha256": digest}},
        "counts": after["counts"],
        "counts_before": before["counts"],
        "fingerprint": after["fingerprint"],
        "documents_digest": scan["digest"],
        "archives": scan["archives"],
        "thumbnails": scan["thumbnails"],
        "version": scan["version"],
        "quiescent": before == after,
        "sanity": [list(r) for r in sanity],
        "egress": scan["egress"],
        "duplicate_checksums": scan["duplicates"],
        "stale_swept": swept,
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
    if manifest.get("format") != 2 or not isinstance(manifest.get("sanity"), list):
        raise MigrateError(
            f"{dump_dir}: an older dump (no sanity findings of the source): dump again"
        )
    c = manifest.get("counts")
    if not isinstance(c, dict) or set(c) != set(COUNT_KEYS):
        raise MigrateError(f"{dump_dir}: {MANIFEST} holds no usable counts")
    return manifest


MODULE_DIR = Path(__file__).resolve().parents[2] / "modules" / "documents"


_VERSION = re.compile(r"[0-9]+(?:\.[0-9]+){0,3}")


def _version_key(text: str) -> tuple[int, ...] | None:
    """``3.4.2`` (up to four dotted parts) -> ``(3, 4, 2, 0)``; None for anything else."""
    text = str(text).strip()
    if not _VERSION.fullmatch(text):
        return None
    nums = [int(n) for n in text.split(".")]
    return (*nums, *([0] * (4 - len(nums))))


def pinned_version(module_dir: Path = MODULE_DIR) -> str:
    """``product.version`` of the module's manifest (the version its image pin carries)."""
    manifest = (module_dir / "module.yml").read_text(encoding="utf-8")
    block = re.search(r"^product:\n((?:[ \t]+.*\n|\n)*)", manifest, re.MULTILINE)
    found = (
        re.search(r"^[ \t]+version:[ \t]*(\S+)", block.group(1), re.MULTILINE) if block else None
    )
    version = found.group(1).strip("\"'") if found else ""
    if _version_key(version) is None:
        raise MigrateError(f"{module_dir / 'module.yml'}: no product.version")
    return version


def check_version(recorded: str, given: str | None, target: str) -> str:
    """The source version a restore may go ahead with; refuse a downgrade (MigrateError).

    A newer application migrates its database and writes records an older one cannot open, so an
    export of a newer version is not restored into an older one.  The version is the one the
    export recorded (its ``metadata.json``) and/or ``given`` (``--source-version``); when both are
    present the newer decides.  No usable version at all is refused too: unknown is not "ok".
    """
    if given is not None and _version_key(given) is None:
        raise MigrateError(f"--source-version {given!r}: not a version")
    known = [v for v in (recorded, given) if v and _version_key(v) is not None]
    if not known:
        raise MigrateError(
            "the dump records no version of its source: pass --source-version (the source's "
            "image tag), refusing to guess"
        )
    source = max(known, key=_version_key)
    if _version_key(source) > _version_key(target):
        raise MigrateError(
            f"the source application is {source}, newer than the target {target}: restoring it "
            "would be a downgrade; pin the module to the source's version or newer"
        )
    return source


def restore(
    target: Endpoint,
    dump_dir: str | os.PathLike,
    *,
    source_version: str | None = None,
    expect_counts: Mapping[str, int] | None = None,
    require_quiescent: bool = False,
    disable_egress: bool = False,
    _ctx: _Ctx | None = None,
) -> dict:
    """Import ``dump_dir`` into an empty ``target`` and verify it; return the report.

    Refused before anything is written: a source application newer than the module's pinned
    version (a downgrade), or one that records no version (``--source-version`` supplies it); a dump whose tar is not what its manifest says, or not
    whole; a dump not taken from a source that stood still (``require_quiescent``); one that is not
    the state ``expect_counts`` names; a target that holds any document or account.  After the
    import the counts and the checksum of every file on disk must equal the dump's.  A failure
    leaves the staging directory (and a half-filled target) for inspection and says so.

    Also proved from the target itself: its library re-exported by the product's exporter has the
    same relationships per document and a thumbnail for every document, and the sanity checker finds
    nothing the source's did not (the source's own findings are reported, not failed).  Mail rules
    and e-mail or webhook workflows that came with the import are reported, and switched off with
    ``disable_egress``.
    """
    ctx = _ctx or _Ctx()
    root = Path(dump_dir)
    manifest = _read_manifest(root)
    target_version = pinned_version()
    source_seen = check_version(str(manifest.get("version") or ""), source_version, target_version)
    if not target.staging_dir:
        raise MigrateError("restore needs a staging directory in the target's export volume")
    scan = scan_export(root / TAR_FILE)
    if scan["version"] != str(manifest.get("version") or ""):
        raise VerifyMismatch(f"{root / TAR_FILE}: its version is not what {MANIFEST} recorded")
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
        # the relationships, read back out of the target by the product's own exporter: the same
        # per-document names (tags, correspondent, type, storage path, field values, notes) as the
        # dump's, and a thumbnail for every document
        again = root / VERIFY_TAR
        _export_tar(ctx, target, root, again)
        back = scan_export(again)
        if back["thumbnails"] != back["documents"]:
            raise VerifyMismatch(
                f"{back['documents'] - back['thumbnails']} documents have no thumbnail on the target"
            )
        if back["archives"] != scan["archives"]:
            raise VerifyMismatch(
                f"{back['archives']} archive copies on the target, {scan['archives']} in the dump"
            )
        apart = _relation_differences(scan["relations"], back["relations"])
        if apart:
            raise VerifyMismatch(
                f"{len(apart)} documents differ in their relationships: " + "; ".join(apart[:20])
            )
        again.unlink()
        # a problem the sanity checker finds on the target and did not find on the source
        known = Counter(map(tuple, manifest["sanity"]))
        found = Counter(_sanity(ctx, target))
        fresh = found - known
        if fresh:
            raise VerifyMismatch(
                "the sanity checker finds problems on the target that the source did not have: "
                + "; ".join(f"document {p} ({m})" for (p, _, m) in list(fresh)[:20])
            )
        egress = _egress(ctx, target, disable=disable_egress)
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
        "relationships_verified": len(scan["relations"]),
        "duplicate_checksums": scan["duplicates"],
        "sanity_known_from_source": sum(known.values()),
        "egress": egress,
        "source_version": source_seen,
        "target_version": target_version,
    }


def _egress(ctx: _Ctx, ep: Endpoint, *, disable: bool) -> dict:
    """What can reach out of the application by itself, as found on the endpoint after an import:
    reported, and turned off (mail rules, workflows that send e-mail or call a webhook) on request."""
    code = EGRESS_CODE.replace("DISABLE = False", f"DISABLE = {disable!r}", 1)
    return _json_line(_run(ctx, ep, _manage(ep, "shell", "-c", code)), "egress")


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
    ap.add_argument("--source-version",
                    help="restore: the source application's version (its image tag); refused when newer than the module's pin")  # fmt: skip
    ap.add_argument("--disable-egress", action="store_true",
                    help="restore: switch off imported mail rules and e-mail/webhook workflows")  # fmt: skip
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
        ep,
        a.dir,
        expect_counts=_expect(a.expect_counts),
        require_quiescent=a.require_quiescent,
        source_version=a.source_version,
        disable_egress=a.disable_egress,
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
