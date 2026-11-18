# SPDX-License-Identifier: Apache-2.0
"""tools/migrate/documents.py: dump, restore, counts, stop and start over ssh pipes, against a fake
host (the application container's database, scratch and staging trees behind the ``docker exec``
command line the tool builds).  What is pinned: the dump reads only (its one write is a scratch
directory in the container, removed again) and is never staged in a temporary directory; every
document's files are hashed against the checksum the export's own manifest records and a
difference, a missing file, a link, a path that leaves the tree, or a source that changed during
the export is refused; a restore refuses a tampered tar and a target that holds anything before it
writes, verifies counts and the checksum of every file on disk after it imports, refuses a pass
that proved nothing, and leaves its staging directory when it fails; the recursive deletes act only
on a generated directory directly under the named one, with no link in it."""

from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import os
import shlex
import shutil
import signal
import sys
import tarfile
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location(
    "migrate_tool", ROOT / "tools" / "migrate" / "documents.py"
)
mt = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = mt
_spec.loader.exec_module(mt)

DEST = "ops@host.example.internal"
SRC_DIR = "/opt/app/src"
SCRATCH = "/tmp/hnx-dump"
STAGING = "/opt/app/export"
OTHERS = ("tags", "correspondents", "document_types", "custom_fields", "custom_field_instances",
          "notes", "storage_paths", "users")  # fmt: skip
LABELS = {v: k for k, v in mt.MODEL_KEYS.items()}


def src_ep(**kw):
    return mt.Endpoint(container="app-src", src_dir=SRC_DIR, ssh=DEST, exec_user="appuser",
                       scratch_dir=SCRATCH, containers=("app-src", "broker-src"), **kw)  # fmt: skip


def dst_ep(**kw):
    return mt.Endpoint(container="app-dst", src_dir=SRC_DIR, ssh=DEST, staging_dir=STAGING,
                       containers=("app-dst",), **kw)  # fmt: skip


@pytest.fixture
def private():
    """A directory outside the system temporary directory, which the tool refuses for a dump."""
    base = ROOT / "build"
    base.mkdir(exist_ok=True)
    d = Path(tempfile.mkdtemp(prefix="migrate-", dir=base))
    assert not any(str(d).startswith(p) for p in mt.SCRATCH_DIRS), "run the checkout outside /tmp"
    yield d
    shutil.rmtree(d, ignore_errors=True)


def digest(data: bytes, algo: str) -> str:
    return hashlib.new(algo, data).hexdigest()


class Host:
    """One host's application container: documents (original, archive copy), counts of the other
    tables, a scratch tree the exporter writes to and a staging tree the importer reads."""

    def __init__(self, documents=3, others=None, algo="sha256"):
        self.docs: dict[int, dict] = {}
        self.others = (
            dict.fromkeys(OTHERS, 0) | {"users": 2, "tags": 4, "notes": 1} | (others or {})
        )
        self.version = 1
        for i in range(1, documents + 1):
            self.add_doc(i, algo)
        self.dirs: set[str] = set()
        self.scratch: dict[str, dict[str, bytes]] = {}
        self.staging: dict[str, dict[str, bytes]] = {}
        self.disk: dict[int, tuple[bytes, bytes | None]] = {}
        self.running = {"app-src", "broker-src", "app-dst"}
        self.log: list[list[str]] = []
        self.argv: list[list[str]] = []
        self.fail: set[str] = set()
        self.on_export = None  # called when the exporter runs (a write during the export)
        self.corrupt_export: str | None = None  # a file of the export whose bytes are changed
        self.drop_on_import = False
        self.corrupt_on_import = False
        self.import_nothing = False
        self.sanity_issues: list[list] = []  # [document, level, message] the checker finds
        self.size_bytes = 1000
        self.free_kb = 10**9
        self.stale: list[str] = []  # directories `find` says an earlier dump left
        self.removed: list[str] = []
        self.egress = {"mail_accounts": 0, "mail_rules": [], "workflows": []}
        self.egress_disabled = False
        self.imported: list[dict] | None = None  # the records an import wrote
        self.drop_tag_on_import = False
        self.lose_thumbnail_on_import = False
        self.change_correspondent_on_import = False
        self.links: dict[str, str] = {}  # path -> what readlink -f says
        self.extra_member: tuple[str, bytes] | None = None
        self.note_on: list[int] = []  # the document each note belongs to (default: document 1)
        # (from, to): a note lands on the twin instead
        self.move_note_on_import: tuple[int, int] | None = None
        self.change_owner_on_import = False

    def add_doc(self, pk, algo="sha256", archive=True, same_as=None):
        """A document; ``same_as`` names an earlier one whose files (and so checksums) it shares."""
        seed = pk if same_as is None else same_as
        orig = f"original {seed}".encode() * 20
        arch = f"archive {seed}".encode() * 20 if archive else None
        self.docs[pk] = {
            "orig": orig, "arch": arch, "algo": algo,
            "checksum": digest(orig, algo), "archive_checksum": digest(arch, algo) if arch else None,
        }  # fmt: skip
        self.version += 1

    # ---- what the application reports
    def counts(self):
        return {"documents": len(self.docs), **self.others}

    def state(self):
        return {"counts": self.counts(), "fingerprint": {"modified": f"2026-11-0{self.version % 9}", "max_id": max(self.docs, default=0)}}  # fmt: skip

    def _imported_tree(self):
        tree = {
            mt.EXPORT_MANIFEST: json.dumps(self.imported).encode(),
            mt.EXPORT_METADATA: b'{"version": "3.4.2"}',
        }
        for r in self.imported:
            if r["model"] != "documents.document":
                continue
            orig, arch = self.disk[r["pk"]]
            tree[r[mt.FILE_KEY]] = orig
            if mt.THUMB_KEY in r:
                tree[r[mt.THUMB_KEY]] = b"thumb"
            if arch is not None:
                tree[r[mt.ARCHIVE_KEY]] = arch
        return tree

    def export_tree(self):
        if self.imported is not None:
            return self._imported_tree()
        records = []
        for pk, d in sorted(self.docs.items()):
            rel = {
                "title": f"doc {pk}", "content": f"text {pk}", "created": "2026-01-01",
                "tags": [1] if self.others["tags"] else [],
                "correspondent": 1 if self.others["correspondents"] else None,
                "document_type": None, "storage_path": None,
                "owner": 1 if self.others["users"] else None,
            }  # fmt: skip
            rec = {"model": "documents.document", "pk": pk, "fields": {"checksum": d["checksum"], "archive_checksum": d["archive_checksum"], **rel},
                   mt.FILE_KEY: f"{pk:07}.pdf", mt.THUMB_KEY: f"{pk:07}-thumbnail.webp"}  # fmt: skip
            if d["arch"]:
                rec[mt.ARCHIVE_KEY] = f"{pk:07}-archive.pdf"
            records.append(rec)
        for key, n in self.others.items():
            records += [
                {"model": LABELS[key], "pk": i, "fields": self._fields(key, i)}
                for i in range(1, n + 1)
            ]
        tree = {
            mt.EXPORT_MANIFEST: json.dumps(records).encode(),
            mt.EXPORT_METADATA: b'{"version": "3.4.2"}',
        }
        for pk, d in self.docs.items():
            tree[f"{pk:07}.pdf"] = d["orig"]
            tree[f"{pk:07}-thumbnail.webp"] = b"thumb"
            if d["arch"]:
                tree[f"{pk:07}-archive.pdf"] = d["arch"]
        if self.corrupt_export:
            tree[self.corrupt_export] = tree[self.corrupt_export] + b"!"
        if self.extra_member:
            tree[self.extra_member[0]] = self.extra_member[1]
        return tree

    def _fields(self, key, i):
        if key == "notes":
            on = self.note_on[i - 1] if i <= len(self.note_on) else 1
            return {"document": on, "note": f"note {i}", "created": "2026-01-01T00:00:00Z"}
        if key == "users":
            return {"username": f"user{i}"}
        if key == "custom_field_instances":
            return {"document": 1, "field": 1, "value_text": f"value {i}"}
        return {"name": f"{key} {i}"}

    # ---- the runner the tool is given
    def __call__(self, argv, *, stdin=None, stdout=None):
        argv = list(argv)
        self.argv.append(argv)
        if argv[0] == "ssh":
            rest = argv[1:]
            if rest[0] == "-n":
                assert stdin is None, "-n with a pipe"
                rest = rest[1:]
            else:
                assert stdin is not None, "a stdin pipe needs no -n; no pipe needs -n"
            assert rest[:3] == ["-o", "BatchMode=yes", DEST] and len(rest) == 4
            argv = shlex.split(rest[3])
        assert argv[:2] == ["sudo", "-n"]
        inner = argv[2:]
        self.log.append(inner)
        if any(f in " ".join(inner[:10]) for f in self.fail):
            return 1, b"", b"boom\nit failed"
        out = self._do(inner, stdin)
        if stdout is not None:
            stdout.write(out)
            return 0, b"", b""
        return 0, out, b""

    def _do(self, inner, stdin):
        if inner[:2] == ["docker", "stop"]:
            self.running -= set(inner[2:])
            return b""
        if inner[:2] == ["docker", "start"]:
            self.running |= set(inner[2:])
            return b""
        if inner[:2] == ["docker", "inspect"]:
            return b"true\n" if inner[-1] in self.running else b"false\n"
        assert inner[:2] == ["docker", "exec"]
        rest = inner[2:]
        if rest[0] == "-i":
            rest = rest[1:]
        if rest[0] == "-u":
            rest = rest[2:]
        cwd = None
        if rest[0] == "-w":
            cwd, rest = rest[1], rest[2:]
        container, c = rest[0], rest[1:]
        return self._cmd(container, cwd, c, stdin)

    def _cmd(self, container, cwd, c, stdin):
        if c[:2] == ["python3", "manage.py"]:
            assert cwd == SRC_DIR
            sub = c[2]
            if sub == "shell":
                code = c[c.index("-c") + 1]
                if "Max(" in code:
                    return b"warning noise\nHNX-JSON " + json.dumps(self.state()).encode() + b"\n"
                if "check_sanity" in code:
                    return (
                        b"HNX-JSON " + json.dumps({"issues": self.sanity_issues}).encode() + b"\n"
                    )
                if "getsize" in code:
                    return b"HNX-JSON " + json.dumps({"bytes": self.size_bytes}).encode() + b"\n"
                if "MailRule" in code:
                    self.egress_disabled = "DISABLE = True" in code
                    report = {**self.egress, "disabled": self.egress_disabled}
                    return b"HNX-JSON " + json.dumps(report).encode() + b"\n"
                return b"HNX-JSON " + json.dumps(self.files_report()).encode() + b"\n"
            if sub == "document_exporter":
                path = c[3]
                assert path in self.dirs and "--no-progress-bar" in c
                tree = self.export_tree()  # what the exporter read ...
                if self.on_export:
                    self.on_export()  # ... and a write that lands after it
                self.scratch[path] = tree
                return b""
            if sub == "document_importer":
                return self.do_import(c[3])
            raise AssertionError(c)
        if c[0] == "df":
            return f"Filesystem 1024-blocks Used Available Capacity Mounted on\nx 100 1 {self.free_kb} 1% /\n".encode()  # fmt: skip
        if c[0] == "find" and "-mindepth" in c:
            return ("".join(p + "\n" for p in self.stale)).encode()
        if c[0] == "mkdir":
            path = c[-1]
            self.dirs.add(path)
            return b""
        if c[0] == "readlink":
            path = c[-1]
            return (self.links.get(path, path) + "\n").encode()
        if c[0] == "rm":
            assert c[1:3] == ["-rf", "--"]
            path = c[3]
            self.removed.append(path)
            self.scratch.pop(path, None)
            self.staging.pop(path, None)
            self.dirs.discard(path)
            return b""
        if c[0] == "tar" and "-cf" in c:
            buf = io.BytesIO()
            with tarfile.open(fileobj=buf, mode="w") as t:
                for name, data in sorted(self.scratch[c[c.index("-C") + 1]].items()):
                    ti = tarfile.TarInfo("./" + name)
                    ti.size = len(data)
                    t.addfile(ti, io.BytesIO(data))
            return buf.getvalue()
        if c[0] == "tar" and "-x" in c:
            where = c[c.index("-C") + 1]
            assert "--no-same-owner" in c and "--no-same-permissions" in c
            with tarfile.open(fileobj=io.BytesIO(stdin.read()), mode="r") as t:
                self.staging[where] = {
                    m.name.removeprefix("./"): t.extractfile(m).read() for m in t if m.isfile()
                }
            return b""
        if c[0] == "find":
            return ("".join(f"{c[1]}/{n}\n" for n in self.staging.get(c[1], {}))).encode()
        raise AssertionError(c)

    def do_import(self, staged):
        files = self.staging[staged]
        records = json.loads(files[mt.EXPORT_MANIFEST])
        if self.import_nothing:
            return b""
        docs = [r for r in records if r["model"] == "documents.document"]
        if self.drop_on_import:
            docs = docs[:-1]
        if docs and self.drop_tag_on_import:
            docs[0]["fields"]["tags"] = []
        if docs and self.change_correspondent_on_import:
            docs[0]["fields"]["correspondent"] = 2
        if docs and self.lose_thumbnail_on_import:
            del docs[0][mt.THUMB_KEY]
        if docs and self.change_owner_on_import:
            docs[0]["fields"]["owner"] = 2
        if self.move_note_on_import:
            src, dst = self.move_note_on_import
            for r in records:
                if r["model"] == "documents.note" and r["fields"]["document"] == src:
                    r["fields"]["document"] = dst
        self.imported = [r for r in records if r["model"] != "documents.document" or r in docs]
        self.docs = {}
        for r in docs:
            f = r["fields"]
            algo = "md5" if len(f["checksum"]) == 32 else "sha256"
            self.docs[r["pk"]] = {"orig": b"", "arch": None, "algo": algo, "checksum": f["checksum"], "archive_checksum": f["archive_checksum"]}  # fmt: skip
            orig = files[r[mt.FILE_KEY]]
            arch = files.get(r.get(mt.ARCHIVE_KEY, ""))
            if self.corrupt_on_import and r["pk"] == docs[0]["pk"]:
                orig = orig + b"x"
            self.disk[r["pk"]] = (orig, arch)
        for key in OTHERS:
            self.others[key] = sum(1 for r in records if r["model"] == LABELS[key])
        return b"imported\n"

    def files_report(self):
        lines, bad = [], []
        for pk, d in sorted(self.docs.items()):
            orig, arch = self.disk.get(pk, (None, None))
            o = digest(orig, d["algo"]) if orig is not None else ""
            a = digest(arch, d["algo"]) if arch is not None else ""
            if (
                not o
                or o != d["checksum"]
                or (d["archive_checksum"] and a != d["archive_checksum"])
            ):
                bad.append(pk)
            lines.append(f"{pk}:{o}:{a}")
        return {"documents": len(lines), "bad": bad, "digest": hashlib.sha256("\n".join(lines).encode()).hexdigest()}  # fmt: skip


class _Failure(Exception):
    pass


def _runner(host):
    """The host as a runner, failing the way a command does: a return code and a message."""

    def run(argv, *, stdin=None, stdout=None):
        try:
            return host(argv, stdin=stdin, stdout=stdout)
        except _Failure:
            return 1, b"", b"sanity: 2 errors"

    return run


def ctx_for(host):
    return mt._Ctx(runner=_runner(host))


def made_dump(private, host=None):
    host = host or Host()
    out = private / "dump"
    manifest = mt.dump(src_ep(), out, _ctx=ctx_for(host))
    return host, out, manifest


# ----------------------------------------------------------------------------- counts


def test_counts_reads_every_table_and_ignores_noise_before_the_answer():
    host = Host(documents=5)
    c = mt.counts(src_ep(), _ctx=ctx_for(host))
    assert c == host.counts() and set(c) == set(mt.COUNT_KEYS) and c["documents"] == 5


def test_counts_refuses_an_answer_that_is_not_the_schema():
    class Wrong(Host):
        def state(self):
            return {"counts": {"documents": 1}, "fingerprint": {}}

    with pytest.raises(mt.MigrateError, match="not the expected tables"):
        mt.counts(src_ep(), _ctx=ctx_for(Wrong()))


def test_counts_refuses_a_container_that_printed_no_answer():
    class Mute(Host):
        def _cmd(self, container, cwd, c, stdin):
            return b"Traceback ...\n"

    with pytest.raises(mt.MigrateError, match="printed no answer"):
        mt.counts(src_ep(), _ctx=ctx_for(Mute()))


# ----------------------------------------------------------------------------- dump


def test_dump_writes_a_private_tar_and_a_manifest_and_reads_only(private):
    host, out, m = made_dump(private)
    assert oct(out.stat().st_mode & 0o777) == "0o700"
    assert oct((out / "export.tar").stat().st_mode & 0o777) == "0o600"
    assert m["counts"] == host.counts() and m["counts_before"] == host.counts()
    assert m["quiescent"] is True and m["archives"] == 3 and m["thumbnails"] == 3
    assert json.loads((out / "dump-manifest.json").read_text()) == m
    assert (
        m["files"]["export.tar"]["sha256"]
        == hashlib.sha256((out / "export.tar").read_bytes()).hexdigest()
    )
    # the scratch directory the tool made was removed; nothing else was deleted or written
    assert host.scratch == {} and not any(d.startswith(SCRATCH + "/") for d in host.dirs)
    verbs = {i[i.index("app-src") + 1] for i in host.log if "app-src" in i}
    assert verbs <= {"python3", "mkdir", "tar", "readlink", "rm", "find", "df"}
    rms = [i for i in host.log if "rm" in i]
    assert len(rms) == 1 and rms[0][-1].startswith(SCRATCH + "/")
    # the commands ran as the configured account, in the application's directory
    assert all(i[i.index("-u") + 1] == "appuser" for i in host.log if i[:2] == ["docker", "exec"])


def test_dump_accepts_md5_checksums_too(private):
    _, _, m = made_dump(private, Host(algo="md5"))
    assert m["counts"]["documents"] == 3


def test_dump_is_not_quiescent_when_the_source_changed_but_no_count_moved(private):
    host = Host()
    host.on_export = lambda: setattr(host, "version", host.version + 1)
    _, _, m = made_dump(private, host)
    assert m["quiescent"] is False


@pytest.mark.parametrize("scratch", ["/tmp", "/var/tmp/x", "/dev/shm"])
def test_dump_refuses_a_directory_in_scratch_space(scratch):
    with pytest.raises(mt.MigrateError, match="private directory"):
        mt.dump(src_ep(), Path(scratch) / "d", _ctx=ctx_for(Host()))


def test_dump_refuses_a_directory_that_is_not_empty(private):
    (private / "d").mkdir()
    (private / "d" / "x").write_text("x")
    with pytest.raises(mt.MigrateError, match="not empty"):
        mt.dump(src_ep(), private / "d", _ctx=ctx_for(Host()))


def test_dump_refuses_a_file_that_differs_from_its_recorded_checksum(private):
    host = Host()
    host.corrupt_export = "0000002.pdf"
    with pytest.raises(mt.VerifyMismatch, match=r"document 2.*0000002\.pdf"):
        mt.dump(src_ep(), private / "d", _ctx=ctx_for(host))
    assert host.scratch == {}  # the scratch directory is removed on a failure too


def test_dump_refuses_an_export_that_lacks_a_file(private):
    class Lacking(Host):
        def export_tree(self):
            t = super().export_tree()
            del t["0000003-archive.pdf"]
            return t

    with pytest.raises(mt.MigrateError, match=r"document 3.*archive.*not in the export"):
        mt.dump(src_ep(), private / "d", _ctx=ctx_for(Lacking()))


def test_dump_refuses_a_source_that_changed_during_the_export(private):
    host = Host()
    host.on_export = lambda: host.others.__setitem__("tags", 9)  # the live database moves on
    with pytest.raises(mt.CountMismatch, match="tags"):
        mt.dump(src_ep(), private / "d", _ctx=ctx_for(host))


def test_dump_refuses_a_vacuous_source_unless_told_it_is_empty(private):
    host = Host(documents=0)
    with pytest.raises(mt.MigrateError, match="vacuous"):
        mt.dump(src_ep(), private / "d", _ctx=ctx_for(host))
    shutil.rmtree(private / "d")
    assert mt.dump(src_ep(), private / "d", allow_empty=True, _ctx=ctx_for(Host(documents=0)))["counts"]["documents"] == 0  # fmt: skip


def test_dump_removes_nothing_when_the_scratch_resolves_elsewhere(private):
    host = Host()

    class Linked(Host):
        pass

    host.links = {}
    orig = host._cmd

    def cmd(container, cwd, c, stdin):
        if c[0] == "readlink":
            return b"/etc/\n"
        return orig(container, cwd, c, stdin)

    host._cmd = cmd
    with pytest.raises(mt.MigrateError, match="through a link"):
        mt.dump(src_ep(), private / "d", _ctx=ctx_for(host))
    assert not any(i[-4:-1] == ["rm", "-rf", "--"] for i in host.log if "rm" in i)


@pytest.mark.parametrize(
    "path, parent",
    [
        ("/", SCRATCH),
        ("/tmp", "/"),
        ("/tmp/hnx-dump", "/tmp"),  # a component short of three
        ("/tmp/hnx-dump/../etc/aaaaaaaaaaaa", SCRATCH),
        ("relative/path/aaaaaaaaaaaa", "relative/path"),
        ("/tmp/hnx-dump/not-generated", SCRATCH),
        ("/tmp/hnx-dump/aaaaaaaaaaaa/", SCRATCH),
        ("/tmp/other/aaaaaaaaaaaa", SCRATCH),  # not directly under the named directory
        ("/tmp/hnx-dump/x/aaaaaaaaaaaa", SCRATCH),
    ],
)
def test_the_recursive_delete_refuses_anything_it_did_not_generate(path, parent):
    with pytest.raises(mt.MigrateError):
        mt.guard_dir(path, parent=parent)
    host = Host()
    with pytest.raises(mt.MigrateError):
        mt._remove_dir(ctx_for(host), src_ep(), path, parent)
    assert host.log == []


def test_an_endpoint_refuses_a_directory_that_is_not_canonical():
    for bad in ("/", "rel", "/a/../b", "/a/./b", "/a//b"):
        with pytest.raises(mt.MigrateError):
            mt.Endpoint(container="c", src_dir=SRC_DIR, scratch_dir=bad)


@pytest.mark.parametrize("name", ["../escape", "/abs/path", "a/../../b"])
def test_scan_refuses_a_member_that_leaves_the_tree(tmp_path, name):
    p = tmp_path / "x.tar"
    with tarfile.open(p, "w") as t:
        ti = tarfile.TarInfo(name)
        ti.size = 1
        t.addfile(ti, io.BytesIO(b"x"))
    with pytest.raises(mt.MigrateError, match="leaves its directory"):
        mt.scan_export(p)


@pytest.mark.parametrize(
    "kind", [tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.FIFOTYPE, tarfile.CHRTYPE]
)
def test_scan_refuses_a_link_or_special_member(tmp_path, kind):
    p = tmp_path / "x.tar"
    with tarfile.open(p, "w") as t:
        ti = tarfile.TarInfo("evil")
        ti.type, ti.linkname = kind, "/etc/passwd"
        t.addfile(ti)
    with pytest.raises(mt.MigrateError, match="link or special"):
        mt.scan_export(p)


def test_scan_refuses_a_tar_without_a_manifest(tmp_path):
    p = tmp_path / "x.tar"
    with tarfile.open(p, "w") as t:
        ti = tarfile.TarInfo("a.pdf")
        ti.size = 1
        t.addfile(ti, io.BytesIO(b"x"))
    with pytest.raises(mt.MigrateError, match=r"no manifest\.json"):
        mt.scan_export(p)


# ----------------------------------------------------------------------------- restore


def test_restore_imports_into_an_empty_target_and_proves_every_file(private):
    _, out, manifest = made_dump(private)
    target = Host(documents=0, others=dict.fromkeys(OTHERS, 0))
    report = mt.restore(dst_ep(), out, expect_counts=manifest["counts"], require_quiescent=True, _ctx=ctx_for(target))  # fmt: skip
    assert report["counts"] == manifest["counts"] and report["documents_verified"] == 3
    assert (
        report["digest"] == manifest["documents_digest"] and report["sanity_known_from_source"] == 0
    )
    assert len(target.disk) == 3
    # the staging directory was removed; the import ran after the files were staged
    assert target.staging == {}
    verbs = [i[i.index("app-dst") + 1] if "app-dst" in i else i[1] for i in target.log]
    assert verbs.index("mkdir") < verbs.index("tar") < verbs.index("find")


def _fresh_target():
    return Host(documents=0, others=dict.fromkeys(OTHERS, 0))


def test_restore_proves_every_documents_relationships_and_a_thumbnail_for_each(private):
    source = Host(others={"correspondents": 2, "custom_fields": 1, "custom_field_instances": 2})
    _, out, _ = made_dump(private, source)
    assert len(mt.scan_export(out / "export.tar")["relations"]) == 3
    report = mt.restore(dst_ep(), out, _ctx=ctx_for(_fresh_target()))
    assert report["relationships_verified"] == 3
    assert not (
        out / "verify-target.tar"
    ).exists()  # the re-export of the target is removed after it passed


@pytest.mark.parametrize("flag, words", [
    ("drop_tag_on_import", "tags differ"),
    ("change_correspondent_on_import", "correspondent differ"),
])  # fmt: skip
def test_restore_fails_when_a_document_lost_a_tag_or_changed_correspondent(private, flag, words):
    _, out, _ = made_dump(private, Host(others={"correspondents": 2}))
    target = _fresh_target()
    setattr(target, flag, True)
    with pytest.raises(mt.VerifyMismatch, match=words):
        mt.restore(dst_ep(), out, _ctx=ctx_for(target))
    assert (out / "verify-target.tar").exists()  # kept for inspection


def test_restore_fails_when_a_document_has_no_thumbnail_on_the_target(private):
    _, out, _ = made_dump(private)
    target = _fresh_target()
    target.lose_thumbnail_on_import = True
    with pytest.raises(mt.VerifyMismatch, match="no thumbnail"):
        mt.restore(dst_ep(), out, _ctx=ctx_for(target))


def test_relations_are_by_name_so_a_moved_id_is_not_a_difference_but_a_changed_name_is():
    def rec(model, pk, **f):
        return {"model": model, "pk": pk, "fields": f}

    def lib(tag_pk, tag_name):
        return [
            rec("documents.tag", tag_pk, name=tag_name),
            rec("documents.document", 1, checksum="c" * 64, tags=[tag_pk], title="t", content="x"),
        ]

    assert mt._relations(lib(1, "tax")) == mt._relations(lib(7, "tax"))
    a, b = mt._relations(lib(1, "tax")), mt._relations(lib(1, "legal"))
    assert mt._relation_differences(a, b) == ["document 1: tags differ"]
    assert mt._relation_differences(a, {}) == ["document 1 is missing on the target"]
    with pytest.raises(mt.MigrateError, match="does not hold"):
        mt._relations([rec("documents.document", 1, checksum="c" * 64, tags=[9])])


def test_a_problem_the_source_already_had_is_reported_not_failed_a_new_one_fails(private):
    known = [2, 40, "original is missing"]
    source = Host()
    source.sanity_issues = [known, [0, 20, "info is not a problem"]]
    _, out, manifest = made_dump(private, source)
    assert manifest["sanity"] == [known]  # info level is not kept
    target = _fresh_target()
    target.sanity_issues = [known]
    assert mt.restore(dst_ep(), out, _ctx=ctx_for(target))["sanity_known_from_source"] == 1
    shutil.rmtree(private / "dump")
    shutil.rmtree(out, ignore_errors=True)
    out2 = private / "dump2"
    mt.dump(src_ep(), out2, _ctx=ctx_for(source))
    worse = _fresh_target()
    worse.sanity_issues = [known, [3, 40, "archive differs"]]
    with pytest.raises(mt.VerifyMismatch, match=r"document 3 \(archive differs"):
        mt.restore(dst_ep(), out2, _ctx=ctx_for(worse))


def test_imported_mail_rules_and_workflows_are_reported_and_switched_off_on_request(private):
    _, out, _ = made_dump(private)
    target = _fresh_target()
    target.egress = {"mail_accounts": 1, "mail_rules": ["inbox"], "workflows": ["notify"]}
    report = mt.restore(dst_ep(), out, _ctx=ctx_for(target))
    assert report["egress"]["mail_rules"] == ["inbox"] and report["egress"]["disabled"] is False
    assert target.egress_disabled is False
    shutil.rmtree(out)
    _, out, _ = made_dump(private)
    again = _fresh_target()
    assert mt.restore(dst_ep(), out, disable_egress=True, _ctx=ctx_for(again))["egress"]["disabled"] is True  # fmt: skip
    assert again.egress_disabled is True


def test_the_dump_counts_what_could_reach_out_from_the_export(private):
    class Mail(Host):
        def export_tree(self):
            t = super().export_tree()
            records = json.loads(t[mt.EXPORT_MANIFEST])
            records += [{"model": "paperless_mail.mailrule", "pk": 1, "fields": {}},
                        {"model": "documents.workflowactionwebhook", "pk": 1, "fields": {}}]  # fmt: skip
            t[mt.EXPORT_MANIFEST] = json.dumps(records).encode()
            return t

    _, _, manifest = made_dump(private, Mail())
    assert manifest["egress"] == {"mail_accounts": 0, "mail_rules": 1, "email_actions": 0, "webhook_actions": 1}  # fmt: skip


def test_an_older_dump_without_the_sources_sanity_findings_is_refused(private):
    _, out, manifest = made_dump(private)
    del manifest["sanity"]
    (out / "dump-manifest.json").write_text(json.dumps(manifest))
    with pytest.raises(mt.MigrateError, match="dump again"):
        mt.restore(dst_ep(), out, _ctx=ctx_for(_fresh_target()))


# ----------------------------------------------------------------------------- duplicates
# The product lets two documents carry the same original (one consumed twice and kept), each with
# its own notes, tags, owner and field values; its importer writes each under its id.  The migration
# carries every one of them and proves each by its id, never merging or dropping one.


def _twins_host():
    """Eight documents in four pairs that share a file; one of the last pair has a note its twin
    lacks (the pair that differs only by a note)."""
    host = Host(documents=0, others={"notes": 2})
    for pk in (1, 2, 3, 4):
        host.add_doc(pk)
    for pk, twin in ((5, 1), (6, 2), (7, 3), (8, 4)):
        host.add_doc(pk, same_as=twin)
    host.note_on = [1, 4]  # note 1 on document 1, note 2 only on document 4 (not on its twin 8)
    return host


def test_a_dump_carries_every_document_that_shares_a_checksum_and_lists_them(private):
    host = _twins_host()
    assert host.docs[4]["checksum"] == host.docs[8]["checksum"]
    _, out, manifest = made_dump(private, host)
    assert manifest["counts"]["documents"] == 8 and manifest["archives"] == 8
    assert manifest["duplicate_checksums"] == [[1, 5], [2, 6], [3, 7], [4, 8]]
    rel = mt.scan_export(out / "export.tar")["relations"]
    assert sorted(rel) == list(range(1, 9))  # every document, by its id
    assert rel[4]["checksum"] == rel[8]["checksum"] and rel[4]["notes"] != rel[8]["notes"]


def test_a_library_without_duplicates_lists_none(private):
    _, _, manifest = made_dump(private)
    assert manifest["duplicate_checksums"] == []


def test_restore_carries_and_proves_each_duplicate_on_its_own(private):
    _, out, manifest = made_dump(private, _twins_host())
    target = _fresh_target()
    report = mt.restore(dst_ep(), out, expect_counts=manifest["counts"], _ctx=ctx_for(target))
    assert report["documents_verified"] == 8 and report["relationships_verified"] == 8
    assert report["duplicate_checksums"] == [[1, 5], [2, 6], [3, 7], [4, 8]]
    assert sorted(target.disk) == list(range(1, 9))
    assert target.disk[4] == target.disk[8]  # the same bytes, twice: nothing was merged


def test_restore_fails_when_a_note_lands_on_the_twin_instead(private):
    _, out, _ = made_dump(private, _twins_host())
    target = _fresh_target()
    target.move_note_on_import = (4, 8)  # counts and files equal; only the note moved
    with pytest.raises(
        mt.VerifyMismatch, match=r"document 4: notes differ; document 8: notes differ"
    ):
        mt.restore(dst_ep(), out, _ctx=ctx_for(target))


def test_restore_fails_when_a_documents_owner_changed(private):
    _, out, _ = made_dump(private)
    target = _fresh_target()
    target.change_owner_on_import = True
    with pytest.raises(mt.VerifyMismatch, match="document 1: owner differ"):
        mt.restore(dst_ep(), out, _ctx=ctx_for(target))


def test_a_twin_whose_file_does_not_hash_to_its_checksum_is_still_refused(private):
    host = _twins_host()
    host.corrupt_export = "0000008.pdf"  # its twin 4 is intact: corruption is caught per document
    with pytest.raises(mt.VerifyMismatch, match=r"document 8.*0000008\.pdf"):
        mt.dump(src_ep(), private / "d", _ctx=ctx_for(host))


def test_an_export_that_holds_one_document_id_twice_is_refused():
    rec = {"model": "documents.document", "pk": 3, "fields": {"checksum": "c" * 64}}
    with pytest.raises(mt.MigrateError, match="document 3 twice"):
        mt._relations([rec, rec])


# ----------------------------------------------------------------------------- robustness


def test_a_dump_sweeps_only_stale_scratch_directories_it_could_have_made(private):
    host = Host()
    mine = f"{SCRATCH}/aaaaaaaaaaaa"
    host.stale = [mine, f"{SCRATCH}/not-ours", f"{SCRATCH}/AAAAAAAAAAAA", "/etc/aaaaaaaaaaaa", f"{SCRATCH}/x/bbbbbbbbbbbb"]  # fmt: skip
    host.dirs.add(mine)
    _, _, manifest = made_dump(private, host)
    assert manifest["stale_swept"] == [mine]
    removed = [r for r in host.removed if r != host.removed[-1]]
    assert removed == [mine]  # the others were never touched


def test_a_dump_refuses_when_the_container_or_this_host_lacks_the_room(private):
    host = Host()
    host.size_bytes, host.free_kb = 10 << 30, 1024  # 10 GiB to copy, 1 MiB free
    with pytest.raises(mt.MigrateError, match="in the container has"):
        mt.dump(src_ep(), private / "d", _ctx=ctx_for(host))
    assert host.scratch == {} and not [c for c in host.log if "document_exporter" in c]
    shutil.rmtree(private / "d")
    big = Host()
    big.size_bytes = 1 << 60
    big.free_kb = 1 << 60
    with pytest.raises(mt.MigrateError, match=r"has \d+ bytes free; the export needs"):
        mt.dump(src_ep(), private / "d", _ctx=ctx_for(big))


@pytest.mark.parametrize("sig", [signal.SIGTERM, signal.SIGHUP])
def test_a_dump_cleans_up_its_scratch_directory_when_it_is_terminated(private, sig):
    host = Host()
    host.on_export = lambda: os.kill(os.getpid(), sig)
    before = signal.getsignal(sig)
    with pytest.raises(BaseException, match=sig.name) as e:
        mt.dump(src_ep(), private / "d", _ctx=ctx_for(host))
    assert not isinstance(e.value, Exception)  # it unwinds as a BaseException, never swallowed
    assert host.scratch == {} and len(host.removed) == 1  # the one generated directory
    assert not (private / "d" / "export.tar").exists()
    assert signal.getsignal(sig) == before  # the handler is put back


@pytest.mark.parametrize("held", ["documents", "users", "tags", "notes"])
def test_restore_refuses_a_target_that_holds_anything_before_writing(private, held):
    _, out, _ = made_dump(private)
    target = Host(documents=0, others=dict.fromkeys(OTHERS, 0))
    if held == "documents":
        target.add_doc(1)
    else:
        target.others[held] = 1
    with pytest.raises(mt.MigrateError, match="not empty"):
        mt.restore(dst_ep(), out, _ctx=ctx_for(target))
    assert not any(c[1] == "exec" and ("mkdir" in c or "tar" in c) for c in target.log)
    assert target.staging == {} and target.disk == {}


def test_restore_refuses_a_tampered_tar_before_touching_the_target(private):
    _, out, _ = made_dump(private)
    with (out / "export.tar").open("ab") as f:
        f.write(b"\0" * 1024)
    target = Host(documents=0, others=dict.fromkeys(OTHERS, 0))
    with pytest.raises(mt.VerifyMismatch, match="size or sha256"):
        mt.restore(dst_ep(), out, _ctx=ctx_for(target))
    assert target.log == []


def test_restore_refuses_a_manifest_that_does_not_describe_its_tar(private):
    _, out, manifest = made_dump(private)
    manifest["counts"]["tags"] += 1
    (out / "dump-manifest.json").write_text(json.dumps(manifest))
    target = Host(documents=0, others=dict.fromkeys(OTHERS, 0))
    with pytest.raises(mt.VerifyMismatch, match=r"not what dump-manifest\.json recorded"):
        mt.restore(dst_ep(), out, _ctx=ctx_for(target))
    assert target.log == []


def test_restore_refuses_a_dump_taken_while_the_source_changed(private):
    host = Host()
    host.on_export = lambda: setattr(host, "version", host.version + 1)
    _, out, _ = made_dump(private, host)
    target = Host(documents=0, others=dict.fromkeys(OTHERS, 0))
    with pytest.raises(mt.MigrateError, match="stood still"):
        mt.restore(dst_ep(), out, require_quiescent=True, _ctx=ctx_for(target))
    assert target.log == []


def test_restore_refuses_counts_other_than_the_ones_the_freeze_reported(private):
    _, out, manifest = made_dump(private)
    expect = dict(manifest["counts"], documents=manifest["counts"]["documents"] + 1)
    target = Host(documents=0, others=dict.fromkeys(OTHERS, 0))
    with pytest.raises(mt.CountMismatch, match="documents"):
        mt.restore(dst_ep(), out, expect_counts=expect, _ctx=ctx_for(target))
    assert target.log == []


def test_restore_needs_a_staging_directory(private):
    _, out, _ = made_dump(private)
    with pytest.raises(mt.MigrateError, match="staging directory"):
        mt.restore(mt.Endpoint(container="c", src_dir=SRC_DIR, ssh=DEST), out, _ctx=ctx_for(Host(documents=0)))  # fmt: skip


def test_restore_refuses_a_vacuous_dump(private):
    out = private / "dump"
    mt.dump(src_ep(), out, allow_empty=True, _ctx=ctx_for(Host(documents=0)))
    with pytest.raises(mt.MigrateError, match="vacuous"):
        mt.restore(dst_ep(), out, _ctx=ctx_for(Host(documents=0, others=dict.fromkeys(OTHERS, 0))))


def test_restore_fails_when_the_import_dropped_a_document_and_keeps_the_staging(private):
    _, out, _ = made_dump(private)
    target = Host(documents=0, others=dict.fromkeys(OTHERS, 0))
    target.drop_on_import = True
    with pytest.raises(mt.CountMismatch, match="documents") as e:
        mt.restore(dst_ep(), out, _ctx=ctx_for(target))
    assert any("staging directory" in n for n in e.value.__notes__)
    assert len(target.staging) == 1  # left for inspection


def test_restore_fails_when_a_file_on_disk_is_not_the_exported_one(private):
    _, out, _ = made_dump(private)
    target = Host(documents=0, others=dict.fromkeys(OTHERS, 0))
    target.corrupt_on_import = True
    with pytest.raises(mt.VerifyMismatch, match="missing or differ"):
        mt.restore(dst_ep(), out, _ctx=ctx_for(target))


def test_restore_does_not_pass_vacuously_when_the_importer_imported_nothing(private):
    _, out, _ = made_dump(private)
    target = Host(documents=0, others=dict.fromkeys(OTHERS, 0))
    target.import_nothing = True
    with pytest.raises(mt.CountMismatch):
        mt.restore(dst_ep(), out, _ctx=ctx_for(target))


def test_restore_fails_when_the_staged_files_are_not_all_there(private):
    _, out, _ = made_dump(private)
    target = Host(documents=0, others=dict.fromkeys(OTHERS, 0))
    orig = target._cmd

    def cmd(container, cwd, c, stdin):
        if c[0] == "find":
            return b""
        return orig(container, cwd, c, stdin)

    target._cmd = cmd
    with pytest.raises(mt.VerifyMismatch, match="staged 0 files"):
        mt.restore(dst_ep(), out, _ctx=ctx_for(target))


def test_a_failing_command_is_reported_with_its_tail(private):
    _, out, _ = made_dump(private)
    target = Host(documents=0, others=dict.fromkeys(OTHERS, 0))
    target.fail = {"document_importer"}
    with pytest.raises(mt.MigrateError, match=r"document_importer.*failed \(1\).*it failed"):
        mt.restore(dst_ep(), out, _ctx=ctx_for(target))


# ----------------------------------------------------------------------------- stop, start, CLI


def test_stop_checks_that_nothing_runs_and_start_undoes_it():
    host = Host()
    assert mt.stop(src_ep(), _ctx=ctx_for(host)) == {"stopped": ["app-src", "broker-src"]}
    assert host.running == {"app-dst"}
    mt.start(src_ep(), _ctx=ctx_for(host))
    assert {"app-src", "broker-src"} <= host.running


def test_stop_fails_when_a_container_keeps_running():
    host = Host()
    host._do_orig = host._do

    def do(inner, stdin):
        if inner[:2] == ["docker", "stop"]:
            return b""
        return host._do_orig(inner, stdin)

    host._do = do
    with pytest.raises(mt.MigrateError, match="still running"):
        mt.stop(src_ep(), _ctx=ctx_for(host))


def test_stop_needs_named_containers():
    with pytest.raises(mt.MigrateError, match="name the containers"):
        mt.stop(mt.Endpoint(container="c", src_dir=SRC_DIR), _ctx=ctx_for(Host()))


def test_the_command_line_maps_failures_to_exit_codes(capsys, monkeypatch):
    assert mt.main(["counts"]) == 2  # no container named
    assert "needs --app-container" in capsys.readouterr().err
    assert mt.main(["dump", "--app-container", "c", "--src-dir", SRC_DIR]) == 2  # no --dir
    host = Host()
    monkeypatch.setattr(mt, "_subprocess_runner", _runner(host))
    argv = ["counts", "--ssh", DEST, "--app-container", "app-src", "--src-dir", SRC_DIR]
    assert mt.main(argv) == 0
    assert json.loads(capsys.readouterr().out) == host.counts()
    host.corrupt_export = "0000001.pdf"
    code = mt.main(["dump", *argv[1:], "--dir", str(ROOT / "build" / "cli-dump")])
    assert code == 1 and "document 1" in capsys.readouterr().err
    shutil.rmtree(ROOT / "build" / "cli-dump", ignore_errors=True)
