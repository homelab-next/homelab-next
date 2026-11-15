# SPDX-License-Identifier: Apache-2.0
"""tools/migrate/openproject.py: dump, restore, counts, freeze and unfreeze over ssh pipes, against
a fake host (a sqlite database and an in-memory attachments tree behind the ``docker`` command
line the tool builds).  What is pinned: the counts (accounts of the real kind only) and a content
fingerprint; the dump is read-only on the source and never staged in a temporary directory; a
freeze stops every writer and a dump records whether the source was frozen; a restore refuses a
dump that is not what its manifest says before it touches the target, verifies counts, content and
every attachment file after it writes, and leaves the target stopped on any failure; the final
delta after a freeze leaves the target equal to the frozen source; and the recursive deletes act
only on a guarded attachments directory."""

from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import shlex
import shutil
import sqlite3
import sys
import tarfile
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location(
    "migrate_tool", ROOT / "tools" / "migrate" / "openproject.py"
)
mt = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = mt
_spec.loader.exec_module(mt)

DEST = "ops@host.example.internal"
DATA_ROOT = "/srv/data"
ASSETS = "/srv/data/assets"
TABLES = ("projects", "work_packages", "users", "attachments", "journals", "time_entries",
          "members", "versions", "custom_fields")  # fmt: skip


@pytest.fixture
def private(request):
    """A directory outside the system temporary directory, which the tool refuses for a dump."""
    base = ROOT / "build"
    base.mkdir(exist_ok=True)
    d = Path(tempfile.mkdtemp(prefix="migrate-", dir=base))
    assert not any(str(d).startswith(p) for p in mt.SCRATCH_DIRS), "run the checkout outside /tmp"
    yield d
    shutil.rmtree(d, ignore_errors=True)


class Host:
    """One host's containers: a database, an attachments tree, the set of running processes."""

    def __init__(self, projects=0, work_packages=0, users=0, attachments=()):
        self.db = sqlite3.connect(":memory:")
        for t in TABLES:
            cols = "id INTEGER PRIMARY KEY, body TEXT" + (", type TEXT" if t == "users" else "")
            self.db.execute(f"CREATE TABLE {t} ({cols})")
        # the product also keeps an anonymous user and system users in the same table
        self.db.executemany("INSERT INTO users(body, type) VALUES (?, ?)",
                            [("anon", "AnonymousUser"), ("sys", "SystemUser"), ("gone", "DeletedUser")])  # fmt: skip
        self.add(projects, work_packages, users)
        self.files: dict[str, bytes] = {}
        for name in attachments:
            self.attach(name)
        self.running = {"web", "worker"}
        self.log: list[list[str]] = []  # the inner commands, ssh and sudo removed
        self.argv: list[list[str]] = []
        self.fail: set[str] = set()
        self.on_dump = None  # called when pg_dump runs (a write during the dump)
        self.drop_on_restore = False
        self.corrupt_files_on_restore = False
        self.links: dict[str, str] = {}  # path -> what readlink -f says

    def add(self, projects=0, work_packages=0, users=0):
        for i in range(projects):
            self.db.execute("INSERT INTO projects(body) VALUES (?)", (f"p{i}",))
        for i in range(work_packages):
            self.db.execute("INSERT INTO work_packages(body) VALUES (?)", (f"w{i}",))
        for i in range(users):
            self.db.execute("INSERT INTO users(body, type) VALUES (?, 'User')", (f"u{i}",))

    def edit(self):
        """A change that moves no count."""
        self.db.execute("UPDATE work_packages SET body = body || '!' WHERE id = 1")

    def attach(self, name):
        self.files[f"./files/{name}"] = name.encode() * 10
        self.db.execute("INSERT INTO attachments(body) VALUES (?)", (name,))

    def unattach(self, name):
        self.files.pop(f"./files/{name}")
        self.db.execute("DELETE FROM attachments WHERE body = ?", (name,))

    def rows(self):
        return {t: sorted(self.db.execute(f"SELECT * FROM {t}").fetchall()) for t in TABLES}

    def fingerprint(self):
        return hashlib.md5(json.dumps(self.rows(), sort_keys=True).encode()).hexdigest()

    # the runner the tool is given
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
        if any(f in " ".join(inner[:6]) for f in self.fail):
            return 1, b"", b"boom\nit failed"
        out = self._do(inner, stdin)
        if stdout is not None:
            stdout.write(out)
            return 0, b"", b""
        return 0, out, b""

    def _do(self, inner, stdin):
        if inner[:2] == ["docker", "exec"]:
            rest = inner[2:]
            if rest[0] == "-i":
                rest = rest[1:]
            return self._cmd(rest[1:], stdin)
        if inner[:2] == ["docker", "stop"]:
            self.running -= set(self._names(inner[2:]))
            return b""
        if inner[:2] == ["docker", "start"]:
            self.running |= set(self._names(inner[2:]))
            return b""
        if inner[:2] == ["docker", "inspect"]:
            name = self._names([inner[-1]])[0]
            return b"true\n" if name in self.running else b"false\n"
        if inner[:2] == ["docker", "compose"]:
            if "stop" in inner:
                self.running -= set(inner[inner.index("stop") + 1 :])
            if "up" in inner and "web" in inner:
                self.running |= {"web", "worker"}
            return b""
        return self._cmd(inner, stdin)

    @staticmethod
    def _names(names):
        return [n.removeprefix("op-") for n in names]

    def _cmd(self, c, stdin):
        if c[0] == "psql":
            sql = c[c.index("-c") + 1]
            assert sql.lstrip().upper().startswith("SELECT")
            if "md5" in sql:
                return (self.fingerprint() + "\n").encode()
            sql = sql.replace("coalesce", "")
            return ("|".join(str(v) for v in self.db.execute(sql).fetchone()) + "\n").encode()
        if c[0] == "pg_dump":
            if self.on_dump:
                self.on_dump()
            return b"PGDMP" + json.dumps(self.rows()).encode()
        if c[0] == "pg_restore":
            assert {"--clean", "--if-exists", "--single-transaction", "--exit-on-error"} <= set(c)
            assert not ({"web", "worker"} & self.running), "restored under a running app"
            data = json.loads(stdin.read()[5:])
            for t, rows in data.items():
                self.db.execute(f"DELETE FROM {t}")
                for r in (
                    rows[: len(rows) - 1] if self.drop_on_restore and t == "projects" else rows
                ):
                    self.db.execute(f"INSERT INTO {t} VALUES ({','.join('?' * len(r))})", r)
            return b""
        if c[0] == "tar" and "--create" in c:
            buf = io.BytesIO()
            with tarfile.open(fileobj=buf, mode="w") as t:
                for name, data in sorted(self.files.items()):
                    ti = tarfile.TarInfo(name)
                    ti.size = len(data)
                    ti.mtime = 0
                    t.addfile(ti, io.BytesIO(data))
            return buf.getvalue()
        if c[0] == "tar" and "--extract" in c:
            assert "--no-same-owner" in c
            with tarfile.open(fileobj=io.BytesIO(stdin.read()), mode="r") as t:
                for m in t.getmembers():
                    data = t.extractfile(m).read()
                    if self.corrupt_files_on_restore:
                        data = data + b"x"
                    self.files[m.name] = data
            return b""
        if c[0] == "find" and "-delete" in c:
            assert "-mindepth" in c and "-xdev" in c
            self.files.clear()
            return b""
        if c[0] == "sh" and "sha256sum" in c[2]:
            return "".join(
                f"{hashlib.sha256(d).hexdigest()}  {n}\n" for n, d in sorted(self.files.items())
            ).encode()
        if c[0] == "readlink":
            return (self.links.get(c[-1], c[-1]) + "\n").encode()
        if c[0] == "chown":
            return b""
        raise AssertionError(f"unexpected command {c}")


def source_endpoint(**kw):
    kw = {"db_container": "db", "db_user": "u", "db_name": "n", "ssh": DEST,
          "assets_container": "assets", "writers": ("op-web", "op-worker"), **kw}  # fmt: skip
    return mt.Endpoint(**kw)


def target_endpoint(**kw):
    kw = {"db_container": "db", "db_user": "u", "db_name": "n", "ssh": DEST,
          "assets_host_path": ASSETS, "data_root": DATA_ROOT,
          "writers": ("op-web", "op-worker"), **kw}  # fmt: skip
    return mt.Endpoint(**kw)


def ctx(host):
    return mt._Ctx(runner=host)


def dump(src, ep, d):
    return mt.dump(ep, d, scratch_dirs=("/tmp",), _ctx=ctx(src))


@pytest.fixture
def source():
    return Host(projects=37, work_packages=101, users=7, attachments=[f"f{i}" for i in range(6)])


# ----------------------------------------------------------------------------- counts


def test_counts_cover_the_nine_tables_and_count_real_accounts_only(source):
    got = mt.counts(source_endpoint(), _ctx=ctx(source))
    assert list(got) == list(mt.COUNT_KEYS)
    assert list(mt.COUNT_KEYS[:4]) == ["projects", "work_packages", "users", "attachments"]
    assert {"journals", "time_entries", "members", "versions", "custom_fields"} <= set(got)
    assert got["projects"] == 37 and got["work_packages"] == 101 and got["users"] == 7
    assert got["attachments"] == 6 and got["journals"] == 0


def test_counts_refuse_an_unreadable_answer():
    h = Host()
    h._cmd = lambda c, stdin: b"not|numbers\n"
    with pytest.raises(mt.MigrateError, match="unreadable"):
        mt.counts(source_endpoint(), _ctx=ctx(h))


def test_every_command_goes_through_ssh_as_one_quoted_string_with_sudo(source):
    c = ctx(source)
    mt.counts(source_endpoint(), _ctx=c)
    argv = c.log[0]
    assert argv[:5] == ["ssh", "-n", "-o", "BatchMode=yes", DEST] and len(argv) == 6
    assert shlex.split(argv[5])[:3] == ["sudo", "-n", "docker"]
    local = mt._Ctx(runner=lambda a, **k: (0, b"1|2|3|4|5|6|7|8|9\n", b""))
    mt.counts(source_endpoint(ssh=None, sudo=False), _ctx=local)
    assert local.log[0][0] == "docker"


def test_ssh_reads_the_callers_stdin_only_when_a_pipe_is_given():
    ep = source_endpoint()
    assert "-n" in mt._wrap(ep, ["true"])
    assert "-n" not in mt._wrap(ep, ["true"], has_stdin=True)


# ----------------------------------------------------------------------------- dump


def test_dump_writes_the_files_and_a_manifest_and_only_reads_the_source(source, private):
    before = source.rows()
    manifest = dump(source, source_endpoint(), private / "d")
    d = private / "d"
    assert sorted(p.name for p in d.iterdir()) == ["attachments.tar", "db.dump", "manifest.json"]
    assert oct(d.stat().st_mode & 0o777) == "0o700"
    assert {oct(p.stat().st_mode & 0o777) for p in d.glob("*.*") if p.name != "manifest.json"} == {"0o600"}  # fmt: skip
    for name in ("db.dump", "attachments.tar"):
        data = (d / name).read_bytes()
        assert manifest["files"][name] == {"size": len(data), "sha256": hashlib.sha256(data).hexdigest()}  # fmt: skip
    assert manifest["counts"]["projects"] == 37 and manifest["counts"]["attachments"] == 6
    assert manifest["fingerprint"] == source.fingerprint()
    assert manifest["attachment_files"]["count"] == 6
    assert manifest["frozen"] is False and manifest["quiescent"] is False  # writers were running
    assert manifest["writers"] == {"op-web": True, "op-worker": True}
    assert json.loads((d / "manifest.json").read_text()) == manifest
    # read-only: inspect, SELECTs, pg_dump and tar --create, nothing else
    kinds = {c[3] if c[2] != "-i" else c[4] for c in source.log if c[:2] == ["docker", "exec"]}
    assert kinds == {"psql", "pg_dump", "tar"}
    assert {c[1] for c in source.log if c[0] == "docker" and c[1] != "exec"} == {"inspect"}
    assert all("--create" in c for c in source.log if "tar" in c)
    assert source.rows() == before and source.running == {"web", "worker"}


def test_a_frozen_source_dumps_as_frozen_and_quiescent(source, private):
    mt.freeze(source_endpoint(), _ctx=ctx(source))
    manifest = dump(source, source_endpoint(), private / "d")
    assert manifest["frozen"] is True and manifest["quiescent"] is True
    assert manifest["writers"] == {"op-web": False, "op-worker": False}


def test_a_source_with_only_the_web_stopped_is_not_frozen(source, private):
    source.running = {"worker"}
    manifest = dump(source, source_endpoint(), private / "d")
    assert manifest["frozen"] is False and manifest["quiescent"] is False


def test_an_edit_that_moves_no_count_moves_the_fingerprint_and_unsettles_the_dump(source, private):
    source.running = set()
    source.on_dump = source.edit
    manifest = dump(source, source_endpoint(), private / "d")
    assert manifest["counts"] == mt.counts(source_endpoint(), _ctx=ctx(source))
    assert manifest["frozen"] is True and manifest["quiescent"] is False


@pytest.mark.parametrize("where", ["/tmp/x", "/var/tmp/x", "/dev/shm/x"])
def test_dump_never_stages_in_a_temporary_directory(source, where):
    with pytest.raises(mt.MigrateError, match="refusing to stage"):
        mt.dump(source_endpoint(), where, _ctx=ctx(source))
    assert source.log == []  # not even a read happened


def test_dump_tightens_an_existing_directory_and_refuses_a_non_empty_one(source, private):
    (private / "d").mkdir(mode=0o755)
    dump(source, source_endpoint(), private / "d")
    assert oct((private / "d").stat().st_mode & 0o777) == "0o700"
    with pytest.raises(mt.MigrateError, match="not empty"):
        dump(source, source_endpoint(), private / "d")


def test_a_failed_command_leaves_no_partial_file(source, private):
    source.fail = {"tar"}
    with pytest.raises(mt.MigrateError, match="boom"):
        dump(source, source_endpoint(), private / "d")
    assert sorted(p.name for p in (private / "d").iterdir()) == ["db.dump"]


# ----------------------------------------------------------------------------- restore


def _dumped(source, private, name="d1"):
    dump(source, source_endpoint(), private / name)
    return Host(), private / name


def test_restore_replaces_the_target_verifies_it_and_returns_the_manifests_counts(source, private):
    target, d = _dumped(source, private)
    target.running = set()
    got = mt.restore(target_endpoint(), d, _ctx=ctx(target))
    assert got == mt.counts(source_endpoint(), _ctx=ctx(source))
    assert target.rows() == source.rows() and target.files == source.files
    names = [" ".join(c[:3]) for c in target.log]
    assert names[0] == "readlink -f --"  # the directory is resolved before anything is deleted
    stop = names.index("docker stop op-web")
    assert stop < next(i for i, c in enumerate(target.log) if "pg_restore" in c)
    assert target.running == {"web", "worker"}


def test_restore_verifies_before_it_migrates_or_starts(source, private):
    target, d = _dumped(source, private)
    ep = target_endpoint(writers=(), compose_file="/opt/compose/x/docker-compose.yml")
    mt.restore(ep, d, _ctx=ctx(target))
    flat = [" ".join(c) for c in target.log]
    idx = lambda s: next(i for i, c in enumerate(flat) if s in c)  # noqa: E731
    assert idx(" stop web worker") < idx("pg_restore") < idx("sha256sum") < idx(" run --rm -T --no-deps web ./docker/prod/seeder") < idx("up -d web worker")  # fmt: skip


@pytest.mark.parametrize("what", ["db.dump", "attachments.tar"])
def test_restore_refuses_a_dump_that_is_not_what_its_manifest_says_before_touching_the_target(
    source, private, what
):
    target, d = _dumped(source, private)
    (d / what).write_bytes((d / what).read_bytes() + b"x")
    with pytest.raises(mt.MigrateError, match="not what the manifest recorded"):
        mt.restore(target_endpoint(), d, _ctx=ctx(target))
    assert target.log == []


def test_restore_refuses_a_missing_manifest_and_a_linked_file(source, private):
    target, d = _dumped(source, private)
    (d / "db.dump").rename(private / "real")
    (d / "db.dump").symlink_to(private / "real")
    with pytest.raises(mt.MigrateError, match="missing from the manifest or the directory"):
        mt.restore(target_endpoint(), d, _ctx=ctx(target))
    (d / "manifest.json").unlink()
    with pytest.raises(mt.MigrateError, match="no readable"):
        mt.restore(target_endpoint(), d, _ctx=ctx(target))
    assert target.log == []


def test_a_count_that_differs_is_raised_and_the_target_is_left_stopped(source, private):
    target, d = _dumped(source, private)
    target.drop_on_restore = True
    with pytest.raises(mt.CountMismatch) as e:
        mt.restore(target_endpoint(), d, _ctx=ctx(target))
    assert e.value.expected["projects"] == 37 and e.value.got["projects"] == 36
    assert any("left stopped" in n for n in e.value.__notes__)
    assert target.running == set()


def test_attachment_rows_without_their_files_are_caught(source, private):
    """The 6 attachment rows match; the files that landed differ."""
    target, d = _dumped(source, private)
    target.corrupt_files_on_restore = True
    with pytest.raises(mt.VerifyMismatch, match="attachment files"):
        mt.restore(target_endpoint(), d, _ctx=ctx(target))
    assert target.running == set()


def test_a_failed_restore_leaves_the_target_stopped_and_raises_the_original(source, private):
    target, d = _dumped(source, private)
    target.fail = {"pg_restore"}
    with pytest.raises(mt.MigrateError, match="pg_restore") as e:
        mt.restore(target_endpoint(), d, _ctx=ctx(target))
    assert target.running == set()
    assert any("left stopped" in n for n in e.value.__notes__)


def test_restore_refuses_a_target_whose_attachments_are_reached_through_a_container(
    source, private
):
    target, d = _dumped(source, private)
    ep = mt.Endpoint(db_container="db", db_user="u", db_name="n", ssh=DEST,
                     assets_container="op-web", writers=("op-web",))  # fmt: skip
    with pytest.raises(mt.MigrateError, match="assets_host_path"):
        mt.restore(ep, d, _ctx=ctx(target))
    assert target.log == []


# ----------------------------------------------------------------------------- the guard


@pytest.mark.parametrize(
    "path, why",
    [
        ("/", "fewer than 3"),
        ("/var", "fewer than 3"),
        ("/var/lib", "fewer than 3"),
        ("/srv/data/../..", "canonical"),
        ("/srv/data/assets/..", "canonical"),
        ("/srv/data/./assets", "canonical"),
        ("/srv//data/assets", "canonical"),
        ("/srv/data/assets/", "canonical"),
        ("srv/data/assets", "canonical"),
        ("/home/ops/other", "not inside the data root"),
        ("/srv/data", "fewer than 3|not inside"),
    ],
)  # fmt: skip
def test_the_attachments_directory_is_guarded_lexically(path, why):
    with pytest.raises(mt.MigrateError, match=why):
        mt.Endpoint(db_container="d", db_user="u", db_name="n", assets_host_path=path, data_root=DATA_ROOT)  # fmt: skip


def test_a_container_path_is_guarded_too():
    for bad in ("/", "/var", "/var/openproject/..", "relative/dir/x"):
        with pytest.raises(mt.MigrateError):
            mt.Endpoint(db_container="d", db_user="u", db_name="n", assets_container="a", assets_path=bad)  # fmt: skip


def test_a_host_path_needs_a_data_root_and_one_way_to_the_files():
    with pytest.raises(mt.MigrateError, match="data_root"):
        mt.Endpoint(db_container="d", db_user="u", db_name="n", assets_host_path=ASSETS)
    with pytest.raises(mt.MigrateError, match="exactly one"):
        mt.Endpoint(db_container="d", db_user="u", db_name="n")
    with pytest.raises(mt.MigrateError, match="exactly one"):
        mt.Endpoint(db_container="d", db_user="u", db_name="n", assets_container="a", assets_host_path=ASSETS, data_root=DATA_ROOT)  # fmt: skip


@pytest.mark.parametrize("real", ["/etc", "/srv/data/other", "/srv/data/assets/../x"])
def test_a_directory_that_resolves_elsewhere_is_never_deleted(source, private, real):
    target, d = _dumped(source, private)
    target.links[ASSETS] = real  # the endpoint says the path is (or runs through) a link
    with pytest.raises(mt.MigrateError, match="resolves to"):
        mt.restore(target_endpoint(), d, _ctx=ctx(target))
    assert not any(c[0] in ("find", "chown") for c in target.log)
    assert not any("pg_restore" in c for c in target.log)  # nothing written, nothing stopped
    assert target.running == {"web", "worker"}


# ----------------------------------------------------------------------------- the final delta


def test_the_final_delta_after_a_freeze_leaves_the_target_equal_to_the_frozen_source(
    source, private
):
    """Review Focus 1: freeze stops every writer, the dump is of the frozen state, and the target
    equals what freeze reported by counts, content and attachment files."""
    target = Host()
    dump(source, source_endpoint(), private / "rehearsal")
    mt.restore(target_endpoint(), private / "rehearsal", _ctx=ctx(target))
    # people keep working on the source: new work, an edit that moves no count, a file swapped
    source.add(projects=2, work_packages=5, users=1)
    source.edit()
    source.attach("new")
    source.unattach("f0")
    assert target.fingerprint() != source.fingerprint()
    frozen = mt.freeze(source_endpoint(), _ctx=ctx(source))
    assert source.running == set()  # the web app AND the worker
    dump(source, source_endpoint(), private / "final")
    got = mt.restore(target_endpoint(), private / "final", expect_counts=frozen,
                     require_quiescent=True, _ctx=ctx(target))  # fmt: skip
    assert got == frozen and frozen["projects"] == 39 and frozen["work_packages"] == 106
    assert target.rows() == source.rows() and target.fingerprint() == source.fingerprint()
    assert "./files/new" in target.files and "./files/f0" not in target.files
    mt.unfreeze(source_endpoint(), _ctx=ctx(source))
    assert source.running == {"web", "worker"}


def test_expect_counts_must_equal_the_dump_before_the_target_is_touched(source, private):
    source.running = set()
    dump(source, source_endpoint(), private / "d")
    stale = {**mt.counts(source_endpoint(), _ctx=ctx(source)), "projects": 36}
    target = Host()
    with pytest.raises(mt.CountMismatch):
        mt.restore(target_endpoint(), private / "d", expect_counts=stale, _ctx=ctx(target))
    assert target.log == []


def test_a_dump_of_a_live_source_is_refused_as_a_final_copy(source, private):
    dump(source, source_endpoint(), private / "d")  # nothing was frozen
    target = Host()
    counts = mt.counts(source_endpoint(), _ctx=ctx(source))
    with pytest.raises(mt.MigrateError, match="not dumped from a frozen source"):
        mt.restore(target_endpoint(), private / "d", expect_counts=counts,
                   require_quiescent=True, _ctx=ctx(target))  # fmt: skip
    with pytest.raises(mt.MigrateError, match="needs expect_counts"):
        mt.restore(target_endpoint(), private / "d", require_quiescent=True, _ctx=ctx(target))
    assert target.log == []


def test_freeze_stops_every_writer_and_needs_them_named():
    with pytest.raises(mt.MigrateError, match="writers"):
        mt.freeze(source_endpoint(writers=()), _ctx=ctx(Host()))
    h = Host()
    mt.freeze(source_endpoint(), _ctx=ctx(h))
    assert h.running == set()


def test_freeze_fails_loudly_when_a_writer_will_not_stop():
    h = Host()
    real = h._do
    h._do = lambda inner, stdin: b"" if inner[:2] == ["docker", "stop"] else real(inner, stdin)
    with pytest.raises(mt.MigrateError, match="still running"):
        mt.freeze(source_endpoint(), _ctx=ctx(h))


# ----------------------------------------------------------------------------- command line


def test_the_command_line_prints_json_and_maps_failures_to_exit_codes(
    monkeypatch, capsys, source, tmp_path
):
    monkeypatch.setattr(mt, "_subprocess_runner", source)
    common = ["--ssh", DEST, "--db-container", "db", "--db-user", "u", "--db-name", "n",
              "--assets-container", "assets", "--writer", "op-web", "--writer", "op-worker"]  # fmt: skip
    assert mt.main(["counts", *common]) == 0
    assert json.loads(capsys.readouterr().out)["projects"] == 37
    assert mt.main(["freeze", *common]) == 0
    frozen = json.loads(capsys.readouterr().out)
    assert frozen["work_packages"] == 101 and source.running == set()
    assert mt.main(["dump", *common]) == 2  # --dir missing
    assert "needs --dir" in capsys.readouterr().err
    f = tmp_path / "c.json"
    f.write_text(json.dumps(frozen))
    assert mt._expect("@" + str(f)) == frozen and mt._expect(json.dumps(frozen)) == frozen
    with pytest.raises(mt.MigrateError, match="expect-counts"):
        mt._expect("not json")
    source.fail = {"psql"}
    assert mt.main(["counts", *common]) == 2
    assert "failed" in capsys.readouterr().err
