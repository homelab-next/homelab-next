# SPDX-License-Identifier: Apache-2.0
"""tools/migrate/openproject.py: dump, restore, counts, freeze and unfreeze over ssh pipes, against
a fake host (a sqlite database and an in-memory attachments tree behind the ``docker`` command
line the tool builds).  What is pinned: the four counts (accounts of the real kind only); the dump
is read-only on the source and never staged in a temporary directory; a restore refuses a dump that
is not what its manifest says before it touches the target; a restore stops the web processes
first, starts them again whatever happened and compares the target with the manifest; and the final
delta after a freeze (dump again, restore again) leaves the target equal to the frozen source,
attachments deleted at the source included."""

from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import shlex
import sqlite3
import sys
import tarfile
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
SCHEMA = """
CREATE TABLE projects (id INTEGER PRIMARY KEY, name TEXT);
CREATE TABLE work_packages (id INTEGER PRIMARY KEY, subject TEXT);
CREATE TABLE users (id INTEGER PRIMARY KEY, login TEXT, type TEXT);
CREATE TABLE attachments (id INTEGER PRIMARY KEY, file TEXT);
"""


class Host:
    """One host's containers: a database, an attachments tree, the set of running web processes."""

    def __init__(self, projects=0, work_packages=0, users=0, attachments=()):
        self.db = sqlite3.connect(":memory:")
        self.db.executescript(SCHEMA)
        # the product also keeps an anonymous user and system users in the same table
        self.db.executemany("INSERT INTO users(login, type) VALUES (?, ?)",
                            [("anon", "AnonymousUser"), ("sys", "SystemUser"), ("gone", "DeletedUser")])  # fmt: skip
        self.add(projects, work_packages, users)
        self.files: dict[str, bytes] = {}
        for name in attachments:
            self.attach(name)
        self.running = {"web", "worker"}
        self.log: list[list[str]] = []  # the inner commands, ssh and sudo removed
        self.fail: set[str] = set()
        self.on_dump = None  # called when pg_dump runs (a write during the dump)
        self.drop_on_restore = False

    def add(self, projects=0, work_packages=0, users=0):
        for i in range(projects):
            self.db.execute("INSERT INTO projects(name) VALUES (?)", (f"p{i}",))
        for i in range(work_packages):
            self.db.execute("INSERT INTO work_packages(subject) VALUES (?)", (f"w{i}",))
        for i in range(users):
            self.db.execute("INSERT INTO users(login, type) VALUES (?, 'User')", (f"u{i}",))

    def attach(self, name):
        self.files[f"./files/{name}"] = name.encode() * 10
        self.db.execute("INSERT INTO attachments(file) VALUES (?)", (name,))

    def unattach(self, name):
        self.files.pop(f"./files/{name}")
        self.db.execute("DELETE FROM attachments WHERE file = ?", (name,))

    def rows(self):
        return {t: sorted(self.db.execute(f"SELECT * FROM {t}").fetchall())
                for t in ("projects", "work_packages", "users", "attachments")}  # fmt: skip

    # the runner the tool is given
    def __call__(self, argv, *, stdin=None, stdout=None):
        argv = list(argv)
        if argv[0] == "ssh":
            assert argv[1:4] == ["-o", "BatchMode=yes", DEST] and len(argv) == 5
            argv = shlex.split(argv[4])
        assert argv[:2] == ["sudo", "-n"]
        inner = argv[2:]
        self.log.append(inner)
        key = " ".join(inner[:4])
        if any(f in key or f in " ".join(inner) for f in self.fail):
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
            rest = rest[1:]  # the container
            return self._cmd(rest, stdin)
        if inner[:2] == ["docker", "stop"]:
            self.running -= set(self._names(inner[2:]))
            return b""
        if inner[:2] == ["docker", "start"]:
            self.running |= set(self._names(inner[2:]))
            return b""
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
                    self.files[m.name] = t.extractfile(m).read()
            return b""
        if c[0] == "find":
            assert "-delete" in c and "-mindepth" in c
            self.files.clear()
            return b""
        if c[0] == "chown":
            return b""
        raise AssertionError(f"unexpected command {c}")


def source_endpoint(**kw):
    kw = {"db_container": "db", "db_user": "u", "db_name": "n", "ssh": DEST,
          "assets_container": "assets", "web_containers": ("op-web",), **kw}  # fmt: skip
    return mt.Endpoint(**kw)


def target_endpoint(**kw):
    kw = {"db_container": "db", "db_user": "u", "db_name": "n", "ssh": DEST,
          "assets_host_path": "/srv/data/assets", "web_containers": ("op-web", "op-worker"), **kw}  # fmt: skip
    return mt.Endpoint(**kw)


def ctx(host):
    return mt._Ctx(runner=host)


@pytest.fixture(autouse=True)
def _private_tmp(monkeypatch):
    """pytest's tmp_path lives under the system temp directory, which the tool refuses; the
    refusal tests put the real list back."""
    monkeypatch.setattr(mt, "SCRATCH_DIRS", ())


@pytest.fixture
def source():
    return Host(projects=37, work_packages=101, users=7, attachments=[f"f{i}" for i in range(6)])


# ----------------------------------------------------------------------------- counts


def test_counts_are_the_four_figures_and_count_real_accounts_only(source):
    got = mt.counts(source_endpoint(), _ctx=ctx(source))
    assert got == {"projects": 37, "work_packages": 101, "users": 7, "attachments": 6}
    assert list(got) == list(mt.COUNT_KEYS)
    assert [c[0] for c in source.log] == ["docker"]  # one read: docker exec <db> psql ... SELECT


def test_counts_refuse_an_unreadable_answer():
    h = Host()
    h._cmd = lambda c, stdin: b"not|numbers\n"
    with pytest.raises(mt.MigrateError, match="unreadable"):
        mt.counts(source_endpoint(), _ctx=ctx(h))


def test_every_command_goes_through_ssh_as_one_quoted_string_with_sudo(source):
    c = ctx(source)
    mt.counts(source_endpoint(), _ctx=c)
    argv = c.log[0]
    assert argv[:4] == ["ssh", "-o", "BatchMode=yes", DEST] and len(argv) == 5
    assert shlex.split(argv[4])[:3] == ["sudo", "-n", "docker"]
    local = mt._Ctx(runner=lambda a, **k: (0, b"1|2|3|4\n", b""))
    mt.counts(source_endpoint(ssh=None, sudo=False), _ctx=local)
    assert local.log[0][0] == "docker"


# ----------------------------------------------------------------------------- dump


def test_dump_writes_the_files_and_a_manifest_and_only_reads_the_source(source, tmp_path):
    before = source.rows()
    manifest = mt.dump(source_endpoint(), tmp_path / "d", _ctx=ctx(source))
    d = tmp_path / "d"
    assert sorted(p.name for p in d.iterdir()) == ["attachments.tar", "db.dump", "manifest.json"]
    assert oct(d.stat().st_mode & 0o777) == "0o700"
    assert {oct(p.stat().st_mode & 0o777) for p in d.glob("*.*") if p.name != "manifest.json"} == {
        "0o600"
    }
    for name in ("db.dump", "attachments.tar"):
        data = (d / name).read_bytes()
        assert manifest["files"][name] == {
            "size": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
        }
    assert manifest["counts"] == {
        "projects": 37,
        "work_packages": 101,
        "users": 7,
        "attachments": 6,
    }
    assert manifest["quiescent"] is True
    assert json.loads((d / "manifest.json").read_text()) == manifest
    # read-only: a SELECT, pg_dump and tar --create, nothing else; the source did not change
    kinds = [
        (c[3] if c[2] != "-i" else c[4]) if c[:2] == ["docker", "exec"] else c[0]
        for c in source.log
    ]
    assert set(kinds) == {"psql", "pg_dump", "tar"}
    assert all("--create" in c for c in source.log if "tar" in c)
    assert source.rows() == before and source.running == {"web", "worker"}


def test_dump_notes_a_source_that_changed_while_it_was_dumped(source, tmp_path):
    source.on_dump = lambda: source.add(projects=1)
    manifest = mt.dump(source_endpoint(), tmp_path / "d", _ctx=ctx(source))
    assert manifest["quiescent"] is False
    assert manifest["counts_before"]["projects"] == 37 and manifest["counts"]["projects"] == 38


@pytest.mark.parametrize("where", ["/tmp/x", "/var/tmp/x", "/dev/shm/x"])
def test_dump_never_stages_in_a_temporary_directory(source, where, monkeypatch):
    monkeypatch.setattr(mt, "SCRATCH_DIRS", ("/tmp", "/var/tmp", "/dev/shm"))
    with pytest.raises(mt.MigrateError, match="refusing to stage"):
        mt.dump(source_endpoint(), where, _ctx=ctx(source))
    assert source.log == []  # not even a read happened


def test_dump_refuses_a_directory_that_is_not_empty(source, tmp_path):
    (tmp_path / "d").mkdir()
    (tmp_path / "d" / "old").write_text("x")
    with pytest.raises(mt.MigrateError, match="not empty"):
        mt.dump(source_endpoint(), tmp_path / "d", _ctx=ctx(source))


def test_a_failed_command_leaves_no_partial_file(source, tmp_path):
    source.fail = {"tar"}
    with pytest.raises(mt.MigrateError, match="boom"):
        mt.dump(source_endpoint(), tmp_path / "d", _ctx=ctx(source))
    assert sorted(p.name for p in (tmp_path / "d").iterdir()) == [
        "db.dump"
    ]  # the finished one only


# ----------------------------------------------------------------------------- restore


def _cutover_pair(source, tmp_path, **kw):
    mt.dump(source_endpoint(), tmp_path / "d1", _ctx=ctx(source))
    return Host(), tmp_path / "d1"


def test_restore_replaces_the_target_and_returns_counts_equal_to_the_manifest(source, tmp_path):
    target, d = _cutover_pair(source, tmp_path)
    target.running = set()
    got = mt.restore(target_endpoint(), d, _ctx=ctx(target))
    assert got == {"projects": 37, "work_packages": 101, "users": 7, "attachments": 6}
    assert target.rows() == source.rows() and target.files == source.files
    names = [" ".join(c[:3]) for c in target.log]
    assert names[0] == "docker stop op-web"  # stopped before anything is written
    assert [c for c in names if "start" in c] == ["docker start op-web"]
    assert names.index("docker stop op-web") < next(
        i for i, c in enumerate(target.log) if "pg_restore" in c
    )
    assert target.running == {"web", "worker"}


def test_restore_runs_the_migrations_and_starts_through_compose_when_given(source, tmp_path):
    target, d = _cutover_pair(source, tmp_path)
    ep = target_endpoint(web_containers=(), compose_file="/opt/compose/projects/docker-compose.yml")
    mt.restore(ep, d, _ctx=ctx(target))
    flat = [" ".join(c) for c in target.log]
    assert any("compose" in c and " stop web worker" in c for c in flat)
    seed = next(
        i for i, c in enumerate(flat) if " run --rm -T --no-deps web ./docker/prod/seeder" in c
    )
    restore_i = next(i for i, c in enumerate(flat) if "pg_restore" in c)
    start = next(i for i, c in enumerate(flat) if c.endswith("up -d web worker"))
    assert restore_i < seed < start


@pytest.mark.parametrize("what", ["db.dump", "attachments.tar"])
def test_restore_refuses_a_dump_that_is_not_what_its_manifest_says_before_touching_the_target(
    source, tmp_path, what
):
    target, d = _cutover_pair(source, tmp_path)
    (d / what).write_bytes((d / what).read_bytes() + b"x")
    with pytest.raises(mt.MigrateError, match="not what the manifest recorded"):
        mt.restore(target_endpoint(), d, _ctx=ctx(target))
    assert target.log == []


def test_restore_refuses_a_missing_manifest_and_a_linked_file(source, tmp_path):
    target, d = _cutover_pair(source, tmp_path)
    (d / "db.dump").rename(tmp_path / "real")
    (d / "db.dump").symlink_to(tmp_path / "real")
    with pytest.raises(mt.MigrateError, match="missing from the manifest or the directory"):
        mt.restore(target_endpoint(), d, _ctx=ctx(target))
    (d / "manifest.json").unlink()
    with pytest.raises(mt.MigrateError, match="no readable"):
        mt.restore(target_endpoint(), d, _ctx=ctx(target))
    assert target.log == []


def test_a_count_that_differs_is_raised_and_the_target_is_started_again(source, tmp_path):
    target, d = _cutover_pair(source, tmp_path)
    target.drop_on_restore = True
    with pytest.raises(mt.CountMismatch) as e:
        mt.restore(target_endpoint(), d, _ctx=ctx(target))
    assert e.value.expected["projects"] == 37 and e.value.got["projects"] == 36
    assert target.running == {"web", "worker"}


def test_a_failed_restore_starts_the_target_again_and_reports_the_command(source, tmp_path):
    target, d = _cutover_pair(source, tmp_path)
    target.fail = {"pg_restore"}
    with pytest.raises(mt.MigrateError, match="pg_restore"):
        mt.restore(target_endpoint(), d, _ctx=ctx(target))
    assert target.running == {"web", "worker"}


def test_restore_refuses_attachments_read_through_a_container_it_stops(source, tmp_path):
    target, d = _cutover_pair(source, tmp_path)
    ep = mt.Endpoint(db_container="db", db_user="u", db_name="n", ssh=DEST,
                     assets_container="op-web", web_containers=("op-web",))  # fmt: skip
    with pytest.raises(mt.MigrateError, match="assets_host_path"):
        mt.restore(ep, d, _ctx=ctx(target))
    assert target.log == []


def test_an_endpoint_names_exactly_one_way_to_the_attachments():
    with pytest.raises(mt.MigrateError, match="exactly one"):
        mt.Endpoint(db_container="d", db_user="u", db_name="n")
    with pytest.raises(mt.MigrateError, match="exactly one"):
        mt.Endpoint(
            db_container="d", db_user="u", db_name="n", assets_container="a", assets_host_path="/x"
        )
    with pytest.raises(mt.MigrateError, match="absolute"):
        mt.Endpoint(db_container="d", db_user="u", db_name="n", assets_host_path="rel")


# ----------------------------------------------------------------------------- the final delta


def test_the_final_delta_after_a_freeze_leaves_the_target_equal_to_the_frozen_source(
    source, tmp_path
):
    """Review Focus 1: writes after the rehearsal copy are not lost: freeze, dump again, restore
    again, and the target's counts equal the source's counts read AFTER the freeze."""
    target = Host()
    # rehearsal: the source is live and the target equals it
    mt.dump(source_endpoint(), tmp_path / "rehearsal", _ctx=ctx(source))
    mt.restore(target_endpoint(), tmp_path / "rehearsal", _ctx=ctx(target))
    # people keep working on the source: new work, a new account, an attachment added and one deleted
    source.add(projects=2, work_packages=5, users=1)
    source.attach("new")
    source.unattach("f0")
    assert mt.counts(target_endpoint(), _ctx=ctx(target)) != mt.counts(
        source_endpoint(), _ctx=ctx(source)
    )
    # cutover: freeze, dump again, restore again, re-count
    frozen = mt.freeze(source_endpoint(), _ctx=ctx(source))
    assert source.running == {"worker"}  # op-web stopped, nothing writes
    mt.dump(source_endpoint(), tmp_path / "final", _ctx=ctx(source))
    got = mt.restore(
        target_endpoint(), tmp_path / "final", require_quiescent=True, _ctx=ctx(target)
    )
    assert got == frozen == {"projects": 39, "work_packages": 106, "users": 8, "attachments": 6}
    assert target.rows() == source.rows()
    assert "./files/new" in target.files and "./files/f0" not in target.files
    # rollback of the cutover: the source runs again
    mt.unfreeze(source_endpoint(), _ctx=ctx(source))
    assert source.running == {"web", "worker"}


def test_a_dump_taken_while_the_source_changed_is_refused_as_a_final_copy(source, tmp_path):
    source.on_dump = lambda: source.add(projects=1)
    mt.dump(source_endpoint(), tmp_path / "d", _ctx=ctx(source))
    target = Host()
    with pytest.raises(mt.MigrateError, match="changed while it was dumped"):
        mt.restore(target_endpoint(), tmp_path / "d", require_quiescent=True, _ctx=ctx(target))
    assert target.log == []


def test_freeze_needs_the_processes_to_stop():
    with pytest.raises(mt.MigrateError, match="web_containers"):
        mt.freeze(source_endpoint(web_containers=()), _ctx=ctx(Host()))


# ----------------------------------------------------------------------------- command line


def test_the_command_line_prints_json_and_maps_failures_to_exit_codes(monkeypatch, capsys, source):
    monkeypatch.setattr(mt, "_subprocess_runner", source)
    common = ["--ssh", DEST, "--db-container", "db", "--db-user", "u", "--db-name", "n",
              "--assets-container", "assets"]  # fmt: skip
    assert mt.main(["counts", *common]) == 0
    assert json.loads(capsys.readouterr().out) == {
        "projects": 37, "work_packages": 101, "users": 7, "attachments": 6}  # fmt: skip
    assert mt.main(["dump", *common]) == 2  # --dir missing
    assert "needs --dir" in capsys.readouterr().err
    source.fail = {"psql"}
    assert mt.main(["counts", *common]) == 2
    assert "failed" in capsys.readouterr().err
