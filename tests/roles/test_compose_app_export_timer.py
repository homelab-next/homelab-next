# SPDX-License-Identifier: Apache-2.0
"""The scheduled database dump of compose_app (ADR-0042 decision 2): the dump script against a fake
``docker compose exec``, and the role's timer task end to end on localhost."""

from __future__ import annotations

import grp
import importlib.util
import json
import os
import stat
import sys
from pathlib import Path

import pytest
from rolerun import calls, fake, first_run, logging_fake, run_role

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "ansible/roles/compose_app/files/hnx-export-run.py"


def load():
    spec = importlib.util.spec_from_file_location("hnx_export_run", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# A fake `docker compose -f F exec -T <service> <argv...>`: answers by what is asked.
DOCKER = r"""
import os, sys
a = sys.argv[1:]
cmd = " ".join(a[a.index("-T") + 2:])
log = open(LOG, "a"); log.write(cmd + "\n"); log.close()
if os.path.exists(FAIL + ".all"):
    sys.stderr.write("boom\n"); sys.exit(1)
if "pg_database" in cmd:
    sys.stdout.write("appdb\nother\n")
elif "pg_dumpall" in cmd:
    sys.stdout.write("-- PostgreSQL database cluster dump complete\n")
elif "pg_dump -Fc" in cmd:
    if os.path.exists(FAIL + ".pg"):
        sys.stderr.write("denied\n"); sys.exit(1)
    sys.stdout.buffer.write(b"PGDMP" + b"x" * 64)
elif "mariadb-dump" in cmd:
    sys.stdout.write("-- Dump completed on 2026-11-22\n" if not os.path.exists(FAIL + ".trunc") else "CREATE TABLE")
"""


@pytest.fixture
def env(tmp_path, monkeypatch):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    body = DOCKER.replace("LOG", repr(str(tmp_path / "docker.log"))).replace(
        "FAIL", repr(str(tmp_path / "fail"))
    )
    fake(bindir / "docker", body)
    monkeypatch.setenv("PATH", f"{bindir}{os.pathsep}{os.environ['PATH']}")
    return tmp_path


def manifest(tmp_path, jobs, export=None):
    export = export or str(tmp_path / "var" / "backups" / "compose" / "app" / "export" / "db")
    doc = {
        "app": "app",
        "compose_file": str(tmp_path / "docker-compose.yml"),
        "export_dir": export,
        "jobs": jobs,
        "images": {"db": "x@sha256:" + "0" * 64},
    }
    p = tmp_path / "manifest.json"
    p.write_text(json.dumps(doc))
    return p, Path(export)


def test_postgres_dumps_every_database_and_the_globals_and_lists_them(env):
    mod = load()
    mf, export = manifest(env, [{"service": "db", "engine": "postgres"}])
    assert mod.main(["--manifest", str(mf)]) == 0
    assert sorted(p.name for p in (export / "db").iterdir()) == [
        "appdb.dump",
        "globals.sql",
        "other.dump",
    ]
    listing = (export / "listing.sha256").read_text()
    assert "db/appdb.dump" in listing and "db/globals.sql" in listing
    meta = json.loads((export / "manifest.json").read_text())
    assert meta["jobs"]["db"]["engine"] == "postgres" and "image backup" in meta["does_not_carry"]
    assert stat.S_IMODE((export / "db" / "appdb.dump").stat().st_mode) == 0o600
    assert stat.S_IMODE(export.stat().st_mode) == 0o700
    # the dump ran inside the container as its own user: no password on any command line
    assert all(
        "PASSWORD" not in line.split("MYSQL_PWD")[0]
        for line in (env / "docker.log").read_text().splitlines()
    )


def test_mysql_dump_is_a_single_transaction_dump_checked_for_its_trailer(env):
    mod = load()
    mf, export = manifest(env, [{"service": "db", "engine": "mysql"}])
    assert mod.main(["--manifest", str(mf)]) == 0
    assert (export / "db" / "all-databases.sql").read_text().startswith("-- Dump completed")
    assert "--single-transaction" in (env / "docker.log").read_text()


def test_a_truncated_dump_fails_the_run_and_leaves_the_last_good_one(env):
    mod = load()
    mf, export = manifest(env, [{"service": "db", "engine": "mysql"}])
    assert mod.main(["--manifest", str(mf)]) == 0
    good = (export / "db" / "all-databases.sql").read_text()
    (env / "fail.trunc").write_text("")
    assert mod.main(["--manifest", str(mf)]) == 1
    assert (export / "db" / "all-databases.sql").read_text() == good
    assert not [p for p in export.iterdir() if p.name.startswith(".stage-")]


def test_one_failing_service_does_not_stop_the_others_and_keeps_its_old_dump(env):
    mod = load()
    jobs = [{"service": "db", "engine": "postgres"}, {"service": "sql", "engine": "mysql"}]
    mf, export = manifest(env, jobs)
    assert mod.main(["--manifest", str(mf)]) == 0
    (env / "fail.pg").write_text("")
    assert mod.main(["--manifest", str(mf)]) == 1
    meta = json.loads((export / "manifest.json").read_text())
    assert meta["jobs"]["db"].get("stale") is True and "stale" not in meta["jobs"]["sql"]
    assert (export / "db" / "appdb.dump").exists()


def test_the_previous_dump_is_kept_once(env):
    mod = load()
    mf, export = manifest(env, [{"service": "sql", "engine": "mysql"}])
    assert mod.main(["--manifest", str(mf)]) == 0
    assert mod.main(["--manifest", str(mf)]) == 0
    assert mod.main(["--manifest", str(mf)]) == 0
    assert sorted(p.name for p in export.iterdir() if p.is_dir()) == ["sql", "sql.prev"]


def test_a_dead_engine_container_fails(env):
    mod = load()
    mf, _ = manifest(env, [{"service": "db", "engine": "postgres"}])
    (env / "fail.all").write_text("")
    assert mod.main(["--manifest", str(mf)]) == 1


@pytest.mark.parametrize(
    "export",
    ["relative/path", "/var/../etc/x", "/tmp", "/a/b"],
)
def test_a_shallow_or_traversing_export_dir_is_refused(env, export):
    mod = load()
    mf, _ = manifest(env, [{"service": "db", "engine": "postgres"}], export=export)
    assert mod.main(["--manifest", str(mf)]) == 2


def test_a_symlinked_export_dir_is_refused(env):
    mod = load()
    real = env / "real" / "deep" / "dir"
    real.mkdir(parents=True)
    link = env / "link" / "to" / "x"
    link.parent.mkdir(parents=True)
    link.symlink_to(real)
    mf, _ = manifest(env, [{"service": "db", "engine": "postgres"}], export=str(link))
    assert mod.main(["--manifest", str(mf)]) == 2


def test_an_unknown_engine_or_name_is_refused(env):
    mod = load()
    for job in ({"service": "db", "engine": "mongo"}, {"service": "../x", "engine": "postgres"}):
        mf, _ = manifest(env, [job])
        assert mod.main(["--manifest", str(mf)]) == 2


def test_no_jobs_is_a_clean_no_op(env):
    mod = load()
    mf, export = manifest(env, [])
    assert mod.main(["--manifest", str(mf)]) == 0
    assert not export.exists()


# ------------------------------------------------------------------ file jobs (sqlite, tree)
def make_db(path, rows=3, wal=False):
    import sqlite3

    path.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(path)
    if wal:
        con.execute("PRAGMA journal_mode=WAL")
    con.execute("create table t (x integer)")
    con.executemany("insert into t values (?)", [(i,) for i in range(rows)])
    con.commit()
    return con  # left open: a live database


def test_a_sqlite_job_copies_every_matching_database_while_it_is_open_and_checks_the_copy(env):
    import sqlite3

    mod = load()
    live = [make_db(env / "data" / "users" / u / "db.sqlite", wal=True) for u in ("a", "b")]
    mf, export = manifest(
        env, [{"service": "feeds", "engine": "sqlite", "glob": str(env / "data/users/*/db.sqlite")}]
    )
    assert mod.main(["--manifest", str(mf)]) == 0
    assert sorted(p.name for p in (export / "feeds").iterdir()) == ["a__db.sqlite", "b__db.sqlite"]
    assert sqlite3.connect(export / "feeds" / "a__db.sqlite").execute(
        "select count(*) from t"
    ).fetchone() == (3,)
    assert stat.S_IMODE((export / "feeds" / "a__db.sqlite").stat().st_mode) == 0o600
    assert "feeds/a__db.sqlite" in (export / "listing.sha256").read_text()
    for con in live:
        con.close()


def test_a_glob_that_matches_nothing_fails_instead_of_passing_empty(env):
    mod = load()
    mf, export = manifest(
        env, [{"service": "feeds", "engine": "sqlite", "glob": str(env / "none/*/db.sqlite")}]
    )
    assert mod.main(["--manifest", str(mf)]) == 1
    assert not (export / "feeds").exists()


def test_a_file_that_is_not_a_database_fails_and_keeps_the_last_good_copy(env):
    mod = load()
    make_db(env / "data" / "x" / "db.sqlite").close()
    mf, export = manifest(
        env, [{"service": "feeds", "engine": "sqlite", "glob": str(env / "data/x/db.sqlite")}]
    )
    assert mod.main(["--manifest", str(mf)]) == 0
    good = (export / "feeds" / "db.sqlite").read_bytes()
    (env / "data" / "x" / "db.sqlite").write_bytes(b"this is not a database" * 50)
    assert mod.main(["--manifest", str(mf)]) == 1
    assert (export / "feeds" / "db.sqlite").read_bytes() == good


def test_a_tree_job_archives_the_directory_minus_the_exclusions(env):
    import tarfile

    mod = load()
    src = env / "state"
    (src / "sub").mkdir(parents=True)
    (src / "keep.json").write_text("{}")
    (src / "sub" / "log.txt").write_text("x")
    (src / "store.db-wal").write_text("skip")
    mf, export = manifest(
        env,
        [{"service": "state", "engine": "tree", "path": str(src), "exclude": ["*.db-wal", "sub"]}],
    )
    assert mod.main(["--manifest", str(mf)]) == 0
    with tarfile.open(export / "state" / "state.tar.gz") as tar:
        names = sorted(m.name for m in tar if m.isfile())
    assert names == ["tree/keep.json"]
    assert stat.S_IMODE((export / "state" / "state.tar.gz").stat().st_mode) == 0o600
    meta = json.loads((export / "manifest.json").read_text())
    assert (
        meta["jobs"]["state"]["engine"] == "tree"
        and "not a quiesced dump" in meta["does_not_carry"]
    )


def test_a_tree_that_is_empty_or_missing_fails(env):
    mod = load()
    (env / "empty").mkdir()
    for path in (env / "empty", env / "absent"):
        mf, _ = manifest(env, [{"service": "state", "engine": "tree", "path": str(path)}])
        assert mod.main(["--manifest", str(mf)]) == 1


def test_file_jobs_need_no_compose_file_and_refuse_a_bad_source(env):
    mod = load()
    make_db(env / "data" / "x" / "db.sqlite").close()
    mf, _ = manifest(
        env, [{"service": "feeds", "engine": "sqlite", "glob": str(env / "data/x/db.sqlite")}]
    )
    doc = json.loads(mf.read_text())
    del doc["compose_file"]
    mf.write_text(json.dumps(doc))
    assert mod.main(["--manifest", str(mf)]) == 0
    for bad in (
        {"engine": "sqlite", "glob": "rel/*.db"},
        {"engine": "tree", "path": "/a/b"},
        {"engine": "tree", "path": "/a/../b/c"},
    ):
        mf, _ = manifest(env, [{"service": "x", **bad}])
        assert mod.main(["--manifest", str(mf)]) == 2
    # a database job still needs the compose file
    mf, _ = manifest(env, [{"service": "db", "engine": "postgres"}])
    doc = json.loads(mf.read_text())
    del doc["compose_file"]
    mf.write_text(json.dumps(doc))
    assert mod.main(["--manifest", str(mf)]) == 2


def test_two_jobs_cannot_share_a_name(env):
    mod = load()
    jobs = [{"service": "x", "engine": "tree", "path": str(env / "a" / "b")}] * 2
    mf, _ = manifest(env, jobs)
    assert mod.main(["--manifest", str(mf)]) == 2


# ------------------------------------------------------------------ the role's timer task
SPEC = {
    "services": {
        "web": {
            "image": "registry.example.internal/org/web",
            "tag": "1",
            "digest": "sha256:" + "a" * 64,
        },
        "db": {"image": "docker.io/library/postgres", "tag": "17", "digest": "sha256:" + "b" * 64},
        "maria": {
            "image": "docker.io/library/mariadb",
            "tag": "11",
            "digest": "sha256:" + "c" * 64,
        },
        "cache": {"image": "docker.io/library/valkey", "tag": "8", "digest": "sha256:" + "d" * 64},
    }
}


def role_vars(tmp_path, spec=SPEC, **kw):
    d = {
        "compose_app_name": "app",
        "compose_app_spec": spec,
        "compose_app_dir": str(tmp_path / "opt"),
        "compose_app_export_dir": str(tmp_path / "export"),
        "compose_app_owner": os.getenv("USER") or "root",
        "compose_app_group": grp.getgrgid(os.getgid()).gr_name,
        "compose_app_unit_dir": str(tmp_path / "units"),
        "compose_app_systemctl_cli": logging_fake(tmp_path, "systemctl", out="disabled\n"),
        "compose_app_export_script": str(tmp_path / "libexec" / "hnx-export-run"),
        "compose_app_export_last_run_dir": str(tmp_path / "last-run"),
        "compose_app_export_last_run_group": grp.getgrgid(os.getgid()).gr_name,
        "compose_app_export_last_run_writer": str(tmp_path / "libexec" / "hnx-last-run"),
    }
    (tmp_path / "units").mkdir(exist_ok=True)
    (tmp_path / "opt").mkdir(exist_ok=True)
    d.update(kw)
    return d


def _timer_first(tmp_path):
    return {"role": "compose_app", "tasks_from": "export_timer", "extra_vars": role_vars(tmp_path)}


@first_run(_timer_first)
def test_the_timer_task_installs_script_manifest_units_and_arms_the_timer(first):
    result, tmp = first
    assert result.returncode == 0, result.stdout + result.stderr
    mf = json.loads((tmp / "opt" / "export-manifest.json").read_text())
    assert mf["jobs"] == [
        {"service": "db", "engine": "postgres"},
        {"service": "maria", "engine": "mysql"},
    ]
    assert mf["export_dir"] == str(tmp / "export" / "db")
    assert mf["images"]["db"].endswith("@sha256:" + "b" * 64)
    assert stat.S_IMODE((tmp / "opt" / "export-manifest.json").stat().st_mode) == 0o600
    service = (tmp / "units" / "hnx-export-app.service").read_text()
    assert "hnx-export-run --manifest" in service and "timer:compose_app/export " in service
    timer = (tmp / "units" / "hnx-export-app.timer").read_text()
    assert "OnCalendar=*-*-* 07:30:00 UTC" in timer and "RandomizedDelaySec=15min" in timer
    assert (tmp / "libexec" / "hnx-export-run").stat().st_mode & stat.S_IEXEC
    log = calls(tmp)
    assert "systemctl daemon-reload" in log and "systemctl enable --now hnx-export-app.timer" in log


def test_an_existing_export_directory_keeps_the_module_s_owner_and_mode(tmp_path):
    """A module that owns export/db as its database's user keeps it: the dump never changes it."""
    db = tmp_path / "export" / "db"
    db.mkdir(parents=True)
    db.chmod(0o750)  # a mode the role would not choose: kept means untouched
    before = db.stat()
    r = run_role(tmp_path, "compose_app", tasks_from="export_timer", extra_vars=role_vars(tmp_path))
    assert r.returncode == 0, r.stdout + r.stderr
    after = db.stat()
    assert stat.S_IMODE(after.st_mode) == 0o750
    assert (after.st_uid, after.st_gid) == (before.st_uid, before.st_gid)


def test_an_override_can_disable_or_add_an_engine_and_a_bad_one_is_refused(tmp_path):
    ok = run_role(
        tmp_path,
        "compose_app",
        "export_timer",
        role_vars(tmp_path, compose_app_export_engines={"db": "none", "web": "mysql"}),
    )
    assert ok.returncode == 0, ok.stdout + ok.stderr
    jobs = json.loads((tmp_path / "opt" / "export-manifest.json").read_text())["jobs"]
    assert [j["service"] for j in jobs] == ["maria", "web"]
    bad = tmp_path / "bad"
    bad.mkdir()
    for eng in ({"db": "mongo"}, {"nosuch": "postgres"}):
        r = run_role(
            bad, "compose_app", "export_timer", role_vars(bad, compose_app_export_engines=eng)
        )
        assert r.returncode != 0 and "compose_app_export_engines" in r.stdout + r.stderr


def test_an_application_with_no_database_gets_no_timer(tmp_path):
    spec = {"services": {"web": SPEC["services"]["web"], "cache": SPEC["services"]["cache"]}}
    r = run_role(tmp_path, "compose_app", "export_timer", role_vars(tmp_path, spec=spec))
    assert r.returncode == 0, r.stdout + r.stderr
    assert not (tmp_path / "units" / "hnx-export-app.timer").exists()
    assert "enable" not in " ".join(calls(tmp_path))


def test_the_timer_a_database_left_is_removed_when_the_database_goes(tmp_path):
    first = run_role(tmp_path, "compose_app", "export_timer", role_vars(tmp_path))
    assert first.returncode == 0, first.stdout + first.stderr
    (tmp_path / "calls.log").unlink()
    spec = {"services": {"web": SPEC["services"]["web"]}}
    r = run_role(tmp_path, "compose_app", "export_timer", role_vars(tmp_path, spec=spec))
    assert r.returncode == 0, r.stdout + r.stderr
    assert not (tmp_path / "units" / "hnx-export-app.timer").exists()
    assert "systemctl disable --now hnx-export-app.timer" in calls(tmp_path)


FILES = [
    {"name": "app-db", "kind": "sqlite", "glob": "/srv/app/data/users/*/db.sqlite"},
    {"name": "app-state", "kind": "tree", "path": "/srv/app/state", "exclude": ["*.lock"]},
]


def test_files_alone_install_the_timer_with_no_compose_file_and_no_docker_condition(tmp_path):
    r = run_role(
        tmp_path,
        "compose_app",
        "export_timer",
        role_vars(tmp_path, spec={"services": {}}, compose_app_export_files=FILES),
    )
    assert r.returncode == 0, r.stdout + r.stderr
    mf = json.loads((tmp_path / "opt" / "export-manifest.json").read_text())
    assert mf["jobs"] == [
        {"service": "app-db", "engine": "sqlite", "glob": "/srv/app/data/users/*/db.sqlite"},
        {"service": "app-state", "engine": "tree", "path": "/srv/app/state", "exclude": ["*.lock"]},
    ]
    assert "compose_file" not in mf
    assert "ConditionPathExists" not in (tmp_path / "units" / "hnx-export-app.service").read_text()
    assert "systemctl enable --now hnx-export-app.timer" in calls(tmp_path)


def test_files_beside_a_database_keep_the_database_jobs_and_the_compose_file(tmp_path):
    r = run_role(
        tmp_path, "compose_app", "export_timer", role_vars(tmp_path, compose_app_export_files=FILES)
    )
    assert r.returncode == 0, r.stdout + r.stderr
    mf = json.loads((tmp_path / "opt" / "export-manifest.json").read_text())
    assert [j["engine"] for j in mf["jobs"]] == ["postgres", "mysql", "sqlite", "tree"]
    assert mf["compose_file"].endswith("docker-compose.yml")
    assert "ConditionPathExists" in (tmp_path / "units" / "hnx-export-app.service").read_text()


@pytest.mark.parametrize(
    "bad",
    [
        [{"name": "x", "kind": "zip", "path": "/a/b/c"}],
        [{"name": "x", "kind": "sqlite"}],
        [{"name": "x", "kind": "tree"}],
        [
            {"name": "x", "kind": "tree", "path": "/a/b/c"},
            {"name": "x", "kind": "tree", "path": "/a/b/d"},
        ],
        [{"name": "db", "kind": "tree", "path": "/a/b/c"}],  # a service of the spec
    ],
)
def test_a_file_job_the_script_would_not_run_is_refused_by_the_role(tmp_path, bad):
    r = run_role(
        tmp_path, "compose_app", "export_timer", role_vars(tmp_path, compose_app_export_files=bad)
    )
    assert r.returncode != 0 and "compose_app_export_files" in r.stdout + r.stderr


@pytest.mark.static
def test_the_script_is_a_program_the_interpreter_can_compile():
    compile(SCRIPT.read_text(), str(SCRIPT), "exec")
    assert sys.version_info >= (3, 8)
