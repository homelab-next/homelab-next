# SPDX-License-Identifier: Apache-2.0
"""The forge role's two helper scripts (modules/<id>/roles/<id>/files), run against real archives:
the helper reads a dump's counts and a content fingerprint and refuses a schema it does not know or
an instance with no account; the restore script places a dump into the data directory beside what
is there, takes only what it may, and refuses every path, member and state it must before it writes."""

from __future__ import annotations

import importlib.util
import json
import os
import sqlite3
import stat
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest
import yaml
from forge_front import dump_sql, make_dump

ROOT = Path(__file__).resolve().parents[2]


def _files_dir() -> Path:
    for d in sorted((ROOT / "modules").iterdir()):
        m = d / "module.yml"
        if m.is_file() and "forge" in (
            yaml.safe_load(m.read_text()).get("provides", {}).get("slots") or {}
        ):
            return d / "roles" / d.name / "files"
    raise AssertionError("no module fills the forge slot")


FILES = _files_dir()
P = FILES.parent.name  # the module id, which is the product the restore speaks
sys.dont_write_bytecode = True
sys.path.insert(0, str(FILES))


def _load(path: Path):
    spec = importlib.util.spec_from_file_location(path.stem, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


(HELPER_PATH,) = FILES.glob("hnx_*.py")
(RESTORE_PATH,) = FILES.glob("*_restore.py")
helper = _load(HELPER_PATH)
restore = _load(RESTORE_PATH)


@pytest.fixture
def data(tmp_path):
    d = tmp_path / "srv" / "app" / "data"
    d.mkdir(parents=True)
    return d


def cfg(data, zpath, **kw):
    return {
        "data": str(data),
        "zip": str(zpath),
        "uid": os.getuid(),
        "gid": os.getgid(),
        "stamp": "20261116T120000Z",
        **kw,
    }


# ----------------------------------------------------------------------------- the helper


def test_counts_and_fingerprint_come_from_the_dump_and_move_with_the_content(tmp_path):
    a = make_dump(tmp_path / "a.zip")
    b = make_dump(tmp_path / "b.zip", admin_hash="changed")
    fa, fb = helper.dbcounts({"zip": str(a)}), helper.dbcounts({"zip": str(b)})
    assert fa["counts"] == {
        "users": 2,
        "orgs": 1,
        "repos": 2,
        "issues": 0,
        "public_keys": 0,
        "access_tokens": 0,
        "packages": 0,
    }
    assert fa["counts"] == fb["counts"]  # a changed password hash moves no count ...
    assert (
        fa["fingerprint"]["user"] != fb["fingerprint"]["user"]
    )  # ... and does move the fingerprint
    assert fa["fingerprint"]["repository"] == fb["fingerprint"]["repository"]


def test_the_database_file_gives_the_same_facts_as_the_dump_it_was_built_from(tmp_path):
    z = make_dump(tmp_path / "a.zip")
    db = tmp_path / "x.db"
    sqlite3.connect(db).executescript(dump_sql())
    assert helper.dbcounts({"db": str(db)}) == helper.dbcounts({"zip": str(z)})


@pytest.mark.parametrize("kw, message", [
    ({"users": 0, "orgs": 0}, "no account"),
])  # fmt: skip
def test_an_instance_with_no_account_is_an_error_not_a_zero(tmp_path, kw, message):
    z = make_dump(tmp_path / "a.zip", **kw)
    with pytest.raises(helper.HelperError, match=message):
        helper.dbcounts({"zip": str(z)})


def test_a_schema_it_does_not_know_and_a_dump_without_sql_are_refused(tmp_path):
    db = tmp_path / "other.db"
    sqlite3.connect(db).executescript("CREATE TABLE unrelated (id INTEGER);")
    with pytest.raises(helper.HelperError, match="not an instance database"):
        helper.dbcounts({"db": str(db)})
    z = tmp_path / "nosql.zip"
    with zipfile.ZipFile(z, "w") as f:
        f.writestr("repos/a/b.git/HEAD", "x")
    with pytest.raises(helper.HelperError, match=r"no .*sql"):
        helper.dbcounts({"zip": str(z)})


def test_the_command_line_contract_reports_one_line_and_echoes_nothing(tmp_path):
    secret = "s" * 24
    r = subprocess.run([sys.executable, "-I", str(HELPER_PATH), "signin"], input=json.dumps({"admin_password": secret}),
                       capture_output=True, text=True)  # fmt: skip
    assert r.returncode == 1 and secret not in r.stderr and len(r.stderr.strip().splitlines()) == 1
    r = subprocess.run(
        [sys.executable, "-I", str(HELPER_PATH), "nope"], input="{}", capture_output=True, text=True
    )
    assert r.returncode == 2


# ----------------------------------------------------------------------------- the restore script


def test_it_places_the_instance_and_takes_only_what_it_may(tmp_path, data):
    z = make_dump(tmp_path / "d.zip")
    out = restore.restore(cfg(data, z))
    assert sorted(out["restored"]) == ["avatars", "git/repositories", f"{P}.db", "jwt"]
    assert (
        (data / "git" / "repositories" / "labs" / "alpha.git" / "HEAD")
        .read_text()
        .startswith("ref:")
    )
    assert (data / "avatars" / "a.png").is_file() and (data / "jwt" / "private.pem").is_file()
    for never in ("ssh", "log", "app.ini", ".restore-stage"):
        assert not (data / never).exists(), never
    assert out["counts"]["repos"] == 2 and out["aside"] == [] and out["leftover"] == []
    assert helper.dbcounts({"db": str(data / f"{P}.db")})["counts"] == out["counts"]
    for p in (data / "git", data / f"{P}.db", data / "git" / "repositories" / "labs"):
        assert p.stat().st_uid == os.getuid()


def test_what_is_there_is_renamed_aside_never_deleted_and_a_second_restore_keeps_both(
    tmp_path, data
):
    z = make_dump(tmp_path / "d.zip")
    restore.restore(cfg(data, z))
    (data / "git" / "repositories" / "labs" / "alpha.git" / "marker").write_text("first")
    (data / f"{P}.db-wal").write_text("w")
    out = restore.restore(cfg(data, z, stamp="20261116T130000Z"))
    aside = sorted(Path(p).name for p in out["aside"])
    assert aside == [f"{P}.db-wal.before-restore.20261116T130000Z", f"{P}.db.before-restore.20261116T130000Z",
                     "repositories.before-restore.20261116T130000Z"] or "repositories.before-restore.20261116T130000Z" in aside  # fmt: skip
    old = (
        data
        / "git"
        / "repositories.before-restore.20261116T130000Z"
        / "labs"
        / "alpha.git"
        / "marker"
    )
    assert old.read_text() == "first"
    assert not (data / "git" / "repositories" / "labs" / "alpha.git" / "marker").exists()


def test_a_stamp_already_used_stops_the_run_and_undoes_what_it_did(tmp_path, data):
    z = make_dump(tmp_path / "d.zip")
    restore.restore(cfg(data, z))
    (data / f"{P}.db.before-restore.20261116T130000Z").write_text("taken")
    (data / "git" / "repositories" / "marker").write_text("live")
    with pytest.raises(restore.RestoreError, match="already exists"):
        restore.restore(cfg(data, z, stamp="20261116T130000Z"))
    assert (data / "git" / "repositories" / "marker").read_text() == "live"  # untouched
    assert (data / f"{P}.db").is_file() and not (data / ".restore-stage").exists()


@pytest.mark.parametrize(
    "name", ["../escape", "repos/../../escape", "/abs/path", "repos/a\\b", "data/avatars/../../x"]
)
def test_a_member_that_could_leave_the_directory_is_refused_before_anything_is_written(
    tmp_path, data, name
):
    z = make_dump(tmp_path / "d.zip", extra=[(name, "x")])
    with pytest.raises(restore.RestoreError, match="refusing the member"):
        restore.restore(cfg(data, z))
    assert not (data / f"{P}.db").exists() and not (data / ".restore-stage").exists()
    assert not (tmp_path / "escape").exists()


def test_a_symbolic_link_member_is_refused(tmp_path, data):
    z = make_dump(tmp_path / "d.zip")
    with zipfile.ZipFile(z, "a") as f:
        info = zipfile.ZipInfo("repos/labs/alpha.git/link")
        info.external_attr = (stat.S_IFLNK | 0o777) << 16
        f.writestr(info, "/etc/passwd")
    with pytest.raises(restore.RestoreError, match="symbolic link"):
        restore.restore(cfg(data, z))
    assert not (data / f"{P}.db").exists() and not (data / ".restore-stage").exists()


def test_a_dump_with_no_repository_is_refused_unless_it_is_allowed(tmp_path, data):
    z = make_dump(tmp_path / "d.zip", repos=())
    with pytest.raises(restore.RestoreError, match="vacuous"):
        restore.restore(cfg(data, z))
    assert not (data / f"{P}.db").exists() and not (data / ".restore-stage").exists()
    out = restore.restore(cfg(data, z, allow_empty=True))
    assert out["counts"]["repos"] == 0


def test_an_unknown_schema_is_refused_and_the_stage_is_cleaned(tmp_path, data):
    z = tmp_path / "d.zip"
    with zipfile.ZipFile(z, "w") as f:
        f.writestr(f"{P}-db.sql", "CREATE TABLE unrelated (id INTEGER);")
        f.writestr("repos/a/b.git/HEAD", "x")
    with pytest.raises(helper.HelperError, match="not an instance database"):
        restore.restore(cfg(data, z))
    assert not (data / ".restore-stage").exists() and not (data / f"{P}.db").exists()


def test_a_leftover_stage_is_never_touched(tmp_path, data):
    (data / ".restore-stage").mkdir()
    (data / ".restore-stage" / "keep").write_text("evidence")
    with pytest.raises(restore.RestoreError, match="left by an earlier restore"):
        restore.restore(cfg(data, make_dump(tmp_path / "d.zip")))
    assert (data / ".restore-stage" / "keep").read_text() == "evidence"


@pytest.mark.parametrize(
    "path",
    [
        "/",
        "/srv",
        "/srv/app",
        "relative/dir",
        "/srv/../etc/x/y",
        "/srv/app//data",
        "/srv/app/data/",
    ],
)
def test_a_data_path_that_is_shallow_or_not_canonical_is_refused(tmp_path, path):
    with pytest.raises(restore.RestoreError):
        restore.restore(cfg(path, make_dump(tmp_path / "d.zip")))


def test_a_data_path_through_a_symbolic_link_is_refused(tmp_path, data):
    link = tmp_path / "srv" / "app" / "alias"
    link.symlink_to(data)
    with pytest.raises(restore.RestoreError, match="not a real directory"):
        restore.restore(cfg(link, make_dump(tmp_path / "d.zip")))


def test_a_live_path_that_is_a_symbolic_link_is_refused(tmp_path, data):
    (data / "avatars").symlink_to(tmp_path)
    with pytest.raises(restore.RestoreError, match="symbolic link"):
        restore.restore(cfg(data, make_dump(tmp_path / "d.zip")))
    assert not (data / ".restore-stage").exists()


def test_the_archive_must_be_a_regular_file(tmp_path, data):
    z = make_dump(tmp_path / "d.zip")
    link = tmp_path / "l.zip"
    link.symlink_to(z)
    with pytest.raises(restore.RestoreError, match="not a regular file"):
        restore.restore(cfg(data, link))
    with pytest.raises(restore.RestoreError, match="not a regular file"):
        restore.restore(cfg(data, tmp_path / "missing.zip"))
