# SPDX-License-Identifier: Apache-2.0
"""tools/migrate/forge.py: dump, stage, verify, freeze and unfreeze over ssh pipes, against a fake
host (a stopped or running container behind the ``docker`` command line the tool builds, a real
dump archive and a real SQLite database).  What is pinned: the dump is read-only on the source and
refused while it runs unless the caller says so; the export is never staged in a temporary
directory; counts, a content fingerprint and every repository's refs digest and fsck verdict are
recorded and compared; a source that proves nothing or disagrees with itself is refused; verify
finds a repository that moved, a changed account, a missing repository and a damaged export, and
removes only its own temporary file; stage creates a new directory under the data root and
overwrites nothing."""

from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import shlex
import shutil
import sqlite3
import sys
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tests" / "roles"))
sys.dont_write_bytecode = True
_spec = importlib.util.spec_from_file_location(
    "forge_migrate_tool", ROOT / "tools" / "migrate" / "forge.py"
)
mt = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = mt
_spec.loader.exec_module(mt)

from forge_front import dump_sql, make_dump, tsv

DEST = "ops@host.example.internal"
DATA_ROOT = "/srv/data/forge"
STAGE = "/srv/data/forge/export/incoming"
REPOS = (("labs", "alpha"), ("labs", "beta"))
# the three application secrets, built at run time from short pieces (never a long literal)
KEYS = {"SECRET_KEY": "k" * 40, "INTERNAL_TOKEN": "i" * 60, "JWT_SECRET": "j" * 43}
ALPHA = ("alpha" * 64)[:64]  # the digest the fake manifest gives labs/alpha


@pytest.fixture
def private():
    """A directory outside the system temporary directory, which the tool refuses for a dump."""
    base = ROOT / "build"
    base.mkdir(exist_ok=True)
    d = Path(tempfile.mkdtemp(prefix="migrate-", dir=base))
    assert not any(str(d).startswith(p) for p in mt.SCRATCH_DIRS)
    yield d
    shutil.rmtree(d, ignore_errors=True)


class Host:
    """One host's container: running or not, a repositories' manifest, a database file and the
    archive its dump command streams.  Every command the tool runs is interpreted from its argv."""

    def __init__(
        self,
        work: Path,
        *,
        running=False,
        repos=REPOS,
        fsck="ok",
        users=2,
        hook=None,
        keys=None,
        policy="always",
        encrypted=(),
        key_tables=True,
    ):
        self.running, self.fsck, self.repos, self.files, self.log = (
            running,
            fsck,
            list(repos),
            {},
            [],
        )
        self.users, self.hook, self.policy = users, hook, policy
        k = {**KEYS, **(keys or {})}
        # a stock app.ini: the product writes APP_NAME, RUN_MODE and WORK_PATH above the first section
        self.config = (
            "APP_NAME = Gitea: Git with a cup of tea\nRUN_MODE = prod\nWORK_PATH = /data/gitea\n\n"
            "[server]\nSSH_PORT = 22\n"
            f"[security]\nINSTALL_LOCK = true\nSECRET_KEY = {k['SECRET_KEY']}\n"
            f"INTERNAL_TOKEN = {k['INTERNAL_TOKEN']}\n[oauth2]\nJWT_SECRET = {k['JWT_SECRET']}\n"
        )
        sql_kw = {"repos": repos, "users": users, "encrypted": encrypted, "key_tables": key_tables}
        self.zip = make_dump(work / "src.zip", **sql_kw)
        self.db = work / "src.db"
        self.db.unlink(missing_ok=True)
        sqlite3.connect(self.db).executescript(dump_sql(**sql_kw))
        self.fail_dump = False

    def lines(self) -> str:
        return tsv(self.repos, self.fsck)

    def __call__(self, argv, *, stdin=None, stdout=None):
        self.log.append(list(argv))
        cmd = shlex.split(argv[-1]) if argv[0] == "ssh" else list(argv)
        if cmd[:2] == ["sudo", "-n"]:
            cmd = cmd[2:]
        out = self._run(cmd, stdin)
        if isinstance(out, int):
            return out, b"", b"failed"
        if stdout is not None:
            stdout.write(out)
            return 0, b"", b""
        return 0, out, b""

    def _inner(self, cmd):
        """The command a ``docker exec`` or one-off ``docker run`` runs in the container."""
        if cmd[1] == "exec":
            rest = cmd[2:]
            if rest[0] == "-u":
                rest = rest[2:]
            return rest[1:]
        i = cmd.index("--entrypoint")
        return [cmd[i + 1], *cmd[i + 3 :]]

    def _run(self, cmd, stdin):
        if cmd[0] == "docker":
            if cmd[1] == "inspect":
                if "RestartPolicy" in cmd[3]:
                    return self.policy.encode()
                return (
                    (b"true" if self.running else b"false")
                    if "State.Running" in cmd[3]
                    else b"img:1"
                )
            if cmd[1] == "update":
                self.policy = cmd[2].split("=", 1)[1]
                return b""
            if cmd[1] in ("stop", "start"):
                self.running = cmd[1] == "start"
                return b""
            inner = self._inner(cmd)
            if self.hook:
                self.hook(self, inner)
            if inner[:2] == [mt.PRODUCT, "--version"]:
                return f"{mt.PRODUCT} version 28.4.0 built with go".encode()
            if inner[0] == "sh":
                return self.lines().encode()
            if inner[0] == "cat":
                return self.config.encode() if inner[1].endswith(".ini") else self.db.read_bytes()
            if inner[0] == mt.PRODUCT and "dump" in inner:
                return 1 if self.fail_dump else self.zip.read_bytes()
        if cmd[0] == "mkdir":
            if cmd[-1] in self.files.get("dirs", set()):
                return 1
            self.files.setdefault("dirs", set()).add(cmd[-1])
            return b""
        if cmd[0] == "sh":
            path = cmd[-1]
            if path in self.files:
                return 1
            self.files[path] = stdin.read()
            return b""
        if cmd[0] == "sha256sum":
            return f"{hashlib.sha256(self.files[cmd[-1]]).hexdigest()}  {cmd[-1]}\n".encode()
        raise AssertionError(f"unexpected command {cmd}")

    def ctx(self):
        return mt._Ctx(runner=self)


def ep(**kw):
    return mt.Endpoint(container="forge-1", ssh=DEST, data_root=DATA_ROOT, **kw)


def _dump(private, host, **kw):
    return mt.dump(ep(), private / "out", _ctx=host.ctx(), **kw)


# ----------------------------------------------------------------------------- dump


def test_a_stopped_source_is_dumped_read_only_with_counts_fingerprint_and_every_repository(private):
    host = Host(private)
    m = _dump(private, host)
    out = private / "out"
    assert sorted(p.name for p in out.iterdir()) == [
        "dump.zip",
        "listing.jsonl",
        "manifest.json",
        "repos.tsv",
    ]
    assert (
        oct(out.stat().st_mode & 0o777) == "0o700"
        and oct((out / "dump.zip").stat().st_mode & 0o777) == "0o600"
    )
    assert m["counts"]["users"] == 2 and m["counts"]["repos"] == 2 and m["repositories"] == 2
    assert m["product_version"] == "28.4.0" and m["source"] == {"frozen": True, "quiescent": True}
    assert (out / "repos.tsv").read_text() == tsv(REPOS)
    for row in map(json.loads, (out / "listing.jsonl").read_text().splitlines()):
        assert hashlib.sha256((out / row["key"]).read_bytes()).hexdigest() == row["sha256"]
    # a stopped source is read through a one-off container over its volumes: nothing is started
    assert not any(shlex.split(a[-1])[3:4] in (["stop"], ["start"], ["rm"]) for a in host.log)
    assert any("--volumes-from" in a[-1] for a in host.log) and not any(
        " exec " in a[-1] for a in host.log
    )


def test_a_running_source_is_refused_unless_a_live_copy_is_asked_for_and_then_says_it_was_not_frozen(
    private,
):
    host = Host(private, running=True)
    with pytest.raises(mt.MigrateError, match="freeze it first"):
        _dump(private, host)
    assert not any("dump" in a[-1] for a in host.log)
    m = mt.dump(ep(), private / "live", allow_live=True, _ctx=host.ctx())
    assert m["source"] == {"frozen": False, "quiescent": False}
    assert any(" exec " in a[-1] for a in host.log)


def test_a_source_whose_repositories_move_during_the_dump_is_not_quiescent(private):
    host = Host(private)
    moved = tsv((*REPOS[:1], ("labs", "beta"))).replace(ALPHA, "9" * 64)
    states = iter([tsv(REPOS)])
    host.lines = lambda: next(states, moved)  # the first read, then a push has landed
    m = mt.dump(ep(), private / "out2", _ctx=host.ctx())
    assert m["source"]["frozen"] is True and m["source"]["quiescent"] is False


def test_an_export_is_never_staged_in_a_temporary_directory_or_a_non_empty_one(private):
    host = Host(private)
    with pytest.raises(mt.MigrateError, match="password hash"):
        mt.dump(ep(), Path(tempfile.gettempdir()) / "forge-x", _ctx=host.ctx())
    (private / "full").mkdir()
    (private / "full" / "f").write_text("x")
    with pytest.raises(mt.MigrateError, match="not empty"):
        mt.dump(ep(), private / "full", _ctx=host.ctx())
    assert (private / "full" / "f").read_text() == "x" and not any(
        "dump" in a[-1] for a in host.log
    )


@pytest.mark.parametrize("kw, message", [
    ({"fsck": "fail"}, "fsck fails"),
    ({"users": 0}, "no account|vacuous"),
    ({"repos": ()}, "vacuous"),
])  # fmt: skip
def test_a_source_that_proves_nothing_or_is_damaged_is_refused_and_leaves_no_archive(
    private, kw, message
):
    host = Host(private, **kw)
    with pytest.raises(mt.VerifyMismatch, match=message):
        _dump(private, host)
    assert not (private / "out" / "dump.zip").exists()


def test_a_database_and_a_disk_that_disagree_are_refused(private):
    host = Host(private)
    host.repos = host.repos[:1]  # the manifest the disk gives has one repository, the database two
    with pytest.raises(mt.VerifyMismatch, match="disagrees with itself"):
        _dump(private, host)


def test_a_failing_dump_command_leaves_no_partial_archive(private):
    host = Host(private)
    host.fail_dump = True
    with pytest.raises(mt.MigrateError, match="failed"):
        _dump(private, host)
    assert not (private / "out" / "dump.zip").exists()


def test_an_empty_instance_is_dumped_only_when_it_is_asked_for(private):
    host = Host(private, repos=())
    with pytest.raises(mt.VerifyMismatch):
        _dump(private, host)
    m = mt.dump(ep(), private / "empty", allow_empty=True, _ctx=host.ctx())
    assert m["counts"]["repos"] == 0


# ----------------------------------------------------------------------------- verify


def _exported(private, **kw):
    src = Host(private / "s" if False else private, **kw)
    mt.dump(ep(), private / "out", _ctx=src.ctx())
    return src


def test_a_target_equal_to_the_export_verifies_and_the_temporary_file_is_gone(private):
    _exported(private)
    target = Host(private)
    r = mt.verify(ep(), private / "out", _ctx=target.ctx())
    assert r["verified"] is True and r["repositories"] == 2 and r["counts"]["users"] == 2
    assert [p.name for p in (private / "out").iterdir() if p.name.startswith(".")] == []


@pytest.mark.parametrize("make, message", [
    (lambda w: Host(w, users=3), "counts differ"),
    (lambda w: Host(w, repos=(("labs", "alpha"), ("labs", "zeta"))), "repositories differ"),
    (lambda w: Host(w, fsck="fail"), "repositories differ"),
])  # fmt: skip
def test_a_target_that_differs_is_named(private, make, message):
    _exported(private)
    with pytest.raises(mt.VerifyMismatch, match=message):
        mt.verify(ep(), private / "out", _ctx=make(private).ctx())
    assert not (private / "out" / ".verify.db").exists()  # removed even on failure


def test_a_changed_account_that_moves_no_count_is_found_by_the_fingerprint(private):
    _exported(private)
    target = Host(private)
    db = sqlite3.connect(target.db)
    db.execute("UPDATE \"user\" SET passwd = 'other' WHERE id = 1")
    db.commit()
    db.close()
    with pytest.raises(mt.VerifyMismatch, match="content of user differs"):
        mt.verify(ep(), private / "out", _ctx=target.ctx())


def test_a_repository_that_moved_is_found_by_its_refs_digest(private):
    _exported(private)
    target = Host(private)
    target.lines = lambda: tsv(REPOS).replace(ALPHA, "9" * 64)
    with pytest.raises(mt.VerifyMismatch, match=r"labs/alpha\.git"):
        mt.verify(ep(), private / "out", _ctx=target.ctx())


def test_a_damaged_export_is_refused_before_the_target_is_read(private):
    _exported(private)
    with (private / "out" / "dump.zip").open("ab") as f:
        f.write(b"x")
    target = Host(private)
    with pytest.raises(mt.VerifyMismatch, match="differs from its listing"):
        mt.verify(ep(), private / "out", _ctx=target.ctx())
    assert target.log == []


def test_an_export_that_holds_nothing_verifies_nothing(private):
    _exported(private)
    m = json.loads((private / "out" / "manifest.json").read_text())
    m["counts"]["repos"] = 0
    (private / "out" / "manifest.json").write_text(json.dumps(m))
    rows = []
    for n in ("dump.zip", "manifest.json", "repos.tsv"):
        b = (private / "out" / n).read_bytes()
        rows.append(json.dumps({"key": n, "size": len(b), "sha256": hashlib.sha256(b).hexdigest()}))
    (private / "out" / "listing.jsonl").write_text("\n".join(rows) + "\n")
    with pytest.raises(mt.MigrateError, match="refusing to call anything verified"):
        mt.verify(ep(), private / "out", _ctx=Host(private).ctx())


def test_a_final_delta_needs_an_export_from_a_frozen_source(private):
    mt.dump(ep(), private / "out", allow_live=True, _ctx=Host(private, running=True).ctx())
    with pytest.raises(mt.MigrateError, match="not dumped from a frozen source"):
        mt.verify(ep(), private / "out", require_quiescent=True, _ctx=Host(private).ctx())


# ----------------------------------------------------------------------------- stage


def test_stage_creates_a_new_directory_under_the_data_root_and_checks_every_file(private):
    _exported(private)
    target = Host(private)
    assert mt.stage(ep(), private / "out", STAGE, _ctx=target.ctx()) == STAGE
    assert sorted(k.rsplit("/", 1)[1] for k in target.files if k != "dirs") == [
        "dump.zip",
        "listing.jsonl",
        "manifest.json",
        "repos.tsv",
    ]
    assert target.files[f"{STAGE}/dump.zip"] == (private / "out" / "dump.zip").read_bytes()
    with pytest.raises(mt.MigrateError, match="failed"):  # a second stage into the same directory
        mt.stage(ep(), private / "out", STAGE, _ctx=target.ctx())


@pytest.mark.parametrize("dest", [
    "/", "/srv", "/srv/data", "/srv/data/forge", "relative/dir", "/srv/data/forge/../x/y",
    "/srv/data/forge//x", "/srv/data/forge/x/", "/etc/forge/incoming", "/srv/data/forgery/incoming",
])  # fmt: skip
def test_a_destination_that_is_shallow_not_canonical_or_outside_the_data_root_is_refused(
    private, dest
):
    _exported(private)
    target = Host(private)
    with pytest.raises(mt.MigrateError):
        mt.stage(ep(), private / "out", dest, _ctx=target.ctx())
    assert target.log == []


def test_stage_needs_the_data_root_and_an_intact_export(private):
    _exported(private)
    with pytest.raises(mt.MigrateError, match="data root"):
        mt.stage(
            mt.Endpoint(container="c", ssh=DEST), private / "out", STAGE, _ctx=Host(private).ctx()
        )
    with (private / "out" / "repos.tsv").open("a") as f:
        f.write("x\n")
    target = Host(private)
    with pytest.raises(mt.MigrateError, match="differs from its listing"):
        mt.stage(ep(), private / "out", STAGE, _ctx=target.ctx())
    assert target.log == []


def test_a_copy_that_arrives_different_is_an_error(private):
    _exported(private)
    target = Host(private)
    real = target._run

    def bad(cmd, stdin):
        if cmd[0] == "sha256sum":
            return b"0" * 64 + b"  x\n"
        return real(cmd, stdin)

    target._run = bad
    with pytest.raises(mt.MigrateError, match="sha256 differs"):
        mt.stage(ep(), private / "out", STAGE, _ctx=target.ctx())


# ----------------------------------------------------------------------------- freeze, guards, cli


def test_freeze_and_unfreeze_only_stop_and_start_the_container():
    host = Host(
        Path(tempfile.mkdtemp(dir=ROOT / "build" if (ROOT / "build").exists() else None)),
        running=True,
    )
    got = mt.freeze(ep(), _ctx=host.ctx())
    assert got == {"stopped": "forge-1", "running": False, "restart_policy_was": "always"}
    assert host.policy == "no"  # a reboot of the source's host cannot start it again
    assert mt.unfreeze(ep(), restart=got["restart_policy_was"], _ctx=host.ctx()) == {
        "started": "forge-1",
        "running": True,
    }
    assert host.policy == "always"
    verbs = [shlex.split(a[-1])[3] for a in host.log if shlex.split(a[-1])[3] in ("stop", "start")]
    assert verbs == ["stop", "start"]
    with pytest.raises(mt.MigrateError, match="--restart"):
        mt.unfreeze(ep(), restart="sometimes", _ctx=host.ctx())


def test_a_freeze_of_an_instance_with_no_restart_policy_changes_no_policy():
    host = Host(Path(tempfile.mkdtemp(dir=ROOT / "build" if (ROOT / "build").exists() else None)),
                running=True, policy="no")  # fmt: skip
    assert mt.freeze(ep(), _ctx=host.ctx())["restart_policy_was"] == "no"
    assert not any(shlex.split(a[-1])[3:4] == ["update"] for a in host.log)


@pytest.mark.parametrize("path, ok", [
    ("/srv/data/x", True), ("/srv/data", False), ("/", False), ("/srv", False), ("srv/data/x", False),
    ("/srv/data/../x", False), ("/srv//data/x", False), ("/srv/data/x/", False), ("/srv/./data/x", False),
])  # fmt: skip
def test_guard_dir_refuses_shallow_and_non_canonical_paths(path, ok):
    if ok:
        assert mt.guard_dir(path) == path
    else:
        with pytest.raises(mt.MigrateError):
            mt.guard_dir(path)


def test_guard_dir_keeps_a_path_inside_its_root_and_the_endpoint_refuses_relative_paths():
    assert mt.guard_dir("/srv/data/forge/x", root="/srv/data/forge")
    for bad in ("/srv/data/forge", "/srv/data/other/x", "/srv/data/forgery/x"):
        with pytest.raises(mt.MigrateError):
            mt.guard_dir(bad, root="/srv/data/forge")
    with pytest.raises(mt.MigrateError):
        mt.Endpoint(container="c", db_path="relative.db")


def test_the_command_line_maps_a_mismatch_to_1_and_a_usage_error_to_2(private, capsys, monkeypatch):
    host = Host(private)
    monkeypatch.setattr(mt, "_subprocess_runner", host)
    base = ["--ssh", DEST, "--container", "forge-1"]
    assert mt.main(["dump", *base, "--dir", str(private / "out")]) == 0
    assert json.loads(capsys.readouterr().out)["counts"]["users"] == 2
    host.users = 3
    host.db.unlink()
    sqlite3.connect(host.db).executescript(dump_sql(users=3))
    assert mt.main(["verify", *base, "--dir", str(private / "out")]) == 1
    assert "counts differ" in capsys.readouterr().err
    assert mt.main(["verify", *base]) == 2  # no --dir
    assert mt.main(["stage", *base, "--dir", str(private / "out")]) == 2  # no --dest
    assert io.StringIO is not None


# ----------------------------------------------------------------------------- the secrets


def _zip_names(path):
    import zipfile

    with zipfile.ZipFile(path) as z:
        return z.namelist()


def test_the_export_has_no_configuration_and_records_fingerprints_never_values(private):
    host = Host(private)
    assert "app.ini" in _zip_names(host.zip)  # the product's dump carries it
    m = _dump(private, host)
    out = private / "out"
    assert "app.ini" not in _zip_names(out / "dump.zip")
    assert "data/jwt/private.pem" in _zip_names(out / "dump.zip")  # the rest of the archive is kept
    assert sorted(m["app_key_fingerprints"]) == ["internal_token", "jwt_secret", "secret_key"]
    assert m["config_included"] is False
    blob = b"".join(p.read_bytes() for p in out.iterdir())
    for value in KEYS.values():
        assert value.encode() not in blob
    assert not (out / ".dump.stripped").exists()
    assert all(oct(p.stat().st_mode & 0o777) == "0o600" for p in out.iterdir())


def test_a_target_with_the_sources_secrets_verifies_and_one_with_another_secret_key_is_refused(
    private,
):
    _dump(private, Host(private))
    ok = mt.verify(ep(), private / "out", _ctx=Host(private).ctx())
    assert ok["verified"] is True
    other = Host(private, keys={"SECRET_KEY": "x" * 40})
    with pytest.raises(mt.VerifyMismatch, match="secret_key") as e:
        mt.verify(ep(), private / "out", _ctx=other.ctx())
    assert "x" * 40 not in str(e.value) and "k" * 40 not in str(e.value)
    assert "internal_token" not in str(e.value)  # only the one that differs is named
    for name in ("INTERNAL_TOKEN", "JWT_SECRET"):
        with pytest.raises(mt.VerifyMismatch, match=name.lower()):
            mt.verify(ep(), private / "out", _ctx=Host(private, keys={name: "y" * 50}).ctx())


def test_an_export_with_no_fingerprints_and_a_target_without_the_keys_prove_nothing(private):
    _dump(private, Host(private))
    path = private / "out" / "manifest.json"
    doc = json.loads(path.read_text())
    del doc["app_key_fingerprints"]
    path.write_text(json.dumps(doc))
    rows = [json.loads(ln) for ln in (private / "out" / "listing.jsonl").read_text().splitlines()]
    for r in rows:
        if r["key"] == "manifest.json":
            r["size"], r["sha256"] = mt._sha256(path)
    (private / "out" / "listing.jsonl").write_text("\n".join(json.dumps(r) for r in rows) + "\n")
    with pytest.raises(mt.VerifyMismatch, match="no fingerprint"):
        mt.verify(ep(), private / "out", _ctx=Host(private).ctx())
    bare = Host(private)
    bare.config = "[server]\nSSH_PORT = 22\n"
    # no SECRET_KEY is the built-in key's case (below); the other two must still be in plain text
    with pytest.raises(mt.MigrateError, match="INTERNAL_TOKEN"):
        mt.dump(ep(), private / "out3", _ctx=bare.ctx())
    assert not (private / "out3" / "dump.zip").exists()


def test_an_export_with_an_attach_statement_is_refused_and_creates_no_file(private):
    import zipfile

    target = private / "created-by-the-dump"
    host = Host(private)
    sql = f"ATTACH DATABASE '{target}' AS x;\nCREATE TABLE x.t (a);\n" + dump_sql()
    bad = private / "bad.zip"
    with zipfile.ZipFile(bad, "w") as z:
        z.writestr(f"{mt.MID}-db.sql", sql)
    host.zip = bad
    with pytest.raises(mt.VerifyMismatch, match="SQL was refused"):
        _dump(private, host)
    assert not target.exists()
    assert not (private / "out" / "dump.zip").exists()


# ----------------------------------------------------------------------------- a SECRET_KEY never set
# The source's configuration sets no SECRET_KEY, so the product runs on its built-in default key.
# That key is not carried: the dump proves from its own database that nothing is encrypted under
# it and records the proof, and the target then takes a fresh key; a row encrypted under it, an
# unknown schema or a missing proof is a refusal. The source's own key keeps the copy path.

FRESH = {"SECRET_KEY": "f" * 43}  # what a generated secret looks like (43 URL-safe characters)
_helper = mt._load_helper()


def _builtin_source(private, how="empty", **kw):
    host = Host(private, keys={"SECRET_KEY": ""}, **kw)
    if how == "absent":
        host.config = host.config.replace("SECRET_KEY = \n", "")
    elif how == "default":
        host.config = host.config.replace(
            "SECRET_KEY = ", "SECRET_KEY = " + _helper.BUILTIN_APP_KEY
        )
    return host


@pytest.mark.parametrize("how", ["empty", "absent", "default"])
def test_a_source_on_the_built_in_key_with_nothing_under_it_is_dumped_with_the_proof(private, how):
    m = _dump(private, _builtin_source(private, how))
    assert m["secret_key_source"] == "builtin-default"
    proof = m["secret_key_unused_proof"]
    assert proof["rules"] == _helper.APP_KEY_USES_RULES
    assert proof["encrypted_rows"] == dict.fromkeys(sorted(_helper.APP_KEY_USES), 0)
    # the key is not carried, so it has no fingerprint; the other two are the source's
    assert sorted(m["app_key_fingerprints"]) == ["internal_token", "jwt_secret"]
    assert _helper.BUILTIN_APP_KEY.encode() not in (private / "out" / "manifest.json").read_bytes()


def test_a_target_with_a_fresh_key_verifies_and_one_on_the_default_or_other_secrets_does_not(
    private,
):
    _dump(private, _builtin_source(private))
    ok = mt.verify(ep(), private / "out", _ctx=Host(private, keys=FRESH).ctx())
    assert ok["verified"] is True
    with pytest.raises(mt.VerifyMismatch, match="built-in default SECRET_KEY"):
        mt.verify(ep(), private / "out", _ctx=Host(private, keys={"SECRET_KEY": ""}).ctx())
    for name in ("INTERNAL_TOKEN", "JWT_SECRET"):
        other = Host(private, keys={**FRESH, name: "y" * 50})
        with pytest.raises(mt.VerifyMismatch, match=name.lower()):
            mt.verify(ep(), private / "out", _ctx=other.ctx())


@pytest.mark.parametrize("table", ["two_factor", "secret", "webhook", "login_source", "task"])
def test_a_source_on_the_built_in_key_with_a_row_encrypted_under_it_is_refused(private, table):
    with pytest.raises(mt.VerifyMismatch, match=rf"built-in default SECRET_KEY.*{table}: 1 rows"):
        _dump(private, _builtin_source(private, encrypted=[table]))
    assert not (private / "out" / "dump.zip").exists()
    assert not (private / "out" / "manifest.json").exists()


def test_a_source_on_the_built_in_key_whose_schema_is_unknown_is_refused(private):
    with pytest.raises(mt.VerifyMismatch, match="cannot prove what is encrypted"):
        _dump(private, _builtin_source(private, key_tables=False))
    assert not (private / "out" / "dump.zip").exists()


def _edit_manifest(out: Path, edit) -> None:
    path = out / "manifest.json"
    doc = json.loads(path.read_text())
    edit(doc)
    path.write_text(json.dumps(doc))
    rows = [json.loads(ln) for ln in (out / "listing.jsonl").read_text().splitlines()]
    for r in rows:
        if r["key"] == "manifest.json":
            r["size"], r["sha256"] = mt._sha256(path)
    (out / "listing.jsonl").write_text("\n".join(json.dumps(r) for r in rows) + "\n")


@pytest.mark.parametrize("edit, message", [
    (lambda m: m.pop("secret_key_unused_proof"), "no proof"),
    (lambda m: m["secret_key_unused_proof"].update(rules="1.0.0"), "no proof"),
    (lambda m: m["secret_key_unused_proof"]["encrypted_rows"].pop("task"), "no proof"),
    (lambda m: m["secret_key_unused_proof"]["encrypted_rows"].update(two_factor=2), "records rows"),
])  # fmt: skip
def test_verify_refuses_an_export_whose_proof_is_absent_incomplete_or_not_zero(
    private, edit, message
):
    _dump(private, _builtin_source(private))
    _edit_manifest(private / "out", edit)
    with pytest.raises(mt.VerifyMismatch, match=message):
        mt.verify(ep(), private / "out", _ctx=Host(private, keys=FRESH).ctx())


def test_a_source_with_its_own_key_keeps_the_copy_path_and_a_fresh_key_is_refused(private):
    m = _dump(private, Host(private))
    assert m["secret_key_source"] == "configured" and "secret_key_unused_proof" not in m
    assert sorted(m["app_key_fingerprints"]) == ["internal_token", "jwt_secret", "secret_key"]
    with pytest.raises(mt.VerifyMismatch, match="secret_key is not the source's"):
        mt.verify(ep(), private / "out", _ctx=Host(private, keys=FRESH).ctx())


@pytest.mark.parametrize(
    "top", ["", "APP_NAME = x\nRUN_MODE = prod\n\n", "; a comment\nWORK_PATH = /data/gitea\n"]
)
def test_a_configuration_with_keys_above_the_first_section_is_read(private, top):
    # the product's own app.ini starts with section-less keys (go-ini's default section)
    host = Host(private)
    host.config = top + host.config.split("\n\n", 1)[-1]
    m = _dump(private, host)
    assert m["secret_key_source"] == "configured"
    assert sorted(m["app_key_fingerprints"]) == ["internal_token", "jwt_secret", "secret_key"]
