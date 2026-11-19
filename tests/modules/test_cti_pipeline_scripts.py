# SPDX-License-Identifier: Apache-2.0
"""The cti-pipeline module's scripts (modules/cti-pipeline/roles/cti_pipeline/files), run in
process: standard library only, no ansible, no network.

* ``cti_artefact.py``: an artefact is installed only when it hashes to the pin (a wrong one is
  refused before anything is unpacked, and leaves no trace), unpacked only of regular files and
  directories (a climbing path, a link, a shipped venv refused), renamed into place when complete,
  and a second install of the same pin changes nothing; prune never takes the current release.
* ``hnx-cti-run``: the lane guard (the shadow lane stages and writes only a shadow schema), a spec
  only root (here: the test's uid) can write, the dispatcher's lane, credentials exported to the
  step processes only, the steps in order with the first failure ending the job, and the run record
  the freshness check reads.
* ``cti_state.py``: export then check round-trips; a store whose row counts differ from its
  counts (or the source's) is refused; restore moves the replaced directories aside; freshness
  and the gateway verdict (empty content is a failure).
"""

from __future__ import annotations

import hashlib
import importlib.machinery
import importlib.util
import io
import json
import os
import sqlite3
import sys
import tarfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
FILES = ROOT / "modules" / "cti-pipeline" / "roles" / "cti_pipeline" / "files"


def _load(name: str, path: Path):
    loader = importlib.machinery.SourceFileLoader(name, str(path))
    spec = importlib.util.spec_from_loader(name, loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


art = _load("cti_artefact", FILES / "cti_artefact.py")
run = _load("hnx_cti_run", FILES / "hnx-cti-run")
state = _load("cti_state", FILES / "cti_state.py")


# ----------------------------------------------------------------------------- the artefact


def _tar(path: Path, members: dict[str, bytes], links: dict[str, str] | None = None) -> str:
    with tarfile.open(path, "w:gz") as tf:
        for name, data in members.items():
            ti = tarfile.TarInfo(name)
            ti.size = len(data)
            ti.mode = 0o755 if name.endswith(".sh") else 0o644
            tf.addfile(ti, io.BytesIO(data))
        for name, target in (links or {}).items():
            ti = tarfile.TarInfo(name)
            ti.type = tarfile.SYMTYPE
            ti.linkname = target
            tf.addfile(ti)
    return hashlib.sha256(path.read_bytes()).hexdigest()


GOOD = {
    "hnx-artefact.json": json.dumps({"name": "intel-app", "version": "1.0"}).encode(),
    "app/run.py": b"print('ok')\n",
    "app/scripts/episode.sh": b"#!/bin/sh\n",
}


@pytest.fixture
def releases(tmp_path):
    d = tmp_path / "opt" / "hnx" / "intel" / "releases"
    d.mkdir(parents=True)
    return d


def test_an_artefact_is_installed_once_and_renamed_into_place(tmp_path, releases):
    sha = _tar(tmp_path / "a.tar.gz", GOOD)
    out = art.install(str(tmp_path / "a.tar.gz"), sha, str(releases), sys.executable)
    rel = releases / sha[:16]
    assert out["changed"] and out["release"] == str(rel) and out["version"] == "1.0"
    assert (rel / ".hnx-installed").read_text().strip() == sha
    assert (rel / "venv" / "bin" / "python").exists()  # built on the host, offline
    assert (
        os.stat(rel / "app" / "scripts" / "episode.sh").st_mode & 0o777 == 0o700
    )  # owner-only until the role grants the group
    assert os.stat(rel / "app" / "run.py").st_mode & 0o777 == 0o600
    assert sorted(p.name for p in releases.iterdir()) == [sha[:16]]  # no incoming left
    again = art.install(str(tmp_path / "a.tar.gz"), sha, str(releases), sys.executable)
    assert again == {"changed": False, "release": str(rel)}


def test_an_artefact_that_is_not_the_pin_is_refused_before_anything_is_written(tmp_path, releases):
    _tar(tmp_path / "a.tar.gz", GOOD)
    other = hashlib.sha256(b"another build").hexdigest()
    with pytest.raises(art.Refused, match=r"hashes to .* the pin is"):
        art.install(str(tmp_path / "a.tar.gz"), other, str(releases), sys.executable)
    assert list(releases.iterdir()) == []
    assert (
        art.main(["install", str(tmp_path / "a.tar.gz"), other, str(releases), sys.executable]) == 1
    )


@pytest.mark.parametrize(
    ("members", "links", "why"),
    [
        ({**GOOD, "../escape.txt": b"x"}, None, "climbs out"),
        ({**GOOD, "/etc/passwd": b"x"}, None, "absolute"),
        (GOOD, {"app/link": "/etc"}, "not a regular file"),
        ({**GOOD, "venv/bin/python": b"x"}, None, "carries a venv"),
        ({"app/run.py": b"x"}, None, "no hnx-artefact.json"),
        ({**GOOD, "App/Run.py": b"x", "app/run.PY": b"y", "APP/RUN.PY": b"z"}, None, "repeats"),
    ],
)
def test_an_unsafe_or_malformed_artefact_is_refused_and_leaves_nothing(
    tmp_path, releases, members, links, why
):
    sha = _tar(tmp_path / "bad.tar.gz", members, links)
    with pytest.raises(art.Refused, match=why):
        art.install(str(tmp_path / "bad.tar.gz"), sha, str(releases), sys.executable)
    assert list(releases.iterdir()) == []


def test_prune_keeps_the_newest_and_never_the_current_release(releases):
    names = [f"{i:016x}" for i in range(5)]
    for i, name in enumerate(names):
        (releases / name).mkdir()
        os.utime(releases / name, (1_000_000 + i, 1_000_000 + i))
    (releases / "not-a-release").mkdir()
    out = art.prune(str(releases), names[0], 2)  # the oldest is current: kept
    assert sorted(out["removed"]) == names[1:4]
    assert sorted(p.name for p in releases.iterdir()) == sorted(
        [names[0], names[4], "not-a-release"]
    )


# ----------------------------------------------------------------------------- the job wrapper


def _spec(tmp_path: Path, lane: str = "real", **over) -> tuple[Path, dict]:
    root = tmp_path / "var" / "lib" / "intel" / lane
    (root / "hnx-runs").mkdir(parents=True)
    probe = tmp_path / "probe.py"
    probe.write_text(
        "import json, os, sys\n"
        "out = {k: os.environ.get(k) for k in ['FEED_USER', 'APP_MODE', 'LAKE_SCHEMA', 'PUBLISH_MODE', 'HNX_RUN_ID']}\n"
        "out['argv'] = sys.argv[1:]\nout['cwd'] = os.getcwd()\n"
        "open(os.environ['PROBE_OUT'], 'a').write(json.dumps(out) + '\\n')\n"
        "sys.exit(int(sys.argv[1]) if sys.argv[1:2] and sys.argv[1].isdigit() else 0)\n"
    )
    spec = {
        "version": 1, "set": "intel", "job": "fresh", "lane": lane, "instance": f"fresh-{lane}",
        "lane_root": str(root), "runs_dir": str(root / "hnx-runs"),
        "steps": [["{python}", str(probe), "first"], ["{python}", str(probe), "{lane_root}"]],
        "env": {"APP_MODE": "x", "PROBE_OUT": str(tmp_path / "probe.jsonl")},
        "forced_env": {"LAKE_SCHEMA": "intel_shadow" if lane == "shadow" else "intel", "PUBLISH_MODE": "stage"},
        "lake_schema_env": "LAKE_SCHEMA", "publish_mode_env": "PUBLISH_MODE",
        "placeholders": {"python": sys.executable, "lane_root": str(root)},
    }  # fmt: skip
    spec.update(over)
    path = tmp_path / "etc" / f"fresh-{lane}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(spec))
    path.chmod(0o644)
    return path, spec


def _creds(tmp_path: Path, lane: str = "real") -> Path:
    d = tmp_path / "creds"
    d.mkdir(exist_ok=True)
    (d / "FEED_USER").write_text("alice\n")
    (d / "hnx-dispatch").write_text(
        json.dumps({"run_id": "run-1", "lane": lane, "agent_key": "intel-fresh"})
    )
    return d


def _main(spec: Path, instance: str, creds: Path, monkeypatch) -> int:
    # the wrapper changes into the lane root: monkeypatch puts this process's directory back after
    # the test (other suites resolve paths against it)
    monkeypatch.chdir(os.getcwd())
    monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(creds))
    return run.main(["--spec", str(spec), "--instance", instance, "--spec-owner", str(os.getuid())])


def test_the_steps_run_in_the_lane_root_with_the_credentials_in_their_environment_only(
    tmp_path, monkeypatch, capsys
):
    spec, body = _spec(tmp_path)
    assert _main(spec, "fresh-real", _creds(tmp_path), monkeypatch) == 0
    rows = [json.loads(x) for x in (tmp_path / "probe.jsonl").read_text().splitlines()]
    assert [r["argv"][0] for r in rows] == ["first", body["lane_root"]]
    assert {r["cwd"] for r in rows} == {body["lane_root"]}
    assert (
        rows[0]["FEED_USER"] == "alice"
        and rows[0]["APP_MODE"] == "x"
        and rows[0]["HNX_RUN_ID"] == "run-1"
    )
    assert rows[0]["LAKE_SCHEMA"] == "intel" and rows[0]["PUBLISH_MODE"] == "stage"
    assert "alice" not in capsys.readouterr().out  # never in the log
    rec = json.loads(Path(body["runs_dir"], "fresh.json").read_text())
    assert (
        rec["ok"] is True and rec["exit"] == 0 and rec["run_id"] == "run-1" and rec["finished_at"]
    )


def test_the_first_failing_step_ends_the_job_and_is_recorded(tmp_path, monkeypatch):
    probe = tmp_path / "probe.py"
    spec, body = _spec(tmp_path)
    body["steps"] = [["{python}", str(probe), "3"], ["{python}", str(probe), "never"]]
    spec.write_text(json.dumps(body))
    assert _main(spec, "fresh-real", _creds(tmp_path), monkeypatch) == 3
    assert len((tmp_path / "probe.jsonl").read_text().splitlines()) == 1
    rec = json.loads(Path(body["runs_dir"], "fresh.json").read_text())
    assert rec["ok"] is False and rec["exit"] == 3 and rec["step"] == 1


@pytest.mark.parametrize(
    ("lane", "over", "why"),
    [
        (
            "shadow",
            {"forced_env": {"LAKE_SCHEMA": "intel", "PUBLISH_MODE": "stage"}},
            "not a shadow schema",
        ),
        (
            "shadow",
            {"forced_env": {"LAKE_SCHEMA": "intel_shadow", "PUBLISH_MODE": "live"}},
            "never publishes",
        ),
        (
            "real",
            {"forced_env": {"LAKE_SCHEMA": "intel_shadow", "PUBLISH_MODE": "stage"}},
            "is a shadow schema",
        ),
        ("real", {"forced_env": {"LAKE_SCHEMA": "intel"}}, "never publishes"),
        ("real", {"instance": "other-real"}, "another instance"),
    ],
)
def test_the_lane_guard_and_the_spec_checks_refuse_before_any_step(tmp_path, lane, over, why):
    spec, _ = _spec(tmp_path, lane, **over)
    with pytest.raises(run.Refused, match=why):
        run.load_spec(str(spec), os.getuid(), f"fresh-{lane}")
    assert not (tmp_path / "probe.jsonl").exists()


def test_a_spec_another_user_could_write_is_refused(tmp_path):
    spec, _ = _spec(tmp_path)
    spec.chmod(0o664)
    with pytest.raises(run.Refused, match="writable by no one else"):
        run.load_spec(str(spec), os.getuid(), "fresh-real")
    spec.chmod(0o644)
    with pytest.raises(run.Refused, match="must belong to uid"):
        run.load_spec(str(spec), os.getuid() + 1, "fresh-real")


def test_a_run_for_the_other_lane_or_a_credential_named_like_an_env_value_is_refused(
    tmp_path, monkeypatch, capsys
):
    spec, _ = _spec(tmp_path, "shadow")
    creds = _creds(tmp_path, lane="real")  # the dispatcher says real; the unit is shadow
    assert _main(spec, "fresh-shadow", creds, monkeypatch) == 2
    (creds / "hnx-dispatch").write_text(json.dumps({"run_id": "run-2", "lane": "shadow"}))
    (creds / "APP_MODE").write_text("from-the-store\n")  # loaded, and also the spec's env name
    assert _main(spec, "fresh-shadow", creds, monkeypatch) == 2
    assert not (tmp_path / "probe.jsonl").exists()
    out = capsys.readouterr().out
    assert "share a name" in out and "from-the-store" not in out and "alice" not in out


def test_the_log_carries_no_value_from_the_spec_or_a_credential(tmp_path, monkeypatch, capsys):
    spec, _ = _spec(tmp_path)
    assert _main(spec, "fresh-real", _creds(tmp_path), monkeypatch) == 0
    out = capsys.readouterr().out
    assert out.splitlines() == [
        "hnx-cti-run: fresh-real: started",
        "hnx-cti-run: fresh-real: step 1 started",
        "hnx-cti-run: fresh-real: step 2 started",
    ]


# ----------------------------------------------------------------------------- the state


def _lane(tmp_path: Path, rows: int = 3) -> Path:
    root = tmp_path / "var" / "lib" / "intel" / "real"
    for d in ("data", "state", "podcast/archive"):
        (root / d).mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(root / "data" / "cti.db")
    con.execute("CREATE TABLE seen_urls (u TEXT)")
    con.execute("CREATE TABLE reports (r TEXT)")
    con.executemany("INSERT INTO seen_urls VALUES (?)", [(str(i),) for i in range(rows)])
    con.commit()
    con.close()
    (root / "data" / "terms.json").write_text("{}")
    (root / "state" / "zero_runs.json").write_text("[]")
    (root / "podcast" / "archive" / "weekly.mp3").write_bytes(b"ID3")
    return root


def _export(tmp_path: Path, root: Path) -> Path:
    exports = tmp_path / "var" / "lib" / "intel" / "export"
    exports.mkdir(parents=True, exist_ok=True)
    dest = exports / "real-20261119T000000Z"
    out = state.export(str(root), str(dest), ["data", "state", "podcast"])
    assert out["counts"] == {"reports": 0, "seen_urls": 3} and out["files"] == 5
    return dest


def test_an_export_checks_clean_and_restores_with_the_replaced_directories_moved_aside(tmp_path):
    root = _lane(tmp_path)
    dest = _export(tmp_path, root)
    assert not (dest / "files" / "data" / "cti.db").exists()  # the copy replaces the live store
    assert state.check(str(dest))["rows"] == 3
    (root / "data" / "terms.json").write_text('{"changed": 1}')
    out = state.restore(str(dest), str(root), os.getuid(), os.getgid())
    assert out["restored"] == ["data", "podcast", "state"]
    assert (root / "data" / "terms.json").read_text() == "{}"
    aside = root / f"data.before-restore-{out['stamp']}"
    assert (aside / "terms.json").read_text() == '{"changed": 1}'  # nothing deleted
    assert state.table_counts(str(root / "data" / "cti.db")) == {"reports": 0, "seen_urls": 3}


def test_a_store_whose_row_counts_differ_is_refused(tmp_path):
    dest = _export(tmp_path, _lane(tmp_path))
    con = sqlite3.connect(dest / "cti.db")
    con.execute("DELETE FROM seen_urls WHERE u = '0'")
    con.commit()
    con.close()
    with pytest.raises(state.Refused, match="size or sha256 differs"):
        state.check(str(dest))
    # the listing made to agree, the counts still do not
    rows = [json.loads(x) for x in (dest / "listing.jsonl").read_text().splitlines()]
    for r in rows:
        if r["path"] == "cti.db":
            r["sha256"] = hashlib.sha256((dest / "cti.db").read_bytes()).hexdigest()
            r["size"] = (dest / "cti.db").stat().st_size
    (dest / "listing.jsonl").write_text("".join(json.dumps(r) + "\n" for r in rows))
    with pytest.raises(state.Refused, match=r"row counts differ from counts\.json"):
        state.check(str(dest))


def test_the_sources_own_counts_must_match(tmp_path):
    dest = _export(tmp_path, _lane(tmp_path))
    expect = tmp_path / "source-counts.json"
    expect.write_text(json.dumps({"seen_urls": 4, "reports": 0}))
    with pytest.raises(state.Refused, match="differ from the source's"):
        state.check(str(dest), str(expect))
    assert state.main(["check", str(dest), "--expect-counts", str(expect)]) == 1


def test_an_export_with_an_unlisted_file_or_a_link_is_refused(tmp_path):
    dest = _export(tmp_path, _lane(tmp_path))
    (dest / "files" / "extra.txt").write_text("x")
    with pytest.raises(state.Refused, match="unlisted"):
        state.check(str(dest))
    root = _lane(tmp_path / "b")
    (root / "state" / "link").symlink_to("/etc")
    with pytest.raises(state.Refused, match="link"):
        _export(tmp_path / "b", root)


def test_freshness_judges_ok_and_age(tmp_path):
    runs = tmp_path / "runs"
    runs.mkdir()
    (runs / "fresh.json").write_text(
        json.dumps({"ok": True, "exit": 0, "finished_at": "2026-11-19T10:00:00Z"})
    )
    (runs / "cve.json").write_text(
        json.dumps({"ok": False, "exit": 1, "finished_at": "2026-11-19T10:00:00Z"})
    )
    now = 1_795_086_000  # 2026-11-19T11:00:00Z
    out = state.freshness(str(runs), {"fresh": 7200, "cve": 90000, "rotation": 3600}, now)
    assert out["jobs"]["fresh"]["fresh"] and out["jobs"]["fresh"]["age_s"] == 3600
    assert (
        not out["jobs"]["cve"]["fresh"] and not out["jobs"]["rotation"]["fresh"] and not out["ok"]
    )
    assert not state.freshness(str(runs), {"fresh": 1800}, now)["ok"]


@pytest.mark.parametrize(
    ("status", "body", "ok"),
    [
        (
            200,
            {
                "choices": [
                    {"message": {"content": "A CVE is an identifier."}, "finish_reason": "stop"}
                ]
            },
            True,
        ),
        (
            200,
            {
                "choices": [
                    {
                        "message": {"content": "", "reasoning_content": "..."},
                        "finish_reason": "length",
                    }
                ]
            },
            False,
        ),
        (200, {"choices": [{"message": {"content": None}}]}, False),
        (200, {"error": "no"}, False),
        (500, {}, False),
    ],
)
def test_the_gateway_probe_passes_only_on_content(status, body, ok):
    assert state.completion_verdict(status, json.dumps(body).encode())["ok"] is ok


def test_prune_exports_keeps_the_newest_of_its_lane(tmp_path):
    d = tmp_path / "var" / "lib" / "export"
    d.mkdir(parents=True)
    names = [f"real-2026111{i}T000000Z" for i in range(4)] + ["shadow-20261110T000000Z", "keep-me"]
    for n in names:
        (d / n).mkdir()
    out = state.prune_exports(str(d), "real", 2)
    assert sorted(out["removed"]) == names[:2]
    assert sorted(p.name for p in d.iterdir()) == sorted(names[2:])
