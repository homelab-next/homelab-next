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
import pwd
import sqlite3
import subprocess
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
        (
            {**GOOD, "app/run.py/inner": b"x"},
            None,
            "does not unpack cleanly",
        ),  # a file, then a dir in it
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

USER = pwd.getpwuid(os.getuid()).pw_name


def _release(install: Path, name: str) -> Path:
    rel = install / "releases" / name
    (rel / "app").mkdir(parents=True)
    (rel / ".hnx-installed").write_text(name + "\n")
    return rel


def _point(install: Path, name: str) -> None:
    tmp = install / ".current.new"
    tmp.symlink_to(install / "releases" / name)
    os.replace(tmp, install / "current")


def _spec(tmp_path: Path, lane: str = "real", **over) -> tuple[Path, dict]:
    root = tmp_path / "var" / "lib" / "intel" / lane
    (root / "hnx-runs").mkdir(parents=True)
    (root / "hnx-consumed").mkdir()
    install = tmp_path / "opt" / "hnx" / "intel"
    if not (install / "current").exists():
        _release(install, "a" * 16)
        _release(install, "b" * 16)
        _point(install, "a" * 16)
    (tmp_path / "run" / "intel").mkdir(parents=True, exist_ok=True)
    probe = tmp_path / "probe.py"
    probe.write_text(
        "import json, os, sys\n"
        "out = {k: os.environ.get(k) for k in ['FEED_USER', 'APP_MODE', 'LAKE_SCHEMA', 'PUBLISH_MODE', 'HNX_RUN_ID']}\n"
        "out['argv'] = sys.argv[1:]\nout['cwd'] = os.getcwd()\n"
        "open(os.environ['PROBE_OUT'], 'a').write(json.dumps(out) + '\\n')\n"
        "sys.exit(int(sys.argv[1]) if sys.argv[1:2] and sys.argv[1].isdigit() else 0)\n"
    )
    for rel in ("a" * 16, "b" * 16):  # the shadow lane runs it as {app}/probe.py (its allowlist)
        (install / "releases" / rel / "app" / "probe.py").write_text(probe.read_text())
    prog = "{app}/probe.py" if lane == "shadow" else str(probe)
    spec = {
        "version": 1, "set": "intel", "job": "fresh", "lane": lane, "instance": f"fresh-{lane}",
        "lane_root": str(root), "runs_dir": str(root / "hnx-runs"),
        "steps": [["{python}", prog, "first"], ["{python}", prog, "{lane_root}", "{app}"]],
        "env": {"APP_MODE": "x", "PROBE_OUT": str(tmp_path / "probe.jsonl")},
        "forced_env": {"LAKE_SCHEMA": "intel_shadow" if lane == "shadow" else "intel", "PUBLISH_MODE": "stage"},
        "lake_schema_env": "LAKE_SCHEMA", "publish_mode_env": "PUBLISH_MODE", "real_lake_schema": "intel",
        "release_link": str(install / "current"),
        "run_file": str(tmp_path / "run" / "intel" / f"fresh-{lane}.json"), "run_owner": USER,
        "consumed_dir": str(root / "hnx-consumed"),
        "placeholders": {"python": sys.executable, "lane_root": str(root), "app": str(install / "current" / "app")},
    }  # fmt: skip
    spec.update(over)
    path = tmp_path / "etc" / f"fresh-{lane}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(spec))
    path.chmod(0o644)
    return path, spec


NOW = 1_795_086_000  # 2026-11-19T11:00:00Z: the wrapper's clock in these tests


@pytest.fixture(autouse=True)
def _clock(monkeypatch):
    monkeypatch.setattr(run, "now_epoch", lambda: NOW)


def _run_file(spec: dict, run_id: str = "run-1", dispatch: str = "d" * 32, **over) -> Path:
    raw = over.pop("_raw", None)
    body = {"version": 2, "dispatch_id": dispatch, "run_id": run_id, "lane": spec["lane"],
            "agent_key": "intel-fresh", "job": spec["job"],
            "unit": f"hnx-intel@{spec['instance']}.service", "task": "",
            "dispatched_at": "2026-11-19T10:00:00Z", **over}  # fmt: skip
    path = Path(spec["run_file"])
    path.write_text(raw or json.dumps(body))
    path.chmod(0o640)
    return path


def _creds(tmp_path: Path) -> Path:
    d = tmp_path / "creds"
    d.mkdir(exist_ok=True)
    (d / "FEED_USER").write_text("alice\n")
    return d


def _main(spec: Path, instance: str, creds: Path, monkeypatch) -> int:
    # the wrapper changes into the lane root: monkeypatch puts this process's directory back after
    # the test (other suites resolve paths against it)
    monkeypatch.chdir(os.getcwd())
    monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(creds))
    return run.main(["--spec", str(spec), "--instance", instance, "--spec-owner", str(os.getuid())])


def _rows(tmp_path: Path) -> list[dict]:
    p = tmp_path / "probe.jsonl"
    return [json.loads(x) for x in p.read_text().splitlines()] if p.exists() else []


def test_the_steps_run_in_the_lane_root_with_the_credentials_in_their_environment_only(
    tmp_path, monkeypatch, capsys
):
    spec, body = _spec(tmp_path)
    _run_file(body)
    assert _main(spec, "fresh-real", _creds(tmp_path), monkeypatch) == 0
    rows = _rows(tmp_path)
    assert [r["argv"][0] for r in rows] == ["first", body["lane_root"]]
    assert {r["cwd"] for r in rows} == {body["lane_root"]}
    assert rows[0]["FEED_USER"] == "alice" and rows[0]["APP_MODE"] == "x"
    assert rows[0]["HNX_RUN_ID"] == "run-1"
    assert rows[0]["LAKE_SCHEMA"] == "intel" and rows[0]["PUBLISH_MODE"] == "stage"
    assert "alice" not in capsys.readouterr().out  # never in the log
    rec = json.loads(Path(body["runs_dir"], "fresh.json").read_text())
    assert rec["ok"] is True and rec["exit"] == 0 and rec["run_id"] == "run-1"
    assert sorted(p.name for p in Path(body["consumed_dir"]).iterdir()) == ["d" * 32]


def test_a_retry_with_the_same_run_id_runs_and_a_copied_run_file_is_refused(tmp_path, monkeypatch):
    spec, body = _spec(tmp_path)
    _run_file(body, run_id="run-1", dispatch="a" * 32)
    assert _main(spec, "fresh-real", _creds(tmp_path), monkeypatch) == 0
    # the controller retries the run: the same run id, a fresh dispatch: it runs
    _run_file(body, run_id="run-1", dispatch="b" * 32)
    assert _main(spec, "fresh-real", _creds(tmp_path), monkeypatch) == 0
    assert sorted(p.name for p in Path(body["consumed_dir"]).iterdir()) == ["a" * 32, "b" * 32]
    # the first dispatch's file presented again (copied back): refused as consumed
    _run_file(body, run_id="run-1", dispatch="a" * 32)
    assert _main(spec, "fresh-real", _creds(tmp_path), monkeypatch) == 2
    assert len(_rows(tmp_path)) == 4  # two runs of two steps; the replay ran nothing


def test_consumed_markers_past_the_keep_window_are_pruned_and_nothing_else(tmp_path):
    _, body = _spec(tmp_path)
    consumed = Path(body["consumed_dir"])
    old, fresh, linked = "1" * 32, "2" * 32, "3" * 32
    for name in (old, fresh, "not-a-dispatch"):
        (consumed / name).write_text("")
    outside = tmp_path / "outside"
    outside.write_text("keep")
    (consumed / linked).symlink_to(outside)
    stale = NOW - run.KEEP_S - 60
    for name in (old, "not-a-dispatch"):
        os.utime(consumed / name, (stale, stale))
    os.utime(consumed / linked, (stale, stale), follow_symlinks=False)
    _run_file(body, dispatch="4" * 32)
    run.dispatch_run(body)
    left = sorted(p.name for p in consumed.iterdir())
    assert left == sorted([fresh, linked, "4" * 32, "not-a-dispatch"])
    assert outside.read_text() == "keep"


@pytest.mark.parametrize(
    "over",
    [
        {"dispatched_at": "2026-10-01T10:00:00Z"},  # older than the keep window
        {"dispatched_at": "2026-11-19T12:30:00Z"},  # more than an hour ahead
        {"dispatched_at": "yesterday"},
    ],
)
def test_a_run_file_outside_the_keep_window_is_refused(tmp_path, over):
    _, body = _spec(tmp_path)
    _run_file(body, **over)
    with pytest.raises(run.Refused, match=r"dispatched_at|keep window"):
        run.dispatch_run(body)
    assert list(Path(body["consumed_dir"]).iterdir()) == []


def test_a_deeply_nested_run_file_is_a_refusal_not_a_crash(tmp_path):
    _, body = _spec(tmp_path)
    _run_file(body, _raw="[" * 100_000 + "]" * 100_000)
    with pytest.raises(run.Refused, match="not UTF-8 JSON"):
        run.dispatch_run(body)


def _hard_link(path: Path) -> None:
    other = path.with_name("other.json")
    os.link(path, other)


@pytest.mark.parametrize(
    "kind", ["symlink", "directory", "fifo", "hardlink", "writable", "foreign", "big"]
)
def test_a_run_file_that_is_not_the_dispatchers_is_refused_before_it_is_read(
    tmp_path, monkeypatch, kind
):
    spec, body = _spec(tmp_path)
    path = Path(body["run_file"])
    if kind == "symlink":
        real = _run_file(body).rename(tmp_path / "elsewhere.json")
        path.symlink_to(real)
    elif kind == "directory":
        path.mkdir()
    elif kind == "fifo":
        os.mkfifo(path)  # O_NONBLOCK: the open never waits for a writer
    elif kind == "hardlink":
        _hard_link(_run_file(body))
    elif kind == "writable":
        _run_file(body).chmod(0o662)
    elif kind == "foreign":
        body["run_owner"] = "root" if os.getuid() != 0 else "nobody"
        spec.write_text(json.dumps(body))
        _run_file(body)
    else:
        _run_file(body, task="x" * (300 << 10))
    with pytest.raises(run.Refused):
        run.dispatch_run(body)
    assert list(Path(body["consumed_dir"]).iterdir()) == []


@pytest.mark.parametrize(
    "over",
    [
        {"lane": "shadow"},
        {"job": "other"},
        {"unit": "@".join(["hnx-other", "fresh-real.service"])},
        {"version": 1},
        {"run_id": "../x"},
        {"agent_key": "Bad Key"},
        {"dispatch_id": "D" * 32},
        {"dispatch_id": "a" * 31},
    ],
)
def test_a_run_file_for_another_run_or_malformed_is_refused(tmp_path, over):
    _, body = _spec(tmp_path)
    _run_file(body, **over)
    with pytest.raises(run.Refused, match="not this instance's run"):
        run.dispatch_run(body)


def test_a_failing_step_ends_the_job_with_1_and_its_own_status_in_the_record(tmp_path, monkeypatch):
    probe = tmp_path / "probe.py"
    spec, body = _spec(tmp_path)
    for i, (status, steps) in enumerate(
        [
            (2, [["{python}", str(probe), "2"], ["{python}", str(probe), "never"]]),
            (143, [["{python}", str(probe), "143"]]),
            (-9, [["{python}", "-c", "import os, signal; os.kill(os.getpid(), signal.SIGKILL)"]]),
        ]
    ):
        body["steps"] = steps
        spec.write_text(json.dumps(body))
        _run_file(
            body, run_id="run-1", dispatch=f"{i}" * 32
        )  # the controller's retries: one run id
        assert _main(spec, "fresh-real", _creds(tmp_path), monkeypatch) == 1  # never 2 or 143
        rec = json.loads(Path(body["runs_dir"], "fresh.json").read_text())
        assert rec["ok"] is False and rec["exit"] == 1 and rec["step_status"] == status
    assert [r["argv"][0] for r in _rows(tmp_path)] == ["2", "143"]  # "never" never ran


def test_the_release_is_pinned_at_start_and_never_pruned_while_a_job_runs_it(tmp_path, monkeypatch):
    spec, body = _spec(tmp_path)
    install = Path(body["release_link"]).parent
    switch = (
        "import os, sys; p = sys.argv[1]; t = p + '.new'; "
        "os.symlink(sys.argv[2], t); os.replace(t, p)"
    )
    body["steps"] = [
        [
            "{python}",
            "-c",
            switch,
            str(install / "current"),
            str(install / "releases" / ("b" * 16)),
        ],
        ["{python}", str(tmp_path / "probe.py"), "{app}"],
    ]
    spec.write_text(json.dumps(body))
    _run_file(body)
    assert _main(spec, "fresh-real", _creds(tmp_path), monkeypatch) == 0
    assert _rows(tmp_path)[0]["argv"] == [str(install / "releases" / ("a" * 16) / "app")]
    # a job holding release a: prune (current b, keep 1) skips it, and removes it once released
    held = dict(body, placeholders=dict(body["placeholders"]))
    _point(install, "a" * 16)
    fd = run.pin_release(held)
    _point(install, "b" * 16)
    out = art.prune(str(install / "releases"), "b" * 16, 1)
    assert out["removed"] == [] and out["in_use"] == ["a" * 16]
    os.close(fd)
    assert art.prune(str(install / "releases"), "b" * 16, 1)["removed"] == ["a" * 16]


@pytest.mark.parametrize(
    ("lane", "over", "why"),
    [
        ("shadow", {"forced_env": {"LAKE_SCHEMA": "intel", "PUBLISH_MODE": "stage"}}, "not a shadow schema"),
        ("shadow", {"forced_env": {"LAKE_SCHEMA": "intel_shadow", "PUBLISH_MODE": "live"}}, "never publishes"),
        ("real", {"forced_env": {"LAKE_SCHEMA": "intel_shadow", "PUBLISH_MODE": "stage"}}, "is a shadow schema"),
        ("real", {"forced_env": {"LAKE_SCHEMA": "intel"}}, "never publishes"),
        ("real", {"instance": "other-real"}, "another instance"),
        ("shadow", {"steps": [["{python}", "{app}/load.py", "--schema", "intel"]]}, "names the real lake schema"),
        ("shadow", {"steps": [["{python}", "{app}/load.py", "--schema=intel"]]}, "names the real lake schema"),
        ("shadow", {"env": {"TABLE": "intel.items"}}, "names the real lake schema"),
        *[("shadow", {"steps": [["{python}", "{app}/load.py", arg]]}, "names the real lake schema")
          for arg in ["|intel|", "<intel>", "+intel", "INTEL", "--schema=INTEL", "Intel.items", "lake.intel.items", "`intel`", "(intel)",
                      "[intel]", "intel;", "{intel}", 'in""tel', "in\\tel", "'intel'"]],
        *[("shadow", {"steps": [step]}, "off the allowlist") for step in [
            ["/bin/sh", "-c", "run --schema in''tel"], ["/usr/bin/env", "python3", "x.py"],
            ["{python}", "-c", "print(1)"], ["{python}", "-Ic", "print(1)"], ["{python}", "-I", "{app}/x.py"],
            ["/usr/bin/perl", "-e", "print 1"], ["/usr/bin/node", "-e", "1"],
            ["/usr/bin/awk", "BEGIN{system(\"x\")}"], ["/usr/bin/fish", "-c", "x"], ["/bin/csh", "-c", "x"],
            ["/usr/bin/flock", "/tmp/l", "-c", "x"], ["/usr/bin/script", "-qc", "x"], ["/usr/bin/xargs", "x"],
            ["/usr/bin/find", ".", "-exec", "x", ";"], ["/usr/bin/nice", "sh", "-c", "x"],
            ["/usr/bin/timeout", "9", "bash", "-c", "x"], ["load.py"], ["{python}", "load.py"],
            ["{app}/../outside.py"], ["{python}", "{app}/a/../../x.py"], ["{python}", "-m", "a;b"],
        ]],
        ("shadow", {"steps": [["{python}", "{app}/x.py", "-m", "intel.items"]]}, "names the real lake schema"),
        ("shadow", {"real_lake_schema": ""}, "does not name the real lake schema"),
    ],
)  # fmt: skip
def test_the_lane_guard_and_the_spec_checks_refuse_before_any_step(tmp_path, lane, over, why):
    steps = over.get("steps") or [["{python}", "{app}/x.py"]]
    if why == "names the real lake schema":  # the token is what refuses, never the allowlist
        assert all(run.shadow_program_ok(step, []) for step in steps)
    spec, _ = _spec(tmp_path, lane, **over)
    with pytest.raises(run.Refused, match=why):
        run.load_spec(str(spec), os.getuid(), f"fresh-{lane}")
    assert not (tmp_path / "probe.jsonl").exists()


def test_a_shadow_job_may_run_a_module_named_like_the_schema_and_paths_that_contain_it(tmp_path):
    spec, _ = _spec(
        tmp_path, "shadow",
        steps=[["{python}", "-m", "intel.cve", "--all"], ["{python}", "{app}/x.py", "intel-rollup"],
               ["{app}/scripts/episode.sh", "weekly"], ["/opt/site/tool", "--day"]],
        shadow_programs=["/opt/site/tool"],
        env={"SITE": "intel-rollup", "DIR": "/var/intel/shadow"},
    )  # fmt: skip
    run.load_spec(str(spec), os.getuid(), "fresh-shadow")


def test_a_spec_another_user_could_write_is_refused(tmp_path):
    spec, _ = _spec(tmp_path)
    spec.chmod(0o664)
    with pytest.raises(run.Refused, match="writable by no one else"):
        run.load_spec(str(spec), os.getuid(), "fresh-real")
    spec.chmod(0o644)
    with pytest.raises(run.Refused, match="must belong to uid"):
        run.load_spec(str(spec), os.getuid() + 1, "fresh-real")


def test_a_credential_named_like_an_env_value_is_refused(tmp_path, monkeypatch, capsys):
    spec, body = _spec(tmp_path, "shadow")
    _run_file(body)
    creds = _creds(tmp_path)
    (creds / "APP_MODE").write_text("from-the-store\n")  # loaded, and also the spec's env name
    assert _main(spec, "fresh-shadow", creds, monkeypatch) == 2
    assert not (tmp_path / "probe.jsonl").exists()
    out = capsys.readouterr().out
    assert "share a name" in out and "from-the-store" not in out and "alice" not in out


def test_the_log_carries_no_value_from_the_spec_or_a_credential(tmp_path, monkeypatch, capsys):
    spec, body = _spec(tmp_path)
    _run_file(body)
    assert _main(spec, "fresh-real", _creds(tmp_path), monkeypatch) == 0
    assert capsys.readouterr().out.splitlines() == [
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


def test_an_export_refuses_a_file_with_more_than_one_link(tmp_path):
    root = _lane(tmp_path)
    os.link(root / "state" / "zero_runs.json", root / "state" / "second.json")
    exports = tmp_path / "var" / "lib" / "intel" / "export"
    exports.mkdir(parents=True)
    with pytest.raises(state.Refused, match="more than one link"):
        state.export(str(root), str(exports / "real-1"), ["data", "state", "podcast"])
    assert list(exports.iterdir()) == []


def test_an_export_never_follows_a_directory_swapped_for_a_link_mid_walk(tmp_path, monkeypatch):
    root = _lane(tmp_path)
    (root / "state" / "sub").mkdir()
    (root / "state" / "sub" / "ok.json").write_text("{}")
    secret = tmp_path / "secrets"
    secret.mkdir()
    (secret / "FEED_USER").write_text("alice")
    listed = state.listdir_fd

    def swap_after_listing(fd):
        names = listed(fd)
        if (
            "sub" in names
            and (root / "state" / "sub").is_dir()
            and not (root / "state" / "sub").is_symlink()
        ):
            (root / "state" / "sub").rename(root / "state" / "sub.moved")
            (root / "state" / "sub").symlink_to(secret)  # the lane swaps it after the listing
        return names

    monkeypatch.setattr(state, "listdir_fd", swap_after_listing)
    exports = tmp_path / "var" / "lib" / "intel" / "export"
    exports.mkdir(parents=True)
    with pytest.raises(state.Refused, match="sub"):
        state.export(str(root), str(exports / "real-1"), ["data", "state", "podcast"])
    assert list(exports.iterdir()) == []  # the stage was removed; nothing of the secret copied


@pytest.mark.parametrize("planted", ["data", "state", "state/inner"])
def test_an_export_refuses_a_linked_directory_anywhere(tmp_path, planted):
    root = _lane(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "cti.db").write_bytes((root / "data" / "cti.db").read_bytes())
    target = root / planted
    if target.exists():
        target.rename(target.with_name(target.name + ".moved"))
    target.symlink_to(outside)
    exports = tmp_path / "var" / "lib" / "intel" / "export"
    exports.mkdir(parents=True)
    with pytest.raises(state.Refused, match=r"link|not a directory"):
        state.export(str(root), str(exports / "real-1"), ["data", "state", "podcast"])
    assert list(exports.iterdir()) == []


def test_restore_stages_beside_the_lane_root_and_only_moves_a_planted_link_aside(tmp_path):
    root = _lane(tmp_path)
    dest = _export(tmp_path, root)
    victim = tmp_path / "victim"
    victim.mkdir()
    (victim / "keep.txt").write_text("untouched")
    import shutil as _shutil

    _shutil.rmtree(root / "state")
    (root / "state").symlink_to(victim)  # the lane plants a link where a directory is restored
    out = state.restore(str(dest), str(root), os.getuid(), os.getgid())
    assert (root / "state").is_dir() and not (root / "state").is_symlink()
    assert (root / f"state.before-restore-{out['stamp']}").is_symlink()  # moved aside, not followed
    assert sorted(p.name for p in victim.iterdir()) == ["keep.txt"]
    assert (victim / "keep.txt").read_text() == "untouched"
    data_root = root.parent
    assert not [p for p in data_root.iterdir() if p.name.startswith(".restore-")]  # stage removed
    assert not [p for p in root.iterdir() if p.name.startswith(".restore")]  # never inside the lane


READER = (
    ROOT / "modules" / "orchestration" / "roles" / "orchestration" / "files" / "hnx-dispatch-read"
)


@pytest.mark.parametrize(
    "case",
    ["ok", "replay", "symlink", "directory", "fifo", "hardlink", "writable", "big", "old", "future",
     "version", "dispatch", "lane", "unit", "nested", "job", "run_id", "agent_key", "task",
     "dispatched_at", "owner"],
)  # fmt: skip
def test_the_wrapper_accepts_and_refuses_exactly_what_the_reference_reader_does(tmp_path, case):
    """The orchestration module's own reader (contract v3) is the reference: on every case the
    wrapper's verdict is the reader's."""
    _, body = _spec(tmp_path)
    path = Path(body["run_file"])
    over = {"old": {"dispatched_at": "2026-10-01T10:00:00Z"},
            "future": {"dispatched_at": "2026-11-19T12:30:00Z"}, "version": {"version": 1},
            "dispatch": {"dispatch_id": "D" * 32}, "lane": {"lane": "shadow"},
            "unit": {"unit": "@".join(["hnx-other", "fresh-real.service"])},
            "big": {"task": "x" * (300 << 10)},
            "nested": {"_raw": "[" * 100_000 + "]" * 100_000}, "job": {"job": "other"},
            "run_id": {"run_id": "../x"}, "agent_key": {"agent_key": "Bad Key"},
            "task": {"task": 7}, "dispatched_at": {"dispatched_at": "2026-11-19 10:00:00"},
            }.get(case, {})  # fmt: skip
    owner_uid = os.getuid()
    if case == "owner":  # a run file of the right shape, but the controller's user is another
        body["run_owner"] = "root" if os.getuid() != 0 else "nobody"
        owner_uid = pwd.getpwnam(body["run_owner"]).pw_uid
    if case == "symlink":
        path.symlink_to(_run_file(body).rename(tmp_path / "elsewhere.json"))
    elif case == "directory":
        path.mkdir()
    elif case == "fifo":
        os.mkfifo(path)
    elif case == "hardlink":
        _hard_link(_run_file(body))
    elif case == "writable":
        _run_file(body).chmod(0o662)
    else:
        _run_file(body, **over)
    theirs = tmp_path / "reader-consumed"
    theirs.mkdir()
    if case == "replay":
        (theirs / ("d" * 32)).write_text("")
        (Path(body["consumed_dir"]) / ("d" * 32)).write_text("")
    r = subprocess.run(
        [sys.executable, "-I", str(READER), "--dir", str(path.parent), "--instance", "fresh-real",
         "--owner-uid", str(owner_uid), "--consumed-dir", str(theirs), "--now", str(NOW)],
        capture_output=True, text=True, timeout=60, check=False,
    )  # fmt: skip
    assert r.returncode in (0, 1), r.stderr
    try:
        run.dispatch_run(body)
        ours = 0
    except run.Refused:
        ours = 1
    assert ours == r.returncode, (case, r.stderr)
    assert (case == "ok") == (ours == 0)


STDLIB_RUNNERS = [
    "timeit",
    "pdb",
    "cProfile",
    "trace",
    "http.server",
    "runpy",
    "code",
    "pip",
    "unittest",
]


def _pinned_shadow(tmp_path, steps, modules=None, packages=None):
    """A shadow spec with ``steps``, its release pinned; the artefact declares ``packages``."""
    _, body = _spec(tmp_path, "shadow", steps=steps, shadow_modules=modules or [])
    install = Path(body["release_link"]).parent
    if packages is not None:
        for rel in ("a" * 16, "b" * 16):
            (install / "releases" / rel / "hnx-artefact.json").write_text(
                json.dumps({"name": "intel-app", "version": "1", "packages": packages})
            )
    fd = run.pin_release(body)
    return body, fd


@pytest.mark.parametrize("module", STDLIB_RUNNERS)
def test_a_shadow_step_never_runs_the_interpreters_own_modules(tmp_path, module):
    body, fd = _pinned_shadow(
        tmp_path, [["{python}", "-m", module, "x"]], modules=["intel"], packages=["intel"]
    )
    try:
        with pytest.raises(run.Refused, match="not the app's own"):
            run.check_release_paths(body)
    finally:
        os.close(fd)


@pytest.mark.parametrize(
    ("modules", "packages", "module", "ok"),
    [
        (["intel"], None, "intel.cve", True),  # the site's list
        (["intel"], None, "intel", True),
        ([], ["intel", "intelx"], "intelx.run", True),  # the artefact's own packages
        ([], ["intel"], "timeit", False),
        ([], None, "intel.cve", False),  # nothing declared: no -m at all
        (["intel"], ["timeit"], "timeit", False),  # the site's list wins over the artefact's
        ([], ["intel"], "intelligence.x", False),  # a prefix is not the package
    ],
)
def test_a_shadow_module_must_be_one_of_the_apps_packages(tmp_path, modules, packages, module, ok):
    body, fd = _pinned_shadow(
        tmp_path, [["{python}", "-m", module]], modules=modules, packages=packages
    )
    try:
        if ok:
            run.check_release_paths(body)
        else:
            with pytest.raises(run.Refused, match="not the app's own"):
                run.check_release_paths(body)
    finally:
        os.close(fd)


@pytest.mark.parametrize("arg", ["{app}/..{lane_root}", "{app}/../../x", "{app}/x/../../y"])
def test_an_app_argument_that_leaves_the_release_once_filled_is_refused(tmp_path, arg):
    body, fd = _pinned_shadow(tmp_path, [["{python}", "{app}/run.py", arg]], modules=["intel"])
    try:
        with pytest.raises(run.Refused, match="leaves the release"):
            run.check_release_paths(body)
    finally:
        os.close(fd)
    body, fd = _pinned_shadow(tmp_path / "ok", [["{python}", "{app}/run.py", "{app}/a/b"]])
    try:
        run.check_release_paths(body)
    finally:
        os.close(fd)


def test_the_artefact_declares_its_packages_as_names_only(tmp_path, releases):
    meta = {"name": "intel-app", "version": "1.0", "packages": ["intel", "x.y"]}
    sha = _tar(tmp_path / "p.tar.gz", {**GOOD, "hnx-artefact.json": json.dumps(meta).encode()})
    with pytest.raises(art.Refused, match="packages"):
        art.install(str(tmp_path / "p.tar.gz"), sha, str(releases), sys.executable)
