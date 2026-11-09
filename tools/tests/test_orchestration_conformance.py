# SPDX-License-Identifier: Apache-2.0
"""The orchestration suite's fault injection against this repository's controller (ADR-0026 stage
2, PR 2.8): the two MUST checks that need it run and pass on the real binary, and the pieces they
rest on (the runner body's pid file, the adapter's process faults) hold on their own."""

from __future__ import annotations

import json
import os
import re
import signal
import sqlite3
import subprocess
import sys
import time
from pathlib import Path

import pytest

from conformance.fakes import llm_orchestrator_hermes as body
from homelabnext.conform.adapters import orchestrator as adapter
from homelabnext.conform.adapters._env import AdapterConfigError
from tests.conform.controller_rig import build_controller

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))
import orchestration_conformance as harness

RUN = "0123456789abcdef0123456789abcdef"
FAULT_CHECKS = harness.FAULT_CHECKS


def test_the_fault_injection_checks_pass_strict_on_the_real_controller(tmp_path):
    binary = build_controller(tmp_path)  # CI's prebuilt one (HNX_CONTROLLER_BIN), or a build
    out = tmp_path / "result.json"
    args = [
        "run",
        "--controller",
        str(binary),
        "--work",
        str(tmp_path / "work"),
        "--strict",
        "--out",
        str(out),
    ]
    for c in FAULT_CHECKS:
        args += ["--check", c]
    work = tmp_path / "work"
    rc = harness.main(args)
    assert rc == 0, f"harness exit {rc}\n{_diagnose(work, out)}"
    (run,) = json.loads(out.read_text())["runs"]
    results = {r["check"]: r["status"] for r in run["results"]}
    assert results == dict.fromkeys(FAULT_CHECKS, "pass"), f"{results}\n{_diagnose(work, out)}"
    assert harness.main(["verdict", str(out)]) == 0  # the report CI's verdict step reads
    # a session that ended removed its pid file; one that was killed left it, and is not running
    for p in (tmp_path / "work" / "pids").glob("*.pid"):
        assert not harness.is_session(int(p.read_text()), p.name.removesuffix(".pid")), p
    # the restart check's executing run was reconciled by the restarted controller: failed with
    # the reconciliation's reason, and never retried (a session killed while the controller ran
    # would have been a recorded failure, with an automatic retry of the work)
    db = sqlite3.connect(tmp_path / "work" / "state" / "controller.db")
    try:
        reconciled = [
            r
            for (r,) in db.execute(
                "SELECT run_id FROM jobs WHERE local_failed_reason LIKE ?",
                ("%controller-restart-reconciliation%",),
            )
        ]
        assert len(reconciled) == 1, f"reconciled runs {reconciled}\n{_diagnose(work, out)}"
        retries = db.execute(
            "SELECT COUNT(*) FROM jobs WHERE retry_of_run_id = ?", (reconciled[0],)
        ).fetchone()[0]
        assert retries == 0, (
            f"the reconciled run {reconciled[0]} was retried\n{_diagnose(work, out)}"
        )
    finally:
        db.close()


def _diagnose(work: Path, out: Path) -> str:
    """What a failed strict run leaves to read: every job row, each failing check's evidence, the
    controller log's tail."""
    lines = []
    try:
        db = sqlite3.connect(work / "state" / "controller.db")
        try:
            for row in db.execute(
                "SELECT run_id, agent_key, state, attempts, retry_of_run_id, local_failed_reason FROM jobs ORDER BY seq"
            ):
                lines.append("job " + " | ".join(str(c)[:160] for c in row))
        finally:
            db.close()
    except sqlite3.Error as exc:
        lines.append(f"(no job rows: {exc})")
    try:
        for r in json.loads(out.read_text())["runs"][0]["results"]:
            if r["status"] != "pass":
                lines.append(f"check {r['check']}: {r['status']}: {str(r.get('evidence'))[:400]}")
    except (OSError, ValueError, KeyError, IndexError):
        lines.append("(no suite result)")
    try:
        tail = (work / "controller.log").read_text(errors="replace").splitlines()[-40:]
        lines += ["controller log:", *tail]
    except OSError:
        lines.append("(no controller log)")
    return "\n".join(lines)


def test_the_runner_body_records_its_session_pid(tmp_path):
    path = body.write_pid_file({body.PID_DIR_ENV: str(tmp_path), "HNX_RUN_ID": RUN}, 4242)
    assert path == tmp_path / f"{RUN}.pid" and path.read_text() == "4242\n"
    assert not list(tmp_path.glob("*.tmp"))
    assert body.write_pid_file({"HNX_RUN_ID": RUN}, 1) is None
    assert body.write_pid_file({body.PID_DIR_ENV: str(tmp_path), "HNX_RUN_ID": "../x"}, 1) is None


def test_the_runner_body_reads_its_prompt_from_stdin():
    code, _, err = body.run(["--stdin"], stdin=lambda: "no job line here")
    assert code == 1 and "no hnx-conform-job: line" in err
    code, _, err = body.run([], stdin=lambda: "x")
    assert code == 2 and "--stdin" in err


def test_process_faults_kill_the_recorded_session(tmp_path, caplog):
    proc = subprocess.Popen(["sleep", "30"], env=dict(os.environ, HNX_RUN_ID=RUN))
    other = subprocess.Popen(["sleep", "30"])  # a reused pid: not the run's session
    try:
        faults = adapter.ProcessFaults(tmp_path, ["true"], lambda: True)
        other_run = "c" * 32
        (tmp_path / f"{other_run}.pid").write_text(f"{other.pid}\n")
        faults.kill(other_run)
        (tmp_path / f"{'b' * 32}.pid").write_text("1\n")
        faults.kill("b" * 32)  # never pid 1
        assert other.poll() is None, "a process that is not the run's session was killed"
        said = caplog.text
        assert "no longer that run's session" in said and "refused pid 1" in said, said
        (tmp_path / f"{RUN}.pid").write_text(f"{proc.pid}\n")
        faults.kill(RUN)
        assert proc.wait(timeout=30) == -signal.SIGKILL
        with pytest.raises(ValueError):
            faults.kill("../../etc")
    finally:
        for p in (proc, other):
            p.kill()
            p.wait()


def test_process_faults_restart_runs_the_command_and_waits_for_health(tmp_path):
    marker = tmp_path / "restarted"
    calls = []

    def healthy():
        calls.append(1)
        return len(calls) > 2

    faults = adapter.ProcessFaults(tmp_path, ["touch", str(marker)], healthy, sleep=lambda s: None)
    faults.restart()
    assert marker.exists() and len(calls) == 3
    failing = adapter.ProcessFaults(tmp_path, ["false"], lambda: True)
    with pytest.raises(Exception, match="restart command failed"):
        failing.restart()
    clock = iter(range(0, 1000, 10))
    never = adapter.ProcessFaults(
        tmp_path, ["true"], lambda: False, wait_s=5, clock=lambda: next(clock), sleep=lambda s: None
    )
    with pytest.raises(Exception, match="did not answer"):
        never.restart()


def test_a_session_without_a_pid_file_is_not_measured(tmp_path):
    clock = iter(range(0, 1000, 10))
    faults = adapter.ProcessFaults(
        tmp_path, ["true"], lambda: True, wait_s=5, clock=lambda: next(clock), sleep=lambda s: None
    )
    with pytest.raises(Exception, match="no session pid"):
        faults.kill(RUN)


def test_fault_injection_needs_both_settings(monkeypatch, tmp_path):
    monkeypatch.setenv("HNX_ENDPOINT_ORCHESTRATION", f"http://{harness.LOOPBACK}:9")
    monkeypatch.setenv(adapter.PROFILES_ENV, str(tmp_path))
    monkeypatch.delenv(adapter.PID_DIR_ENV, raising=False)
    monkeypatch.delenv(adapter.RESTART_ENV, raising=False)
    with pytest.raises(AdapterConfigError, match=adapter.PID_DIR_ENV):
        adapter.make(fault_injection=True)
    monkeypatch.setenv(adapter.PID_DIR_ENV, str(tmp_path))
    monkeypatch.setenv(adapter.RESTART_ENV, "not json")
    with pytest.raises(AdapterConfigError, match="JSON"):
        adapter.make(fault_injection=True)
    monkeypatch.setenv(adapter.RESTART_ENV, json.dumps(["restart"]))
    subject = adapter.make(fault_injection=True)
    assert isinstance(subject._faults, adapter.ProcessFaults)
    assert adapter.make()._faults is None  # a target without fault_injection declares none


def test_the_harness_refuses_a_used_work_directory(tmp_path):
    (tmp_path / "x").write_text("")
    assert harness.main(["run", "--controller", "/bin/true", "--work", str(tmp_path)]) == 2
    assert harness.main(["run", "--controller", "/bin/true", "--work", "relative"]) == 2


def test_the_harness_config_gives_sessions_only_the_pid_directory(tmp_path):
    cfg = json.loads(harness.write_config(tmp_path, 18000).read_text())
    assert cfg["runner"]["env_allowlist"] == ["HNX_CONFORM_PID_DIR"]
    assert cfg["api_auth"] == {"enabled": False} and cfg["http_addr"].startswith(
        harness.LOOPBACK + ":"
    )
    assert "{prompt}" not in cfg["runner"]["exec"]["argv"]  # the prompt goes on stdin


def _spawn(argv, **env):
    return subprocess.Popen(argv, env=dict(os.environ, **env), start_new_session=True)


def _fake_controller(work: Path) -> subprocess.Popen:
    """A process whose command line is exactly what start() gives the controller of ``work``."""
    (work / "serve").write_text("while :; do sleep 1; done\n")  # sh runs it in place: argv stays
    binary = str(work / "controller")
    (work / "controller.bin").write_text(binary + "\n")
    proc = subprocess.Popen(
        [
            "bash",
            "-c",
            'exec -a "$0" sh "$@"',
            binary,
            "serve",
            "--config",
            str(work / "controller.yaml"),
        ],
        cwd=work,
        start_new_session=True,
    )
    # bash execs into the stand-in: wait until the command line is the controller's
    deadline = time.monotonic() + 30
    while not harness.is_controller(proc.pid, work):
        assert time.monotonic() < deadline, "the stand-in controller never started"
        time.sleep(0.01)
    return proc


def test_a_restart_kills_the_controller_before_its_sessions(tmp_path, monkeypatch):
    """A session killed while its controller still runs is a failure that controller records
    (and retries), not a crash it reconciles: the controller goes first, and is waited for."""
    work = tmp_path
    (work / "pids").mkdir()
    controller = _fake_controller(work)
    session = _spawn(["sleep", "30"], HNX_RUN_ID=RUN)
    stale = _spawn(["sleep", "30"], HNX_RUN_ID="f" * 32)  # a pid file naming another run's pid
    impostor = _spawn(["sleep", "30"])  # serve --config elsewhere is not this controller
    try:
        (work / "controller.pid").write_text(f"{controller.pid}\n")
        (work / "pids" / f"{RUN}.pid").write_text(f"{session.pid}\n")
        (work / "pids" / f"{'e' * 32}.pid").write_text(f"{stale.pid}\n")
        (work / "pids" / f"{'d' * 32}.pid").write_text("1\n")
        assert not harness.is_controller(impostor.pid, work)
        order = []
        real_kill = harness._kill

        def kill(pid, still):
            if real_kill(pid, still):
                order.append(pid)
            return pid in order

        monkeypatch.setattr(harness, "_kill", kill)
        harness.stop(work)
        assert order == [controller.pid, session.pid], order
        assert not Path(f"/proc/{controller.pid}").exists(), "the controller was not waited for"
        assert session.wait(timeout=30) == -signal.SIGKILL
        assert stale.poll() is None, "a pid that was no longer the run's session was killed"
        assert not list((work / "pids").glob("*.pid"))
    finally:
        for p in (controller, session, stale, impostor):
            p.kill()
            p.wait()


def test_a_restart_fails_loudly_when_the_controller_outlives_its_kill(tmp_path, monkeypatch):
    """A controller still running after the wait is a failed restart, never a silent one: its
    sessions are left alone (killed under it they would be retried, not reconciled)."""
    work = tmp_path
    (work / "pids").mkdir()
    controller = _fake_controller(work)
    session = _spawn(["sleep", "30"], HNX_RUN_ID=RUN)
    try:
        (work / "controller.pid").write_text(f"{controller.pid}\n")
        (work / "pids" / f"{RUN}.pid").write_text(f"{session.pid}\n")
        # a controller that survives its SIGKILL (stuck in the kernel, say): the kill is "sent"
        # and the wait runs out
        monkeypatch.setattr(harness, "_kill", lambda pid, still=None: still is None or still(pid))
        monkeypatch.setattr(harness, "_gone", lambda pid, wait_s=None: False)
        with pytest.raises(RuntimeError, match="still runs"):
            harness.stop(work)
        assert session.poll() is None, "a session was killed under a live controller"
        assert harness.cmd_restart(work) == 1
    finally:
        for p in (controller, session):
            p.kill()
            p.wait()


def _ci() -> dict:
    import yaml

    return yaml.safe_load((ROOT / ".github" / "workflows" / "ci.yml").read_text())


def test_the_ci_job_runs_the_check_and_the_strict_suite_on_loopback():
    job = _ci()["jobs"]["orchestration-conformance"]
    assert "if" not in job and "continue-on-error" not in job
    assert not any("continue-on-error" in step or "if" in step for step in job["steps"])
    runs = [s.get("run", "") for s in job["steps"]]
    assert any("make controller-check" in r for r in runs)
    last, verdict = runs[-2:]
    assert "tools/orchestration_conformance.py run" in last and "--strict" in last
    # the run writes its report, and the job fails unless both fault checks in it passed
    assert '--out "$OUT"' in last and '"OUT=$RUNNER_TEMP/orchestration.json"' in last
    assert "tools/orchestration_conformance.py verdict" in verdict
    assert '"$RUNNER_TEMP/orchestration.json"' in verdict
    # loopback only, as the runner user under no_new_privs
    assert "unshare --net" in last and "setpriv --no-new-privs --reuid=" in last
    assert job["env"] == {"GOFLAGS": "-mod=readonly", "GOTOOLCHAIN": "local", "GOWORK": "off"}
    for step in job["steps"]:
        if "uses" in step:
            assert re.fullmatch(r"[\w-]+/[\w-]+@[0-9a-f]{40}", step["uses"]), step["uses"]


def test_go_ok_requires_the_orchestration_job():
    ok = _ci()["jobs"]["go-ok"]
    assert "orchestration-conformance" in ok["needs"] and ok["if"] == "always()"
    (step,) = ok["steps"]
    assert step["env"]["ORCHESTRATION"] == "${{ needs.orchestration-conformance.result }}"
    assert '[ "$ORCHESTRATION" = success ]' in step["run"]


def test_a_kill_without_pidfds_does_not_claim_the_session_ended(tmp_path, monkeypatch, caplog):
    """ENOSYS from pidfd_open says nothing about the session, so the skip must not say it ended."""
    import errno

    def no_pidfds(pid):
        raise OSError(errno.ENOSYS, "Function not implemented")

    monkeypatch.setattr(adapter.os, "pidfd_open", no_pidfds)
    (tmp_path / f"{RUN}.pid").write_text("4242\n")
    adapter.ProcessFaults(tmp_path, ["true"], lambda: True).kill(RUN)
    assert "not signalled" in caplog.text and "already ended" not in caplog.text, caplog.text


def test_the_harness_says_it_is_linux_only(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(harness.sys, "platform", "darwin")
    work = tmp_path / "work"
    assert harness.main(["run", "--controller", "/bin/true", "--work", str(work)]) == 2
    assert harness.main(["restart", "--work", str(work)]) == 2
    err = capsys.readouterr().err
    assert err.count("Linux only") == 2 and not work.exists(), err


def test_a_run_whose_stop_fails_says_so_in_one_line(tmp_path, monkeypatch, capsys):
    """cmd_run's stop() raising in its finally is a one-line failure, as in cmd_restart, not a
    traceback that hides the suite's verdict."""
    monkeypatch.setattr(harness, "write_config", lambda work, port: None)
    monkeypatch.setattr(harness, "free_port", lambda: 0)
    monkeypatch.setattr(harness, "start", lambda work: (work / "endpoint").write_text("http://x\n"))

    def stuck(work):
        raise RuntimeError("the controller (pid 7) still runs")

    monkeypatch.setattr(harness, "stop", stuck)
    monkeypatch.setattr(
        harness.subprocess, "run", lambda *a, **k: subprocess.CompletedProcess(a, 0)
    )
    rc = harness.main(["run", "--controller", "/bin/true", "--work", str(tmp_path / "w")])
    err = capsys.readouterr().err
    assert (
        rc == 1 and err == "orchestration-conformance: run: the controller (pid 7) still runs\n"
    ), err


def _report(tmp_path, ok=True, **status) -> Path:
    results = [{"check": c, "status": status.get(c, "pass")} for c in FAULT_CHECKS]
    path = tmp_path / "report.json"
    path.write_text(json.dumps({"runs": [{"ok": ok, "results": results}]}))
    return path


def test_the_verdict_needs_both_fault_checks_passed(tmp_path, capsys):
    """A strict run whose target lost fault_injection: true can pass with the fault checks
    skipped; the verdict CI runs after it cannot."""
    assert harness.main(["verdict", str(_report(tmp_path))]) == 0
    skipped = {FAULT_CHECKS[1]: "skip"}
    assert harness.main(["verdict", str(_report(tmp_path, **skipped))]) == 1
    assert f"{FAULT_CHECKS[1]}: skip" in capsys.readouterr().err
    assert harness.main(["verdict", str(_report(tmp_path, ok=False))]) == 1
    absent = tmp_path / "absent.json"
    absent.write_text(json.dumps({"runs": [{"ok": True, "results": []}]}))
    assert harness.main(["verdict", str(absent)]) == 1
    assert "not run" in capsys.readouterr().err
    (tmp_path / "junk.json").write_text("{")
    assert harness.main(["verdict", str(tmp_path / "junk.json")]) == 1


def test_a_prebuilt_controller_is_used_and_never_silently_rebuilt(tmp_path, monkeypatch):
    """CI's Go leg builds the controller once before the network namespace; the tests take it
    from HNX_CONTROLLER_BIN, and a bad value fails rather than falling back to a build."""
    import tests.conform.controller_rig as rig

    prebuilt = tmp_path / "controller"
    prebuilt.write_text("#!/bin/sh\n")
    prebuilt.chmod(0o755)
    monkeypatch.setattr(rig.subprocess, "run", lambda *a, **k: pytest.fail(f"built: {a}"))
    monkeypatch.setenv(rig.PREBUILT_ENV, str(prebuilt))
    assert build_controller(tmp_path / "unused") == prebuilt
    for bad in ("controller", str(tmp_path / "absent")):
        monkeypatch.setenv(rig.PREBUILT_ENV, bad)
        with pytest.raises(pytest.fail.Exception, match="HNX_CONTROLLER_BIN"):
            build_controller(tmp_path / "unused")


def test_the_go_test_leg_builds_the_controller_once_for_its_shards():
    job = _ci()["jobs"]["test"]
    (build,) = [s for s in job["steps"] if "go build" in s.get("run", "")]
    assert build["if"] == "matrix.python.go" and build["working-directory"] == "orchestrator"
    assert (
        build["run"] == 'go mod download && go build -o "$RUNNER_TEMP/controller" ./cmd/controller'
    )
    (suite,) = [s for s in job["steps"] if "pytest" in s.get("run", "")]
    assert suite["env"]["HNX_CONTROLLER_BIN"] == (
        "${{ matrix.python.go && format('{0}/controller', runner.temp) || '' }}"
    )
